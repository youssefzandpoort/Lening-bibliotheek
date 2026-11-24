import re
import click
import secrets
from functools import wraps
from datetime import date, timedelta
from flask import Flask, render_template, request, redirect, url_for, flash, session, abort
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager, UserMixin, login_user, logout_user, login_required, current_user
from flask_wtf import CSRFProtect
from sqlalchemy import or_, func, inspect, text
from werkzeug.security import generate_password_hash, check_password_hash
from itsdangerous import URLSafeTimedSerializer, SignatureExpired, BadSignature


app = Flask(__name__)
app.config["SQLALCHEMY_DATABASE_URI"] = "sqlite:///bib.db"
app.config["SECRET_KEY"] = "b26d28a71494ef17f3f557353a205dfe33fa982c3fc2e000cf0ce2395a2f228a"
app.config["PERMANENT_SESSION_LIFETIME"] = timedelta(minutes=15)
app.config["SESSION_REFRESH_EACH_REQUEST"] = True
db = SQLAlchemy(app)
csrf = CSRFProtect(app)

serializer = URLSafeTimedSerializer(app.config["SECRET_KEY"])

login_manager = LoginManager(app)
login_manager.login_view = "login"
login_manager.login_message = "Log eerst in."

ROLLEN = ("leerling", "leerkracht", "bibliothecaris", "admin")
BEHEER_ROLLEN = ("bibliothecaris", "admin")

STANDAARD_DAGEN = 14      # uitleenperiode als er geen boek- of klasregel is
MAX_VERLENGINGEN = 2      # hoe vaak een uitlening verlengd mag worden
TOON_OPTIES = ("open", "te_laat", "alle")

# Na zoveel keer te laat teruggebracht krijgt een leerling automatisch een maatregel.
MAATREGELEN = {3: "melding", 5: "gedragsnota", 7: "strafstudie"}
SOORTEN = tuple(MAATREGELEN.values())


# ---------- modellen ----------

class Categorie(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    naam = db.Column(db.String(50), unique=True, nullable=False)

    boeken = db.relationship("Boek", back_populates="categorie")


class Boek(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    titel = db.Column(db.String(200), nullable=False)
    auteur = db.Column(db.String(100))
    beschrijving = db.Column(db.Text)
    jaar = db.Column(db.Integer)
    uitleenperiode = db.Column(db.Integer)  # dagen, leeg = standaard of klasregel
    categorie_id = db.Column(db.Integer, db.ForeignKey("categorie.id"))

    categorie = db.relationship("Categorie", back_populates="boeken")
    exemplaren = db.relationship(
        "Exemplaar", back_populates="boek", cascade="all, delete-orphan",
        order_by="Exemplaar.id",
    )

    @property
    def aantal_exemplaren(self):
        return len(self.exemplaren)

    @property
    def aantal_beschikbaar(self):
        return sum(1 for e in self.exemplaren if e.beschikbaar)


class Exemplaar(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    boek_id = db.Column(db.Integer, db.ForeignKey("boek.id"), nullable=False)
    barcode = db.Column(db.String(50), unique=True, nullable=False)
    beschikbaar = db.Column(db.Boolean, nullable=False, default=True)

    boek = db.relationship("Boek", back_populates="exemplaren")
    uitleningen = db.relationship(
        "Uitlening", back_populates="exemplaar", order_by="Uitlening.id"
    )

    @property
    def huidige_uitlening(self):
        for uitlening in self.uitleningen:
            if uitlening.teruggebracht_op is None:
                return uitlening
        return None


class User(UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True)
    naam = db.Column(db.String(100), nullable=False)
    email = db.Column(db.String(120), unique=True, nullable=False)
    wachtwoord_hash = db.Column(db.String(255), nullable=False)
    rol = db.Column(db.String(20), nullable=False, default="leerling")
    actief = db.Column(db.Boolean, nullable=False, default=True)
    klas = db.Column(db.String(20))

    uitleningen = db.relationship("Uitlening", back_populates="user")
    maatregelen = db.relationship("Maatregel", back_populates="user")

    @property
    def is_active(self):
        return self.actief

    @property
    def aantal_te_laat(self):
        """Hoe vaak deze gebruiker een boek te laat heeft teruggebracht."""
        return sum(
            1 for u in self.uitleningen
            if u.teruggebracht_op and u.teruggebracht_op > u.uiterste_datum
        )

    def set_password(self, wachtwoord):
        self.wachtwoord_hash = generate_password_hash(wachtwoord)

    def check_password(self, wachtwoord):
        return check_password_hash(self.wachtwoord_hash, wachtwoord)


class Uitlening(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    exemplaar_id = db.Column(db.Integer, db.ForeignKey("exemplaar.id"), nullable=False)
    user_id = db.Column(db.Integer, db.ForeignKey("user.id"), nullable=False)
    uitgeleend_op = db.Column(db.Date, nullable=False, default=date.today)
    uiterste_datum = db.Column(db.Date, nullable=False)
    teruggebracht_op = db.Column(db.Date)
    aantal_verlengingen = db.Column(db.Integer, nullable=False, default=0)

    exemplaar = db.relationship("Exemplaar", back_populates="uitleningen")
    user = db.relationship("User", back_populates="uitleningen")
    maatregelen = db.relationship("Maatregel", back_populates="uitlening")

    @property
    def is_open(self):
        return self.teruggebracht_op is None

    @property
    def te_laat_dagen(self):
        einde = self.teruggebracht_op or date.today()
        return max(0, (einde - self.uiterste_datum).days)


class KlasPeriode(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    klas = db.Column(db.String(20), unique=True, nullable=False)
    dagen = db.Column(db.Integer, nullable=False)


class Maatregel(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey("user.id"), nullable=False)
    uitlening_id = db.Column(db.Integer, db.ForeignKey("uitlening.id"))
    soort = db.Column(db.String(20), nullable=False)  # melding, gedragsnota, strafstudie
    reden = db.Column(db.String(200), nullable=False)
    datum = db.Column(db.Date, nullable=False, default=date.today)
    afgehandeld = db.Column(db.Boolean, nullable=False, default=False)

    user = db.relationship("User", back_populates="maatregelen")
    uitlening = db.relationship("Uitlening", back_populates="maatregelen")


@login_manager.user_loader
def load_user(user_id):
    user = db.session.get(User, int(user_id))
    if user and user.actief:
        return user
    return None


# ---------- database aanmaken ----------

# Nieuwe kolommen in bestaande tabellen voegt create_all() niet toe.
# Dat doen we hier zelf, zodat je je database niet hoeft te verwijderen.
EXTRA_KOLOMMEN = [
    ("user", "klas", "VARCHAR(20)"),
    ("boek", "uitleenperiode", "INTEGER"),
]


def maak_database():
    db.create_all()
    inspector = inspect(db.engine)
    for tabel, kolom, kolomtype in EXTRA_KOLOMMEN:
        bestaande = [k["name"] for k in inspector.get_columns(tabel)]
        if kolom not in bestaande:
            with db.engine.begin() as verbinding:
                verbinding.execute(
                    text(f'ALTER TABLE "{tabel}" ADD COLUMN {kolom} {kolomtype}')
                )


# ---------- hulpfuncties ----------

def rol_vereist(*rollen):
    def decorator(f):
        @wraps(f)
        def wrapper(*args, **kwargs):
            if not current_user.is_authenticated:
                return login_manager.unauthorized()
            if current_user.rol not in rollen:
                abort(403)
            return f(*args, **kwargs)
        return wrapper
    return decorator


@app.errorhandler(403)
def geen_toegang(e):
    return "Geen toegang: je hebt hier de juiste rol niet voor.", 403


@app.template_filter("datum")
def datum_filter(waarde):
    return waarde.strftime("%d/%m/%Y") if waarde else "-"


def wachtwoord_fout(wachtwoord):
    if len(wachtwoord) < 8:
        return "Wachtwoord moet minstens 8 tekens zijn."
    if not re.search(r"[A-Z]", wachtwoord):
        return "Wachtwoord moet een hoofdletter bevatten."
    if not re.search(r"[a-z]", wachtwoord):
        return "Wachtwoord moet een kleine letter bevatten."
    if not re.search(r"\d", wachtwoord):
        return "Wachtwoord moet een cijfer bevatten."
    return None


def gebruiker_fout(naam, email, rol, klas=""):
    if not naam or len(naam) > 100:
        return "Naam is verplicht (max 100 tekens)."
    if len(email) > 120 or not re.fullmatch(r"[^@\s]+@[^@\s]+\.[^@\s]+", email):
        return "Geef een geldig e-mailadres op."
    if rol not in ROLLEN:
        return "Ongeldige rol."
    if len(klas) > 20:
        return "Klas mag maximaal 20 tekens zijn."
    return None


def lees_boek_formulier():
    """Leest en controleert het boekformulier. Geeft (velden, fout) terug."""
    titel = request.form.get("titel", "").strip()
    auteur = request.form.get("auteur", "").strip()
    beschrijving = request.form.get("beschrijving", "").strip()
    jaar_tekst = request.form.get("jaar", "").strip()
    periode_tekst = request.form.get("uitleenperiode", "").strip()
    categorie_id = request.form.get("categorie_id", type=int)

    fout = None
    jaar = None
    periode = None
    if not titel or len(titel) > 200:
        fout = "Titel is verplicht (max 200 tekens)."
    elif len(auteur) > 100:
        fout = "Auteur mag maximaal 100 tekens zijn."
    elif len(beschrijving) > 2000:
        fout = "Beschrijving mag maximaal 2000 tekens zijn."
    elif jaar_tekst and (not jaar_tekst.isdigit() or not 1000 <= int(jaar_tekst) <= 2100):
        fout = "Jaar moet tussen 1000 en 2100 liggen."
    elif periode_tekst and (not periode_tekst.isdigit() or not 1 <= int(periode_tekst) <= 365):
        fout = "Uitleenperiode moet tussen 1 en 365 dagen liggen."
    else:
        jaar = int(jaar_tekst) if jaar_tekst else None
        periode = int(periode_tekst) if periode_tekst else None
    if not fout and categorie_id and not db.session.get(Categorie, categorie_id):
        fout = "Ongeldige categorie."

    velden = dict(
        titel=titel, auteur=auteur, beschrijving=beschrijving, jaar=jaar,
        uitleenperiode=periode, categorie_id=categorie_id,
    )
    return velden, fout


def alle_categorieen():
    return Categorie.query.order_by(Categorie.naam).all()


def zoek_exemplaar(code):
    """Zoekt een exemplaar op barcode, of op exemplaarnummer."""
    code = code.strip()
    if not code:
        return None
    exemplaar = Exemplaar.query.filter(
        func.lower(Exemplaar.barcode) == code.lower()
    ).first()
    if not exemplaar and code.isdigit():
        exemplaar = db.session.get(Exemplaar, int(code))
    return exemplaar


def uitleenperiode_voor(boek, gebruiker):
    """Boekregel gaat voor klasregel, en die gaat voor de standaard."""
    if boek.uitleenperiode:
        return boek.uitleenperiode
    if gebruiker.klas:
        regel = KlasPeriode.query.filter(
            func.lower(KlasPeriode.klas) == gebruiker.klas.lower()
        ).first()
        if regel:
            return regel.dagen
    return STANDAARD_DAGEN


def naar_overzicht(toon=None):
    toon = toon or request.form.get("toon")
    if toon not in TOON_OPTIES:
        toon = "open"
    return redirect(url_for("uitleningen", toon=toon))


def neem_terug(uitlening):
    uitlening.teruggebracht_op = date.today()
    uitlening.exemplaar.beschikbaar = True
    gebruiker = uitlening.user
    titel = uitlening.exemplaar.boek.titel
    te_laat = uitlening.te_laat_dagen

    boodschap = f"'{titel}' teruggenomen van {gebruiker.naam}."
    if te_laat:
        aantal = gebruiker.aantal_te_laat
        boodschap = (
            f"'{titel}' teruggenomen, maar {te_laat} dag(en) te laat. "
            f"{gebruiker.naam} was nu {aantal} keer te laat."
        )
        soort = MAATREGELEN.get(aantal)
        if soort:
            db.session.add(Maatregel(
                user_id=gebruiker.id, uitlening_id=uitlening.id, soort=soort,
                reden=f"{aantal} keer te laat ingeleverd",
            ))
            boodschap += f" Automatisch geregistreerd: {soort}."
    db.session.commit()
    flash(boodschap)
    return "alle" if te_laat else None


# ---------- publieke pagina's ----------

@app.route("/")
def home():
    return "Hallo bib"


@app.route("/registreren", methods=["GET", "POST"])
def registreren():
    if request.method == "POST":
        naam = request.form["naam"].strip()
        email = request.form["email"].strip().lower()
        wachtwoord = request.form["wachtwoord"]
        rol = request.form["rol"]
        klas = request.form.get("klas", "").strip()

        if rol not in ("leerling", "leerkracht"):
            rol = "leerling"
        fout = gebruiker_fout(naam, email, rol, klas) or wachtwoord_fout(wachtwoord)
        if fout:
            flash(fout)
        elif User.query.filter_by(email=email).first():
            flash("Dit e-mailadres is al in gebruik.")
        else:
            user = User(naam=naam, email=email, rol=rol, klas=klas or None)
            user.set_password(wachtwoord)
            db.session.add(user)
            db.session.commit()
            flash("Account aangemaakt, je kan nu inloggen.")
            return redirect(url_for("login"))
    return render_template("registreren.html")


@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        email = request.form["email"].strip().lower()
        user = User.query.filter_by(email=email).first()
        if user and user.check_password(request.form["wachtwoord"]):
            if not user.actief:
                flash("Dit account is inactief. Neem contact op met de admin.")
            else:
                session.permanent = True
                login_user(user)
                return redirect(url_for("boeken"))
        else:
            flash("Verkeerd e-mailadres of wachtwoord.")
    return render_template("login.html")


@app.route("/logout", methods=["POST"])
@login_required
def logout():
    logout_user()
    return redirect(url_for("login"))


@app.route("/wachtwoord-vergeten", methods=["GET", "POST"])
def wachtwoord_vergeten():
    if request.method == "POST":
        email = request.form["email"].strip().lower()
        user = User.query.filter_by(email=email).first()
        if user:
            token = serializer.dumps(
                {"email": user.email, "h": user.wachtwoord_hash[-10:]}, salt="reset"
            )
            link = url_for("wachtwoord_resetten", token=token, _external=True)
            print("RESET LINK:", link)  # later vervangen door een mail
        flash("Als dit e-mailadres bestaat, is er een resetlink verstuurd.")
        return redirect(url_for("login"))
    return render_template("wachtwoord_vergeten.html")


@app.route("/wachtwoord-resetten/<token>", methods=["GET", "POST"])
def wachtwoord_resetten(token):
    try:
        data = serializer.loads(token, salt="reset", max_age=3600)
    except (SignatureExpired, BadSignature):
        flash("Deze link is ongeldig of verlopen.")
        return redirect(url_for("wachtwoord_vergeten"))

    user = User.query.filter_by(email=data["email"]).first()
    if not user or user.wachtwoord_hash[-10:] != data["h"]:
        flash("Deze link is al gebruikt of ongeldig.")
        return redirect(url_for("wachtwoord_vergeten"))

    if request.method == "POST":
        wachtwoord = request.form["wachtwoord"]
        fout = wachtwoord_fout(wachtwoord)
        if fout:
            flash(fout)
        else:
            user.set_password(wachtwoord)
            db.session.commit()
            flash("Wachtwoord aangepast, je kan nu inloggen.")
            return redirect(url_for("login"))
    return render_template("wachtwoord_resetten.html")


# ---------- boeken ----------

@app.route("/boeken")
@login_required
def boeken():
    q = request.args.get("q", "").strip()
    cat = request.args.get("categorie", type=int)
    sorteer = request.args.get("sorteer", "titel")
    alleen_beschikbaar = request.args.get("beschikbaar") == "1"

    query = Boek.query.outerjoin(Categorie)
    if q:
        zoek = f"%{q}%"
        query = query.filter(or_(
            Boek.titel.ilike(zoek),
            Boek.auteur.ilike(zoek),
            Categorie.naam.ilike(zoek),
        ))
    if cat:
        query = query.filter(Boek.categorie_id == cat)
    if alleen_beschikbaar:
        query = query.filter(Boek.exemplaren.any(Exemplaar.beschikbaar.is_(True)))

    sortering = {
        "titel": Boek.titel,
        "auteur": Boek.auteur,
        "nieuwste": Boek.id.desc(),
    }
    query = query.order_by(sortering.get(sorteer, Boek.titel))

    return render_template(
        "boeken.html", boeken=query.all(), categorieen=alle_categorieen(),
        q=q, cat=cat, sorteer=sorteer, alleen_beschikbaar=alleen_beschikbaar,
    )


@app.route("/boeken/<int:id>")
@login_required
def boek_detail(id):
    boek = db.get_or_404(Boek, id)
    return render_template("boek_detail.html", boek=boek, standaard=STANDAARD_DAGEN)


@app.route("/boeken/nieuw", methods=["GET", "POST"])
@rol_vereist(*BEHEER_ROLLEN)
def boek_toevoegen():
    boek = None
    if request.method == "POST":
        velden, fout = lees_boek_formulier()
        if fout:
            flash(fout)
            boek = Boek(**velden)  # niet opgeslagen, enkel om de invoer te tonen
        else:
            boek = Boek(**velden)
            db.session.add(boek)
            db.session.commit()
            flash("Boek toegevoegd. Voeg hieronder exemplaren toe.")
            return redirect(url_for("boek_detail", id=boek.id))
    return render_template("boek_form.html", boek=boek, categorieen=alle_categorieen(),
                           standaard=STANDAARD_DAGEN)


@app.route("/boeken/<int:id>/bewerken", methods=["GET", "POST"])
@rol_vereist(*BEHEER_ROLLEN)
def boek_bewerken(id):
    boek = db.get_or_404(Boek, id)
    if request.method == "POST":
        velden, fout = lees_boek_formulier()
        if fout:
            flash(fout)
        else:
            for sleutel, waarde in velden.items():
                setattr(boek, sleutel, waarde)
            db.session.commit()
            flash("Boek aangepast.")
            return redirect(url_for("boek_detail", id=boek.id))
    return render_template("boek_form.html", boek=boek, categorieen=alle_categorieen(),
                           standaard=STANDAARD_DAGEN)


@app.route("/boeken/<int:id>/verwijderen", methods=["POST"])
@rol_vereist(*BEHEER_ROLLEN)
def boek_verwijderen(id):
    boek = db.get_or_404(Boek, id)
    if any(e.uitleningen for e in boek.exemplaren):
        flash("Dit boek heeft uitleengeschiedenis en kan niet verwijderd worden.")
        return redirect(url_for("boek_detail", id=boek.id))
    db.session.delete(boek)
    db.session.commit()
    flash("Boek verwijderd.")
    return redirect(url_for("boeken"))


# ---------- exemplaren ----------

@app.route("/boeken/<int:id>/exemplaren/nieuw", methods=["POST"])
@rol_vereist(*BEHEER_ROLLEN)
def exemplaar_toevoegen(id):
    boek = db.get_or_404(Boek, id)
    barcode = request.form.get("barcode", "").strip()
    if len(barcode) > 50:
        flash("Barcode mag maximaal 50 tekens zijn.")
    elif barcode and Exemplaar.query.filter_by(barcode=barcode).first():
        flash("Deze barcode bestaat al.")
    else:
        exemplaar = Exemplaar(
            boek_id=boek.id, barcode=barcode or "TMP-" + secrets.token_hex(4)
        )
        db.session.add(exemplaar)
        db.session.flush()
        if not barcode:
            exemplaar.barcode = f"EX{exemplaar.id:05d}"
        db.session.commit()
        flash(f"Exemplaar {exemplaar.barcode} toegevoegd.")
    return redirect(url_for("boek_detail", id=boek.id))


@app.route("/exemplaren/<int:id>/verwijderen", methods=["POST"])
@rol_vereist(*BEHEER_ROLLEN)
def exemplaar_verwijderen(id):
    exemplaar = db.get_or_404(Exemplaar, id)
    boek_id = exemplaar.boek_id
    if not exemplaar.beschikbaar:
        flash("Dit exemplaar is uitgeleend en kan niet verwijderd worden.")
    elif exemplaar.uitleningen:
        flash("Dit exemplaar heeft uitleengeschiedenis en kan niet verwijderd worden.")
    else:
        db.session.delete(exemplaar)
        db.session.commit()
        flash("Exemplaar verwijderd.")
    return redirect(url_for("boek_detail", id=boek_id))


@app.route("/zoek-barcode")
@rol_vereist(*BEHEER_ROLLEN)
def zoek_barcode():
    code = request.args.get("code", "").strip()
    if code:
        exemplaar = zoek_exemplaar(code)
        if exemplaar:
            return redirect(url_for("boek_detail", id=exemplaar.boek_id))
        flash("Geen exemplaar gevonden met deze barcode of dit nummer.")
    return redirect(url_for("boeken"))


# ---------- categorieen ----------

@app.route("/categorieen", methods=["GET", "POST"])
@rol_vereist(*BEHEER_ROLLEN)
def categorie_beheer():
    if request.method == "POST":
        naam = request.form.get("naam", "").strip()
        if not naam or len(naam) > 50:
            flash("Naam is verplicht (max 50 tekens).")
        elif Categorie.query.filter(func.lower(Categorie.naam) == naam.lower()).first():
            flash("Deze categorie bestaat al.")
        else:
            db.session.add(Categorie(naam=naam))
            db.session.commit()
            flash("Categorie toegevoegd.")
            return redirect(url_for("categorie_beheer"))
    return render_template("categorieen.html", categorieen=alle_categorieen())


@app.route("/categorieen/<int:id>/bewerken", methods=["POST"])
@rol_vereist(*BEHEER_ROLLEN)
def categorie_bewerken(id):
    categorie = db.get_or_404(Categorie, id)
    naam = request.form.get("naam", "").strip()
    bestaand = Categorie.query.filter(func.lower(Categorie.naam) == naam.lower()).first()
    if not naam or len(naam) > 50:
        flash("Naam is verplicht (max 50 tekens).")
    elif bestaand and bestaand.id != categorie.id:
        flash("Deze categorie bestaat al.")
    else:
        categorie.naam = naam
        db.session.commit()
        flash("Categorie aangepast.")
    return redirect(url_for("categorie_beheer"))


@app.route("/categorieen/<int:id>/verwijderen", methods=["POST"])
@rol_vereist(*BEHEER_ROLLEN)
def categorie_verwijderen(id):
    categorie = db.get_or_404(Categorie, id)
    if categorie.boeken:
        flash(f"Deze categorie wordt nog gebruikt door {len(categorie.boeken)} boek(en).")
    else:
        db.session.delete(categorie)
        db.session.commit()
        flash("Categorie verwijderd.")
    return redirect(url_for("categorie_beheer"))


# ---------- uitlenen en terugnemen (bibliothecaris) ----------

@app.route("/uitleningen")
@rol_vereist(*BEHEER_ROLLEN)
def uitleningen():
    toon = request.args.get("toon", "open")
    if toon not in TOON_OPTIES:
        toon = "open"

    query = Uitlening.query
    if toon == "alle":
        query = query.order_by(Uitlening.uitgeleend_op.desc(), Uitlening.id.desc())
    else:
        query = query.filter(Uitlening.teruggebracht_op.is_(None))
        if toon == "te_laat":
            query = query.filter(Uitlening.uiterste_datum < date.today())
        query = query.order_by(Uitlening.uiterste_datum)

    gebruikers = User.query.filter_by(actief=True).order_by(User.naam).all()
    return render_template(
        "uitleningen.html", uitleningen=query.all(), toon=toon, gebruikers=gebruikers,
    )


@app.route("/uitleningen/nieuw", methods=["POST"])
@rol_vereist(*BEHEER_ROLLEN)
def uitlening_nieuw():
    gebruiker = db.session.get(User, request.form.get("user_id", type=int) or 0)
    exemplaar = zoek_exemplaar(request.form.get("barcode", ""))

    if not gebruiker or not gebruiker.actief:
        flash("Kies een actieve gebruiker.")
    elif not exemplaar:
        flash("Geen exemplaar gevonden met deze barcode of dit nummer.")
    elif not exemplaar.beschikbaar:
        flash("Dit exemplaar is al uitgeleend.")
    else:
        dagen = uitleenperiode_voor(exemplaar.boek, gebruiker)
        uitlening = Uitlening(
            exemplaar_id=exemplaar.id,
            user_id=gebruiker.id,
            uiterste_datum=date.today() + timedelta(days=dagen),
        )
        exemplaar.beschikbaar = False
        db.session.add(uitlening)
        db.session.commit()
        flash(
            f"'{exemplaar.boek.titel}' uitgeleend aan {gebruiker.naam} "
            f"tot {uitlening.uiterste_datum:%d/%m/%Y} ({dagen} dagen)."
        )
    return naar_overzicht("open")


@app.route("/uitleningen/terugnemen", methods=["POST"])
@rol_vereist(*BEHEER_ROLLEN)
def uitlening_terugnemen_barcode():
    exemplaar = zoek_exemplaar(request.form.get("barcode", ""))
    uitlening = exemplaar.huidige_uitlening if exemplaar else None
    if not exemplaar:
        flash("Geen exemplaar gevonden met deze barcode of dit nummer.")
    elif not uitlening:
        flash("Dit exemplaar is niet uitgeleend.")
    else:
        return naar_overzicht(neem_terug(uitlening) or "open")
    return naar_overzicht("open")


@app.route("/uitleningen/<int:id>/terugnemen", methods=["POST"])
@rol_vereist(*BEHEER_ROLLEN)
def uitlening_terugnemen(id):
    uitlening = db.get_or_404(Uitlening, id)
    if not uitlening.is_open:
        flash("Dit boek is al teruggenomen.")
        return naar_overzicht()
    return naar_overzicht(neem_terug(uitlening))


@app.route("/uitleningen/<int:id>/maatregel", methods=["POST"])
@rol_vereist(*BEHEER_ROLLEN)
def maatregel_registreren(id):
    """Handmatig een maatregel registreren, naast de automatische."""
    uitlening = db.get_or_404(Uitlening, id)
    soort = request.form.get("soort", "")
    reden = request.form.get("reden", "").strip()
    if soort not in SOORTEN:
        flash("Kies melding, gedragsnota of strafstudie.")
    elif not reden or len(reden) > 200:
        flash("Reden is verplicht (max 200 tekens).")
    else:
        db.session.add(Maatregel(
            user_id=uitlening.user_id, uitlening_id=uitlening.id, soort=soort, reden=reden,
        ))
        db.session.commit()
        flash(f"{soort.capitalize()} geregistreerd voor {uitlening.user.naam}.")
    return naar_overzicht()


@app.route("/maatregelen")
@rol_vereist(*BEHEER_ROLLEN)
def maatregelen_overzicht():
    lijst = Maatregel.query.order_by(
        Maatregel.afgehandeld, Maatregel.datum.desc(), Maatregel.id.desc()
    ).all()
    return render_template("maatregelen.html", maatregelen=lijst, drempels=MAATREGELEN)


@app.route("/maatregelen/<int:id>/afgehandeld", methods=["POST"])
@rol_vereist(*BEHEER_ROLLEN)
def maatregel_afgehandeld(id):
    maatregel = db.get_or_404(Maatregel, id)
    maatregel.afgehandeld = not maatregel.afgehandeld
    db.session.commit()
    return redirect(url_for("maatregelen_overzicht"))


@app.route("/uitleenperiodes", methods=["GET", "POST"])
@rol_vereist(*BEHEER_ROLLEN)
def uitleenperiodes():
    if request.method == "POST":
        klas = request.form.get("klas", "").strip()
        dagen = request.form.get("dagen", type=int)
        if not klas or len(klas) > 20:
            flash("Klas is verplicht (max 20 tekens).")
        elif not dagen or not 1 <= dagen <= 365:
            flash("Dagen moet tussen 1 en 365 liggen.")
        else:
            regel = KlasPeriode.query.filter(
                func.lower(KlasPeriode.klas) == klas.lower()
            ).first()
            if regel:
                regel.dagen = dagen
            else:
                db.session.add(KlasPeriode(klas=klas, dagen=dagen))
            db.session.commit()
            flash("Uitleenperiode opgeslagen.")
            return redirect(url_for("uitleenperiodes"))
    regels = KlasPeriode.query.order_by(KlasPeriode.klas).all()
    return render_template("uitleenperiodes.html", regels=regels, standaard=STANDAARD_DAGEN)


@app.route("/uitleenperiodes/<int:id>/verwijderen", methods=["POST"])
@rol_vereist(*BEHEER_ROLLEN)
def uitleenperiode_verwijderen(id):
    regel = db.get_or_404(KlasPeriode, id)
    db.session.delete(regel)
    db.session.commit()
    flash("Regel verwijderd.")
    return redirect(url_for("uitleenperiodes"))


# ---------- mijn boeken (iedereen die ingelogd is) ----------

@app.route("/mijn-boeken")
@login_required
def mijn_boeken():
    open_uitleningen = (
        Uitlening.query.filter_by(user_id=current_user.id, teruggebracht_op=None)
        .order_by(Uitlening.uiterste_datum).all()
    )
    geschiedenis = (
        Uitlening.query
        .filter(Uitlening.user_id == current_user.id, Uitlening.teruggebracht_op.isnot(None))
        .order_by(Uitlening.teruggebracht_op.desc()).all()
    )
    maatregelen = (
        Maatregel.query.filter_by(user_id=current_user.id)
        .order_by(Maatregel.datum.desc(), Maatregel.id.desc()).all()
    )
    return render_template(
        "mijn_boeken.html", open_uitleningen=open_uitleningen,
        geschiedenis=geschiedenis, maatregelen=maatregelen,
        aantal_te_laat=current_user.aantal_te_laat, drempels=MAATREGELEN,
        max_verlengingen=MAX_VERLENGINGEN,
    )


@app.route("/uitleningen/<int:id>/verlengen", methods=["POST"])
@login_required
def uitlening_verlengen(id):
    uitlening = db.get_or_404(Uitlening, id)
    if uitlening.user_id != current_user.id:
        abort(403)
    if not uitlening.is_open:
        flash("Dit boek heb je al teruggebracht.")
    elif uitlening.te_laat_dagen > 0:
        flash("Dit boek is te laat, je kan niet meer verlengen. Breng het terug.")
    elif uitlening.aantal_verlengingen >= MAX_VERLENGINGEN:
        flash(f"Je kan een boek maximaal {MAX_VERLENGINGEN} keer verlengen.")
    else:
        dagen = uitleenperiode_voor(uitlening.exemplaar.boek, uitlening.user)
        uitlening.uiterste_datum += timedelta(days=dagen)
        uitlening.aantal_verlengingen += 1
        db.session.commit()
        flash(
            f"Verlengd tot {uitlening.uiterste_datum:%d/%m/%Y} "
            f"(nog {MAX_VERLENGINGEN - uitlening.aantal_verlengingen} keer mogelijk)."
        )
    return redirect(url_for("mijn_boeken"))


# ---------- gebruikersbeheer (admin) ----------

@app.route("/admin/gebruikers")
@rol_vereist("admin")
def admin_gebruikers():
    gebruikers = User.query.order_by(User.naam).all()
    return render_template("admin_gebruikers.html", gebruikers=gebruikers)


@app.route("/admin/gebruikers/nieuw", methods=["GET", "POST"])
@rol_vereist("admin")
def admin_gebruiker_nieuw():
    if request.method == "POST":
        naam = request.form["naam"].strip()
        email = request.form["email"].strip().lower()
        rol = request.form["rol"]
        klas = request.form.get("klas", "").strip()
        wachtwoord = request.form["wachtwoord"]
        fout = gebruiker_fout(naam, email, rol, klas) or wachtwoord_fout(wachtwoord)
        if not fout and User.query.filter_by(email=email).first():
            fout = "Dit e-mailadres is al in gebruik."
        if fout:
            flash(fout)
        else:
            user = User(naam=naam, email=email, rol=rol, klas=klas or None)
            user.set_password(wachtwoord)
            db.session.add(user)
            db.session.commit()
            flash("Gebruiker toegevoegd.")
            return redirect(url_for("admin_gebruikers"))
    return render_template("admin_gebruiker_form.html", gebruiker=None, rollen=ROLLEN)


@app.route("/admin/gebruikers/<int:id>/bewerken", methods=["GET", "POST"])
@rol_vereist("admin")
def admin_gebruiker_bewerken(id):
    gebruiker = db.get_or_404(User, id)
    if request.method == "POST":
        naam = request.form["naam"].strip()
        email = request.form["email"].strip().lower()
        rol = request.form["rol"]
        klas = request.form.get("klas", "").strip()
        fout = gebruiker_fout(naam, email, rol, klas)
        bestaand = User.query.filter_by(email=email).first()
        if not fout and bestaand and bestaand.id != gebruiker.id:
            fout = "Dit e-mailadres is al in gebruik."
        if not fout and gebruiker.id == current_user.id and rol != gebruiker.rol:
            fout = "Je kan je eigen rol niet wijzigen."
        if fout:
            flash(fout)
        else:
            gebruiker.naam = naam
            gebruiker.email = email
            gebruiker.rol = rol
            gebruiker.klas = klas or None
            db.session.commit()
            flash("Gebruiker aangepast.")
            return redirect(url_for("admin_gebruikers"))
    return render_template("admin_gebruiker_form.html", gebruiker=gebruiker, rollen=ROLLEN)


@app.route("/admin/gebruikers/<int:id>/actief", methods=["POST"])
@rol_vereist("admin")
def admin_gebruiker_actief(id):
    gebruiker = db.get_or_404(User, id)
    if gebruiker.id == current_user.id:
        flash("Je kan jezelf niet op inactief zetten.")
    else:
        gebruiker.actief = not gebruiker.actief
        db.session.commit()
    return redirect(url_for("admin_gebruikers"))


# ---------- eerste admin aanmaken ----------

@app.cli.command("maak-admin")
@click.option("--naam", prompt=True)
@click.option("--email", prompt=True)
@click.option("--wachtwoord", prompt=True, hide_input=True, confirmation_prompt=True)
def maak_admin(naam, email, wachtwoord):
    maak_database()
    email = email.strip().lower()
    fout = gebruiker_fout(naam.strip(), email, "admin") or wachtwoord_fout(wachtwoord)
    if fout:
        click.echo(fout)
        return
    if User.query.filter_by(email=email).first():
        click.echo("Dit e-mailadres bestaat al.")
        return
    user = User(naam=naam.strip(), email=email, rol="admin")
    user.set_password(wachtwoord)
    db.session.add(user)
    db.session.commit()
    click.echo("Admin aangemaakt.")


if __name__ == "__main__":
    with app.app_context():
        maak_database()
    app.run(debug=True)