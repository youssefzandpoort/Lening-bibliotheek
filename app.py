import re
import click
from functools import wraps
from datetime import timedelta
from flask import Flask, render_template, request, redirect, url_for, flash, session, abort
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager, UserMixin, login_user, logout_user, login_required, current_user
from flask_wtf import CSRFProtect
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


class Boek(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    titel = db.Column(db.String(200), nullable=False)
    auteur = db.Column(db.String(100))


class User(UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True)
    naam = db.Column(db.String(100), nullable=False)
    email = db.Column(db.String(120), unique=True, nullable=False)
    wachtwoord_hash = db.Column(db.String(255), nullable=False)
    rol = db.Column(db.String(20), nullable=False, default="leerling")
    actief = db.Column(db.Boolean, nullable=False, default=True)

    @property
    def is_active(self):
        return self.actief

    def set_password(self, wachtwoord):
        self.wachtwoord_hash = generate_password_hash(wachtwoord)

    def check_password(self, wachtwoord):
        return check_password_hash(self.wachtwoord_hash, wachtwoord)


@login_manager.user_loader
def load_user(user_id):
    user = db.session.get(User, int(user_id))
    if user and user.actief:
        return user
    return None


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


def gebruiker_fout(naam, email, rol):
    if not naam or len(naam) > 100:
        return "Naam is verplicht (max 100 tekens)."
    if len(email) > 120 or not re.fullmatch(r"[^@\s]+@[^@\s]+\.[^@\s]+", email):
        return "Geef een geldig e-mailadres op."
    if rol not in ROLLEN:
        return "Ongeldige rol."
    return None


def boek_fout(titel, auteur):
    if not titel or len(titel) > 200:
        return "Titel is verplicht (max 200 tekens)."
    if len(auteur) > 100:
        return "Auteur mag maximaal 100 tekens zijn."
    return None


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

        if rol not in ("leerling", "leerkracht"):
            rol = "leerling"
        fout = gebruiker_fout(naam, email, rol) or wachtwoord_fout(wachtwoord)
        if fout:
            flash(fout)
        elif User.query.filter_by(email=email).first():
            flash("Dit e-mailadres is al in gebruik.")
        else:
            user = User(naam=naam, email=email, rol=rol)
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
    boeklijst = Boek.query.all()
    return render_template("boeken.html", boeken=boeklijst)


@app.route("/boeken/nieuw", methods=["GET", "POST"])
@rol_vereist(*BEHEER_ROLLEN)
def boek_toevoegen():
    if request.method == "POST":
        titel = request.form["titel"].strip()
        auteur = request.form.get("auteur", "").strip()
        fout = boek_fout(titel, auteur)
        if fout:
            flash(fout)
        else:
            db.session.add(Boek(titel=titel, auteur=auteur))
            db.session.commit()
            return redirect(url_for("boeken"))
    return render_template("boek_form.html", boek=None)


@app.route("/boeken/<int:id>/bewerken", methods=["GET", "POST"])
@rol_vereist(*BEHEER_ROLLEN)
def boek_bewerken(id):
    boek = db.get_or_404(Boek, id)
    if request.method == "POST":
        titel = request.form["titel"].strip()
        auteur = request.form.get("auteur", "").strip()
        fout = boek_fout(titel, auteur)
        if fout:
            flash(fout)
        else:
            boek.titel = titel
            boek.auteur = auteur
            db.session.commit()
            return redirect(url_for("boeken"))
    return render_template("boek_form.html", boek=boek)


@app.route("/boeken/<int:id>/verwijderen", methods=["POST"])
@rol_vereist(*BEHEER_ROLLEN)
def boek_verwijderen(id):
    boek = db.get_or_404(Boek, id)
    db.session.delete(boek)
    db.session.commit()
    return redirect(url_for("boeken"))


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
        wachtwoord = request.form["wachtwoord"]
        fout = gebruiker_fout(naam, email, rol) or wachtwoord_fout(wachtwoord)
        if not fout and User.query.filter_by(email=email).first():
            fout = "Dit e-mailadres is al in gebruik."
        if fout:
            flash(fout)
        else:
            user = User(naam=naam, email=email, rol=rol)
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
        fout = gebruiker_fout(naam, email, rol)
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
    db.create_all()
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
        db.create_all()
    app.run(debug=True)