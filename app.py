import os
from flask import Flask, render_template, request, redirect, url_for, flash
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager, UserMixin, login_user, logout_user, login_required
from werkzeug.security import generate_password_hash, check_password_hash
from twilio.rest import Client

app = Flask(__name__)
app.secret_key = os.getenv("FLASK_SECRET_KEY", "devkey")

# ------------------------
# Database Setup
# ------------------------
app.config["SQLALCHEMY_DATABASE_URI"] = "sqlite:///site.db"
app.config["SQLALCHEMY_TRACK_MODIFICATIONS"] = False
db = SQLAlchemy(app)

# ------------------------
# Login Manager
# ------------------------
login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = "login"

# ------------------------
# User Model
# ------------------------
class User(UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True)
    email = db.Column(db.String(120), unique=True, nullable=False)
    password = db.Column(db.String(200), nullable=False)

# ------------------------
# Twilio Settings Model
# ------------------------
class Settings(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    account_sid = db.Column(db.String(64))
    auth_token = db.Column(db.String(64))
    messaging_service_sid = db.Column(db.String(64))

# ------------------------
# Auth Setup
# ------------------------
@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

# ------------------------
# Routes
# ------------------------
@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        email = request.form["email"]
        password = request.form["password"]
        user = User.query.filter_by(email=email).first()
        if user and check_password_hash(user.password, password):
            login_user(user)
            return redirect(url_for("dashboard"))
        else:
            flash("Invalid login", "danger")
    return render_template("login.html")

@app.route("/logout")
@login_required
def logout():
    logout_user()
    return redirect(url_for("login"))

@app.route("/")
@login_required
def dashboard():
    return render_template("dashboard.html")

# ------------------------
# Twilio Settings Page
# ------------------------
@app.route("/admin/settings", methods=["GET", "POST"])
@login_required
def admin_settings():
    settings = Settings.query.first() or Settings()

    if request.method == "POST":
        settings.account_sid = request.form["account_sid"]
        settings.auth_token = request.form["auth_token"]
        settings.messaging_service_sid = request.form["messaging_service_sid"]
        db.session.add(settings)
        db.session.commit()
        flash("Twilio settings updated!", "success")
        return redirect(url_for("admin_settings"))

    return render_template("settings.html", settings=settings)

# ------------------------
# Send SMS (using DB creds)
# ------------------------
def send_sms(to_number, body):
    settings = Settings.query.first()
    if not settings or not settings.account_sid or not settings.auth_token or not settings.messaging_service_sid:
        raise Exception("Twilio is not configured yet")

    client = Client(settings.account_sid, settings.auth_token)
    client.messages.create(
        to=to_number,
        messaging_service_sid=settings.messaging_service_sid,
        body=body
    )

# ------------------------
# Initialize DB + Admin User (Flask 3+ safe)
# ------------------------
with app.app_context():
    db.create_all()
    admin_email = os.getenv("ADMIN_EMAIL", "admin@example.com")
    admin_password = os.getenv("ADMIN_PASSWORD", "password")
    if not User.query.filter_by(email=admin_email).first():
        user = User(email=admin_email, password=generate_password_hash(admin_password))
        db.session.add(user)
        db.session.commit()

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000)
