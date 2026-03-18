import os
import secrets
from datetime import datetime, timedelta

from flask import Flask, request, redirect, session, jsonify, render_template
from flask_sqlalchemy import SQLAlchemy
from werkzeug.security import generate_password_hash, check_password_hash

app = Flask(__name__)
app.config["SECRET_KEY"] = os.getenv("SECRET_KEY", "dev-key")

# MariaDB URL Beispiel:
# mysql+pymysql://fitnessuser:PASS@127.0.0.1:3306/fitnessapp
db_url = os.getenv("DATABASE_URL")

if db_url and db_url.startswith("postgres://"):
    db_url = db_url.replace("postgres://", "postgresql://", 1)

app.config["SQLALCHEMY_DATABASE_URI"] = db_url or "sqlite:///local_dev.db"
app.config["SQLALCHEMY_TRACK_MODIFICATIONS"] = False

db = SQLAlchemy()
db.init_app(app)


# -----------------------
# Datenbank Modelle
# -----------------------
class User(db.Model):
    __tablename__ = "users"
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    email = db.Column(db.String(120), unique=True, nullable=False)
    password_hash = db.Column(db.String(255), nullable=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)


class Workout(db.Model):
    __tablename__ = "workouts"
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey("users.id"), nullable=False)
    title = db.Column(db.String(120), nullable=False)
    workout_date = db.Column(db.Date, nullable=False)
    workout_type = db.Column(db.String(50), nullable=False)
    notes = db.Column(db.Text, nullable=True)
    duration_min = db.Column(db.Integer, nullable=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)


class ApiToken(db.Model):
    __tablename__ = "api_tokens"
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey("users.id"), nullable=False)
    token = db.Column(db.String(64), unique=True, nullable=False)
    expires_at = db.Column(db.DateTime, nullable=False)


# -----------------------
# Helpers
# -----------------------
def current_user_id():
    return session.get("user_id")


def require_login():
    return current_user_id() is not None


def token_user_id(auth_header: str):
    # Header: Authorization: Bearer <token>
    if not auth_header or not auth_header.startswith("Bearer "):
        return None
    token_value = auth_header.replace("Bearer ", "").strip()
    t = ApiToken.query.filter_by(token=token_value).first()
    if not t:
        return None
    if t.expires_at < datetime.utcnow():
        return None
    return t.user_id


# -----------------------
# Healthcheck / DB check
# -----------------------
@app.get("/dbcheck")
def dbcheck():
    try:
        db.session.execute(db.text("SELECT 1"))
        return "DB Verbindung OK\n"
    except Exception as e:
        return f"DB Verbindung FEHLER: {e}\n", 500


# -----------------------
# Web UI
# -----------------------
@app.get("/")
def home():
    return render_template("home.html", title="Home", message="FitnessApp läuft")


@app.route("/register", methods=["GET", "POST"])
def register():
    if request.method == "POST":
        username = request.form.get("username", "").strip()
        email = request.form.get("email", "").strip()
        password = request.form.get("password", "")

        if not username or not email or not password:
            return render_template(
                "register.html",
                title="Register",
                error="Bitte alle Felder ausfüllen",
                username=username,
                email=email,
            )

        if User.query.filter((User.username == username) | (User.email == email)).first():
            return render_template(
                "register.html",
                title="Register",
                error="Username oder Email existiert bereits",
                username=username,
                email=email,
            )

        pw_hash = generate_password_hash(password)
        u = User(username=username, email=email, password_hash=pw_hash)
        db.session.add(u)
        db.session.commit()
        return redirect("/login")

    return render_template("register.html", title="Register")


@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        email = request.form.get("email", "").strip()
        password = request.form.get("password", "")

        u = User.query.filter_by(email=email).first()
        if not u or not check_password_hash(u.password_hash, password):
            return render_template("login.html", title="Login", error="Login fehlgeschlagen", email=email)

        session["user_id"] = u.id
        return redirect("/workouts")

    return render_template("login.html", title="Login")


@app.get("/logout")
def logout():
    session.clear()
    return redirect("/login")


@app.route("/workouts", methods=["GET", "POST"])
def workouts():
    if not require_login():
        return redirect("/login")

    uid = current_user_id()

    if request.method == "POST":
        title = request.form.get("title", "").strip()
        workout_date_str = request.form.get("workout_date", "").strip()
        workout_type = request.form.get("workout_type", "").strip()
        duration = request.form.get("duration_min", "").strip()
        notes = request.form.get("notes", "").strip()

        # Validierung
        if not title:
            error = "Titel ist notwendig"
        elif not workout_date_str:
            error = "Datum ist notwendig"
        elif not workout_type:
            error = "Typ ist notwendig"
        elif not duration.isdigit():
            error = "Dauer muss eine Zahl sein"
        else:
            error = None

        if error:
            items = Workout.query.filter_by(user_id=uid).order_by(Workout.created_at.desc()).all()
            return render_template(
                "workouts.html",
                title="Workouts",
                workouts=items,
                error=error,
                title_value=title,
                duration_value=duration,
                workout_date_value=workout_date_str,
                workout_type_value=workout_type,
                notes_value=notes,
            )

        workout_date = datetime.strptime(workout_date_str, "%Y-%m-%d").date()

        w = Workout(
            user_id=uid,
            title=title,
            workout_date=workout_date,
            workout_type=workout_type,
            duration_min=int(duration),
            notes=notes if notes else None,
        )
        db.session.add(w)
        db.session.commit()
        return redirect("/workouts")

    items = Workout.query.filter_by(user_id=uid).order_by(Workout.created_at.desc()).all()
    return render_template("workouts.html", title="Workouts", workouts=items)


@app.get("/workouts/delete/<int:w_id>")
def delete_workout(w_id):
    if not require_login():
        return redirect("/login")

    uid = current_user_id()
    w = Workout.query.filter_by(id=w_id, user_id=uid).first()
    if not w:
        return "Nicht gefunden\n", 404

    db.session.delete(w)
    db.session.commit()
    return redirect("/workouts")


# -----------------------
# REST API
# -----------------------
@app.post("/api/login")
def api_login():
    data = request.get_json(silent=True) or {}
    email = (data.get("email") or "").strip()
    password = data.get("password") or ""

    u = User.query.filter_by(email=email).first()
    if not u or not check_password_hash(u.password_hash, password):
        return jsonify({"error": "unauthorized"}), 401

    token_value = secrets.token_hex(24)
    expires = datetime.utcnow() + timedelta(hours=24)

    t = ApiToken(user_id=u.id, token=token_value, expires_at=expires)
    db.session.add(t)
    db.session.commit()

    return jsonify({"token": token_value, "expires_at": expires.isoformat()})


@app.get("/api/workouts")
def api_workouts():
    uid = token_user_id(request.headers.get("Authorization"))
    if not uid:
        return jsonify({"error": "unauthorized"}), 401

    items = Workout.query.filter_by(user_id=uid).order_by(Workout.created_at.desc()).all()
    return jsonify(
        [
            {
                "id": w.id,
                "title": w.title,
                "workout_date": w.workout_date.isoformat() if w.workout_date else None,
                "workout_type": w.workout_type,
                "duration_min": w.duration_min,
                "notes": w.notes,
                "created_at": w.created_at.isoformat() if w.created_at else None,
            }
            for w in items
        ]
    )


with app.app_context():
    db.create_all()

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000)
