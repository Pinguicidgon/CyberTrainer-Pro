from __future__ import annotations

import json
import os
import random
from datetime import datetime
from typing import Any

from flask import Flask, render_template, request, redirect, url_for, session

from database import init_db, get_connection

app = Flask(__name__)
init_db()
app.secret_key = "cybertrainer_secret_key_change_me"

DATA_FILE = os.path.join("data", "phishing_emails.json")


# ============================================================
# UTILIDADES GENERALES
# ============================================================

def load_emails() -> list[dict[str, Any]]:
    with open(DATA_FILE, "r", encoding="utf-8") as file:
        return json.load(file)


def initialize_session() -> None:
    if "password_checks" not in session:
        session["password_checks"] = []

    if "phishing_answers" not in session:
        session["phishing_answers"] = []

    if "last_email_index" not in session:
        session["last_email_index"] = None


def get_dashboard_stats() -> dict[str, Any]:
    password_checks = session.get("password_checks", [])
    phishing_answers = session.get("phishing_answers", [])

    total_password_checks = len(password_checks)
    total_phishing_answers = len(phishing_answers)
    phishing_correct = sum(1 for item in phishing_answers if item.get("correct"))

    phishing_accuracy = 0
    if total_phishing_answers > 0:
        phishing_accuracy = round((phishing_correct / total_phishing_answers) * 100, 2)

    average_password_score = 0
    if total_password_checks > 0:
        average_password_score = round(
            sum(item["score"] for item in password_checks) / total_password_checks,
            2,
        )

    risk_level = calculate_global_risk(average_password_score, phishing_accuracy)

    return {
        "total_password_checks": total_password_checks,
        "total_phishing_answers": total_phishing_answers,
        "phishing_correct": phishing_correct,
        "phishing_accuracy": phishing_accuracy,
        "average_password_score": average_password_score,
        "risk_level": risk_level,
    }


def calculate_global_risk(password_score: float, phishing_accuracy: float) -> str:
    if password_score >= 75 and phishing_accuracy >= 75:
        return "Bajo"
    if password_score >= 50 and phishing_accuracy >= 50:
        return "Medio"
    return "Alto"


# ============================================================
# LÓGICA DE CONTRASEÑAS
# ============================================================

def evaluate_password(password: str) -> dict[str, Any]:
    score = 0
    feedback = []

    if len(password) >= 12:
        score += 25
    elif len(password) >= 8:
        score += 15
    else:
        feedback.append("La contraseña es demasiado corta.")

    if any(char.islower() for char in password):
        score += 15
    else:
        feedback.append("Faltan letras minúsculas.")

    if any(char.isupper() for char in password):
        score += 15
    else:
        feedback.append("Faltan letras mayúsculas.")

    if any(char.isdigit() for char in password):
        score += 15
    else:
        feedback.append("Faltan números.")

    if any(not char.isalnum() for char in password):
        score += 15
    else:
        feedback.append("Faltan caracteres especiales.")

    common_patterns = ["1234", "password", "admin", "qwerty", "1111", "abcd"]
    if any(pattern in password.lower() for pattern in common_patterns):
        score -= 20
        feedback.append("Contiene patrones comunes y fáciles de adivinar.")

    unique_chars = len(set(password))
    if unique_chars >= 8:
        score += 15
    else:
        feedback.append("La contraseña tiene poca variedad de caracteres.")

    score = max(0, min(score, 100))

    if score < 40:
        level = "Débil"
        crack_time = "segundos o pocos minutos"
    elif score < 70:
        level = "Media"
        crack_time = "horas o días"
    else:
        level = "Fuerte"
        crack_time = "meses o incluso años"

    if not feedback:
        feedback.append("La contraseña cumple con los criterios recomendados.")

    return {
        "password": password,
        "score": score,
        "level": level,
        "crack_time": crack_time,
        "feedback": feedback,
        "date": datetime.now().strftime("%d/%m/%Y %H:%M:%S"),
    }


# ============================================================
# RUTAS
# ============================================================

@app.route("/login", methods=["GET", "POST"])
def login() -> str:
    if request.method == "GET":
        session.clear()

    if request.method == "POST":
        username = request.form.get("username", "").strip()

        if not username:
            return render_template("login.html")

        conn = get_connection()
        cursor = conn.cursor()

        cursor.execute("SELECT id FROM users WHERE username = ?", (username,))
        user = cursor.fetchone()

        if not user:
            cursor.execute("INSERT INTO users (username) VALUES (?)", (username,))
            conn.commit()
            user_id = cursor.lastrowid
        else:
            user_id = user[0]

        conn.close()

        session["user_id"] = user_id
        session["username"] = username

        return redirect(url_for("home"))

    return render_template("login.html")


@app.route("/")
def home() -> str:
    if "user_id" not in session:
        return redirect(url_for("login"))

    initialize_session()
    stats = get_dashboard_stats()

    password_history = session.get("password_checks", [])
    phishing_history = session.get("phishing_answers", [])

    password_labels = [item["date"] for item in reversed(password_history)]
    password_scores = [item["score"] for item in reversed(password_history)]

    phishing_labels = [item["date"] for item in reversed(phishing_history)]
    phishing_scores = [1 if item["correct"] else 0 for item in reversed(phishing_history)]

    return render_template(
        "dashboard.html",
        stats=stats,
        username=session.get("username", "Usuario"),
        password_labels=password_labels,
        password_scores=password_scores,
        phishing_labels=phishing_labels,
        phishing_scores=phishing_scores,
    )


@app.route("/passwords", methods=["GET", "POST"])
def passwords() -> str:
    initialize_session()
    result = None

    if request.method == "POST":
        password = request.form.get("password", "").strip()

        if password:
            result = evaluate_password(password)

            # 🔥 GUARDAR EN BASE DE DATOS
            conn = get_connection()
            cursor = conn.cursor()

            cursor.execute("""
            INSERT INTO password_checks (user_id, score, level, date)
            VALUES (?, ?, ?, ?)
            """, (
                session["user_id"],
                result["score"],
                result["level"],
                result["date"]
            ))

            conn.commit()
            conn.close()

            history = session.get("password_checks", [])
            history.insert(0, result)
            session["password_checks"] = history[:10]
            session.modified = True

    history = session.get("password_checks", [])
    return render_template("passwords.html", result=result, history=history)


@app.route("/phishing")
def phishing() -> str:
    if "user_id" not in session:
        return redirect(url_for("login"))

    initialize_session()
    emails = load_emails()
    history = session.get("phishing_answers", [])

    return render_template(
        "phishing.html",
        emails=emails,
        history=history,
    )


@app.route("/phishing/email/<int:email_id>")
def open_phishing_email(email_id: int) -> str:
    if "user_id" not in session:
        return redirect(url_for("login"))

    initialize_session()
    emails = load_emails()

    selected_email = next((email for email in emails if email["id"] == email_id), None)

    if not selected_email:
        return redirect(url_for("phishing"))

    return render_template("phishing_email.html", email=selected_email)


@app.route("/phishing/email/<int:email_id>/action/<string:action>")
def phishing_action(email_id: int, action: str) -> str:
    if "user_id" not in session:
        return redirect(url_for("login"))

    initialize_session()
    emails = load_emails()

    selected_email = next((email for email in emails if email["id"] == email_id), None)

    if not selected_email:
        return redirect(url_for("phishing"))

    is_phishing = selected_email["is_phishing"]

    result_title = ""
    result_message = ""
    correct = 0

    if action == "click":
        if is_phishing:
            result_title = "Has caído en un phishing"
            result_message = (
                "Has pulsado en un enlace malicioso. En un entorno real, esto podría "
                "comprometer tus credenciales o instalar software malicioso."
            )
            correct = 0
        else:
            result_title = "Correo legítimo"
            result_message = (
                "El correo era legítimo y el acceso al enlace era seguro dentro del "
                "contexto de esta simulación."
            )
            correct = 1

    elif action == "report":
        if is_phishing:
            result_title = "Buena decisión"
            result_message = (
                "Has identificado correctamente un correo sospechoso y lo has marcado "
                "como phishing."
            )
            correct = 1
        else:
            result_title = "Falso positivo"
            result_message = (
                "El correo era legítimo. Marcarlo como phishing puede generar "
                "interrupciones innecesarias y pérdida de confianza en los sistemas."
            )
            correct = 0
    else:
        return redirect(url_for("phishing"))

    conn = get_connection()
    cursor = conn.cursor()

    cursor.execute("""
    INSERT INTO phishing_results (user_id, correct, date)
    VALUES (?, ?, ?)
    """, (
        session["user_id"],
        int(correct),
        datetime.now().strftime("%d/%m/%Y %H:%M:%S")
    ))

    conn.commit()
    conn.close()

    history = session.get("phishing_answers", [])
    history.insert(
        0,
        {
            "subject": selected_email["subject"],
            "correct": bool(correct),
            "date": datetime.now().strftime("%d/%m/%Y %H:%M:%S"),
        },
    )
    session["phishing_answers"] = history[:10]
    session.modified = True

    return render_template(
        "phishing_result.html",
        email=selected_email,
        result_title=result_title,
        result_message=result_message,
        explanation=selected_email["explanation"],
        correct=bool(correct),
        action=action,
    )


@app.route("/ranking")
def ranking() -> str:
    if "user_id" not in session:
        return redirect(url_for("login"))

    conn = get_connection()
    cursor = conn.cursor()

    cursor.execute("""
    SELECT
        u.id,
        u.username,
        COALESCE(pc.total_passwords, 0) AS total_passwords,
        COALESCE(pc.avg_password_score, 0) AS avg_password_score,
        COALESCE(pr.total_phishing, 0) AS total_phishing,
        COALESCE(pr.phishing_correct, 0) AS phishing_correct
    FROM users u
    LEFT JOIN (
        SELECT
            user_id,
            COUNT(*) AS total_passwords,
            ROUND(AVG(score), 2) AS avg_password_score
        FROM password_checks
        GROUP BY user_id
    ) pc ON u.id = pc.user_id
    LEFT JOIN (
        SELECT
            user_id,
            COUNT(*) AS total_phishing,
            SUM(correct) AS phishing_correct
        FROM phishing_results
        GROUP BY user_id
    ) pr ON u.id = pr.user_id
    ORDER BY avg_password_score DESC, phishing_correct DESC
    """)

    rows = cursor.fetchall()
    conn.close()

    ranking_data = []
    chart_labels = []
    chart_password_scores = []
    chart_phishing_accuracy = []

    for row in rows:
        username = row[1]
        total_passwords = row[2]
        avg_password_score = row[3]
        total_phishing = row[4]
        phishing_correct = row[5]

        phishing_accuracy = 0
        if total_phishing > 0:
            phishing_accuracy = round((phishing_correct / total_phishing) * 100, 2)

        ranking_data.append({
            "username": username,
            "total_passwords": total_passwords,
            "avg_password_score": avg_password_score,
            "total_phishing": total_phishing,
            "phishing_correct": phishing_correct,
            "phishing_accuracy": phishing_accuracy,
        })

        chart_labels.append(username)
        chart_password_scores.append(avg_password_score)
        chart_phishing_accuracy.append(phishing_accuracy)

    return render_template(
        "ranking.html",
        ranking_data=ranking_data,
        chart_labels=chart_labels,
        chart_password_scores=chart_password_scores,
        chart_phishing_accuracy=chart_phishing_accuracy,
    )


@app.route("/about")
def about() -> str:
    return render_template("about.html")


@app.route("/reset")
def reset() -> str:
    session.clear()
    return redirect(url_for("home"))


@app.route("/logout")
def logout() -> str:
    session.clear()
    return redirect(url_for("login"))


if __name__ == "__main__":
    app.run(debug=True)