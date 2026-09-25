
import os
import time
import requests
from flask import Flask, request, jsonify
from dotenv import load_dotenv
from flask_bcrypt import Bcrypt
from flask_cors import CORS

load_dotenv()
API_KEY = os.getenv("VT_API_KEY")

app = Flask(__name__)
CORS(app)

from models import db, User, CheckHistory

app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///linkshield.db'
db.init_app(app)

with app.app_context():
    db.create_all()

bcrypt = Bcrypt(app)


@app.route('/')
def home():
    return "Hello World - LinkShield backend fonctionne !"


@app.route('/signup', methods=['POST'])
def signup():
    data = request.get_json()
    email = data.get('email')
    password = data.get('password')

    if not email or not password:
        return jsonify({"error": "Email et mot de passe requis"}), 400

    existing_user = User.query.filter_by(email=email).first()
    if existing_user:
        return jsonify({"error": "Cet email est deja utilise"}), 400

    password_hash = bcrypt.generate_password_hash(password).decode('utf-8')
    new_user = User(email=email, password_hash=password_hash)

    db.session.add(new_user)
    db.session.commit()

    return jsonify({"message": "Compte cree avec succes", "user_id": new_user.id}), 201


@app.route('/login', methods=['POST'])
def login():
    data = request.get_json()
    email = data.get('email')
    password = data.get('password')

    user = User.query.filter_by(email=email).first()

    if not user or not bcrypt.check_password_hash(user.password_hash, password):
        return jsonify({"error": "Email ou mot de passe incorrect"}), 401

    return jsonify({"message": "Connexion reussie", "user_id": user.id})


@app.route('/check-url', methods=['POST'])
def check_url():
    data = request.get_json()
    url_to_check = data.get('url')
    user_id = data.get('user_id')

    if not url_to_check or not user_id:
        return jsonify({"error": "URL et user_id requis"}), 400

    headers = {"x-apikey": API_KEY}

    submit_response = requests.post(
        "https://www.virustotal.com/api/v3/urls",
        headers=headers,
        data={"url": url_to_check}
    )

    if submit_response.status_code != 200:
        return jsonify({"error": "Erreur lors de la soumission"}), 500

    analysis_id = submit_response.json()["data"]["id"]

    time.sleep(15)

    result_response = requests.get(
        f"https://www.virustotal.com/api/v3/analyses/{analysis_id}",
        headers=headers
    )

    stats = result_response.json()["data"]["attributes"]["stats"]

    total_scans = sum(stats.values())
    malicious_count = stats["malicious"]
    suspicious_count = stats["suspicious"]

    if malicious_count > 0:
        verdict = "dangereux"
        color = "rouge"
        risk_score = round((malicious_count / total_scans) * 100, 1)
    elif suspicious_count > 0:
        verdict = "suspect"
        color = "orange"
        risk_score = round((suspicious_count / total_scans) * 100, 1)
    else:
        verdict = "safe"
        color = "vert"
        risk_score = 0

    new_check = CheckHistory(
        url=url_to_check,
        verdict=verdict,
        risk_score=risk_score,
        user_id=user_id
    )
    db.session.add(new_check)
    db.session.commit()

    return jsonify({
        "url": url_to_check,
        "verdict": verdict,
        "color": color,
        "risk_score": risk_score,
        "stats": stats
    })


@app.route('/history/<int:user_id>', methods=['GET'])
def get_history(user_id):
    checks = CheckHistory.query.filter_by(user_id=user_id).order_by(CheckHistory.date.desc()).all()

    history = [{
        "url": c.url,
        "verdict": c.verdict,
        "risk_score": c.risk_score,
        "date": c.date.strftime("%Y-%m-%d %H:%M")
    } for c in checks]

    return jsonify(history)


if __name__ == '__main__':
    app.run(debug=True)
