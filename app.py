import os
from flask import Flask, request, jsonify
from flask_sqlalchemy import SQLAlchemy
from flask_jwt_extended import JWTManager, create_access_token, jwt_required, get_jwt_identity
from flask_cors import CORS
from datetime import datetime, timedelta
import stripe

# --- Config ---
app = Flask(__name__)
CORS(app)

app.config["SQLALCHEMY_DATABASE_URI"] = "sqlite:///db.sqlite3"
app.config["SQLALCHEMY_TRACK_MODIFICATIONS"] = False
app.config["JWT_SECRET_KEY"] = os.getenv("JWT_SECRET_KEY", "super-secret")

db = SQLAlchemy(app)
jwt = JWTManager(app)

stripe.api_key = os.getenv("STRIPE_SECRET_KEY")
DOMAIN = os.getenv("DOMAIN", "http://localhost:5500")  # адрес frontend

# --- Models ---
class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    email = db.Column(db.String(120), unique=True, nullable=False)
    password = db.Column(db.String(120), nullable=False)
    subscription_until = db.Column(db.DateTime)

# --- Init DB ---
with app.app_context():
    db.create_all()

# --- Routes ---
@app.route("/", methods=["GET"])
def home():
    return jsonify({"message": "Добро пожаловать на DAYDREAM"})

@app.route("/register", methods=["POST"])
def register():
    data = request.json
    if User.query.filter_by(email=data["email"]).first():
        return jsonify({"error": "Email уже зарегистрирован"}), 400
    user = User(email=data["email"], password=data["password"])
    db.session.add(user)
    db.session.commit()
    return jsonify({"message": "Регистрация успешна"})

@app.route("/login", methods=["POST"])
def login():
    data = request.json
    user = User.query.filter_by(email=data["email"], password=data["password"]).first()
    if not user:
        return jsonify({"error": "Неверные данные"}), 401
    token = create_access_token(identity=user.email)
    return jsonify({"token": token})

@app.route("/subscribe", methods=["POST"])
@jwt_required()
def subscribe():
    email = get_jwt_identity()
    session = stripe.checkout.Session.create(
        payment_method_types=["card"],
        mode="payment",
        line_items=[{
            "price_data": {
                "currency": "rub",
                "product_data": {
                    "name": "DAYDREAM подписка (30 дней)"
                },
                "unit_amount": 50000,
            },
            "quantity": 1,
        }],
        success_url=f"{DOMAIN}/?success=true",
        cancel_url=f"{DOMAIN}/?canceled=true",
        metadata={"email": email}
    )
    return jsonify({"id": session.id})

@app.route("/webhook", methods=["POST"])
def webhook():
    payload = request.data
    sig_header = request.headers.get("stripe-signature")
    webhook_secret = os.getenv("STRIPE_WEBHOOK_SECRET")

    try:
        event = stripe.Webhook.construct_event(payload, sig_header, webhook_secret)
    except Exception as e:
        return jsonify({"error": str(e)}), 400

    if event["type"] == "checkout.session.completed":
        email = event["data"]["object"]["metadata"]["email"]
        user = User.query.filter_by(email=email).first()
        if user:
            now = datetime.utcnow()
            if user.subscription_until and user.subscription_until > now:
                user.subscription_until += timedelta(days=30)
            else:
                user.subscription_until = now + timedelta(days=30)
            db.session.commit()

    return jsonify({"status": "success"})

@app.route("/user", methods=["GET"])
@jwt_required()
def get_user():
    email = get_jwt_identity()
    user = User.query.filter_by(email=email).first()
    if not user:
        return jsonify({"error": "Пользователь не найден"}), 404
    return jsonify({
        "email": user.email,
        "subscription_until": user.subscription_until.strftime("%Y-%m-%d") if user.subscription_until else "Нет"
    })

@app.route("/video-url", methods=["GET"])
@jwt_required()
def video_url():
    email = get_jwt_identity()
    user = User.query.filter_by(email=email).first()
    if not user or not user.subscription_until or user.subscription_until < datetime.utcnow():
        return jsonify({"error": "Нет активной подписки"}), 403
    return jsonify({"url": "https://test-streams.mux.dev/x36xhzz/x36xhzz.m3u8"})

# --- Run ---
if __name__ == "__main__":
    app.run(host="0.0.0.0", port=10000)
