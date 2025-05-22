import os
import datetime
import requests
import jwt
from flask import redirect, request, jsonify
from google.oauth2 import id_token
from google.auth.transport import requests as grequests
from config import Config  # Assure-toi que Config.SECRET_KEY est défini

GOOGLE_CLIENT_ID = os.getenv("GOOGLE_CLIENT_ID")
GOOGLE_CLIENT_SECRET = os.getenv("GOOGLE_CLIENT_SECRET")
GOOGLE_REDIRECT_URI = "http://localhost:5000/login/callback"

def get_google_auth_url():
    google_auth_endpoint = "https://accounts.google.com/o/oauth2/v2/auth"
    scope = "openid email profile"
    state = "random_state_string"  # À remplacer par une vraie gestion CSRF

    auth_url = (
        f"{google_auth_endpoint}?"
        f"client_id={GOOGLE_CLIENT_ID}&"
        f"redirect_uri={GOOGLE_REDIRECT_URI}&"
        f"response_type=code&"
        f"scope={scope}&"
        f"state={state}&"
        f"access_type=offline&"
        f"prompt=consent"
    )
    return redirect(auth_url)


def handle_google_callback():
    code = request.args.get('code')
    if not code:
        return jsonify({"error": "Code manquant"}), 400

    token_url = "https://oauth2.googleapis.com/token"
    data = {
        "code": code,
        "client_id": GOOGLE_CLIENT_ID,
        "client_secret": GOOGLE_CLIENT_SECRET,
        "redirect_uri": GOOGLE_REDIRECT_URI,
        "grant_type": "authorization_code"
    }

    token_response = requests.post(token_url, data=data)
    if token_response.status_code != 200:
        return jsonify({"error": "Échec récupération token"}), 400

    token_json = token_response.json()
    id_token_str = token_json.get("id_token")

    try:
        idinfo = id_token.verify_oauth2_token(id_token_str, grequests.Request(), GOOGLE_CLIENT_ID)
    except ValueError:
        return jsonify({"error": "Token invalide"}), 400

    email = idinfo.get('email')
    if not email:
        return jsonify({"error": "Email non trouvé"}), 400

    # Création du JWT de session
    token = jwt.encode(
        {"username": email, "exp": datetime.datetime.utcnow() + datetime.timedelta(hours=1)},
        Config.SECRET_KEY,
        algorithm="HS256"
    )

    return jsonify({"message": "Connexion Google réussie", "token": token}), 200


# Middleware / décorateur pour sécuriser les routes
from functools import wraps

def token_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        token = None
        if 'Authorization' in request.headers:
            auth_header = request.headers['Authorization']
            if auth_header.startswith('Bearer '):
                token = auth_header[7:]
        
        if not token:
            return jsonify({'error': 'Token manquant'}), 401
        
        try:
            data = jwt.decode(token, Config.SECRET_KEY, algorithms=['HS256'])
            request.user = data['username']  # Stocke username dans la requête
        except jwt.ExpiredSignatureError:
            return jsonify({'error': 'Token expiré'}), 401
        except jwt.InvalidTokenError:
            return jsonify({'error': 'Token invalide'}), 401
        
        return f(*args, **kwargs)
    return decorated
