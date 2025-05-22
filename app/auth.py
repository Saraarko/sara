import os
import jwt
import shutil
import logging
import json
from flask import Blueprint, request, jsonify, current_app
from .crypto_utils import sha256_hash
from datetime import datetime

# Configuration des logs
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

auth_bp = Blueprint('auth', __name__, url_prefix='/api')
LOCAL_DATA_DIR = './local_data'

def manage_backups_local(file_path):
    backup_dir = os.path.join(os.path.dirname(file_path), 'backups')
    os.makedirs(backup_dir, exist_ok=True)

    backup_files = sorted(
        [f for f in os.listdir(backup_dir) if f.startswith('data_') and f.endswith('.enc')],
        key=lambda x: int(x.split('_')[1].split('.')[0])
    )

    if len(backup_files) >= 5:
        os.remove(os.path.join(backup_dir, backup_files[0]))
        backup_files.pop(0)

    for i in reversed(range(len(backup_files))):
        old_file = backup_files[i]
        old_index = int(old_file.split('_')[1].split('.')[0])
        new_index = old_index + 1
        old_path = os.path.join(backup_dir, old_file)
        new_path = os.path.join(backup_dir, f"data_{new_index}.enc")
        shutil.move(old_path, new_path)

    if os.path.exists(file_path):
        shutil.copy2(file_path, os.path.join(backup_dir, 'data_1.enc'))

@auth_bp.route('/signup', methods=['POST'])
def signup():
    data = request.json
    username = data.get('username')
    password = data.get('password')

    if not username or not password:
        return jsonify({'error': 'Champs manquants'}), 400

    hashed_username = sha256_hash(username)
    hashed_password = sha256_hash(password)
    user_folder = os.path.join(LOCAL_DATA_DIR, hashed_username, hashed_password)

    if os.path.exists(user_folder):
        return jsonify({'error': 'Utilisateur déjà inscrit'}), 400

    os.makedirs(user_folder, exist_ok=True)
    token = jwt.encode({'username': username}, current_app.config['SECRET_KEY'], algorithm='HS256')
    return jsonify({'message': 'Compte créé', 'token': token}), 201

@auth_bp.route('/signin', methods=['POST'])
def signin():
    data = request.json
    username = data.get('username')
    password = data.get('password')

    hashed_username = sha256_hash(username)
    hashed_password = sha256_hash(password)
    user_folder = os.path.join(LOCAL_DATA_DIR, hashed_username, hashed_password)

    if not os.path.exists(user_folder):
        return jsonify({'error': 'Identifiants invalides'}), 401

    token = jwt.encode({'username': username}, current_app.config['SECRET_KEY'], algorithm='HS256')
    return jsonify({'message': 'Connexion réussie', 'token': token}), 200

@auth_bp.route('/change-password', methods=['POST'])
def change_password():
    token = request.headers.get('Authorization')
    if not token or not token.startswith('Bearer '):
        return jsonify({'error': 'Token manquant'}), 401

    token = token[7:]
    try:
        decoded = jwt.decode(token, current_app.config['SECRET_KEY'], algorithms=['HS256'])
        username = decoded['username']
    except jwt.InvalidTokenError:
        return jsonify({'error': 'Token invalide'}), 401

    data = request.json
    old_password = data.get('old_password')
    new_password = data.get('new_password')

    hashed_username = sha256_hash(username)
    old_hashed_pw = sha256_hash(old_password)
    new_hashed_pw = sha256_hash(new_password)

    old_path = os.path.join(LOCAL_DATA_DIR, hashed_username, old_hashed_pw)
    new_path = os.path.join(LOCAL_DATA_DIR, hashed_username, new_hashed_pw)
    
    if not os.path.exists(old_path):
        return jsonify({'error': 'Ancien mot de passe incorrect'}), 401
    
    shutil.move(old_path, new_path)
    return jsonify({'message': 'Mot de passe changé'}), 200

@auth_bp.route('/write-data', methods=['POST'])
def write_data():
    token = request.headers.get('Authorization')
    if not token or not token.startswith('Bearer '):
        return jsonify({'error': 'Token manquant ou invalide'}), 401

    token = token[7:]
    try:
        decoded = jwt.decode(token, current_app.config['SECRET_KEY'], algorithms=['HS256'])
        username = decoded['username']
    except jwt.InvalidTokenError:
        return jsonify({'error': 'Token invalide'}), 401

    hashed_username = sha256_hash(username)
    hashed_password = request.json.get('hashed_password')
    encrypted_data = request.json.get('encrypted_data')

    if not hashed_password or not encrypted_data:
        return jsonify({'error': 'Paramètres manquants'}), 400

    folder_path = os.path.join(LOCAL_DATA_DIR, hashed_username, hashed_password)
    file_path = os.path.join(folder_path, 'data.enc')
    os.makedirs(folder_path, exist_ok=True)

    try:
        manage_backups_local(file_path)
        with open(file_path, 'w') as f:
            f.write(encrypted_data)
        return jsonify({'message': 'Données enregistrées'}), 200
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@auth_bp.route('/read-data', methods=['GET'])
def read_data():
    token = request.headers.get('Authorization')
    if not token or not token.startswith('Bearer '):
        return jsonify({'error': 'Token manquant ou invalide'}), 401

    token = token[7:]
    try:
        decoded = jwt.decode(token, current_app.config['SECRET_KEY'], algorithms=['HS256'])
        username = decoded['username']
    except jwt.InvalidTokenError:
        return jsonify({'error': 'Token invalide'}), 401

    hashed_username = sha256_hash(username)
    hashed_password = request.args.get('hashed_password')

    if not hashed_password:
        return jsonify({'error': 'Mot de passe manquant'}), 400

    file_path = os.path.join(LOCAL_DATA_DIR, hashed_username, hashed_password, 'data.enc')

    if not os.path.exists(file_path):
        return jsonify({'error': 'Aucune donnée trouvée'}), 404

    try:
        with open(file_path, 'r') as f:
            encrypted_data = f.read()
        return jsonify({'encrypted_data': encrypted_data}), 200
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@auth_bp.route('/health', methods=['GET'])
def health_check():
    return jsonify({'status': 'ok'}), 200

@auth_bp.route('/register', methods=['POST'])
def register():
    try:
        data = request.json
        username = data.get('username')
        password = data.get('password')

        logger.info(f"Tentative de création de compte pour l'utilisateur: {username}")

        if not username or not password:
            logger.error("Champs manquants dans la requête")
            return jsonify({'error': 'Champs manquants'}), 400

        # Créer le dossier local_data s'il n'existe pas
        os.makedirs(LOCAL_DATA_DIR, exist_ok=True)

        # Créer le fichier .enc avec le nom d'utilisateur
        user_file = os.path.join(LOCAL_DATA_DIR, f"{username}.enc")
        
        logger.info(f"Création du fichier utilisateur: {user_file}")

        if os.path.exists(user_file):
            logger.error(f"L'utilisateur {username} existe déjà")
            return jsonify({'error': 'Utilisateur déjà inscrit'}), 400

        # Créer le fichier .enc avec les informations de l'utilisateur
        user_data = {
            "username": username,
            "password_hash": sha256_hash(password),
            "created_at": str(datetime.now()),
            "passwords": []
        }

        # Sauvegarder les données dans le fichier
        with open(user_file, 'w') as f:
            json.dump(user_data, f, indent=4)
        
        logger.info(f"Fichier utilisateur créé avec succès: {user_file}")

        # Générer le token JWT
        token = jwt.encode({'username': username}, current_app.config['SECRET_KEY'], algorithm='HS256')
        logger.info(f"Compte créé avec succès pour {username}")
        
        return jsonify({
            'message': 'Compte créé',
            'token': token,
            'user_file': user_file
        }), 201

    except Exception as e:
        logger.error(f"Erreur lors de la création du compte: {str(e)}")
        return jsonify({'error': str(e)}), 500

@auth_bp.route('/login', methods=['POST'])
def login():
    try:
        data = request.json
        username = data.get('username')
        password = data.get('password')

        logger.info(f"Tentative de connexion pour l'utilisateur: {username}")

        if not username or not password:
            logger.error("Champs manquants dans la requête")
            return jsonify({'error': 'Champs manquants'}), 400

        # Vérifier le fichier utilisateur
        user_file = os.path.join(LOCAL_DATA_DIR, f"{username}.enc")
        
        if not os.path.exists(user_file):
            logger.error(f"Utilisateur {username} non trouvé")
            return jsonify({'error': 'Identifiants invalides'}), 401

        # Lire les données utilisateur
        with open(user_file, 'r') as f:
            user_data = json.load(f)

        # Vérifier le mot de passe
        if user_data['password_hash'] != sha256_hash(password):
            logger.error(f"Mot de passe incorrect pour {username}")
            return jsonify({'error': 'Identifiants invalides'}), 401

        # Générer le token JWT
        token = jwt.encode({'username': username}, current_app.config['SECRET_KEY'], algorithm='HS256')
        logger.info(f"Connexion réussie pour {username}")

        return jsonify({
            'message': 'Connexion réussie',
            'token': token
        }), 200

    except Exception as e:
        logger.error(f"Erreur lors de la connexion: {str(e)}")
        return jsonify({'error': str(e)}), 500

@auth_bp.route('/logout', methods=['POST'])
def logout():
    return jsonify({'message': 'Déconnexion réussie'}), 200

@auth_bp.route('/passwords', methods=['POST'])
def save_password():
    return write_data()

@auth_bp.route('/passwords/<username>', methods=['GET'])
def get_passwords(username):
    return read_data()

@auth_bp.route('/passwords/<password_id>', methods=['PUT'])
def update_password(password_id):
    return write_data()

@auth_bp.route('/passwords/<password_id>', methods=['DELETE'])
def delete_password(password_id):
    token = request.headers.get('Authorization')
    if not token or not token.startswith('Bearer '):
        return jsonify({'error': 'Token manquant'}), 401

    try:
        decoded = jwt.decode(token[7:], current_app.config['SECRET_KEY'], algorithms=['HS256'])
        username = decoded['username']
        return jsonify({'message': 'Mot de passe supprimé'}), 200
    except jwt.InvalidTokenError:
        return jsonify({'error': 'Token invalide'}), 401

