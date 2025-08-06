import os
import sys
from flask import Flask, send_from_directory, request
from flask_cors import CORS
from flask_sqlalchemy import SQLAlchemy
from datetime import datetime, timedelta
import hashlib
import uuid
import platform
import subprocess
import psutil

app = Flask(__name__, static_folder='static')
app.config['SECRET_KEY'] = os.environ.get('SECRET_KEY', 'spiderprint_auth_secret_key_2024')

# Habilitar CORS para todas as rotas
CORS(app)

# Configuração do banco de dados
database_url = os.environ.get('DATABASE_URL')
if database_url:
    # DigitalOcean fornece PostgreSQL
    if database_url.startswith('postgres://'):
        database_url = database_url.replace('postgres://', 'postgresql://', 1)
    app.config['SQLALCHEMY_DATABASE_URI'] = database_url
else:
    # Fallback para desenvolvimento local
    app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///spiderprint.db'

app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

# Inicializar banco de dados
db = SQLAlchemy(app)

# Modelo de usuário
class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    email = db.Column(db.String(120), unique=True, nullable=False)
    password_hash = db.Column(db.String(255), nullable=False)
    hardware_id = db.Column(db.String(255), unique=True, nullable=True)
    is_active = db.Column(db.Boolean, default=True)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    last_login = db.Column(db.DateTime)
    session_token = db.Column(db.String(255), unique=True, nullable=True)
    
    # Campos de licença
    license_type = db.Column(db.String(50), default='trial')  # trial, basic, advanced, premium
    license_expires_at = db.Column(db.DateTime)
    license_duration_days = db.Column(db.Integer, default=7)
    
    def __repr__(self):
        return f'<User {self.username}>'
    
    def check_password(self, password):
        return hashlib.sha256(password.encode()).hexdigest() == self.password_hash
    
    def set_password(self, password):
        self.password_hash = hashlib.sha256(password.encode()).hexdigest()
    
    def is_license_valid(self):
        if not self.license_expires_at:
            return False
        return datetime.utcnow() < self.license_expires_at
    
    def days_until_expiry(self):
        if not self.license_expires_at:
            return 0
        delta = self.license_expires_at - datetime.utcnow()
        return max(0, delta.days)

# Rotas de autenticação
@app.route('/api/auth/login', methods=['POST'])
def login():
    try:
        data = request.get_json()
        username = data.get('username')
        password = data.get('password')
        hardware_id = data.get('hardware_id')
        
        if not username or not password or not hardware_id:
            return {'success': False, 'message': 'Dados incompletos'}, 400
        
        user = User.query.filter_by(username=username).first()
        
        if not user or not user.check_password(password):
            return {'success': False, 'message': 'Credenciais inválidas'}, 401
        
        if not user.is_active:
            return {'success': False, 'message': 'Usuário desativado'}, 401
        
        # Verificar licença
        if not user.is_license_valid():
            return {'success': False, 'message': 'Licença expirada'}, 401
        
        # Verificar hardware ID
        if user.hardware_id and user.hardware_id != hardware_id:
            return {'success': False, 'message': 'Hardware não autorizado'}, 401
        
        # Verificar sessão única
        if user.session_token:
            return {'success': False, 'message': 'Usuário já logado em outro dispositivo'}, 401
        
        # Atualizar hardware ID se for o primeiro login
        if not user.hardware_id:
            user.hardware_id = hardware_id
        
        # Criar sessão
        session_token = str(uuid.uuid4())
        user.session_token = session_token
        user.last_login = datetime.utcnow()
        
        db.session.commit()
        
        return {
            'success': True,
            'message': 'Login realizado com sucesso',
            'token': session_token,
            'user': {
                'username': user.username,
                'email': user.email,
                'license_type': user.license_type,
                'license_expires_at': user.license_expires_at.isoformat() if user.license_expires_at else None,
                'days_until_expiry': user.days_until_expiry()
            }
        }
        
    except Exception as e:
        return {'success': False, 'message': f'Erro interno: {str(e)}'}, 500

@app.route('/api/auth/logout', methods=['POST'])
def logout():
    try:
        data = request.get_json()
        token = data.get('token')
        
        if not token:
            return {'success': False, 'message': 'Token não fornecido'}, 400
        
        user = User.query.filter_by(session_token=token).first()
        
        if user:
            user.session_token = None
            db.session.commit()
        
        return {'success': True, 'message': 'Logout realizado com sucesso'}
        
    except Exception as e:
        return {'success': False, 'message': f'Erro interno: {str(e)}'}, 500

@app.route('/api/auth/verify', methods=['POST'])
def verify_session():
    try:
        data = request.get_json()
        token = data.get('token')
        
        if not token:
            return {'success': False, 'message': 'Token não fornecido'}, 400
        
        user = User.query.filter_by(session_token=token).first()
        
        if not user or not user.is_active:
            return {'success': False, 'message': 'Sessão inválida'}, 401
        
        if not user.is_license_valid():
            return {'success': False, 'message': 'Licença expirada'}, 401
        
        return {
            'success': True,
            'user': {
                'username': user.username,
                'email': user.email,
                'license_type': user.license_type,
                'days_until_expiry': user.days_until_expiry()
            }
        }
        
    except Exception as e:
        return {'success': False, 'message': f'Erro interno: {str(e)}'}, 500

# Rotas administrativas
@app.route('/api/users', methods=['GET'])
def get_users():
    try:
        users = User.query.all()
        users_data = []
        
        for user in users:
            users_data.append({
                'id': user.id,
                'username': user.username,
                'email': user.email,
                'is_active': user.is_active,
                'created_at': user.created_at.isoformat(),
                'last_login': user.last_login.isoformat() if user.last_login else None,
                'license_type': user.license_type,
                'license_expires_at': user.license_expires_at.isoformat() if user.license_expires_at else None,
                'license_valid': user.is_license_valid(),
                'days_until_expiry': user.days_until_expiry(),
                'session_active': bool(user.session_token)
            })
        
        return {'success': True, 'users': users_data}
        
    except Exception as e:
        return {'success': False, 'message': f'Erro interno: {str(e)}'}, 500

@app.route('/api/users', methods=['POST'])
def create_user():
    try:
        data = request.get_json()
        username = data.get('username')
        email = data.get('email')
        password = data.get('password')
        license_type = data.get('license_type', 'trial')
        license_duration_days = data.get('license_duration_days', 7)
        
        if not username or not email or not password:
            return {'success': False, 'message': 'Dados incompletos'}, 400
        
        # Verificar se usuário já existe
        if User.query.filter_by(username=username).first():
            return {'success': False, 'message': 'Nome de usuário já existe'}, 400
        
        if User.query.filter_by(email=email).first():
            return {'success': False, 'message': 'Email já cadastrado'}, 400
        
        # Criar usuário
        user = User(
            username=username,
            email=email,
            license_type=license_type,
            license_duration_days=license_duration_days
        )
        user.set_password(password)
        
        # Definir data de expiração
        user.license_expires_at = datetime.utcnow() + timedelta(days=license_duration_days)
        
        db.session.add(user)
        db.session.commit()
        
        return {'success': True, 'message': 'Usuário criado com sucesso', 'user_id': user.id}
        
    except Exception as e:
        return {'success': False, 'message': f'Erro interno: {str(e)}'}, 500

@app.route('/api/users/<int:user_id>/license', methods=['PUT'])
def update_license(user_id):
    try:
        data = request.get_json()
        license_type = data.get('license_type')
        extend_days = data.get('extend_days', 0)
        
        user = User.query.get(user_id)
        if not user:
            return {'success': False, 'message': 'Usuário não encontrado'}, 404
        
        if license_type:
            user.license_type = license_type
        
        if extend_days > 0:
            if user.license_expires_at and user.license_expires_at > datetime.utcnow():
                # Estender a partir da data atual de expiração
                user.license_expires_at += timedelta(days=extend_days)
            else:
                # Criar nova licença a partir de agora
                user.license_expires_at = datetime.utcnow() + timedelta(days=extend_days)
        
        db.session.commit()
        
        return {'success': True, 'message': 'Licença atualizada com sucesso'}
        
    except Exception as e:
        return {'success': False, 'message': f'Erro interno: {str(e)}'}, 500

@app.route('/api/stats', methods=['GET'])
def get_stats():
    try:
        total_users = User.query.count()
        active_licenses = User.query.filter(User.license_expires_at > datetime.utcnow()).count()
        expired_licenses = User.query.filter(User.license_expires_at <= datetime.utcnow()).count()
        
        # Usuários expirando em 7 dias
        expiring_soon = User.query.filter(
            User.license_expires_at > datetime.utcnow(),
            User.license_expires_at <= datetime.utcnow() + timedelta(days=7)
        ).count()
        
        # Usuários online
        online_users = User.query.filter(User.session_token.isnot(None)).count()
        
        return {
            'success': True,
            'stats': {
                'total_users': total_users,
                'active_licenses': active_licenses,
                'expired_licenses': expired_licenses,
                'expiring_soon': expiring_soon,
                'online_users': online_users
            }
        }
        
    except Exception as e:
        return {'success': False, 'message': f'Erro interno: {str(e)}'}, 500

# Rota para servir arquivos estáticos
@app.route('/', defaults={'path': ''})
@app.route('/<path:path>')
def serve(path):
    static_folder_path = app.static_folder
    if static_folder_path is None:
        return "Static folder not configured", 404
    
    if path != "" and os.path.exists(os.path.join(static_folder_path, path)):
        return send_from_directory(static_folder_path, path)
    else:
        index_path = os.path.join(static_folder_path, 'index.html')
        if os.path.exists(index_path):
            return send_from_directory(static_folder_path, 'index.html')
        else:
            return "Dashboard administrativo não encontrado", 404

# Criar tabelas
with app.app_context():
    db.create_all()
    
    # Criar usuário admin padrão se não existir
    admin = User.query.filter_by(username='admin').first()
    if not admin:
        admin = User(
            username='admin',
            email='admin@spiderprint.com',
            license_type='premium',
            license_duration_days=365
        )
        admin.set_password('admin123')
        admin.license_expires_at = datetime.utcnow() + timedelta(days=365)
        db.session.add(admin)
        db.session.commit()

if __name__ == '__main__':
    port = int(os.environ.get('PORT', 5000))
    app.run(host='0.0.0.0', port=port, debug=False)

