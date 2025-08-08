from flask import Flask, request, jsonify, session, send_file
from flask_cors import CORS
import sqlite3
import hashlib
import secrets
from datetime import datetime, timedelta
import os
import shutil
import zipfile
from werkzeug.utils import secure_filename

app = Flask(__name__)
CORS(app)

# Configuração de sessão
app.secret_key = os.environ.get('SECRET_KEY', secrets.token_hex(32))

# Configuração de fuso horário Brasil (UTC-3)
BRAZIL_OFFSET = timedelta(hours=-3)

# Configuração de admin especial
ADMIN_USERNAME = 'admin'
ADMIN_PASSWORD_HASH = hashlib.sha256('Asd4d45#2365'.encode()).hexdigest()

# Configurações de backup
BACKUP_DIR = 'backups'
UPLOAD_FOLDER = 'uploads'
ALLOWED_EXTENSIONS = {'db', 'sql'}

# Criar diretórios se não existirem
os.makedirs(BACKUP_DIR, exist_ok=True)
os.makedirs(UPLOAD_FOLDER, exist_ok=True)

# Configuração do banco de dados
DATABASE = 'spiderprint_auth.db'

def init_db():
    """Inicializa o banco de dados"""
    conn = sqlite3.connect(DATABASE)
    cursor = conn.cursor()
    
    # Criar tabela de usuários
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT UNIQUE NOT NULL,
            email TEXT UNIQUE NOT NULL,
            password_hash TEXT NOT NULL,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            expires_at TIMESTAMP,
            license_type TEXT DEFAULT 'Trial',
            access_level TEXT DEFAULT 'Básico',
            is_active BOOLEAN DEFAULT 1,
            last_login TIMESTAMP,
            hardware_id TEXT,
            user_type TEXT DEFAULT 'Cliente',
            created_by TEXT,
            is_admin BOOLEAN DEFAULT 0
        )
    ''')
    
    # Criar tabela de logs
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS access_logs (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT,
            action TEXT,
            timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            ip_address TEXT,
            hardware_id TEXT
        )
    ''')
    
    conn.commit()
    conn.close()

def allowed_file(filename):
    """Verifica se o arquivo tem extensão permitida"""
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS

def create_backup():
    """Cria backup do banco de dados"""
    try:
        # Gerar timestamp para o nome do arquivo
        timestamp = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
        backup_filename = f"spiderprint_backup_{timestamp}.db"
        backup_path = os.path.join(BACKUP_DIR, backup_filename)
        
        # Copiar arquivo do banco
        if os.path.exists(DATABASE):
            shutil.copy2(DATABASE, backup_path)
            
            # Criar arquivo de metadados
            metadata = {
                'backup_date': datetime.datetime.now().isoformat(),
                'original_db': DATABASE,
                'backup_size': os.path.getsize(backup_path),
                'version': '1.0'
            }
            
            metadata_path = os.path.join(BACKUP_DIR, f"spiderprint_backup_{timestamp}.json")
            with open(metadata_path, 'w') as f:
                json.dump(metadata, f, indent=2)
            
            # Log da operação
            log_action('admin', 'create_backup', f'Backup criado: {backup_filename}')
            
            return {
                'success': True,
                'filename': backup_filename,
                'path': backup_path,
                'size': os.path.getsize(backup_path),
                'timestamp': timestamp
            }
        else:
            return {'success': False, 'error': 'Banco de dados não encontrado'}
            
    except Exception as e:
        print(f"Erro ao criar backup: {e}")
        return {'success': False, 'error': str(e)}

def restore_backup(backup_path):
    """Restaura backup do banco de dados"""
    try:
        if not os.path.exists(backup_path):
            return {'success': False, 'error': 'Arquivo de backup não encontrado'}
        
        # Criar backup do banco atual antes de restaurar
        current_backup = create_backup()
        if not current_backup['success']:
            return {'success': False, 'error': 'Falha ao criar backup do banco atual'}
        
        # Restaurar o backup
        shutil.copy2(backup_path, DATABASE)
        
        # Log da operação
        log_action('admin', 'restore_backup', f'Backup restaurado: {os.path.basename(backup_path)}')
        
        return {
            'success': True,
            'message': 'Backup restaurado com sucesso',
            'current_backup': current_backup['filename']
        }
        
    except Exception as e:
        print(f"Erro ao restaurar backup: {e}")
        return {'success': False, 'error': str(e)}

def get_backup_list():
    """Lista todos os backups disponíveis"""
    try:
        backups = []
        
        if os.path.exists(BACKUP_DIR):
            for filename in os.listdir(BACKUP_DIR):
                if filename.endswith('.db'):
                    filepath = os.path.join(BACKUP_DIR, filename)
                    metadata_file = filename.replace('.db', '.json')
                    metadata_path = os.path.join(BACKUP_DIR, metadata_file)
                    
                    backup_info = {
                        'filename': filename,
                        'size': os.path.getsize(filepath),
                        'created': datetime.datetime.fromtimestamp(os.path.getctime(filepath)).isoformat(),
                        'modified': datetime.datetime.fromtimestamp(os.path.getmtime(filepath)).isoformat()
                    }
                    
                    # Carregar metadados se existirem
                    if os.path.exists(metadata_path):
                        try:
                            with open(metadata_path, 'r') as f:
                                metadata = json.load(f)
                                backup_info.update(metadata)
                        except:
                            pass
                    
                    backups.append(backup_info)
        
        # Ordenar por data de criação (mais recente primeiro)
        backups.sort(key=lambda x: x['created'], reverse=True)
        
        return {'success': True, 'backups': backups}
        
    except Exception as e:
        print(f"Erro ao listar backups: {e}")
        return {'success': False, 'error': str(e)}

# ===== FUNÇÕES DE UTILIDADE =====

def get_brazil_time():
    """Retorna o horário atual do Brasil (UTC-3)"""
    utc_now = datetime.utcnow()
    return utc_now + BRAZIL_OFFSET

def format_brazil_time(dt_str):
    """Converte timestamp para horário do Brasil"""
    if not dt_str:
        return None
    
    try:
        # Parse do timestamp
        if isinstance(dt_str, str):
            dt = datetime.fromisoformat(dt_str.replace('Z', ''))
        else:
            dt = dt_str
        
        # Se já é um horário do Brasil, retornar formatado
        # Se é UTC, converter para Brasil
        if 'T' in str(dt_str) and ('+' in str(dt_str) or 'Z' in str(dt_str)):
            # É UTC, converter para Brasil
            brazil_time = dt + BRAZIL_OFFSET
        else:
            # Assumir que já é horário local
            brazil_time = dt
            
        return brazil_time.strftime('%d/%m/%Y %H:%M:%S')
    except Exception as e:
        print(f"Erro ao formatar horário: {e}")
        return dt_str

def log_action(username, action, details='', hardware_id=''):
    """Log de ações com horário do Brasil"""
    try:
        conn = sqlite3.connect(DATABASE)
        cursor = conn.cursor()
        
        # Usar horário do Brasil
        brazil_time = get_brazil_time()
        
        cursor.execute('''
            INSERT INTO access_logs (username, action, timestamp, ip_address, details, hardware_id)
            VALUES (?, ?, ?, ?, ?, ?)
        ''', (username, action, brazil_time.isoformat(), request.remote_addr, details, hardware_id))
        
        conn.commit()
        conn.close()
    except Exception as e:
        print(f"Erro ao registrar log: {e}")

def is_admin_user(username):
    """Verifica se é o usuário admin especial"""
    return username == ADMIN_USERNAME

def create_admin_if_not_exists():
    """Criar usuário admin se não existir ou forçar recriação"""
    conn = sqlite3.connect(DATABASE)
    cursor = conn.cursor()
    
    try:
        # SEMPRE recriar o admin para garantir credenciais corretas
        print("🔄 Recriando usuário admin...")
        
        # Deletar admin existente
        cursor.execute('DELETE FROM users WHERE username = ?', (ADMIN_USERNAME,))
        
        # Usar horário do Brasil
        brazil_time = get_brazil_time()
        
        # Inserir novo admin
        cursor.execute('''
            INSERT INTO users (username, email, password_hash, created_at, expires_at, 
                             license_type, access_level, is_active, user_type, is_admin_special)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        ''', (
            ADMIN_USERNAME,
            'admin@spidergrid.com.br',
            ADMIN_PASSWORD_HASH,
            brazil_time.isoformat(),
            None,  # Admin nunca expira
            'Admin',
            'Admin',
            1,
            'Admin',
            1  # Admin especial
        ))
        
        conn.commit()
        print("✅ Usuário admin criado com sucesso!")
        print(f"👤 Usuário: {ADMIN_USERNAME}")
        print(f"🔑 Senha: Asd4d45#2365")
        
    except Exception as e:
        print(f"❌ Erro ao criar admin: {e}")
    finally:
        conn.close()

def allowed_file(filename):
    """Verifica se o arquivo é permitido para upload"""
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS

def delete_backup(filename):
    """Exclui um backup específico"""
    try:
        backup_path = os.path.join(BACKUP_DIR, filename)
        metadata_path = os.path.join(BACKUP_DIR, filename.replace('.db', '.json'))
        
        if os.path.exists(backup_path):
            os.remove(backup_path)
            
            # Remover metadados se existirem
            if os.path.exists(metadata_path):
                os.remove(metadata_path)
            
            # Log da operação
            log_action('admin', 'delete_backup', f'Backup excluído: {filename}')
            
            return {'success': True, 'message': f'Backup {filename} excluído com sucesso'}
        else:
            return {'success': False, 'error': 'Arquivo de backup não encontrado'}
            
    except Exception as e:
        print(f"Erro ao excluir backup: {e}")
        return {'success': False, 'error': str(e)}

def hash_password(password):
    """Hash da senha"""
    return hashlib.sha256(password.encode()).hexdigest()

def require_admin_login():
    """Verifica se o admin está logado"""
    return session.get('admin_logged_in') == True

@app.route('/')
def index():
    """Página inicial - redireciona para login ou dashboard"""
    if require_admin_login():
        return dashboard()
    else:
        return admin_login()

@app.route('/admin/login')
def admin_login():
    """Página de login do administrador"""
    html = '''
<!DOCTYPE html>
<html lang="pt-BR">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>SpiderPrint - Login Administrativo</title>
    <style>
        * {
            margin: 0;
            padding: 0;
            box-sizing: border-box;
        }
        
        body {
            font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif;
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            min-height: 100vh;
            display: flex;
            align-items: center;
            justify-content: center;
            padding: 20px;
        }
        
        .login-container {
            background: rgba(255, 255, 255, 0.95);
            padding: 40px;
            border-radius: 20px;
            box-shadow: 0 20px 60px rgba(0, 0, 0, 0.3);
            width: 100%;
            max-width: 400px;
            text-align: center;
        }
        
        .logo {
            font-size: 3em;
            margin-bottom: 10px;
        }
        
        .title {
            color: #333;
            font-size: 2em;
            font-weight: bold;
            margin-bottom: 10px;
        }
        
        .subtitle {
            color: #666;
            margin-bottom: 30px;
            font-size: 1.1em;
        }
        
        .form-group {
            margin-bottom: 20px;
            text-align: left;
        }
        
        .form-group label {
            display: block;
            margin-bottom: 8px;
            color: #333;
            font-weight: 500;
        }
        
        .form-group input {
            width: 100%;
            padding: 15px;
            border: 2px solid #e1e5e9;
            border-radius: 12px;
            font-size: 16px;
            transition: border-color 0.3s ease;
        }
        
        .form-group input:focus {
            outline: none;
            border-color: #667eea;
            box-shadow: 0 0 0 3px rgba(102, 126, 234, 0.1);
        }
        
        .btn {
            width: 100%;
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            color: white;
            border: none;
            padding: 15px;
            border-radius: 12px;
            cursor: pointer;
            font-size: 16px;
            font-weight: 600;
            transition: transform 0.3s ease, box-shadow 0.3s ease;
            margin-top: 10px;
        }
        
        .btn:hover {
            transform: translateY(-2px);
            box-shadow: 0 10px 30px rgba(102, 126, 234, 0.4);
        }
        
        .error-message {
            background: #fee;
            color: #c33;
            padding: 12px;
            border-radius: 8px;
            margin-bottom: 20px;
            border: 1px solid #fcc;
        }
        
        .info-box {
            background: #f8f9fa;
            padding: 15px;
            border-radius: 8px;
            margin-top: 20px;
            font-size: 0.9em;
            color: #666;
        }
        
        .security-note {
            margin-top: 20px;
            font-size: 0.8em;
            color: #999;
        }
    </style>
</head>
<body>
    <div class="login-container">
        <div class="logo">🕷️</div>
        <h1 class="title">SpiderPrint</h1>
        <p class="subtitle">Dashboard Administrativo</p>
        
        <div id="errorMessage" class="error-message" style="display: none;"></div>
        
        <form id="loginForm">
            <div class="form-group">
                <label for="username">Usuário Administrador:</label>
                <input type="text" id="username" name="username" required autocomplete="username">
            </div>
            
            <div class="form-group">
                <label for="password">Senha:</label>
                <input type="password" id="password" name="password" required autocomplete="current-password">
            </div>
            
            <button type="submit" class="btn">🔐 Entrar no Dashboard</button>
        </form>
        
        <div class="info-box">
            <strong>🛡️ Área Restrita</strong><br>
            Acesso exclusivo para administradores do sistema SpiderPrint.
        </div>
        
        <div class="security-note">
            🔒 Conexão segura • Dados protegidos
        </div>
    </div>
    
    <script>
        document.getElementById('loginForm').addEventListener('submit', function(e) {
            e.preventDefault();
            
            const username = document.getElementById('username').value;
            const password = document.getElementById('password').value;
            const errorDiv = document.getElementById('errorMessage');
            
            if (!username || !password) {
                showError('Por favor, preencha todos os campos.');
                return;
            }
            
            // Fazer login
            fetch('/admin/authenticate', {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/json',
                },
                body: JSON.stringify({
                    username: username,
                    password: password
                })
            })
            .then(response => response.json())
            .then(data => {
                if (data.success) {
                    window.location.href = '/dashboard';
                } else {
                    showError(data.error || 'Credenciais inválidas');
                }
            })
            .catch(error => {
                console.error('Erro:', error);
                showError('Erro de conexão. Tente novamente.');
            });
        });
        
        function showError(message) {
            const errorDiv = document.getElementById('errorMessage');
            errorDiv.textContent = message;
            errorDiv.style.display = 'block';
            
            // Esconder após 5 segundos
            setTimeout(() => {
                errorDiv.style.display = 'none';
            }, 5000);
        }
        
        // Focus no campo usuário
        document.getElementById('username').focus();
    </script>
</body>
</html>
    '''
    return html

@app.route('/admin/authenticate', methods=['POST'])
def admin_authenticate():
    """Autentica o administrador"""
    try:
        data = request.get_json()
        username = data.get('username', '').strip()
        password = data.get('password', '').strip()
        
        if username == ADMIN_USERNAME and password == ADMIN_PASSWORD:
            session['admin_logged_in'] = True
            session['admin_username'] = username
            
            # Log da ação
            conn = sqlite3.connect(DATABASE)
            cursor = conn.cursor()
            cursor.execute("""
                INSERT INTO access_logs (username, action, ip_address)
                VALUES (?, ?, ?)
            """, (f"admin:{username}", 'login administrativo', request.remote_addr))
            conn.commit()
            conn.close()
            
            return jsonify({'success': True})
        else:
            return jsonify({'success': False, 'error': 'Credenciais inválidas'})
            
    except Exception as e:
        return jsonify({'success': False, 'error': 'Erro interno'}), 500

@app.route('/admin/logout')
def admin_logout():
    """Logout do administrador"""
    session.clear()
    return redirect(url_for('admin_login'))

@app.route('/emergency-reset-admin')
def emergency_reset_admin():
    """Rota de emergência para resetar credenciais do admin"""
    try:
        conn = sqlite3.connect(DATABASE)
        cursor = conn.cursor()
        
        # Deletar admin existente
        cursor.execute('DELETE FROM users WHERE username = ?', (ADMIN_USERNAME,))
        
        # Usar horário do Brasil
        brazil_time = get_brazil_time()
        
        # Inserir novo admin
        cursor.execute('''
            INSERT INTO users (username, email, password_hash, created_at, expires_at, 
                             license_type, access_level, is_active, user_type, is_admin_special)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        ''', (
            ADMIN_USERNAME,
            'admin@spidergrid.com.br',
            ADMIN_PASSWORD_HASH,
            brazil_time.isoformat(),
            None,  # Admin nunca expira
            'Admin',
            'Admin',
            1,
            'Admin',
            1  # Admin especial
        ))
        
        conn.commit()
        conn.close()
        
        return f'''
        <html>
        <head><title>Reset Admin - SpiderPrint</title></head>
        <body style="font-family: Arial; text-align: center; padding: 50px; background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);">
            <div style="background: white; padding: 30px; border-radius: 10px; max-width: 500px; margin: 0 auto;">
                <h1 style="color: #333;">✅ Admin Resetado com Sucesso!</h1>
                <h2 style="color: #667eea;">Credenciais Atualizadas:</h2>
                <p style="font-size: 18px;"><strong>Usuário:</strong> admin</p>
                <p style="font-size: 18px;"><strong>Senha:</strong> Asd4d45#2365</p>
                <hr>
                <p style="color: #666;">Hash da senha: {ADMIN_PASSWORD_HASH[:20]}...</p>
                <p style="color: #666;">Horário: {brazil_time.strftime('%d/%m/%Y %H:%M:%S')}</p>
                <br>
                <a href="/admin" style="background: #667eea; color: white; padding: 10px 20px; text-decoration: none; border-radius: 5px;">
                    🔐 Fazer Login Agora
                </a>
            </div>
        </body>
        </html>
        '''
        
    except Exception as e:
        return f'''
        <html>
        <body style="font-family: Arial; text-align: center; padding: 50px;">
            <h1 style="color: red;">❌ Erro ao resetar admin</h1>
            <p>Erro: {str(e)}</p>
            <a href="/admin">Voltar ao Login</a>
        </body>
        </html>
        '''

@app.route('/dashboard')
def dashboard():
    """Dashboard administrativo (protegido)"""
    if not require_admin_login():
        return redirect(url_for('admin_login'))
    
    html = '''
<!DOCTYPE html>
<html lang="pt-BR">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>SpiderPrint - Dashboard Administrativo</title>
    <style>
        * {
            margin: 0;
            padding: 0;
            box-sizing: border-box;
        }
        
        body {
            font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif;
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            min-height: 100vh;
            padding: 20px;
        }
        
        .container {
            max-width: 1400px;
            margin: 0 auto;
        }
        
        /* Header */
        .header {
            background: rgba(255, 255, 255, 0.95);
            padding: 20px 30px;
            border-radius: 15px;
            margin-bottom: 30px;
            box-shadow: 0 8px 32px rgba(0, 0, 0, 0.1);
            display: flex;
            justify-content: space-between;
            align-items: center;
        }
        
        .header-left h1 {
            color: #333;
            display: flex;
            align-items: center;
            gap: 10px;
            font-size: 28px;
        }
        
        .header-left p {
            color: #666;
            margin-top: 5px;
            font-size: 14px;
        }
        
        .header-right {
            display: flex;
            align-items: center;
            gap: 20px;
        }
        
        .admin-info {
            text-align: right;
            color: #666;
            font-size: 14px;
        }
        
        .admin-info strong {
            color: #333;
        }
        
        .logout-btn {
            background: #dc3545;
            color: white;
            border: none;
            padding: 12px 24px;
            border-radius: 8px;
            cursor: pointer;
            font-size: 14px;
            font-weight: 600;
            transition: all 0.3s ease;
            display: flex;
            align-items: center;
            gap: 8px;
        }
        
        .logout-btn:hover {
            background: #c82333;
            transform: translateY(-2px);
            box-shadow: 0 4px 12px rgba(220, 53, 69, 0.3);
        }
        
        /* Tabs */
        .tabs {
            background: rgba(255, 255, 255, 0.95);
            border-radius: 15px;
            margin-bottom: 30px;
            box-shadow: 0 8px 32px rgba(0, 0, 0, 0.1);
            overflow: hidden;
        }
        
        .tab-buttons {
            display: flex;
            background: rgba(0, 0, 0, 0.05);
            padding: 0;
        }
        
        .tab-button {
            flex: 1;
            padding: 20px;
            background: none;
            border: none;
            cursor: pointer;
            font-size: 16px;
            font-weight: 600;
            color: #666;
            transition: all 0.3s ease;
            position: relative;
        }
        
        .tab-button.active {
            background: white;
            color: #333;
        }
        
        .tab-button:hover {
            background: rgba(255, 255, 255, 0.7);
            color: #333;
        }
        
        .tab-content {
            padding: 30px;
            display: none;
        }
        
        .tab-content.active {
            display: block;
        }
        
        /* Stats Grid */
        .stats-grid {
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(250px, 1fr));
            gap: 20px;
            margin-bottom: 30px;
        }
        
        .stat-card {
            background: rgba(255, 255, 255, 0.95);
            padding: 25px;
            border-radius: 15px;
            box-shadow: 0 8px 32px rgba(0, 0, 0, 0.1);
            text-align: center;
            transition: all 0.3s ease;
        }
        
        .stat-card:hover {
            transform: translateY(-5px);
            box-shadow: 0 12px 40px rgba(0, 0, 0, 0.15);
        }
        
        .stat-number {
            font-size: 48px;
            font-weight: bold;
            color: #667eea;
            margin-bottom: 10px;
        }
        
        .stat-label {
            color: #666;
            font-size: 14px;
            text-transform: uppercase;
            letter-spacing: 1px;
            font-weight: 600;
        }
        
        /* Content Cards */
        .content-grid {
            display: grid;
            grid-template-columns: 1fr 1fr;
            gap: 30px;
        }
        
        .content-card {
            background: rgba(255, 255, 255, 0.95);
            border-radius: 15px;
            box-shadow: 0 8px 32px rgba(0, 0, 0, 0.1);
            overflow: hidden;
        }
        
        .card-header {
            padding: 20px 25px;
            background: rgba(0, 0, 0, 0.05);
            border-bottom: 1px solid rgba(0, 0, 0, 0.1);
            display: flex;
            justify-content: between;
            align-items: center;
        }
        
        .card-title {
            font-size: 18px;
            font-weight: 600;
            color: #333;
            display: flex;
            align-items: center;
            gap: 10px;
        }
        
        .card-content {
            padding: 25px;
            max-height: 400px;
            overflow-y: auto;
        }
        
        /* Users Table */
        .users-table {
            width: 100%;
            border-collapse: collapse;
        }
        
        .users-table th,
        .users-table td {
            padding: 12px;
            text-align: left;
            border-bottom: 1px solid rgba(0, 0, 0, 0.1);
        }
        
        .users-table th {
            background: rgba(0, 0, 0, 0.05);
            font-weight: 600;
            color: #333;
        }
        
        .user-status {
            padding: 4px 12px;
            border-radius: 20px;
            font-size: 12px;
            font-weight: 600;
            text-transform: uppercase;
        }
        
        .status-active {
            background: #d4edda;
            color: #155724;
        }
        
        .status-inactive {
            background: #f8d7da;
            color: #721c24;
        }
        
        .user-level {
            padding: 4px 12px;
            border-radius: 20px;
            font-size: 12px;
            font-weight: 600;
            color: white;
        }
        
        .level-basico {
            background: #28a745;
        }
        
        .level-avancado {
            background: #ffc107;
            color: #333;
        }
        
        .level-completo {
            background: #6f42c1;
        }
        
        /* Action Buttons */
        .action-buttons {
            display: flex;
            gap: 8px;
        }
        
        .btn {
            padding: 8px 16px;
            border: none;
            border-radius: 6px;
            cursor: pointer;
            font-size: 12px;
            font-weight: 600;
            transition: all 0.3s ease;
            text-decoration: none;
            display: inline-flex;
            align-items: center;
            gap: 4px;
        }
        
        .btn-edit {
            background: #007bff;
            color: white;
        }
        
        .btn-edit:hover {
            background: #0056b3;
        }
        
        .btn-disable {
            background: #ffc107;
            color: #333;
        }
        
        .btn-disable:hover {
            background: #e0a800;
        }
        
        .btn-delete {
            background: #dc3545;
            color: white;
        }
        
        .btn-delete:hover {
            background: #c82333;
        }
        
        .btn-primary {
            background: #28a745;
            color: white;
            padding: 12px 24px;
            font-size: 14px;
        }
        
        .btn-primary:hover {
            background: #218838;
        }

        /* Alertas */
        .alert {
            padding: 15px;
            border-radius: 8px;
            margin: 10px 0;
            border-left: 4px solid;
        }

        .alert-success {
            background-color: #d4edda;
            border-color: #28a745;
            color: #155724;
        }

        .alert-error {
            background-color: #f8d7da;
            border-color: #dc3545;
            color: #721c24;
        }

        .alert-info {
            background-color: #d1ecf1;
            border-color: #17a2b8;
            color: #0c5460;
        }

        .alert-warning {
            background-color: #fff3cd;
            border-color: #ffc107;
            color: #856404;
        }

        /* Botões de backup */
        .btn-warning {
            background: #ffc107;
            color: #333;
            padding: 12px 24px;
            font-size: 14px;
        }

        .btn-warning:hover {
            background: #e0a800;
        }

        .btn-secondary {
            background: #6c757d;
            color: white;
            padding: 8px 16px;
            font-size: 12px;
        }

        .btn-secondary:hover {
            background: #5a6268;
        }

        .btn-sm {
            padding: 6px 12px;
            font-size: 11px;
        }

        .btn-danger {
            background: #dc3545;
            color: white;
        }

        .btn-danger:hover {
            background: #c82333;
        }

        /* Upload de arquivo */
        .form-control {
            width: 100%;
            padding: 10px;
            border: 2px solid #e1e5e9;
            border-radius: 8px;
            font-size: 14px;
            transition: border-color 0.3s ease;
        }

        .form-control:focus {
            outline: none;
            border-color: #667eea;
            box-shadow: 0 0 0 3px rgba(102, 126, 234, 0.1);
        }

        .form-group {
            margin-bottom: 20px;
        }

        .form-group label {
            display: block;
            margin-bottom: 8px;
            font-weight: 600;
            color: #333;
        }
        
        /* Logs */
        .log-entry {
            padding: 12px;
            border-bottom: 1px solid rgba(0, 0, 0, 0.1);
            font-size: 14px;
        }
        
        .log-time {
            color: #666;
            font-size: 12px;
        }
        
        .log-user {
            font-weight: 600;
            color: #333;
        }
        
        .log-action {
            color: #667eea;
        }
        
        /* Settings Form */
        .settings-form {
            max-width: 500px;
        }
        
        .form-group {
            margin-bottom: 20px;
        }
        
        .form-label {
            display: block;
            margin-bottom: 8px;
            font-weight: 600;
            color: #333;
        }
        
        .form-input {
            width: 100%;
            padding: 12px;
            border: 2px solid rgba(0, 0, 0, 0.1);
            border-radius: 8px;
            font-size: 14px;
            transition: border-color 0.3s ease;
        }
        
        .form-input:focus {
            outline: none;
            border-color: #667eea;
        }
        
        /* Loading */
        .loading {
            text-align: center;
            padding: 40px;
            color: #666;
        }
        
        /* Responsive */
        @media (max-width: 768px) {
            .content-grid {
                grid-template-columns: 1fr;
            }
            
            .stats-grid {
                grid-template-columns: repeat(2, 1fr);
            }
            
            .header {
                flex-direction: column;
                gap: 15px;
                text-align: center;
            }
            
            .tab-buttons {
                flex-direction: column;
            }
        }
    </style>
</head>
<body>
    <div class="container">
        <!-- Header -->
        <div class="header">
            <div class="header-left">
                <h1>🕷️ SpiderPrint</h1>
                <p>Dashboard Administrativo - Sistema de Autenticação com Níveis de Acesso</p>
            </div>
            <div class="header-right">
                <div class="admin-info">
                    <strong>👤 Administrador</strong><br>
                    🔐 Sessão Segura
                </div>
                <button class="logout-btn" onclick="logout()">
                    🚪 Sair
                </button>
            </div>
        </div>

        <!-- Tabs -->
        <div class="tabs">
            <div class="tab-buttons">
                <button class="tab-button active" onclick="showTab('home')">📊 Dashboard</button>
                <button class="tab-button" onclick="showTab('users')">👥 Usuários</button>
                <button class="tab-button" onclick="showTab('staff')">👨‍💼 Staff</button>
                <button class="tab-button" onclick="showTab('logs')">📋 Logs de Acesso</button>
                <button class="tab-button" onclick="showTab('backup')">💾 Backup</button>
                <button class="tab-button" onclick="showTab('settings')">⚙️ Configurações</button>
            </div>

            <!-- Home Tab -->
            <div id="home-tab" class="tab-content active">
                <div class="stats-grid" id="statsGrid">
                    <div class="loading">Carregando estatísticas...</div>
                </div>
                
                <div class="content-grid">
                    <div class="content-card">
                        <div class="card-header">
                            <h3 class="card-title">👥 Usuários Recentes</h3>
                        </div>
                        <div class="card-content" id="recentUsers">
                            <div class="loading">Carregando usuários...</div>
                        </div>
                    </div>
                    
                    <div class="content-card">
                        <div class="card-header">
                            <h3 class="card-title">📋 Logs Recentes</h3>
                        </div>
                        <div class="card-content" id="recentLogs">
                            <div class="loading">Carregando logs...</div>
                        </div>
                    </div>
                </div>
            </div>

            <!-- Users Tab -->
            <div id="users-tab" class="tab-content">
                <div style="margin-bottom: 20px;">
                    <button class="btn btn-primary" onclick="showAddUserModal()">+ Novo Usuário</button>
                </div>
                <div id="usersContent">
                    <div class="loading">Carregando usuários...</div>
                </div>
            </div>

            <!-- Staff Tab -->
            <div id="staff-tab" class="tab-content">
                <div style="margin-bottom: 20px; display: flex; gap: 10px;">
                    <button class="btn btn-primary" onclick="showAddStaffModal()">+ Novo Vendedor/Técnico</button>
                    <button class="btn btn-secondary" onclick="loadStaffActivity()">📊 Atividade Staff</button>
                </div>
                <div id="staffContent">
                    <div class="loading">Carregando staff...</div>
                </div>
            </div>

            <!-- Logs Tab -->
            <div id="logs-tab" class="tab-content">
                <div id="logsContent">
                    <div class="loading">Carregando logs...</div>
                </div>
            </div>

            <!-- Backup Tab -->
            <div id="backup-tab" class="tab-content">
                <div class="content-grid">
                    <!-- Criar Backup -->
                    <div class="content-card">
                        <div class="card-header">
                            <h3 class="card-title">💾 Criar Backup</h3>
                        </div>
                        <div class="card-content">
                            <p>Crie um backup completo do banco de dados para proteger os dados dos usuários.</p>
                            <button class="btn btn-primary" onclick="createBackup()">
                                <span id="createBackupText">💾 Criar Backup Agora</span>
                            </button>
                            <div id="backupResult" style="margin-top: 15px;"></div>
                        </div>
                    </div>

                    <!-- Restaurar Backup -->
                    <div class="content-card">
                        <div class="card-header">
                            <h3 class="card-title">📥 Restaurar Backup</h3>
                        </div>
                        <div class="card-content">
                            <p>Restaure um backup anterior. <strong>Atenção:</strong> Esta ação substituirá todos os dados atuais.</p>
                            <div class="form-group">
                                <label for="backupFile">Selecionar arquivo de backup:</label>
                                <input type="file" id="backupFile" accept=".db,.sql" class="form-control">
                            </div>
                            <button class="btn btn-warning" onclick="uploadBackup()">
                                <span id="uploadBackupText">📥 Restaurar Backup</span>
                            </button>
                            <div id="uploadResult" style="margin-top: 15px;"></div>
                        </div>
                    </div>
                </div>

                <!-- Lista de Backups -->
                <div class="content-card" style="margin-top: 30px;">
                    <div class="card-header">
                        <h3 class="card-title">📋 Backups Disponíveis</h3>
                        <button class="btn btn-secondary" onclick="loadBackups()">🔄 Atualizar</button>
                    </div>
                    <div class="card-content">
                        <div id="backupsList">
                            <div class="loading">Carregando backups...</div>
                        </div>
                    </div>
                </div>
            </div>

            <!-- Settings Tab -->
            <div id="settings-tab" class="tab-content">
                <div class="content-card">
                    <div class="card-header">
                        <h3 class="card-title">🔐 Alterar Senha do Administrador</h3>
                    </div>
                    <div class="card-content">
                        <form class="settings-form" id="changePasswordForm">
                            <div class="form-group">
                                <label class="form-label" for="currentPassword">Senha Atual:</label>
                                <input type="password" class="form-input" id="currentPassword" required>
                            </div>
                            <div class="form-group">
                                <label class="form-label" for="newPassword">Nova Senha:</label>
                                <input type="password" class="form-input" id="newPassword" required>
                            </div>
                            <div class="form-group">
                                <label class="form-label" for="confirmPassword">Confirmar Nova Senha:</label>
                                <input type="password" class="form-input" id="confirmPassword" required>
                            </div>
                            <button type="submit" class="btn btn-primary">🔐 Alterar Senha</button>
                        </form>
                    </div>
                </div>
            </div>
        </div>
    </div>

    <script>
        // Tab Management
        function showTab(tabName) {
            // Hide all tabs
            document.querySelectorAll('.tab-content').forEach(tab => {
                tab.classList.remove('active');
            });
            
            // Remove active from all buttons
            document.querySelectorAll('.tab-button').forEach(btn => {
                btn.classList.remove('active');
            });
            
            // Show selected tab
            document.getElementById(tabName + '-tab').classList.add('active');
            event.target.classList.add('active');
            
            // Load content based on tab
            if (tabName === 'home') {
                loadDashboardData();
            } else if (tabName === 'users') {
                loadUsers();
            } else if (tabName === 'staff') {
                loadStaff();
            } else if (tabName === 'logs') {
                loadLogs();
            } else if (tabName === 'backup') {
                loadBackups();
            }
        }

        // Load Dashboard Data
        function loadDashboardData() {
            fetch('/api/stats')
                .then(response => response.json())
                .then(data => {
                    if (data.error) {
                        document.getElementById('statsGrid').innerHTML = '<div class="loading">Erro ao carregar dados</div>';
                        return;
                    }
                    
                    const statsHtml = `
                        <div class="stat-card">
                            <div class="stat-number">${data.total_users}</div>
                            <div class="stat-label">Total de Usuários</div>
                        </div>
                        <div class="stat-card">
                            <div class="stat-number">${data.active_users}</div>
                            <div class="stat-label">Usuários Ativos</div>
                        </div>
                        <div class="stat-card">
                            <div class="stat-number">${data.basic_users}</div>
                            <div class="stat-label">Nível Básico</div>
                        </div>
                        <div class="stat-card">
                            <div class="stat-number">${data.advanced_users}</div>
                            <div class="stat-label">Nível Avançado</div>
                        </div>
                        <div class="stat-card">
                            <div class="stat-number">${data.complete_users}</div>
                            <div class="stat-label">Nível Completo</div>
                        </div>
                        <div class="stat-card">
                            <div class="stat-number">${data.logins_today}</div>
                            <div class="stat-label">Logins Hoje</div>
                        </div>
                    `;
                    document.getElementById('statsGrid').innerHTML = statsHtml;
                })
                .catch(error => {
                    console.error('Erro:', error);
                    document.getElementById('statsGrid').innerHTML = '<div class="loading">Erro ao carregar dados</div>';
                });

            // Load recent users and logs
            loadRecentUsers();
            loadRecentLogs();
        }

        function loadRecentUsers() {
            fetch('/api/users?limit=5')
                .then(response => response.json())
                .then(data => {
                    if (data.error) {
                        document.getElementById('recentUsers').innerHTML = '<div class="loading">Erro ao carregar usuários</div>';
                        return;
                    }
                    
                    let html = '<table class="users-table"><thead><tr><th>Usuário</th><th>Nível</th><th>Status</th></tr></thead><tbody>';
                    data.users.slice(0, 5).forEach(user => {
                        const statusClass = user.is_active ? 'status-active' : 'status-inactive';
                        const statusText = user.is_active ? 'Ativo' : 'Inativo';
                        const levelClass = `level-${user.access_level.toLowerCase()}`;
                        
                        html += `
                            <tr>
                                <td><strong>${user.username}</strong><br><small>${user.email}</small></td>
                                <td><span class="user-level ${levelClass}">${user.access_level}</span></td>
                                <td><span class="user-status ${statusClass}">${statusText}</span></td>
                            </tr>
                        `;
                    });
                    html += '</tbody></table>';
                    document.getElementById('recentUsers').innerHTML = html;
                })
                .catch(error => {
                    console.error('Erro:', error);
                    document.getElementById('recentUsers').innerHTML = '<div class="loading">Erro ao carregar usuários</div>';
                });
        }

        function loadRecentLogs() {
            fetch('/api/logs?limit=10')
                .then(response => response.json())
                .then(data => {
                    if (data.error) {
                        document.getElementById('recentLogs').innerHTML = '<div class="loading">Erro ao carregar logs</div>';
                        return;
                    }
                    
                    let html = '';
                    data.logs.slice(0, 10).forEach(log => {
                        html += `
                            <div class="log-entry">
                                <div class="log-time">${new Date(log.timestamp).toLocaleString('pt-BR')}</div>
                                <div><span class="log-user">${log.username}</span> - <span class="log-action">${log.action}</span></div>
                            </div>
                        `;
                    });
                    document.getElementById('recentLogs').innerHTML = html;
                })
                .catch(error => {
                    console.error('Erro:', error);
                    document.getElementById('recentLogs').innerHTML = '<div class="loading">Erro ao carregar logs</div>';
                });
        }

        function loadUsers() {
            fetch('/api/users')
                .then(response => response.json())
                .then(data => {
                    if (data.error) {
                        document.getElementById('usersContent').innerHTML = '<div class="loading">Erro ao carregar usuários</div>';
                        return;
                    }
                    
                    // Store users data globally for filtering
                    window.allUsers = data.users;
                    renderUsersTable(data.users);
                })
                .catch(error => {
                    console.error('Erro:', error);
                    document.getElementById('usersContent').innerHTML = '<div class="loading">Erro ao carregar usuários</div>';
                });
        }

        function renderUsersTable(users) {
            let html = `
                <div style="margin-bottom: 20px; display: flex; gap: 15px; align-items: center; flex-wrap: wrap;">
                    <input type="text" id="searchUsers" placeholder="🔍 Buscar por nome ou email..." 
                           style="flex: 1; min-width: 250px; padding: 10px; border: 2px solid rgba(0,0,0,0.1); border-radius: 8px;"
                           onkeyup="filterUsers()">
                    <select id="filterLevel" onchange="filterUsers()" 
                            style="padding: 10px; border: 2px solid rgba(0,0,0,0.1); border-radius: 8px;">
                        <option value="">Todos os níveis</option>
                        <option value="Básico">Básico</option>
                        <option value="Avançado">Avançado</option>
                        <option value="Completo">Completo</option>
                    </select>
                    <select id="filterStatus" onchange="filterUsers()" 
                            style="padding: 10px; border: 2px solid rgba(0,0,0,0.1); border-radius: 8px;">
                        <option value="">Todos os status</option>
                        <option value="active">Ativos</option>
                        <option value="inactive">Inativos</option>
                    </select>
                    <button class="btn btn-primary" onclick="exportUsers()">📊 Exportar CSV</button>
                </div>
                <div style="margin-bottom: 15px; color: #666; font-size: 14px;">
                    Mostrando ${users.length} usuário(s)
                </div>
                <table class="users-table">
                    <thead>
                        <tr>
                            <th><input type="checkbox" id="selectAll" onchange="toggleSelectAll()"> Usuário</th>
                            <th onclick="sortUsers('email')" style="cursor: pointer;">Email 📊</th>
                            <th onclick="sortUsers('access_level')" style="cursor: pointer;">Nível 📊</th>
                            <th onclick="sortUsers('is_active')" style="cursor: pointer;">Status 📊</th>
                            <th onclick="sortUsers('expires_at')" style="cursor: pointer;">Expira 📊</th>
                            <th>Ações</th>
                        </tr>
                    </thead>
                    <tbody>
            `;
            
            users.forEach(user => {
                const statusClass = user.is_active ? 'status-active' : 'status-inactive';
                const statusText = user.is_active ? 'Ativo' : 'Inativo';
                const levelClass = `level-${user.access_level.toLowerCase()}`;
                const expiresDate = user.expires_at ? new Date(user.expires_at).toLocaleDateString('pt-BR') : 'Nunca';
                const isExpired = user.expires_at && new Date(user.expires_at) < new Date();
                
                html += `
                    <tr ${isExpired ? 'style="background-color: #fff3cd;"' : ''}>
                        <td>
                            <input type="checkbox" class="user-checkbox" value="${user.id}">
                            <strong>${user.username}</strong>
                            ${isExpired ? '<br><small style="color: #856404;">⚠️ Expirado</small>' : ''}
                        </td>
                        <td>${user.email}</td>
                        <td><span class="user-level ${levelClass}">${user.access_level}</span></td>
                        <td><span class="user-status ${statusClass}">${statusText}</span></td>
                        <td>${expiresDate}</td>
                        <td>
                            <div class="action-buttons">
                                <button class="btn btn-edit" onclick="editUser(${user.id})" title="Editar">✏️</button>
                                <button class="btn btn-disable" onclick="toggleUser(${user.id})" title="${user.is_active ? 'Desativar' : 'Ativar'}">
                                    ${user.is_active ? '⏸️' : '▶️'}
                                </button>
                                <button class="btn btn-delete" onclick="deleteUser(${user.id})" title="Excluir">🗑️</button>
                            </div>
                        </td>
                    </tr>
                `;
            });
            
            html += `
                    </tbody>
                </table>
                <div style="margin-top: 20px; display: flex; gap: 10px; align-items: center;">
                    <button class="btn btn-edit" onclick="bulkAction('edit')" id="bulkEditBtn" style="display: none;">✏️ Editar Selecionados</button>
                    <button class="btn btn-disable" onclick="bulkAction('toggle')" id="bulkToggleBtn" style="display: none;">⏸️ Ativar/Desativar</button>
                    <button class="btn btn-delete" onclick="bulkAction('delete')" id="bulkDeleteBtn" style="display: none;">🗑️ Excluir Selecionados</button>
                </div>
            `;
            
            document.getElementById('usersContent').innerHTML = html;
        }

        function filterUsers() {
            const searchTerm = document.getElementById('searchUsers').value.toLowerCase();
            const levelFilter = document.getElementById('filterLevel').value;
            const statusFilter = document.getElementById('filterStatus').value;
            
            let filteredUsers = window.allUsers.filter(user => {
                const matchesSearch = user.username.toLowerCase().includes(searchTerm) || 
                                    user.email.toLowerCase().includes(searchTerm);
                const matchesLevel = !levelFilter || user.access_level === levelFilter;
                const matchesStatus = !statusFilter || 
                                    (statusFilter === 'active' && user.is_active) ||
                                    (statusFilter === 'inactive' && !user.is_active);
                
                return matchesSearch && matchesLevel && matchesStatus;
            });
            
            renderUsersTable(filteredUsers);
        }

        function sortUsers(field) {
            if (!window.sortDirection) window.sortDirection = {};
            window.sortDirection[field] = window.sortDirection[field] === 'asc' ? 'desc' : 'asc';
            
            const currentUsers = getCurrentDisplayedUsers();
            currentUsers.sort((a, b) => {
                let aVal = a[field];
                let bVal = b[field];
                
                if (field === 'expires_at') {
                    aVal = aVal ? new Date(aVal) : new Date('9999-12-31');
                    bVal = bVal ? new Date(bVal) : new Date('9999-12-31');
                } else if (typeof aVal === 'string') {
                    aVal = aVal.toLowerCase();
                    bVal = bVal.toLowerCase();
                }
                
                if (window.sortDirection[field] === 'asc') {
                    return aVal > bVal ? 1 : -1;
                } else {
                    return aVal < bVal ? 1 : -1;
                }
            });
            
            renderUsersTable(currentUsers);
        }

        function getCurrentDisplayedUsers() {
            const searchTerm = document.getElementById('searchUsers')?.value.toLowerCase() || '';
            const levelFilter = document.getElementById('filterLevel')?.value || '';
            const statusFilter = document.getElementById('filterStatus')?.value || '';
            
            return window.allUsers.filter(user => {
                const matchesSearch = user.username.toLowerCase().includes(searchTerm) || 
                                    user.email.toLowerCase().includes(searchTerm);
                const matchesLevel = !levelFilter || user.access_level === levelFilter;
                const matchesStatus = !statusFilter || 
                                    (statusFilter === 'active' && user.is_active) ||
                                    (statusFilter === 'inactive' && !user.is_active);
                
                return matchesSearch && matchesLevel && matchesStatus;
            });
        }

        function toggleSelectAll() {
            const selectAll = document.getElementById('selectAll');
            const checkboxes = document.querySelectorAll('.user-checkbox');
            
            checkboxes.forEach(checkbox => {
                checkbox.checked = selectAll.checked;
            });
            
            updateBulkButtons();
        }

        function updateBulkButtons() {
            const checkedBoxes = document.querySelectorAll('.user-checkbox:checked');
            const bulkButtons = ['bulkEditBtn', 'bulkToggleBtn', 'bulkDeleteBtn'];
            
            bulkButtons.forEach(btnId => {
                const btn = document.getElementById(btnId);
                if (btn) {
                    btn.style.display = checkedBoxes.length > 0 ? 'inline-flex' : 'none';
                }
            });
        }

        function exportUsers() {
            const users = getCurrentDisplayedUsers();
            let csv = 'Usuário,Email,Nível,Status,Criado,Expira\\n';
            
            users.forEach(user => {
                const status = user.is_active ? 'Ativo' : 'Inativo';
                const created = new Date(user.created_at).toLocaleDateString('pt-BR');
                const expires = user.expires_at ? new Date(user.expires_at).toLocaleDateString('pt-BR') : 'Nunca';
                
                csv += `"${user.username}","${user.email}","${user.access_level}","${status}","${created}","${expires}"\\n`;
            });
            
            const blob = new Blob([csv], { type: 'text/csv' });
            const url = window.URL.createObjectURL(blob);
            const a = document.createElement('a');
            a.href = url;
            a.download = `usuarios_spiderprint_${new Date().toISOString().split('T')[0]}.csv`;
            a.click();
            window.URL.revokeObjectURL(url);
        }

        function bulkAction(action) {
            const checkedBoxes = document.querySelectorAll('.user-checkbox:checked');
            const userIds = Array.from(checkedBoxes).map(cb => cb.value);
            
            if (userIds.length === 0) {
                alert('Selecione pelo menos um usuário');
                return;
            }
            
            if (action === 'delete') {
                if (!confirm(`Tem certeza que deseja excluir ${userIds.length} usuário(s)? Esta ação não pode ser desfeita.`)) {
                    return;
                }
            } else if (action === 'toggle') {
                if (!confirm(`Tem certeza que deseja alterar o status de ${userIds.length} usuário(s)?`)) {
                    return;
                }
            }
            
            // Implementation for bulk actions
            alert(`Ação em lote "${action}" para ${userIds.length} usuário(s) será implementada em breve`);
        }

        // Add event listener for checkboxes
        document.addEventListener('change', function(e) {
            if (e.target.classList.contains('user-checkbox')) {
                updateBulkButtons();
            }
        });
        }

        function loadLogs() {
            fetch('/api/logs')
                .then(response => response.json())
                .then(data => {
                    if (data.error) {
                        document.getElementById('logsContent').innerHTML = '<div class="loading">Erro ao carregar logs</div>';
                        return;
                    }
                    
                    // Store logs data globally for filtering
                    window.allLogs = data.logs;
                    renderLogsTable(data.logs);
                })
                .catch(error => {
                    console.error('Erro:', error);
                    document.getElementById('logsContent').innerHTML = '<div class="loading">Erro ao carregar logs</div>';
                });
        }

        function renderLogsTable(logs) {
            let html = `
                <div style="margin-bottom: 20px; display: flex; gap: 15px; align-items: center; flex-wrap: wrap;">
                    <input type="text" id="searchLogs" placeholder="🔍 Buscar por usuário ou ação..." 
                           style="flex: 1; min-width: 250px; padding: 10px; border: 2px solid rgba(0,0,0,0.1); border-radius: 8px;"
                           onkeyup="filterLogs()">
                    <select id="filterAction" onchange="filterLogs()" 
                            style="padding: 10px; border: 2px solid rgba(0,0,0,0.1); border-radius: 8px;">
                        <option value="">Todas as ações</option>
                        <option value="login">Login</option>
                        <option value="logout">Logout</option>
                        <option value="create_user">Criar Usuário</option>
                        <option value="update_user">Editar Usuário</option>
                        <option value="delete_user">Excluir Usuário</option>
                        <option value="change_password">Alterar Senha</option>
                    </select>
                    <input type="date" id="filterDate" onchange="filterLogs()" 
                           style="padding: 10px; border: 2px solid rgba(0,0,0,0.1); border-radius: 8px;">
                    <button class="btn btn-primary" onclick="exportLogs()">📊 Exportar CSV</button>
                    <button class="btn btn-delete" onclick="clearOldLogs()">🗑️ Limpar Logs Antigos</button>
                </div>
                <div style="margin-bottom: 15px; color: #666; font-size: 14px;">
                    Mostrando ${logs.length} log(s)
                </div>
                <div style="max-height: 500px; overflow-y: auto; border: 1px solid rgba(0,0,0,0.1); border-radius: 8px;">
            `;
            
            logs.forEach(log => {
                const date = new Date(log.timestamp);
                const timeStr = date.toLocaleString('pt-BR');
                const actionClass = getActionClass(log.action);
                
                html += `
                    <div class="log-entry" style="padding: 15px; border-bottom: 1px solid rgba(0,0,0,0.1); display: flex; justify-content: space-between; align-items: flex-start;">
                        <div style="flex: 1;">
                            <div style="display: flex; align-items: center; gap: 10px; margin-bottom: 5px;">
                                <span class="log-time" style="color: #666; font-size: 12px; background: rgba(0,0,0,0.05); padding: 2px 8px; border-radius: 4px;">
                                    ${timeStr}
                                </span>
                                <span class="log-action ${actionClass}" style="padding: 2px 8px; border-radius: 4px; font-size: 12px; font-weight: 600;">
                                    ${getActionText(log.action)}
                                </span>
                            </div>
                            <div style="margin-bottom: 5px;">
                                <span class="log-user" style="font-weight: 600; color: #333;">👤 ${log.username}</span>
                            </div>
                            ${log.details ? `<div style="color: #666; font-size: 13px; margin-top: 5px;">📋 ${log.details}</div>` : ''}
                            ${log.hardware_id ? `<div style="color: #888; font-size: 11px; margin-top: 3px;">🖥️ Hardware: ${log.hardware_id.substring(0, 16)}...</div>` : ''}
                        </div>
                        <div style="display: flex; gap: 5px;">
                            <button class="btn" style="padding: 4px 8px; font-size: 11px; background: #f8f9fa; color: #666;" 
                                    onclick="showLogDetails('${log.id}')" title="Ver detalhes">
                                👁️
                            </button>
                        </div>
                    </div>
                `;
            });
            
            html += `
                </div>
                <div style="margin-top: 20px; display: flex; justify-content: space-between; align-items: center;">
                    <div style="color: #666; font-size: 14px;">
                        📊 Total de logs: ${logs.length}
                    </div>
                    <div style="display: flex; gap: 10px;">
                        <button class="btn btn-primary" onclick="refreshLogs()">🔄 Atualizar</button>
                        <button class="btn btn-edit" onclick="downloadLogsReport()">📄 Relatório Completo</button>
                    </div>
                </div>
            `;
            
            document.getElementById('logsContent').innerHTML = html;
        }

        function getActionClass(action) {
            const classes = {
                'login': 'action-success',
                'logout': 'action-info',
                'create_user': 'action-primary',
                'update_user': 'action-warning',
                'delete_user': 'action-danger',
                'change_password': 'action-secondary'
            };
            return classes[action] || 'action-default';
        }

        function getActionText(action) {
            const texts = {
                'login': '🔐 Login',
                'logout': '🚪 Logout',
                'create_user': '➕ Criar Usuário',
                'update_user': '✏️ Editar Usuário',
                'delete_user': '🗑️ Excluir Usuário',
                'change_password': '🔑 Alterar Senha'
            };
            return texts[action] || action;
        }

        function filterLogs() {
            const searchTerm = document.getElementById('searchLogs').value.toLowerCase();
            const actionFilter = document.getElementById('filterAction').value;
            const dateFilter = document.getElementById('filterDate').value;
            
            let filteredLogs = window.allLogs.filter(log => {
                const matchesSearch = log.username.toLowerCase().includes(searchTerm) || 
                                    log.action.toLowerCase().includes(searchTerm) ||
                                    (log.details && log.details.toLowerCase().includes(searchTerm));
                const matchesAction = !actionFilter || log.action === actionFilter;
                
                let matchesDate = true;
                if (dateFilter) {
                    const logDate = new Date(log.timestamp).toISOString().split('T')[0];
                    matchesDate = logDate === dateFilter;
                }
                
                return matchesSearch && matchesAction && matchesDate;
            });
            
            // Sort by timestamp (newest first)
            filteredLogs.sort((a, b) => new Date(b.timestamp) - new Date(a.timestamp));
            
            renderLogsTable(filteredLogs);
        }

        function exportLogs() {
            const logs = getCurrentDisplayedLogs();
            let csv = 'Data/Hora,Usuário,Ação,Detalhes,Hardware ID\\n';
            
            logs.forEach(log => {
                const timestamp = new Date(log.timestamp).toLocaleString('pt-BR');
                const details = (log.details || '').replace(/"/g, '""');
                const hardwareId = log.hardware_id || '';
                
                csv += `"${timestamp}","${log.username}","${log.action}","${details}","${hardwareId}"\\n`;
            });
            
            const blob = new Blob([csv], { type: 'text/csv' });
            const url = window.URL.createObjectURL(blob);
            const a = document.createElement('a');
            a.href = url;
            a.download = `logs_spiderprint_${new Date().toISOString().split('T')[0]}.csv`;
            a.click();
            window.URL.revokeObjectURL(url);
        }

        function getCurrentDisplayedLogs() {
            const searchTerm = document.getElementById('searchLogs')?.value.toLowerCase() || '';
            const actionFilter = document.getElementById('filterAction')?.value || '';
            const dateFilter = document.getElementById('filterDate')?.value || '';
            
            return window.allLogs.filter(log => {
                const matchesSearch = log.username.toLowerCase().includes(searchTerm) || 
                                    log.action.toLowerCase().includes(searchTerm) ||
                                    (log.details && log.details.toLowerCase().includes(searchTerm));
                const matchesAction = !actionFilter || log.action === actionFilter;
                
                let matchesDate = true;
                if (dateFilter) {
                    const logDate = new Date(log.timestamp).toISOString().split('T')[0];
                    matchesDate = logDate === dateFilter;
                }
                
                return matchesSearch && matchesAction && matchesDate;
            });
        }

        function showLogDetails(logId) {
            const log = window.allLogs.find(l => l.id == logId);
            if (!log) return;
            
            const details = `
                📅 Data/Hora: ${new Date(log.timestamp).toLocaleString('pt-BR')}
                👤 Usuário: ${log.username}
                🎯 Ação: ${getActionText(log.action)}
                📋 Detalhes: ${log.details || 'Nenhum detalhe adicional'}
                🖥️ Hardware ID: ${log.hardware_id || 'Não informado'}
                🆔 Log ID: ${log.id}
            `;
            
            alert(details);
        }

        function clearOldLogs() {
            const days = prompt('Excluir logs mais antigos que quantos dias?', '30');
            if (!days || isNaN(days)) return;
            
            if (confirm(`Tem certeza que deseja excluir logs mais antigos que ${days} dias? Esta ação não pode ser desfeita.`)) {
                // Implementation would go here
                alert('Funcionalidade de limpeza de logs será implementada em breve');
            }
        }

        function refreshLogs() {
            loadLogs();
        }

        function downloadLogsReport() {
            alert('Relatório completo de logs será implementado em breve');
        }

        // Add CSS for log action classes
        const logStyles = `
            <style>
                .action-success { background: #d4edda; color: #155724; }
                .action-info { background: #d1ecf1; color: #0c5460; }
                .action-primary { background: #cce5ff; color: #004085; }
                .action-warning { background: #fff3cd; color: #856404; }
                .action-danger { background: #f8d7da; color: #721c24; }
                .action-secondary { background: #e2e3e5; color: #383d41; }
                .action-default { background: #f8f9fa; color: #6c757d; }
            </style>
        `;
        
        if (!document.getElementById('logStyles')) {
            const styleElement = document.createElement('div');
            styleElement.id = 'logStyles';
            styleElement.innerHTML = logStyles;
            document.head.appendChild(styleElement);
        }
        }

        // Change Password
        document.getElementById('changePasswordForm').addEventListener('submit', function(e) {
            e.preventDefault();
            
            const currentPassword = document.getElementById('currentPassword').value;
            const newPassword = document.getElementById('newPassword').value;
            const confirmPassword = document.getElementById('confirmPassword').value;
            
            if (newPassword !== confirmPassword) {
                alert('As novas senhas não coincidem!');
                return;
            }
            
            fetch('/admin/change-password', {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/json',
                },
                body: JSON.stringify({
                    current_password: currentPassword,
                    new_password: newPassword,
                    confirm_password: confirmPassword
                })
            })
            .then(response => response.json())
            .then(data => {
                if (data.success) {
                    alert('Senha alterada com sucesso!');
                    document.getElementById('changePasswordForm').reset();
                } else {
                    alert('Erro: ' + data.error);
                }
            })
            .catch(error => {
                console.error('Erro:', error);
                alert('Erro ao alterar senha');
            });
        });

        // User Actions (placeholder functions)
        function editUser(userId) {
            alert('Função de editar usuário será implementada em breve');
        }

        function toggleUser(userId) {
            if (confirm('Tem certeza que deseja alterar o status deste usuário?')) {
                // Implementation will be added
                alert('Função será implementada');
            }
        }

        function deleteUser(userId) {
            if (confirm('Tem certeza que deseja excluir este usuário? Esta ação não pode ser desfeita.')) {
                // Implementation will be added
                alert('Função será implementada');
            }
        }

        function removeHardwareId(userId, username) {
            if (confirm(`🔧 Tem certeza que deseja remover o Hardware ID do usuário "${username}"?\n\nIsso permitirá que ele use o software em outro computador.`)) {
                fetch(`/api/hardware/remove/${userId}`, {
                    method: 'POST',
                    headers: {
                        'Content-Type': 'application/json'
                    }
                })
                .then(response => response.json())
                .then(data => {
                    if (data.error) {
                        alert('Erro: ' + data.error);
                    } else {
                        alert(`✅ Hardware ID removido com sucesso!\n\nO usuário "${username}" agora pode usar o software em outro computador.`);
                        loadUsers(); // Recarregar lista de usuários
                    }
                })
                .catch(error => {
                    console.error('Erro:', error);
                    alert('Erro ao remover hardware ID');
                });
            }
        }

        function showAddUserModal() {
            alert('Modal de adicionar usuário será implementado em breve');
        }

        // ===== FUNÇÕES DE STAFF =====

        function loadStaff() {
            fetch('/api/users?user_type=staff')
                .then(response => response.json())
                .then(data => {
                    if (data.error) {
                        document.getElementById('staffContent').innerHTML = '<div class="loading">Erro ao carregar staff</div>';
                        return;
                    }
                    
                    const staffList = data.filter(user => ['Vendedor', 'Técnico'].includes(user.user_type));
                    renderStaffTable(staffList);
                })
                .catch(error => {
                    console.error('Erro:', error);
                    document.getElementById('staffContent').innerHTML = '<div class="loading">Erro ao carregar staff</div>';
                });
        }

        function renderStaffTable(staff) {
            let html = `
                <div class="table-container">
                    <table class="data-table">
                        <thead>
                            <tr>
                                <th>👤 Nome</th>
                                <th>📧 Email</th>
                                <th>🏷️ Tipo</th>
                                <th>📅 Criado em</th>
                                <th>🎯 Acessos Criados</th>
                                <th>⚙️ Ações</th>
                            </tr>
                        </thead>
                        <tbody>
            `;

            if (staff.length === 0) {
                html += `
                    <tr>
                        <td colspan="6" style="text-align: center; padding: 40px; color: #666;">
                            👨‍💼 Nenhum vendedor ou técnico cadastrado
                        </td>
                    </tr>
                `;
            } else {
                staff.forEach(user => {
                    const statusClass = user.is_active ? 'status-active' : 'status-inactive';
                    const statusText = user.is_active ? 'Ativo' : 'Inativo';
                    
                    html += `
                        <tr>
                            <td><strong>${user.username}</strong></td>
                            <td>${user.email}</td>
                            <td>
                                <span class="badge ${user.user_type === 'Vendedor' ? 'badge-primary' : 'badge-secondary'}">
                                    ${user.user_type === 'Vendedor' ? '💼' : '🔧'} ${user.user_type}
                                </span>
                            </td>
                            <td>${user.created_at}</td>
                            <td>
                                <button class="btn btn-sm btn-info" onclick="viewStaffTrials('${user.username}')">
                                    📊 Ver Acessos
                                </button>
                            </td>
                            <td>
                                <div class="action-buttons">
                                    <button class="btn btn-sm btn-warning" onclick="editStaff(${user.id})">✏️ Editar</button>
                                    <button class="btn btn-sm btn-danger" onclick="deleteStaff(${user.id})">🗑️ Excluir</button>
                                </div>
                            </td>
                        </tr>
                    `;
                });
            }

            html += `
                        </tbody>
                    </table>
                </div>
            `;

            document.getElementById('staffContent').innerHTML = html;
        }

        function showAddStaffModal() {
            const modal = document.createElement('div');
            modal.className = 'modal-overlay';
            modal.innerHTML = `
                <div class="modal-content">
                    <div class="modal-header">
                        <h3>👨‍💼 Novo Vendedor/Técnico</h3>
                        <button class="modal-close" onclick="closeModal()">&times;</button>
                    </div>
                    <div class="modal-body">
                        <form id="addStaffForm">
                            <div class="form-group">
                                <label>👤 Nome de usuário:</label>
                                <input type="text" id="staffUsername" required>
                            </div>
                            <div class="form-group">
                                <label>📧 Email:</label>
                                <input type="email" id="staffEmail" required>
                            </div>
                            <div class="form-group">
                                <label>🔑 Senha:</label>
                                <input type="password" id="staffPassword" required>
                            </div>
                            <div class="form-group">
                                <label>🏷️ Tipo:</label>
                                <select id="staffType" required>
                                    <option value="Vendedor">💼 Vendedor</option>
                                    <option value="Técnico">🔧 Técnico</option>
                                </select>
                            </div>
                        </form>
                    </div>
                    <div class="modal-footer">
                        <button class="btn btn-secondary" onclick="closeModal()">Cancelar</button>
                        <button class="btn btn-primary" onclick="createStaff()">Criar Staff</button>
                    </div>
                </div>
            `;
            document.body.appendChild(modal);
        }

        function createStaff() {
            const username = document.getElementById('staffUsername').value;
            const email = document.getElementById('staffEmail').value;
            const password = document.getElementById('staffPassword').value;
            const staffType = document.getElementById('staffType').value;

            if (!username || !email || !password) {
                alert('Todos os campos são obrigatórios');
                return;
            }

            fetch('/api/staff/create', {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/json'
                },
                body: JSON.stringify({
                    username: username,
                    email: email,
                    password: password,
                    staff_type: staffType
                })
            })
            .then(response => response.json())
            .then(data => {
                if (data.error) {
                    alert('Erro: ' + data.error);
                } else {
                    alert(`${staffType} criado com sucesso!`);
                    closeModal();
                    loadStaff();
                }
            })
            .catch(error => {
                console.error('Erro:', error);
                alert('Erro ao criar staff');
            });
        }

        function viewStaffTrials(staffUsername) {
            // Implementar visualização dos acessos criados pelo staff
            alert(`Visualizar acessos criados por: ${staffUsername}`);
        }

        function editStaff(staffId) {
            alert('Editar staff será implementado');
        }

        function deleteStaff(staffId) {
            if (confirm('Tem certeza que deseja excluir este staff?')) {
                alert('Excluir staff será implementado');
            }
        }

        function loadStaffActivity() {
            fetch('/api/admin/staff-activity')
                .then(response => response.json())
                .then(data => {
                    if (data.error) {
                        alert('Erro ao carregar atividade: ' + data.error);
                        return;
                    }
                    
                    let html = `
                        <div class="modal-overlay">
                            <div class="modal-content" style="max-width: 800px;">
                                <div class="modal-header">
                                    <h3>📊 Atividade dos Vendedores/Técnicos</h3>
                                    <button class="modal-close" onclick="closeModal()">&times;</button>
                                </div>
                                <div class="modal-body">
                                    <div class="table-container">
                                        <table class="data-table">
                                            <thead>
                                                <tr>
                                                    <th>👤 Staff</th>
                                                    <th>🏷️ Tipo</th>
                                                    <th>🎯 Acessos Criados</th>
                                                    <th>📅 Último Acesso Criado</th>
                                                </tr>
                                            </thead>
                                            <tbody>
                    `;

                    if (data.length === 0) {
                        html += `
                            <tr>
                                <td colspan="4" style="text-align: center; padding: 20px;">
                                    📊 Nenhuma atividade registrada
                                </td>
                            </tr>
                        `;
                    } else {
                        data.forEach(item => {
                            html += `
                                <tr>
                                    <td><strong>${item.staff_name}</strong></td>
                                    <td>
                                        <span class="badge ${item.staff_type === 'Vendedor' ? 'badge-primary' : 'badge-secondary'}">
                                            ${item.staff_type === 'Vendedor' ? '💼' : '🔧'} ${item.staff_type}
                                        </span>
                                    </td>
                                    <td><strong>${item.trials_created}</strong></td>
                                    <td>${item.last_trial_created}</td>
                                </tr>
                            `;
                        });
                    }

                    html += `
                                            </tbody>
                                        </table>
                                    </div>
                                </div>
                                <div class="modal-footer">
                                    <button class="btn btn-secondary" onclick="closeModal()">Fechar</button>
                                </div>
                            </div>
                        </div>
                    `;

                    document.body.insertAdjacentHTML('beforeend', html);
                })
                .catch(error => {
                    console.error('Erro:', error);
                    alert('Erro ao carregar atividade');
                });
        }

        function closeModal() {
            const modals = document.querySelectorAll('.modal-overlay');
            modals.forEach(modal => modal.remove());
        }

        function logout() {
            if (confirm('Tem certeza que deseja sair?')) {
                window.location.href = '/admin/logout';
            }
        }

        // Initialize dashboard
        document.addEventListener('DOMContentLoaded', function() {
            loadDashboardData();
        });

        // ===== FUNÇÕES DE BACKUP =====

        // Criar backup
        function createBackup() {
            const button = document.getElementById('createBackupText');
            const result = document.getElementById('backupResult');
            
            button.textContent = '⏳ Criando backup...';
            result.innerHTML = '';
            
            fetch('/api/backup/create', {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/json'
                }
            })
            .then(response => response.json())
            .then(data => {
                button.textContent = '💾 Criar Backup Agora';
                
                if (data.success) {
                    result.innerHTML = `
                        <div class="alert alert-success">
                            <strong>✅ Backup criado com sucesso!</strong><br>
                            📁 Arquivo: ${data.filename}<br>
                            📊 Tamanho: ${formatFileSize(data.size)}<br>
                            ⏰ Data: ${new Date().toLocaleString('pt-BR')}
                        </div>
                    `;
                    loadBackups(); // Atualizar lista
                } else {
                    result.innerHTML = `
                        <div class="alert alert-error">
                            <strong>❌ Erro ao criar backup:</strong><br>
                            ${data.error}
                        </div>
                    `;
                }
            })
            .catch(error => {
                button.textContent = '💾 Criar Backup Agora';
                result.innerHTML = `
                    <div class="alert alert-error">
                        <strong>❌ Erro de conexão:</strong><br>
                        ${error.message}
                    </div>
                `;
            });
        }

        // Upload e restaurar backup
        function uploadBackup() {
            const fileInput = document.getElementById('backupFile');
            const button = document.getElementById('uploadBackupText');
            const result = document.getElementById('uploadResult');
            
            if (!fileInput.files[0]) {
                result.innerHTML = `
                    <div class="alert alert-error">
                        <strong>⚠️ Selecione um arquivo de backup</strong>
                    </div>
                `;
                return;
            }
            
            if (!confirm('⚠️ ATENÇÃO: Esta ação substituirá TODOS os dados atuais do banco de dados.\\n\\nUm backup automático será criado antes da restauração.\\n\\nDeseja continuar?')) {
                return;
            }
            
            const formData = new FormData();
            formData.append('file', fileInput.files[0]);
            
            button.textContent = '⏳ Restaurando backup...';
            result.innerHTML = '';
            
            fetch('/api/backup/upload', {
                method: 'POST',
                body: formData
            })
            .then(response => response.json())
            .then(data => {
                button.textContent = '📥 Restaurar Backup';
                
                if (data.success) {
                    result.innerHTML = `
                        <div class="alert alert-success">
                            <strong>✅ Backup restaurado com sucesso!</strong><br>
                            📁 Backup atual salvo como: ${data.current_backup}<br>
                            🔄 A página será recarregada em 3 segundos...
                        </div>
                    `;
                    
                    // Recarregar página após 3 segundos
                    setTimeout(() => {
                        window.location.reload();
                    }, 3000);
                } else {
                    result.innerHTML = `
                        <div class="alert alert-error">
                            <strong>❌ Erro ao restaurar backup:</strong><br>
                            ${data.error}
                        </div>
                    `;
                }
                
                fileInput.value = ''; // Limpar input
            })
            .catch(error => {
                button.textContent = '📥 Restaurar Backup';
                result.innerHTML = `
                    <div class="alert alert-error">
                        <strong>❌ Erro de conexão:</strong><br>
                        ${error.message}
                    </div>
                `;
                fileInput.value = '';
            });
        }

        // Carregar lista de backups
        function loadBackups() {
            const container = document.getElementById('backupsList');
            container.innerHTML = '<div class="loading">Carregando backups...</div>';
            
            fetch('/api/backup/list')
            .then(response => response.json())
            .then(data => {
                if (data.success && data.backups.length > 0) {
                    let html = `
                        <div class="table-container">
                            <table class="data-table">
                                <thead>
                                    <tr>
                                        <th>📁 Arquivo</th>
                                        <th>📊 Tamanho</th>
                                        <th>📅 Data de Criação</th>
                                        <th>⚡ Ações</th>
                                    </tr>
                                </thead>
                                <tbody>
                    `;
                    
                    data.backups.forEach(backup => {
                        const createdDate = new Date(backup.created).toLocaleString('pt-BR');
                        const fileSize = formatFileSize(backup.size);
                        
                        html += `
                            <tr>
                                <td>
                                    <strong>${backup.filename}</strong>
                                </td>
                                <td>${fileSize}</td>
                                <td>${createdDate}</td>
                                <td>
                                    <button class="btn btn-sm btn-primary" onclick="downloadBackup('${backup.filename}')">
                                        📥 Baixar
                                    </button>
                                    <button class="btn btn-sm btn-danger" onclick="deleteBackup('${backup.filename}')">
                                        🗑️ Excluir
                                    </button>
                                </td>
                            </tr>
                        `;
                    });
                    
                    html += `
                                </tbody>
                            </table>
                        </div>
                    `;
                    
                    container.innerHTML = html;
                } else {
                    container.innerHTML = `
                        <div class="alert alert-info">
                            <strong>📋 Nenhum backup encontrado</strong><br>
                            Crie seu primeiro backup usando o botão acima.
                        </div>
                    `;
                }
            })
            .catch(error => {
                container.innerHTML = `
                    <div class="alert alert-error">
                        <strong>❌ Erro ao carregar backups:</strong><br>
                        ${error.message}
                    </div>
                `;
            });
        }

        // Download de backup
        function downloadBackup(filename) {
            window.open(`/api/backup/download/${filename}`, '_blank');
        }

        // Excluir backup
        function deleteBackup(filename) {
            if (!confirm(`⚠️ Tem certeza que deseja excluir o backup "${filename}"?\\n\\nEsta ação não pode ser desfeita.`)) {
                return;
            }
            
            fetch(`/api/backup/delete/${filename}`, {
                method: 'DELETE'
            })
            .then(response => response.json())
            .then(data => {
                if (data.success) {
                    showAlert('✅ Backup excluído com sucesso!', 'success');
                    loadBackups(); // Atualizar lista
                } else {
                    showAlert(`❌ Erro ao excluir backup: ${data.error}`, 'error');
                }
            })
            .catch(error => {
                showAlert(`❌ Erro de conexão: ${error.message}`, 'error');
            });
        }

        // Formatar tamanho de arquivo
        function formatFileSize(bytes) {
            if (bytes === 0) return '0 Bytes';
            const k = 1024;
            const sizes = ['Bytes', 'KB', 'MB', 'GB'];
            const i = Math.floor(Math.log(bytes) / Math.log(k));
            return parseFloat((bytes / Math.pow(k, i)).toFixed(2)) + ' ' + sizes[i];
        }

        // Mostrar alerta
        function showAlert(message, type) {
            const alertClass = type === 'success' ? 'alert-success' : 'alert-error';
            const alertHtml = `
                <div class="alert ${alertClass}" style="position: fixed; top: 20px; right: 20px; z-index: 9999; max-width: 400px;">
                    ${message}
                </div>
            `;
            
            document.body.insertAdjacentHTML('beforeend', alertHtml);
            
            // Remover após 5 segundos
            setTimeout(() => {
                const alert = document.querySelector('.alert:last-child');
                if (alert) alert.remove();
            }, 5000);
        }
    </script>
</body>
</html>


                    const userList = document.getElementById('userList');
                    if (Array.isArray(users) && users.length > 0) {
                        userList.innerHTML = users.map(user => {
                            const statusClass = user.is_active ? 'status-active' : 'status-inactive';
                            const statusText = user.is_active ? 'Ativo' : 'Inativo';
                            const toggleText = user.is_active ? 'Desativar' : 'Ativar';
                            const toggleClass = user.is_active ? 'btn-warning' : 'btn-success';
                            
                            const accessLevel = user.access_level || 'Básico';
                            const accessClass = `access-${accessLevel.toLowerCase()}`;
                            
                            const hardwareDisplay = user.hardware_id ? 
                                `<div class="hardware-id">🔗 Hardware: ${user.hardware_id.substring(0, 16)}...</div>` : 
                                '<div class="hardware-id">🔗 Hardware: Não vinculado</div>';
                            
                            return `
                                <div class="user-item">
                                    <div class="user-info">
                                        <h4>${user.username} <span class="${statusClass}">(${statusText})</span><span class="access-level ${accessClass}">${accessLevel}</span></h4>
                                        <p>${user.email} - ${user.license_type}</p>
                                        <p>Expira: ${user.expires_at ? new Date(user.expires_at).toLocaleDateString('pt-BR') : 'Nunca'}</p>
                                        ${hardwareDisplay}
                                    </div>
                                    <div class="user-actions">
                                        <button class="btn btn-sm" onclick="openUserModal(${user.id})">✏️ Editar</button>
                                        <button class="btn btn-sm ${toggleClass}" onclick="toggleUserStatus(${user.id}, ${user.is_active})">${toggleText}</button>
                                        ${user.hardware_id ? `<button class="btn btn-sm btn-info" onclick="removeHardwareId(${user.id}, '${user.username}')">🔧 Remover Hardware</button>` : ''}
                                        <button class="btn btn-sm btn-danger" onclick="deleteUser(${user.id}, '${user.username}')">🗑️ Excluir</button>
                                    </div>
                                </div>
                            `;
                        }).join('');
                    } else {
                        userList.innerHTML = '<p style="text-align: center; color: #666; padding: 20px;">Nenhum usuário cadastrado</p>';
                    }
                })
                .catch(error => {
                    console.error('Erro ao carregar usuários:', error);
                    document.getElementById('userList').innerHTML = '<p style="text-align: center; color: #666; padding: 20px;">Erro ao carregar usuários</p>';
                });
        }
        
        function loadLogs() {
            fetch('/api/logs?per_page=20')
                .then(response => response.json())
                .then(logs => {
                    const logsList = document.getElementById('logsList');
                    if (Array.isArray(logs) && logs.length > 0) {
                        logsList.innerHTML = logs.map(log => {
                            const hardwareDisplay = log.hardware_id ? 
                                `<div class="log-hardware">🔗 Hardware: ${log.hardware_id.substring(0, 16)}...</div>` : '';
                            
                            return `
                                <div class="log-item">
                                    <span class="log-time">${new Date(log.timestamp).toLocaleString('pt-BR')}</span>
                                    <span class="log-action">${log.username} - ${log.action}</span>
                                    ${hardwareDisplay}
                                </div>
                            `;
                        }).join('');
                    } else {
                        logsList.innerHTML = '<p style="text-align: center; color: #666; padding: 20px;">Nenhum log disponível</p>';
                    }
                })
                .catch(error => {
                    console.error('Erro ao carregar logs:', error);
                    document.getElementById('logsList').innerHTML = '<p style="text-align: center; color: #666; padding: 20px;">Erro ao carregar logs</p>';
                });
        }
        
        // Criar/Editar usuário
        document.getElementById('userForm').addEventListener('submit', function(e) {
            e.preventDefault();
            
            const formData = new FormData(e.target);
            const userData = {
                username: formData.get('username'),
                email: formData.get('email'),
                duration: parseInt(formData.get('duration')),
                license_type: formData.get('licenseType'),
                access_level: formData.get('accessLevel')
            };
            
            // Adicionar senha apenas se foi preenchida
            const password = formData.get('password');
            if (password) {
                userData.password = password;
            }
            
            const isEditing = editingUserId !== null;
            const url = isEditing ? `/api/users/${editingUserId}` : '/api/users';
            const method = isEditing ? 'PUT' : 'POST';
            
            fetch(url, {
                method: method,
                headers: {
                    'Content-Type': 'application/json',
                },
                body: JSON.stringify(userData)
            })
            .then(response => {
                if (response.ok) {
                    return response.json();
                } else {
                    throw new Error(isEditing ? 'Erro ao editar usuário' : 'Erro ao criar usuário');
                }
            })
            .then(data => {
                alert(isEditing ? 'Usuário editado com sucesso!' : 'Usuário criado com sucesso!');
                closeUserModal();
                loadUsers();
                loadStats();
            })
            .catch(error => {
                console.error('Erro:', error);
                alert((isEditing ? 'Erro ao editar usuário: ' : 'Erro ao criar usuário: ') + error.message);
            });
        });
        
        // Carregar dados iniciais
        loadStats();
        loadUsers();
        loadLogs();
        
        // Atualizar dados a cada 10 segundos
        setInterval(() => {
            loadStats();
            loadUsers();
            loadLogs();
        }, 10000);
    </script>
</body>
</html>
    '''
    return html

@app.route('/api/stats')
def get_stats():
    """Estatísticas do sistema"""
    if not require_admin_login():
        return jsonify({'error': 'Acesso negado'}), 401
    
    try:
        conn = sqlite3.connect(DATABASE)
        cursor = conn.cursor()
        
        # Total de usuários
        cursor.execute("SELECT COUNT(*) FROM users")
        total_users = cursor.fetchone()[0]
        
        # Usuários ativos (não expirados)
        cursor.execute("SELECT COUNT(*) FROM users WHERE (expires_at > datetime('now') OR expires_at IS NULL) AND is_active = 1")
        active_users = cursor.fetchone()[0]
        
        # Usuários por nível de acesso
        cursor.execute("SELECT COUNT(*) FROM users WHERE access_level = 'Básico'")
        basic_users = cursor.fetchone()[0]
        
        cursor.execute("SELECT COUNT(*) FROM users WHERE access_level = 'Avançado'")
        advanced_users = cursor.fetchone()[0]
        
        cursor.execute("SELECT COUNT(*) FROM users WHERE access_level = 'Completo'")
        complete_users = cursor.fetchone()[0]
        
        # Logins hoje
        cursor.execute("SELECT COUNT(*) FROM access_logs WHERE date(timestamp) = date('now') AND action = 'login'")
        today_logins = cursor.fetchone()[0]
        
        conn.close()
        
        return jsonify({
            'total_users': total_users,
            'active_users': active_users,
            'basic_users': basic_users,
            'advanced_users': advanced_users,
            'complete_users': complete_users,
            'today_logins': today_logins
        })
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/api/users', methods=['GET'])
def get_users():
    """Listar usuários"""
    if not require_admin_login():
        return jsonify({'error': 'Acesso negado'}), 401
    
    try:
        conn = sqlite3.connect(DATABASE)
        cursor = conn.cursor()
        
        cursor.execute("""
            SELECT id, username, email, created_at, expires_at, license_type, access_level, is_active, last_login, hardware_id
            FROM users
            ORDER BY created_at DESC
        """)
        
        users = []
        for row in cursor.fetchall():
            users.append({
                'id': row[0],
                'username': row[1],
                'email': row[2],
                'created_at': row[3],
                'expires_at': row[4],
                'license_type': row[5],
                'access_level': row[6] or 'Básico',
                'is_active': row[7],
                'last_login': row[8],
                'hardware_id': row[9]
            })
        
        conn.close()
        return jsonify(users)
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/api/users/<int:user_id>', methods=['GET'])
def get_user(user_id):
    """Obter dados de um usuário específico"""
    if not require_admin_login():
        return jsonify({'error': 'Acesso negado'}), 401
    
    try:
        conn = sqlite3.connect(DATABASE)
        cursor = conn.cursor()
        
        cursor.execute("""
            SELECT id, username, email, created_at, expires_at, license_type, access_level, is_active, last_login, hardware_id
            FROM users
            WHERE id = ?
        """, (user_id,))
        
        row = cursor.fetchone()
        if not row:
            conn.close()
            return jsonify({'error': 'Usuário não encontrado'}), 404
        
        user = {
            'id': row[0],
            'username': row[1],
            'email': row[2],
            'created_at': row[3],
            'expires_at': row[4],
            'license_type': row[5],
            'access_level': row[6] or 'Básico',
            'is_active': row[7],
            'last_login': row[8],
            'hardware_id': row[9]
        }
        
        conn.close()
        return jsonify(user)
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/api/users', methods=['POST'])
def create_user():
    """Criar novo usuário"""
    if not require_admin_login():
        return jsonify({'error': 'Acesso negado'}), 401
    
    try:
        data = request.get_json()
        
        # Validar dados obrigatórios
        if not data or not all(k in data for k in ('username', 'email', 'password')):
            return jsonify({'error': 'Dados obrigatórios: username, email, password'}), 400
        
        username = data['username'].strip()
        email = data['email'].strip()
        password = data['password']
        duration = data.get('duration', 30)
        license_type = data.get('license_type', 'Trial')
        access_level = data.get('access_level', 'Básico')
        
        # Resto da implementação será adicionada
        return jsonify({'success': True, 'message': 'Usuário criado com sucesso'})
    
    except Exception as e:
        return jsonify({'error': str(e)}), 500

# ===== ROTAS DE STAFF =====

@app.route('/api/staff/create', methods=['POST'])
def create_staff():
    """Criar novo vendedor ou técnico"""
    if not require_admin_login():
        return jsonify({'error': 'Acesso negado'}), 401
    
    try:
        data = request.get_json()
        username = data.get('username')
        email = data.get('email')
        password = data.get('password')
        staff_type = data.get('staff_type', 'Vendedor')
        
        if not username or not email or not password:
            return jsonify({'error': 'Username, email e password são obrigatórios'}), 400
        
        # Hash da senha
        password_hash = hash_password(password)
        
        # Calcular data de expiração usando horário do Brasil (staff não expira)
        brazil_time = get_brazil_time()
        
        conn = sqlite3.connect(DATABASE)
        cursor = conn.cursor()
        
        # Verificar se usuário já existe
        cursor.execute('SELECT id FROM users WHERE username = ? OR email = ?', (username, email))
        if cursor.fetchone():
            conn.close()
            return jsonify({'error': 'Usuário ou email já existe'}), 400
        
        # Inserir novo staff
        cursor.execute('''
            INSERT INTO users (username, email, password_hash, created_at, expires_at, 
                             license_type, access_level, is_active, user_type, created_by)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        ''', (username, email, password_hash, brazil_time.isoformat(), None, 
              'Staff', 'Staff', 1, staff_type, session.get('admin_user', 'admin')))
        
        user_id = cursor.lastrowid
        conn.commit()
        conn.close()
        
        # Log da ação
        log_action('create_staff', f'Staff {staff_type} criado: {username}')
        
        return jsonify({
            'success': True, 
            'message': f'{staff_type} criado com sucesso',
            'user_id': user_id
        })
    
    except Exception as e:
        return jsonify({'error': str(e)}), 500
    
    try:
        data = request.get_json()
        
        # Validar dados obrigatórios
        if not data or not all(k in data for k in ('username', 'email')):
            return jsonify({'error': 'Dados obrigatórios: username, email'}), 400
        
        username = data['username'].strip()
        email = data['email'].strip()
        password = data.get('password', '').strip()
        duration = data.get('duration', 30)
        license_type = data.get('license_type', 'Trial')
        access_level = data.get('access_level', 'Básico')
        
        # Validações básicas
        if len(username) < 3:
            return jsonify({'error': 'Username deve ter pelo menos 3 caracteres'}), 400
        
        if password and len(password) < 6:
            return jsonify({'error': 'Senha deve ter pelo menos 6 caracteres'}), 400
        
        if '@' not in email:
            return jsonify({'error': 'Email inválido'}), 400
        
        if access_level not in ['Básico', 'Avançado', 'Completo']:
            access_level = 'Básico'
        
        # Calcular data de expiração
        expires_at = None
        if license_type != 'Vitalícia' and duration > 0:
            expires_at = (datetime.datetime.now() + datetime.timedelta(days=duration)).isoformat()
        
        conn = sqlite3.connect(DATABASE)
        cursor = conn.cursor()
        
        # Verificar se usuário existe
        cursor.execute("SELECT id FROM users WHERE id = ?", (user_id,))
        if not cursor.fetchone():
            conn.close()
            return jsonify({'error': 'Usuário não encontrado'}), 404
        
        # Verificar se username/email já existe em outro usuário
        cursor.execute("SELECT id FROM users WHERE (username = ? OR email = ?) AND id != ?", (username, email, user_id))
        if cursor.fetchone():
            conn.close()
            return jsonify({'error': 'Usuário ou email já existe'}), 400
        
        # Atualizar usuário
        if password:
            # Atualizar com nova senha
            password_hash = hash_password(password)
            cursor.execute("""
                UPDATE users 
                SET username = ?, email = ?, password_hash = ?, expires_at = ?, license_type = ?, access_level = ?
                WHERE id = ?
            """, (username, email, password_hash, expires_at, license_type, access_level, user_id))
        else:
            # Atualizar sem alterar senha
            cursor.execute("""
                UPDATE users 
                SET username = ?, email = ?, expires_at = ?, license_type = ?, access_level = ?
                WHERE id = ?
            """, (username, email, expires_at, license_type, access_level, user_id))
        
        conn.commit()
        conn.close()
        
        return jsonify({
            'id': user_id,
            'username': username,
            'email': email,
            'expires_at': expires_at,
            'license_type': license_type,
            'access_level': access_level,
            'message': 'Usuário atualizado com sucesso'
        })
        
    except Exception as e:
        return jsonify({'error': f'Erro interno: {str(e)}'}), 500

@app.route('/api/users/<int:user_id>/status', methods=['PUT'])
def update_user_status(user_id):
    """Ativar/Desativar usuário"""
    if not require_admin_login():
        return jsonify({'error': 'Acesso negado'}), 401
    
    try:
        data = request.get_json()
        
        if not data or 'is_active' not in data:
            return jsonify({'error': 'Campo obrigatório: is_active'}), 400
        
        is_active = bool(data['is_active'])
        
        conn = sqlite3.connect(DATABASE)
        cursor = conn.cursor()
        
        # Verificar se usuário existe
        cursor.execute("SELECT username FROM users WHERE id = ?", (user_id,))
        user = cursor.fetchone()
        if not user:
            conn.close()
            return jsonify({'error': 'Usuário não encontrado'}), 404
        
        # Atualizar status
        cursor.execute("UPDATE users SET is_active = ? WHERE id = ?", (is_active, user_id))
        
        # Log da ação
        action = 'ativado' if is_active else 'desativado'
        cursor.execute("""
            INSERT INTO access_logs (username, action, ip_address)
            VALUES (?, ?, ?)
        """, (f"admin:{session.get('admin_username', 'admin')}", f'usuário {user[0]} {action}', request.remote_addr))
        
        conn.commit()
        conn.close()
        
        return jsonify({
            'message': f'Usuário {action} com sucesso',
            'is_active': is_active
        })
        
    except Exception as e:
        return jsonify({'error': f'Erro interno: {str(e)}'}), 500

@app.route('/api/users/<int:user_id>', methods=['DELETE'])
def delete_user(user_id):
    """Excluir usuário"""
    if not require_admin_login():
        return jsonify({'error': 'Acesso negado'}), 401
    
    try:
        conn = sqlite3.connect(DATABASE)
        cursor = conn.cursor()
        
        # Verificar se usuário existe
        cursor.execute("SELECT username FROM users WHERE id = ?", (user_id,))
        user = cursor.fetchone()
        if not user:
            conn.close()
            return jsonify({'error': 'Usuário não encontrado'}), 404
        
        # Excluir usuário
        cursor.execute("DELETE FROM users WHERE id = ?", (user_id,))
        
        # Log da ação
        cursor.execute("""
            INSERT INTO access_logs (username, action, ip_address)
            VALUES (?, ?, ?)
        """, (f"admin:{session.get('admin_username', 'admin')}", f'usuário {user[0]} excluído', request.remote_addr))
        
        conn.commit()
        conn.close()
        
        return jsonify({'message': 'Usuário excluído com sucesso'})
        
    except Exception as e:
        return jsonify({'error': f'Erro interno: {str(e)}'}), 500

@app.route('/api/logs')
def get_logs():
    """Logs de acesso com hardware_id"""
    if not require_admin_login():
        return jsonify({'error': 'Acesso negado'}), 401
    
    try:
        per_page = request.args.get('per_page', 50, type=int)
        
        conn = sqlite3.connect(DATABASE)
        cursor = conn.cursor()
        
        cursor.execute("""
            SELECT username, action, timestamp, ip_address, hardware_id
            FROM access_logs
            ORDER BY timestamp DESC
            LIMIT ?
        """, (per_page,))
        
        logs = []
        for row in cursor.fetchall():
            logs.append({
                'username': row[0],
                'action': row[1],
                'timestamp': row[2],
                'ip_address': row[3],
                'hardware_id': row[4]
            })
        
        conn.close()
        return jsonify(logs)
    except Exception as e:
        return jsonify({'error': str(e)}), 500

# ===== ROTAS DE BACKUP =====

@app.route('/api/backup/create', methods=['POST'])
def api_create_backup():
    """API para criar backup do banco de dados"""
    if not require_admin_login():
        return jsonify({'error': 'Acesso negado'}), 401
    
    try:
        result = create_backup()
        if result['success']:
            return jsonify({
                'success': True,
                'message': 'Backup criado com sucesso!',
                'filename': result['filename'],
                'size': result['size'],
                'timestamp': result['timestamp']
            })
        else:
            return jsonify({'success': False, 'error': result['error']}), 500
            
    except Exception as e:
        print(f"Erro ao criar backup via API: {e}")
        return jsonify({'success': False, 'error': 'Erro interno do servidor'}), 500

@app.route('/api/backup/list', methods=['GET'])
def api_list_backups():
    """API para listar backups disponíveis"""
    if not require_admin_login():
        return jsonify({'error': 'Acesso negado'}), 401
    
    try:
        result = get_backup_list()
        return jsonify(result)
        
    except Exception as e:
        print(f"Erro ao listar backups via API: {e}")
        return jsonify({'success': False, 'error': 'Erro interno do servidor'}), 500

@app.route('/api/backup/download/<filename>')
def api_download_backup(filename):
    """API para download de backup"""
    if not require_admin_login():
        return jsonify({'error': 'Acesso negado'}), 401
    
    try:
        # Validar nome do arquivo
        if not filename.endswith('.db') or '..' in filename:
            return jsonify({'error': 'Nome de arquivo inválido'}), 400
        
        backup_path = os.path.join(BACKUP_DIR, filename)
        
        if not os.path.exists(backup_path):
            return jsonify({'error': 'Arquivo de backup não encontrado'}), 404
        
        # Log da operação
        log_action('admin', 'download_backup', f'Backup baixado: {filename}')
        
        return send_file(backup_path, as_attachment=True, download_name=filename)
        
    except Exception as e:
        print(f"Erro ao baixar backup via API: {e}")
        return jsonify({'error': 'Erro interno do servidor'}), 500

@app.route('/api/backup/upload', methods=['POST'])
def api_upload_backup():
    """API para upload e restauração de backup"""
    if not require_admin_login():
        return jsonify({'error': 'Acesso negado'}), 401
    
    try:
        # Verificar se foi enviado um arquivo
        if 'file' not in request.files:
            return jsonify({'success': False, 'error': 'Nenhum arquivo enviado'}), 400
        
        file = request.files['file']
        
        if file.filename == '':
            return jsonify({'success': False, 'error': 'Nenhum arquivo selecionado'}), 400
        
        if file and allowed_file(file.filename):
            # Salvar arquivo temporariamente
            filename = secure_filename(file.filename)
            temp_path = os.path.join(UPLOAD_FOLDER, filename)
            file.save(temp_path)
            
            # Restaurar backup
            result = restore_backup(temp_path)
            
            # Remover arquivo temporário
            if os.path.exists(temp_path):
                os.remove(temp_path)
            
            return jsonify(result)
        else:
            return jsonify({'success': False, 'error': 'Tipo de arquivo não permitido'}), 400
            
    except Exception as e:
        print(f"Erro ao fazer upload de backup via API: {e}")
        return jsonify({'success': False, 'error': 'Erro interno do servidor'}), 500

@app.route('/api/backup/delete/<filename>', methods=['DELETE'])
def api_delete_backup(filename):
    """API para excluir backup"""
    if not require_admin_login():
        return jsonify({'error': 'Acesso negado'}), 401
    
    try:
        # Validar nome do arquivo
        if not filename.endswith('.db') or '..' in filename:
            return jsonify({'error': 'Nome de arquivo inválido'}), 400
        
        result = delete_backup(filename)
        return jsonify(result)
        
    except Exception as e:
        print(f"Erro ao excluir backup via API: {e}")
        return jsonify({'success': False, 'error': 'Erro interno do servidor'}), 500

@app.route('/api/auth/login', methods=['POST'])
def login():
    """Autenticação de usuário"""
    try:
        data = request.get_json()
        username = data.get('username')
        password = data.get('password')
        hardware_id = data.get('hardware_id')
        
        if not username or not password:
            return jsonify({'error': 'Username e senha são obrigatórios'}), 400
        
        conn = sqlite3.connect(DATABASE)
        cursor = conn.cursor()
        
        # Buscar usuário
        cursor.execute("""
            SELECT id, username, password_hash, expires_at, is_active, access_level, user_type, is_admin
            FROM users
            WHERE username = ?
        """, (username,))
        
        user = cursor.fetchone()
        if not user:
            conn.close()
            return jsonify({'error': 'Usuário não encontrado'}), 401
        
        # Verificar senha
        if user[2] != hash_password(password):
            conn.close()
            return jsonify({'error': 'Senha incorreta'}), 401
        
        # Verificar se está ativo
        if not user[4]:
            conn.close()
            return jsonify({'error': 'Usuário desativado'}), 401
        
        # Verificar se é admin especial (sem limitações)
        is_admin_special = user[7] == 1 or user[6] == 'Admin'
        
        # Verificar expiração (admin especial nunca expira)
        if not is_admin_special and user[3]:  # Se não é admin e tem data de expiração
            expires_at = datetime.fromisoformat(user[3])
            brazil_time = get_brazil_time()
            if expires_at.replace(tzinfo=None) < brazil_time.replace(tzinfo=None):
                conn.close()
                return jsonify({'error': 'Licença expirada'}), 401
        
        # Para admin especial, não verificar nem salvar hardware_id
        if is_admin_special:
            # Atualizar apenas último login (sem hardware_id)
            cursor.execute("""
                UPDATE users 
                SET last_login = ?
                WHERE id = ?
            """, (get_brazil_time().isoformat(), user[0]))
            
            # Log de acesso admin (sem hardware_id)
            log_action(username, 'login', 'Login admin especial (sem hardware)', '')
        else:
            # Para usuários normais, verificar e salvar hardware_id
            if not hardware_id:
                conn.close()
                return jsonify({'error': 'Hardware ID é obrigatório'}), 400
            
            # Atualizar último login e hardware_id
            cursor.execute("""
                UPDATE users 
                SET last_login = ?, hardware_id = ?
                WHERE id = ?
            """, (get_brazil_time().isoformat(), hardware_id, user[0]))
            
            # Log de acesso com hardware_id
            log_action(username, 'login', 'Login usuário normal', hardware_id)
        
        conn.commit()
        conn.close()
        
        return jsonify({
            'success': True,
            'message': 'Login realizado com sucesso',
            'username': username,
            'expires_at': user[3] if not is_admin_special else None,
            'access_level': user[5] or 'Completo',
            'user_type': user[6] or 'Cliente',
            'is_admin': is_admin_special,
            'hardware_required': not is_admin_special
        })
        
    except Exception as e:
        return jsonify({'error': f'Erro interno: {str(e)}'}), 500

@app.route('/admin/change-password', methods=['POST'])
def change_admin_password():
    """Permite trocar a senha do administrador"""
    if not require_admin_login():
        return jsonify({'success': False, 'error': 'Não autorizado'}), 401
    
    try:
        data = request.get_json()
        current_password = data.get('current_password', '').strip()
        new_password = data.get('new_password', '').strip()
        confirm_password = data.get('confirm_password', '').strip()
        
        # Validações
        if not current_password or not new_password or not confirm_password:
            return jsonify({'success': False, 'error': 'Todos os campos são obrigatórios'})
        
        # Verificar senha atual
        global ADMIN_PASSWORD
        if current_password != ADMIN_PASSWORD:
            return jsonify({'success': False, 'error': 'Senha atual incorreta'})
        
        # Verificar se as novas senhas coincidem
        if new_password != confirm_password:
            return jsonify({'success': False, 'error': 'As novas senhas não coincidem'})
        
        # Validar força da nova senha
        if len(new_password) < 8:
            return jsonify({'success': False, 'error': 'A nova senha deve ter pelo menos 8 caracteres'})
        
        # Atualizar senha (em produção, isso deveria ser salvo em arquivo de configuração ou banco)
        ADMIN_PASSWORD = new_password
        
        # Log da alteração
        log_action('admin', 'change_password', 'Senha alterada com sucesso')
        
        return jsonify({'success': True, 'message': 'Senha alterada com sucesso!'})
        
    except Exception as e:
        print(f"Erro ao alterar senha: {e}")
        return jsonify({'success': False, 'error': 'Erro interno do servidor'}), 500

# ===== ROTAS PARA SISTEMA VENDEDOR/TÉCNICO =====

        # Log da criação
        log_action(session.get('admin_user', 'admin'), 'create_staff', 
                  f'{staff_type} criado: {username}')
        
        return jsonify({
            'id': staff_id,
            'username': username,
            'email': email,
            'user_type': staff_type,
            'created_at': brazil_time.isoformat()
        }), 201
        
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/api/staff/trial', methods=['POST'])
def create_trial_access():
    """Criar acesso de teste (1 dia) - apenas para Vendedor/Técnico"""
    try:
        # Verificar se é staff (Vendedor/Técnico)
        if 'staff_user' not in session:
            return jsonify({'error': 'Acesso negado - apenas para staff'}), 401
        
        data = request.get_json()
        username = data.get('username')
        email = data.get('email')
        password = data.get('password')
        
        if not username or not email or not password:
            return jsonify({'error': 'Todos os campos são obrigatórios'}), 400
        
        # Hash da senha
        password_hash = hash_password(password)
        
        # Usar horário do Brasil
        brazil_time = get_brazil_time()
        expires_at = brazil_time + timedelta(days=1)  # 1 dia apenas
        
        conn = sqlite3.connect(DATABASE)
        cursor = conn.cursor()
        
        # Verificar se usuário já existe
        cursor.execute('SELECT id FROM users WHERE username = ? OR email = ?', (username, email))
        if cursor.fetchone():
            conn.close()
            return jsonify({'error': 'Usuário ou email já existe'}), 400
        
        # Inserir novo usuário teste
        cursor.execute('''
            INSERT INTO users (username, email, password_hash, created_at, expires_at, 
                             license_type, access_level, is_active, user_type, created_by)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        ''', (username, email, password_hash, brazil_time.isoformat(), expires_at.isoformat(),
              'Trial', 'Avançado', 1, 'Cliente', session.get('staff_user')))
        
        trial_id = cursor.lastrowid
        conn.commit()
        conn.close()
        
        # Log da criação
        log_action(session.get('staff_user'), 'create_trial', 
                  f'Acesso teste criado: {username} (1 dia)')
        
        return jsonify({
            'id': trial_id,
            'username': username,
            'email': email,
            'expires_at': expires_at.isoformat(),
            'message': 'Acesso de teste criado com sucesso (1 dia)'
        }), 201
        
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/api/staff/trials')
def get_staff_trials():
    """Listar acessos criados pelo staff atual"""
    try:
        # Verificar se é staff
        if 'staff_user' not in session:
            return jsonify({'error': 'Acesso negado - apenas para staff'}), 401
        
        staff_username = session.get('staff_user')
        
        conn = sqlite3.connect(DATABASE)
        cursor = conn.cursor()
        
        # Buscar apenas usuários criados por este staff
        cursor.execute('''
            SELECT id, username, email, created_at, expires_at, is_active, last_login
            FROM users
            WHERE created_by = ? AND user_type = 'Cliente'
            ORDER BY created_at DESC
        ''', (staff_username,))
        
        trials = []
        for row in cursor.fetchall():
            trial = {
                'id': row[0],
                'username': row[1],
                'email': row[2],
                'created_at': format_brazil_time(row[3]),
                'expires_at': format_brazil_time(row[4]),
                'is_active': bool(row[5]),
                'last_login': format_brazil_time(row[6]) if row[6] else 'Nunca'
            }
            trials.append(trial)
        
        conn.close()
        return jsonify(trials)
        
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/api/admin/staff-activity')
def get_staff_activity():
    """Monitorar atividade de Vendedores/Técnicos - apenas admin"""
    if not require_admin_login():
        return jsonify({'error': 'Acesso negado'}), 401
    
    try:
        conn = sqlite3.connect(DATABASE)
        cursor = conn.cursor()
        
        # Buscar atividade dos staff
        cursor.execute('''
            SELECT 
                s.username as staff_name,
                s.user_type as staff_type,
                COUNT(u.id) as trials_created,
                MAX(u.created_at) as last_trial_created
            FROM users s
            LEFT JOIN users u ON u.created_by = s.username AND u.user_type = 'Cliente'
            WHERE s.user_type IN ('Vendedor', 'Técnico')
            GROUP BY s.username, s.user_type
            ORDER BY trials_created DESC
        ''')
        
        activity = []
        for row in cursor.fetchall():
            item = {
                'staff_name': row[0],
                'staff_type': row[1],
                'trials_created': row[2],
                'last_trial_created': format_brazil_time(row[3]) if row[3] else 'Nunca'
            }
            activity.append(item)
        
        conn.close()
        return jsonify(activity)
        
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/api/hardware/remove/<int:user_id>', methods=['POST'])
def remove_hardware_id(user_id):
    """Remover Hardware ID de um usuário"""
    if not require_admin_login():
        return jsonify({'error': 'Acesso negado'}), 401
    
    try:
        conn = sqlite3.connect(DATABASE)
        cursor = conn.cursor()
        
        # Buscar usuário
        cursor.execute('SELECT username FROM users WHERE id = ?', (user_id,))
        user = cursor.fetchone()
        
        if not user:
            conn.close()
            return jsonify({'error': 'Usuário não encontrado'}), 404
        
        # Remover hardware_id
        cursor.execute('UPDATE users SET hardware_id = NULL WHERE id = ?', (user_id,))
        conn.commit()
        conn.close()
        
        # Log da operação
        log_action(session.get('admin_user', 'admin'), 'remove_hardware', 
                  f'Hardware ID removido do usuário: {user[0]}')
        
        return jsonify({
            'success': True,
            'message': f'Hardware ID removido do usuário {user[0]}'
        })
        
    except Exception as e:
        return jsonify({'error': str(e)}), 500

if __name__ == '__main__':
    # Verificar se deve resetar o banco
    if os.getenv('RESET_DATABASE') == 'true':
        if os.path.exists(DATABASE):
            os.remove(DATABASE)
        print("Banco de dados resetado!")
    
    init_db()
    create_admin_if_not_exists()
    print("SpiderPrint Auth Server iniciado!")
    print(f"Dashboard: http://localhost:5000")
    print(f"Admin Login: {ADMIN_USERNAME} / Asd4d45#2365")
    
    # Configuração para produção
    port = int(os.environ.get('PORT', 5000))
    app.run(host='0.0.0.0', port=port, debug=False)

