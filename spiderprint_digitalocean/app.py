from flask import Flask, request, jsonify, render_template_string
from flask_cors import CORS
import sqlite3
import hashlib
import datetime
import os
import json

app = Flask(__name__)
CORS(app)

# Configuração do banco de dados
DATABASE = 'spiderprint.db'

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
            is_active BOOLEAN DEFAULT 1,
            last_login TIMESTAMP,
            hardware_id TEXT
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

def hash_password(password):
    """Hash da senha"""
    return hashlib.sha256(password.encode()).hexdigest()

@app.route('/')
def dashboard():
    """Dashboard administrativo"""
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
            max-width: 1200px;
            margin: 0 auto;
        }
        
        .header {
            background: rgba(255, 255, 255, 0.95);
            padding: 20px;
            border-radius: 15px;
            margin-bottom: 30px;
            box-shadow: 0 8px 32px rgba(0, 0, 0, 0.1);
        }
        
        .header h1 {
            color: #333;
            display: flex;
            align-items: center;
            gap: 10px;
        }
        
        .header p {
            color: #666;
            margin-top: 5px;
        }
        
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
            text-align: center;
            box-shadow: 0 8px 32px rgba(0, 0, 0, 0.1);
            transition: transform 0.3s ease;
        }
        
        .stat-card:hover {
            transform: translateY(-5px);
        }
        
        .stat-number {
            font-size: 2.5em;
            font-weight: bold;
            color: #667eea;
            margin-bottom: 10px;
        }
        
        .stat-label {
            color: #666;
            font-size: 0.9em;
            text-transform: uppercase;
            letter-spacing: 1px;
        }
        
        .main-grid {
            display: grid;
            grid-template-columns: 1fr 1fr;
            gap: 30px;
        }
        
        .section {
            background: rgba(255, 255, 255, 0.95);
            padding: 25px;
            border-radius: 15px;
            box-shadow: 0 8px 32px rgba(0, 0, 0, 0.1);
        }
        
        .section h2 {
            color: #333;
            margin-bottom: 20px;
            display: flex;
            align-items: center;
            gap: 10px;
        }
        
        .btn {
            background: #667eea;
            color: white;
            border: none;
            padding: 12px 24px;
            border-radius: 8px;
            cursor: pointer;
            font-size: 14px;
            transition: background 0.3s ease;
        }
        
        .btn:hover {
            background: #5a6fd8;
        }
        
        .btn-success {
            background: #28a745;
        }
        
        .btn-success:hover {
            background: #218838;
        }
        
        .modal {
            display: none;
            position: fixed;
            z-index: 1000;
            left: 0;
            top: 0;
            width: 100%;
            height: 100%;
            background-color: rgba(0, 0, 0, 0.5);
        }
        
        .modal-content {
            background-color: white;
            margin: 5% auto;
            padding: 30px;
            border-radius: 15px;
            width: 90%;
            max-width: 500px;
            box-shadow: 0 20px 60px rgba(0, 0, 0, 0.3);
        }
        
        .close {
            color: #aaa;
            float: right;
            font-size: 28px;
            font-weight: bold;
            cursor: pointer;
        }
        
        .close:hover {
            color: #000;
        }
        
        .form-group {
            margin-bottom: 20px;
        }
        
        .form-group label {
            display: block;
            margin-bottom: 8px;
            color: #333;
            font-weight: 500;
        }
        
        .form-group input,
        .form-group select {
            width: 100%;
            padding: 12px;
            border: 2px solid #e1e5e9;
            border-radius: 8px;
            font-size: 14px;
            transition: border-color 0.3s ease;
        }
        
        .form-group input:focus,
        .form-group select:focus {
            outline: none;
            border-color: #667eea;
        }
        
        .user-list {
            max-height: 400px;
            overflow-y: auto;
        }
        
        .user-item {
            padding: 15px;
            border-bottom: 1px solid #eee;
            display: flex;
            justify-content: space-between;
            align-items: center;
        }
        
        .user-info h4 {
            color: #333;
            margin-bottom: 5px;
        }
        
        .user-info p {
            color: #666;
            font-size: 0.9em;
        }
        
        .logs-list {
            max-height: 400px;
            overflow-y: auto;
        }
        
        .log-item {
            padding: 10px;
            border-bottom: 1px solid #eee;
            font-size: 0.9em;
        }
        
        .log-time {
            color: #666;
            font-weight: 500;
        }
        
        .log-action {
            color: #333;
            margin-left: 10px;
        }
        
        @media (max-width: 768px) {
            .main-grid {
                grid-template-columns: 1fr;
            }
            
            .stats-grid {
                grid-template-columns: repeat(2, 1fr);
            }
        }
    </style>
</head>
<body>
    <div class="container">
        <div class="header">
            <h1>🕷️ SpiderPrint</h1>
            <p>Dashboard Administrativo - Sistema de Autenticação</p>
        </div>
        
        <div class="stats-grid">
            <div class="stat-card">
                <div class="stat-number" id="totalUsers">0</div>
                <div class="stat-label">Total de Usuários</div>
            </div>
            <div class="stat-card">
                <div class="stat-number" id="activeUsers">0</div>
                <div class="stat-label">Usuários Ativos</div>
            </div>
            <div class="stat-card">
                <div class="stat-number" id="onlineUsers">0</div>
                <div class="stat-label">Online Agora</div>
            </div>
            <div class="stat-card">
                <div class="stat-number" id="todayLogins">0</div>
                <div class="stat-label">Logins Hoje</div>
            </div>
            <div class="stat-card">
                <div class="stat-number" id="activeLicenses">-</div>
                <div class="stat-label">Licenças Ativas</div>
            </div>
            <div class="stat-card">
                <div class="stat-number" id="expiringLicenses">-</div>
                <div class="stat-label">Expirando em 7 dias</div>
            </div>
        </div>
        
        <div class="main-grid">
            <div class="section">
                <h2>👥 Usuários</h2>
                <button class="btn btn-success" onclick="openUserModal()">+ Novo Usuário</button>
                <div class="user-list" id="userList">
                    <!-- Usuários serão carregados aqui -->
                </div>
            </div>
            
            <div class="section">
                <h2>📊 Logs de Acesso</h2>
                <div class="logs-list" id="logsList">
                    <!-- Logs serão carregados aqui -->
                </div>
            </div>
        </div>
    </div>
    
    <!-- Modal Novo Usuário -->
    <div id="userModal" class="modal">
        <div class="modal-content">
            <span class="close" onclick="closeUserModal()">&times;</span>
            <h2>Criar Novo Usuário</h2>
            <form id="userForm">
                <div class="form-group">
                    <label for="username">Usuário:</label>
                    <input type="text" id="username" name="username" required>
                </div>
                <div class="form-group">
                    <label for="email">Email:</label>
                    <input type="email" id="email" name="email" required>
                </div>
                <div class="form-group">
                    <label for="password">Senha:</label>
                    <input type="password" id="password" name="password" required>
                </div>
                <div class="form-group">
                    <label for="duration">Duração da Licença (dias):</label>
                    <input type="number" id="duration" name="duration" value="30" min="1" required>
                </div>
                <div class="form-group">
                    <label for="licenseType">Tipo de Licença:</label>
                    <select id="licenseType" name="licenseType">
                        <option value="Trial">Trial</option>
                        <option value="Mensal">Mensal</option>
                        <option value="Anual">Anual</option>
                        <option value="Vitalícia">Vitalícia</option>
                    </select>
                </div>
                <div style="text-align: right; margin-top: 30px;">
                    <button type="button" class="btn" onclick="closeUserModal()">Cancelar</button>
                    <button type="submit" class="btn btn-success">Criar Usuário</button>
                </div>
            </form>
        </div>
    </div>
    
    <script>
        // Funções do Modal
        function openUserModal() {
            document.getElementById('userModal').style.display = 'block';
        }
        
        function closeUserModal() {
            document.getElementById('userModal').style.display = 'none';
            document.getElementById('userForm').reset();
        }
        
        // Fechar modal clicando fora
        window.onclick = function(event) {
            const modal = document.getElementById('userModal');
            if (event.target == modal) {
                closeUserModal();
            }
        }
        
        // Carregar dados
        function loadStats() {
            fetch('/api/stats')
                .then(response => response.json())
                .then(data => {
                    document.getElementById('totalUsers').textContent = data.total_users || 0;
                    document.getElementById('activeUsers').textContent = data.active_users || 0;
                    document.getElementById('onlineUsers').textContent = data.online_users || 0;
                    document.getElementById('todayLogins').textContent = data.today_logins || 0;
                })
                .catch(error => console.error('Erro ao carregar estatísticas:', error));
        }
        
        function loadUsers() {
            fetch('/api/users')
                .then(response => response.json())
                .then(users => {
                    const userList = document.getElementById('userList');
                    if (Array.isArray(users) && users.length > 0) {
                        userList.innerHTML = users.map(user => `
                            <div class="user-item">
                                <div class="user-info">
                                    <h4>${user.username}</h4>
                                    <p>${user.email} - ${user.license_type}</p>
                                    <p>Expira: ${user.expires_at ? new Date(user.expires_at).toLocaleDateString('pt-BR') : 'Nunca'}</p>
                                </div>
                            </div>
                        `).join('');
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
                        logsList.innerHTML = logs.map(log => `
                            <div class="log-item">
                                <span class="log-time">${new Date(log.timestamp).toLocaleString('pt-BR')}</span>
                                <span class="log-action">${log.username} - ${log.action}</span>
                            </div>
                        `).join('');
                    } else {
                        logsList.innerHTML = '<p style="text-align: center; color: #666; padding: 20px;">Nenhum log disponível</p>';
                    }
                })
                .catch(error => {
                    console.error('Erro ao carregar logs:', error);
                    document.getElementById('logsList').innerHTML = '<p style="text-align: center; color: #666; padding: 20px;">Erro ao carregar logs</p>';
                });
        }
        
        function loadLicenseStats() {
            fetch('/api/licenses/stats')
                .then(response => response.json())
                .then(data => {
                    document.getElementById('activeLicenses').textContent = data.active_licenses || 0;
                    document.getElementById('expiringLicenses').textContent = data.expiring_soon || 0;
                })
                .catch(error => console.error('Erro ao carregar estatísticas de licenças:', error));
        }
        
        // Criar usuário
        document.getElementById('userForm').addEventListener('submit', function(e) {
            e.preventDefault();
            
            const formData = new FormData(e.target);
            const userData = {
                username: formData.get('username'),
                email: formData.get('email'),
                password: formData.get('password'),
                duration: parseInt(formData.get('duration')),
                license_type: formData.get('licenseType')
            };
            
            fetch('/api/users', {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/json',
                },
                body: JSON.stringify(userData)
            })
            .then(response => {
                if (response.ok) {
                    return response.json();
                } else {
                    throw new Error('Erro ao criar usuário');
                }
            })
            .then(data => {
                alert('Usuário criado com sucesso!');
                closeUserModal();
                loadUsers();
                loadStats();
            })
            .catch(error => {
                console.error('Erro:', error);
                alert('Erro ao criar usuário: ' + error.message);
            });
        });
        
        // Carregar dados iniciais
        loadStats();
        loadUsers();
        loadLogs();
        loadLicenseStats();
        
        // Atualizar dados a cada 5 segundos
        setInterval(() => {
            loadStats();
            loadUsers();
            loadLogs();
            loadLicenseStats();
        }, 5000);
    </script>
</body>
</html>
    '''
    return html

@app.route('/api/stats')
def get_stats():
    """Estatísticas do sistema"""
    try:
        conn = sqlite3.connect(DATABASE)
        cursor = conn.cursor()
        
        # Total de usuários
        cursor.execute("SELECT COUNT(*) FROM users")
        total_users = cursor.fetchone()[0]
        
        # Usuários ativos (não expirados)
        cursor.execute("SELECT COUNT(*) FROM users WHERE expires_at > datetime('now') OR expires_at IS NULL")
        active_users = cursor.fetchone()[0]
        
        # Logins hoje
        cursor.execute("SELECT COUNT(*) FROM access_logs WHERE date(timestamp) = date('now') AND action = 'login'")
        today_logins = cursor.fetchone()[0]
        
        conn.close()
        
        return jsonify({
            'total_users': total_users,
            'active_users': active_users,
            'online_users': 0,  # Implementar se necessário
            'today_logins': today_logins
        })
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/api/users', methods=['GET'])
def get_users():
    """Listar usuários"""
    try:
        conn = sqlite3.connect(DATABASE)
        cursor = conn.cursor()
        
        cursor.execute("""
            SELECT id, username, email, created_at, expires_at, license_type, is_active, last_login
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
                'is_active': row[6],
                'last_login': row[7]
            })
        
        conn.close()
        return jsonify(users)
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/api/users', methods=['POST'])
def create_user():
    """Criar novo usuário"""
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
        
        # Validações básicas
        if len(username) < 3:
            return jsonify({'error': 'Username deve ter pelo menos 3 caracteres'}), 400
        
        if len(password) < 6:
            return jsonify({'error': 'Senha deve ter pelo menos 6 caracteres'}), 400
        
        if '@' not in email:
            return jsonify({'error': 'Email inválido'}), 400
        
        # Calcular data de expiração
        expires_at = None
        if license_type != 'Vitalícia' and duration > 0:
            expires_at = (datetime.datetime.now() + datetime.timedelta(days=duration)).isoformat()
        
        conn = sqlite3.connect(DATABASE)
        cursor = conn.cursor()
        
        # Verificar se usuário já existe
        cursor.execute("SELECT id FROM users WHERE username = ? OR email = ?", (username, email))
        if cursor.fetchone():
            conn.close()
            return jsonify({'error': 'Usuário ou email já existe'}), 400
        
        # Criar usuário
        password_hash = hash_password(password)
        cursor.execute("""
            INSERT INTO users (username, email, password_hash, expires_at, license_type)
            VALUES (?, ?, ?, ?, ?)
        """, (username, email, password_hash, expires_at, license_type))
        
        user_id = cursor.lastrowid
        conn.commit()
        conn.close()
        
        return jsonify({
            'id': user_id,
            'username': username,
            'email': email,
            'expires_at': expires_at,
            'license_type': license_type,
            'message': 'Usuário criado com sucesso'
        }), 201
        
    except Exception as e:
        return jsonify({'error': f'Erro interno: {str(e)}'}), 500

@app.route('/api/logs')
def get_logs():
    """Logs de acesso"""
    try:
        per_page = request.args.get('per_page', 50, type=int)
        
        conn = sqlite3.connect(DATABASE)
        cursor = conn.cursor()
        
        cursor.execute("""
            SELECT username, action, timestamp, ip_address
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
                'ip_address': row[3]
            })
        
        conn.close()
        return jsonify(logs)
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/api/licenses/stats')
def get_license_stats():
    """Estatísticas de licenças"""
    try:
        conn = sqlite3.connect(DATABASE)
        cursor = conn.cursor()
        
        # Licenças ativas
        cursor.execute("SELECT COUNT(*) FROM users WHERE expires_at > datetime('now') OR expires_at IS NULL")
        active_licenses = cursor.fetchone()[0]
        
        # Expirando em 7 dias
        cursor.execute("""
            SELECT COUNT(*) FROM users 
            WHERE expires_at BETWEEN datetime('now') AND datetime('now', '+7 days')
        """)
        expiring_soon = cursor.fetchone()[0]
        
        conn.close()
        
        return jsonify({
            'active_licenses': active_licenses,
            'expiring_soon': expiring_soon
        })
    except Exception as e:
        return jsonify({'error': str(e)}), 500

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
            SELECT id, username, password_hash, expires_at, is_active
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
        
        # Verificar expiração
        if user[3]:  # Se tem data de expiração
            expires_at = datetime.datetime.fromisoformat(user[3])
            if expires_at < datetime.datetime.now():
                conn.close()
                return jsonify({'error': 'Licença expirada'}), 401
        
        # Atualizar último login
        cursor.execute("""
            UPDATE users 
            SET last_login = datetime('now'), hardware_id = ?
            WHERE id = ?
        """, (hardware_id, user[0]))
        
        # Log de acesso
        cursor.execute("""
            INSERT INTO access_logs (username, action, ip_address, hardware_id)
            VALUES (?, 'login', ?, ?)
        """, (username, request.remote_addr, hardware_id))
        
        conn.commit()
        conn.close()
        
        return jsonify({
            'success': True,
            'message': 'Login realizado com sucesso',
            'username': username,
            'expires_at': user[3]
        })
        
    except Exception as e:
        return jsonify({'error': f'Erro interno: {str(e)}'}), 500

if __name__ == '__main__':
    # Verificar se deve resetar o banco
    if os.getenv('RESET_DATABASE') == 'true':
        if os.path.exists(DATABASE):
            os.remove(DATABASE)
        print("Banco de dados resetado!")
    
    init_db()
    print("SpiderPrint Auth Server iniciado!")
    print("Dashboard: http://localhost:5000")
    
    # Configuração para produção
    port = int(os.environ.get('PORT', 5000))
    app.run(host='0.0.0.0', port=port, debug=False)
