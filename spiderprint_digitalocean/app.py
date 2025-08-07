from flask import Flask, request, jsonify, render_template_string, session, redirect, url_for
from flask_cors import CORS
import sqlite3
import hashlib
import datetime
import os
import json
import secrets

app = Flask(__name__)
CORS(app)

# Configuração de sessão
app.secret_key = os.environ.get('SECRET_KEY', secrets.token_hex(32))

# Configuração do banco de dados
DATABASE = 'spiderprint.db'

# Credenciais de administrador (pode ser alterado via variáveis de ambiente)
ADMIN_USERNAME = os.environ.get('ADMIN_USERNAME', 'admin')
ADMIN_PASSWORD = os.environ.get('ADMIN_PASSWORD', 'spiderprint2024')

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
            max-width: 1200px;
            margin: 0 auto;
        }
        
        .header {
            background: rgba(255, 255, 255, 0.95);
            padding: 20px;
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
        }
        
        .header-left p {
            color: #666;
            margin-top: 5px;
        }
        
        .header-right {
            display: flex;
            align-items: center;
            gap: 15px;
        }
        
        .admin-info {
            text-align: right;
            color: #666;
            font-size: 0.9em;
        }
        
        .logout-btn {
            background: #dc3545;
            color: white;
            border: none;
            padding: 10px 20px;
            border-radius: 8px;
            cursor: pointer;
            font-size: 14px;
            transition: background 0.3s ease;
        }
        
        .logout-btn:hover {
            background: #c82333;
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
            margin-right: 10px;
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
        
        .btn-warning {
            background: #ffc107;
            color: #212529;
        }
        
        .btn-warning:hover {
            background: #e0a800;
        }
        
        .btn-danger {
            background: #dc3545;
        }
        
        .btn-danger:hover {
            background: #c82333;
        }
        
        .btn-sm {
            padding: 8px 16px;
            font-size: 12px;
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
        
        .user-actions {
            display: flex;
            gap: 5px;
        }
        
        .status-active {
            color: #28a745;
            font-weight: bold;
        }
        
        .status-inactive {
            color: #dc3545;
            font-weight: bold;
        }
        
        .access-level {
            display: inline-block;
            padding: 3px 8px;
            border-radius: 12px;
            font-size: 0.8em;
            font-weight: bold;
            margin-left: 8px;
        }
        
        .access-basico {
            background: #e3f2fd;
            color: #1976d2;
        }
        
        .access-avancado {
            background: #fff3e0;
            color: #f57c00;
        }
        
        .access-completo {
            background: #e8f5e8;
            color: #388e3c;
        }
        
        .logs-list {
            max-height: 400px;
            overflow-y: auto;
        }
        
        .log-item {
            padding: 12px;
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
        
        .log-hardware {
            color: #667eea;
            font-size: 0.8em;
            margin-top: 5px;
            font-family: monospace;
        }
        
        .hardware-id {
            color: #667eea;
            font-family: monospace;
            font-size: 0.8em;
            background: #f8f9fa;
            padding: 2px 6px;
            border-radius: 4px;
            margin-top: 3px;
            display: inline-block;
        }
        
        @media (max-width: 768px) {
            .main-grid {
                grid-template-columns: 1fr;
            }
            
            .stats-grid {
                grid-template-columns: repeat(2, 1fr);
            }
            
            .user-item {
                flex-direction: column;
                align-items: flex-start;
                gap: 10px;
            }
            
            .user-actions {
                width: 100%;
                justify-content: flex-end;
            }
            
            .header {
                flex-direction: column;
                gap: 15px;
                text-align: center;
            }
        }
    </style>
</head>
<body>
    <div class="container">
        <div class="header">
            <div class="header-left">
                <h1>🕷️ SpiderPrint</h1>
                <p>Dashboard Administrativo - Sistema de Autenticação com Níveis de Acesso</p>
            </div>
            <div class="header-right">
                <div class="admin-info">
                    <div>👤 Administrador</div>
                    <div>🔐 Sessão Segura</div>
                </div>
                <button class="logout-btn" onclick="logout()">🚪 Sair</button>
            </div>
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
                <div class="stat-number" id="basicUsers">0</div>
                <div class="stat-label">Nível Básico</div>
            </div>
            <div class="stat-card">
                <div class="stat-number" id="advancedUsers">0</div>
                <div class="stat-label">Nível Avançado</div>
            </div>
            <div class="stat-card">
                <div class="stat-number" id="completeUsers">0</div>
                <div class="stat-label">Nível Completo</div>
            </div>
            <div class="stat-card">
                <div class="stat-number" id="todayLogins">0</div>
                <div class="stat-label">Logins Hoje</div>
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
            <h2 id="userModalTitle">Criar Novo Usuário</h2>
            <form id="userForm">
                <input type="hidden" id="userId" name="userId">
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
                    <input type="password" id="password" name="password">
                    <small id="passwordHelp" style="color: #666; font-size: 12px;">Deixe em branco para manter a senha atual (apenas na edição)</small>
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
                <div class="form-group">
                    <label for="accessLevel">Nível de Acesso:</label>
                    <select id="accessLevel" name="accessLevel">
                        <option value="Básico">🔵 Básico - Funcionalidades essenciais</option>
                        <option value="Avançado">🟠 Avançado - Básico + recursos avançados</option>
                        <option value="Completo">🟢 Completo - Acesso total</option>
                    </select>
                </div>
                <div style="text-align: right; margin-top: 30px;">
                    <button type="button" class="btn" onclick="closeUserModal()">Cancelar</button>
                    <button type="submit" class="btn btn-success" id="userSubmitBtn">Criar Usuário</button>
                </div>
            </form>
        </div>
    </div>
    
    <script>
        let editingUserId = null;
        
        // Logout
        function logout() {
            if (confirm('Tem certeza que deseja sair do dashboard?')) {
                window.location.href = '/admin/logout';
            }
        }
        
        // Funções do Modal
        function openUserModal(userId = null) {
            editingUserId = userId;
            const modal = document.getElementById('userModal');
            const title = document.getElementById('userModalTitle');
            const submitBtn = document.getElementById('userSubmitBtn');
            const passwordHelp = document.getElementById('passwordHelp');
            const passwordField = document.getElementById('password');
            
            if (userId) {
                // Modo edição
                title.textContent = 'Editar Usuário';
                submitBtn.textContent = 'Salvar Alterações';
                passwordHelp.style.display = 'block';
                passwordField.required = false;
                
                // Carregar dados do usuário
                loadUserForEdit(userId);
            } else {
                // Modo criação
                title.textContent = 'Criar Novo Usuário';
                submitBtn.textContent = 'Criar Usuário';
                passwordHelp.style.display = 'none';
                passwordField.required = true;
                document.getElementById('userForm').reset();
            }
            
            modal.style.display = 'block';
        }
        
        function closeUserModal() {
            document.getElementById('userModal').style.display = 'none';
            document.getElementById('userForm').reset();
            editingUserId = null;
        }
        
        function loadUserForEdit(userId) {
            fetch(`/api/users/${userId}`)
                .then(response => response.json())
                .then(user => {
                    document.getElementById('userId').value = user.id;
                    document.getElementById('username').value = user.username;
                    document.getElementById('email').value = user.email;
                    document.getElementById('licenseType').value = user.license_type;
                    document.getElementById('accessLevel').value = user.access_level || 'Básico';
                    
                    // Calcular duração restante
                    if (user.expires_at) {
                        const expiresAt = new Date(user.expires_at);
                        const now = new Date();
                        const daysRemaining = Math.ceil((expiresAt - now) / (1000 * 60 * 60 * 24));
                        document.getElementById('duration').value = Math.max(1, daysRemaining);
                    } else {
                        document.getElementById('duration').value = 365; // Vitalícia
                    }
                })
                .catch(error => {
                    console.error('Erro ao carregar usuário:', error);
                    alert('Erro ao carregar dados do usuário');
                });
        }
        
        function toggleUserStatus(userId, currentStatus) {
            const action = currentStatus ? 'desativar' : 'ativar';
            const newStatus = !currentStatus;
            
            if (confirm(`Tem certeza que deseja ${action} este usuário?`)) {
                fetch(`/api/users/${userId}/status`, {
                    method: 'PUT',
                    headers: {
                        'Content-Type': 'application/json',
                    },
                    body: JSON.stringify({ is_active: newStatus })
                })
                .then(response => {
                    if (response.ok) {
                        alert(`Usuário ${action}do com sucesso!`);
                        loadUsers();
                        loadStats();
                    } else {
                        throw new Error(`Erro ao ${action} usuário`);
                    }
                })
                .catch(error => {
                    console.error('Erro:', error);
                    alert(`Erro ao ${action} usuário: ` + error.message);
                });
            }
        }
        
        function deleteUser(userId, username) {
            if (confirm(`Tem certeza que deseja EXCLUIR permanentemente o usuário "${username}"?\\n\\nEsta ação não pode ser desfeita!`)) {
                fetch(`/api/users/${userId}`, {
                    method: 'DELETE'
                })
                .then(response => {
                    if (response.ok) {
                        alert('Usuário excluído com sucesso!');
                        loadUsers();
                        loadStats();
                    } else {
                        throw new Error('Erro ao excluir usuário');
                    }
                })
                .catch(error => {
                    console.error('Erro:', error);
                    alert('Erro ao excluir usuário: ' + error.message);
                });
            }
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
                    document.getElementById('basicUsers').textContent = data.basic_users || 0;
                    document.getElementById('advancedUsers').textContent = data.advanced_users || 0;
                    document.getElementById('completeUsers').textContent = data.complete_users || 0;
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
        
        # Validações básicas
        if len(username) < 3:
            return jsonify({'error': 'Username deve ter pelo menos 3 caracteres'}), 400
        
        if len(password) < 6:
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
        
        # Verificar se usuário já existe
        cursor.execute("SELECT id FROM users WHERE username = ? OR email = ?", (username, email))
        if cursor.fetchone():
            conn.close()
            return jsonify({'error': 'Usuário ou email já existe'}), 400
        
        # Criar usuário
        password_hash = hash_password(password)
        cursor.execute("""
            INSERT INTO users (username, email, password_hash, expires_at, license_type, access_level)
            VALUES (?, ?, ?, ?, ?, ?)
        """, (username, email, password_hash, expires_at, license_type, access_level))
        
        user_id = cursor.lastrowid
        conn.commit()
        conn.close()
        
        return jsonify({
            'id': user_id,
            'username': username,
            'email': email,
            'expires_at': expires_at,
            'license_type': license_type,
            'access_level': access_level,
            'message': 'Usuário criado com sucesso'
        }), 201
        
    except Exception as e:
        return jsonify({'error': f'Erro interno: {str(e)}'}), 500

@app.route('/api/users/<int:user_id>', methods=['PUT'])
def update_user(user_id):
    """Editar usuário existente"""
    if not require_admin_login():
        return jsonify({'error': 'Acesso negado'}), 401
    
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
            SELECT id, username, password_hash, expires_at, is_active, access_level
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
        
        # Atualizar último login e hardware_id
        cursor.execute("""
            UPDATE users 
            SET last_login = datetime('now'), hardware_id = ?
            WHERE id = ?
        """, (hardware_id, user[0]))
        
        # Log de acesso com hardware_id
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
            'expires_at': user[3],
            'access_level': user[5] or 'Básico'
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
    print(f"Dashboard: http://localhost:5000")
    print(f"Admin Login: {ADMIN_USERNAME} / {ADMIN_PASSWORD}")
    
    # Configuração para produção
    port = int(os.environ.get('PORT', 5000))
    app.run(host='0.0.0.0', port=port, debug=False)

