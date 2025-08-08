from flask import Flask, request, jsonify, render_template_string, send_file
from flask_cors import CORS
import sqlite3
import hashlib
import datetime
import os
import json
import shutil
import tempfile
from werkzeug.utils import secure_filename

app = Flask(__name__)
CORS(app)

# Configuração do banco de dados
DATABASE = 'spiderprint.db'

# Configuração de fuso horário Brasil (UTC-3)
BRAZIL_OFFSET = datetime.timedelta(hours=-3)

def get_brazil_time():
    """Retorna o horário atual do Brasil (UTC-3)"""
    return datetime.datetime.utcnow() + BRAZIL_OFFSET

def format_brazil_time(dt_string):
    """Formata timestamp para horário do Brasil"""
    if not dt_string:
        return None
    dt = datetime.datetime.fromisoformat(dt_string.replace('Z', ''))
    brazil_time = dt + BRAZIL_OFFSET
    return brazil_time.strftime('%Y-%m-%d %H:%M:%S')

# Credenciais do admin
ADMIN_USERNAME = 'admin'
ADMIN_PASSWORD = 'Asd4d45#2365'

def init_db():
    """Inicializa o banco de dados"""
    conn = sqlite3.connect(DATABASE)
    cursor = conn.cursor()
    
    # Criar tabela de usuários com campos adicionais
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
            user_type TEXT DEFAULT 'Cliente',
            is_active BOOLEAN DEFAULT 1,
            last_login TIMESTAMP,
            hardware_id TEXT,
            created_by TEXT
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
            hardware_id TEXT,
            details TEXT
        )
    ''')
    
    # Criar tabela de staff (vendedores/técnicos)
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS staff (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT UNIQUE NOT NULL,
            email TEXT UNIQUE NOT NULL,
            password_hash TEXT NOT NULL,
            staff_type TEXT NOT NULL,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            is_active BOOLEAN DEFAULT 1,
            created_by TEXT
        )
    ''')
    
    conn.commit()
    conn.close()

def create_admin_if_not_exists():
    """Cria usuário admin se não existir"""
    conn = sqlite3.connect(DATABASE)
    cursor = conn.cursor()
    
    # Sempre recriar o admin para garantir credenciais corretas
    print("🔄 Recriando usuário admin...")
    
    # Deletar admin existente
    cursor.execute('DELETE FROM users WHERE username = ?', (ADMIN_USERNAME,))
    
    # Inserir novo admin com credenciais corretas
    admin_hash = hash_password(ADMIN_PASSWORD)
    cursor.execute('''
        INSERT INTO users (username, email, password_hash, license_type, access_level, user_type, expires_at)
        VALUES (?, ?, ?, ?, ?, ?, ?)
    ''', (ADMIN_USERNAME, 'admin@spiderprint.com', admin_hash, 'Admin', 'Admin', 'Admin', None))
    
    conn.commit()
    conn.close()
    print(f"✅ Usuário admin criado com sucesso!")
    print(f"👤 Usuário: {ADMIN_USERNAME}")
    print(f"🔑 Senha: {ADMIN_PASSWORD}")

def hash_password(password):
    """Hash da senha"""
    return hashlib.sha256(password.encode()).hexdigest()

@app.route('/')
def dashboard():
    """Dashboard administrativo com sistema de login"""
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
        }
        
        /* Login Page Styles */
        .login-container {
            display: flex;
            justify-content: center;
            align-items: center;
            min-height: 100vh;
            padding: 20px;
        }
        
        .login-card {
            background: rgba(255, 255, 255, 0.95);
            padding: 40px;
            border-radius: 20px;
            box-shadow: 0 20px 60px rgba(0, 0, 0, 0.3);
            width: 100%;
            max-width: 400px;
            text-align: center;
        }
        
        .login-card h1 {
            color: #333;
            margin-bottom: 10px;
            display: flex;
            align-items: center;
            justify-content: center;
            gap: 10px;
        }
        
        .login-card p {
            color: #666;
            margin-bottom: 30px;
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
            padding: 12px;
            border: 2px solid #e1e5e9;
            border-radius: 8px;
            font-size: 14px;
            transition: border-color 0.3s ease;
        }
        
        .form-group input:focus {
            outline: none;
            border-color: #667eea;
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
            width: 100%;
        }
        
        .btn:hover {
            background: #5a6fd8;
        }
        
        .error-message {
            background: #f8d7da;
            color: #721c24;
            padding: 10px;
            border-radius: 5px;
            margin-bottom: 20px;
            display: none;
        }
        
        /* Dashboard Styles */
        .dashboard-container {
            display: none;
            padding: 20px;
            max-width: 1400px;
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
        
        .header h1 {
            color: #333;
            display: flex;
            align-items: center;
            gap: 10px;
        }
        
        .header-actions {
            display: flex;
            gap: 10px;
            align-items: center;
        }
        
        .user-info {
            color: #666;
            margin-right: 15px;
        }
        
        .btn-logout {
            background: #dc3545;
            color: white;
            border: none;
            padding: 8px 16px;
            border-radius: 6px;
            cursor: pointer;
            font-size: 12px;
        }
        
        .btn-logout:hover {
            background: #c82333;
        }
        
        /* Tabs */
        .tabs {
            background: rgba(255, 255, 255, 0.95);
            border-radius: 15px;
            margin-bottom: 20px;
            box-shadow: 0 8px 32px rgba(0, 0, 0, 0.1);
        }
        
        .tab-buttons {
            display: flex;
            border-bottom: 1px solid #eee;
            padding: 0 20px;
        }
        
        .tab-button {
            background: none;
            border: none;
            padding: 15px 20px;
            cursor: pointer;
            font-size: 14px;
            color: #666;
            border-bottom: 3px solid transparent;
            transition: all 0.3s ease;
        }
        
        .tab-button.active {
            color: #667eea;
            border-bottom-color: #667eea;
        }
        
        .tab-button:hover {
            color: #667eea;
        }
        
        .tab-content {
            display: none;
            padding: 20px;
        }
        
        .tab-content.active {
            display: block;
        }
        
        /* Stats Grid */
        .stats-grid {
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(200px, 1fr));
            gap: 20px;
            margin-bottom: 30px;
        }
        
        .stat-card {
            background: rgba(255, 255, 255, 0.95);
            padding: 20px;
            border-radius: 12px;
            text-align: center;
            box-shadow: 0 4px 16px rgba(0, 0, 0, 0.1);
            transition: transform 0.3s ease;
        }
        
        .stat-card:hover {
            transform: translateY(-3px);
        }
        
        .stat-number {
            font-size: 2em;
            font-weight: bold;
            color: #667eea;
            margin-bottom: 8px;
        }
        
        .stat-label {
            color: #666;
            font-size: 0.85em;
            text-transform: uppercase;
            letter-spacing: 1px;
        }
        
        /* Tables */
        .table-container {
            background: white;
            border-radius: 12px;
            overflow: hidden;
            box-shadow: 0 4px 16px rgba(0, 0, 0, 0.1);
        }
        
        .table-header {
            background: #f8f9fa;
            padding: 15px 20px;
            border-bottom: 1px solid #eee;
            display: flex;
            justify-content: space-between;
            align-items: center;
        }
        
        .table-header h3 {
            color: #333;
            margin: 0;
        }
        
        .search-filter {
            display: flex;
            gap: 10px;
            margin-bottom: 15px;
        }
        
        .search-input {
            flex: 1;
            padding: 8px 12px;
            border: 1px solid #ddd;
            border-radius: 6px;
            font-size: 14px;
        }
        
        .filter-select {
            padding: 8px 12px;
            border: 1px solid #ddd;
            border-radius: 6px;
            font-size: 14px;
            min-width: 120px;
        }
        
        .data-table {
            width: 100%;
            border-collapse: collapse;
        }
        
        .data-table th,
        .data-table td {
            padding: 12px 15px;
            text-align: left;
            border-bottom: 1px solid #eee;
        }
        
        .data-table th {
            background: #f8f9fa;
            font-weight: 600;
            color: #333;
            cursor: pointer;
            user-select: none;
        }
        
        .data-table th:hover {
            background: #e9ecef;
        }
        
        .data-table tr:hover {
            background: #f8f9fa;
        }
        
        .status-active {
            color: #28a745;
            font-weight: bold;
        }
        
        .status-inactive {
            color: #dc3545;
            font-weight: bold;
        }
        
        .status-expired {
            color: #ffc107;
            font-weight: bold;
        }
        
        .hardware-id {
            font-family: monospace;
            font-size: 0.8em;
            background: #f8f9fa;
            padding: 2px 6px;
            border-radius: 4px;
            color: #667eea;
        }
        
        /* Action Buttons */
        .btn-sm {
            padding: 6px 12px;
            font-size: 12px;
            margin-right: 5px;
            margin-bottom: 3px;
            white-space: nowrap;
            display: inline-block;
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
        
        .btn-info {
            background: #17a2b8;
        }
        
        .btn-info:hover {
            background: #138496;
        }
        
        /* Modal */
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
        
        /* Backup Section */
        .backup-section {
            background: white;
            padding: 20px;
            border-radius: 12px;
            margin-bottom: 20px;
            box-shadow: 0 4px 16px rgba(0, 0, 0, 0.1);
        }
        
        .backup-actions {
            display: flex;
            gap: 15px;
            margin-bottom: 20px;
            flex-wrap: wrap;
        }
        
        .upload-area {
            border: 2px dashed #ddd;
            border-radius: 8px;
            padding: 20px;
            text-align: center;
            margin-bottom: 20px;
            transition: border-color 0.3s ease;
        }
        
        .upload-area:hover {
            border-color: #667eea;
        }
        
        .upload-area.dragover {
            border-color: #667eea;
            background: #f8f9ff;
        }
        
        .backup-list {
            max-height: 300px;
            overflow-y: auto;
        }
        
        .backup-item {
            display: flex;
            justify-content: space-between;
            align-items: center;
            padding: 10px;
            border-bottom: 1px solid #eee;
        }
        
        .backup-info {
            flex: 1;
        }
        
        .backup-name {
            font-weight: 500;
            color: #333;
        }
        
        .backup-details {
            font-size: 0.85em;
            color: #666;
        }
        
        .backup-actions-btn {
            display: flex;
            gap: 5px;
        }
        
        /* Responsive */
        @media (max-width: 768px) {
            .tab-buttons {
                flex-wrap: wrap;
                padding: 0 10px;
            }
            
            .tab-button {
                padding: 12px 15px;
                font-size: 13px;
            }
            
            .stats-grid {
                grid-template-columns: repeat(2, 1fr);
            }
            
            .search-filter {
                flex-direction: column;
            }
            
            .backup-actions {
                flex-direction: column;
            }
            
            .data-table {
                font-size: 13px;
            }
            
            .data-table th,
            .data-table td {
                padding: 8px 10px;
            }
            
            .btn-sm {
                font-size: 11px;
                padding: 4px 8px;
                margin-right: 3px;
            }
        }
    </style>
</head>
<body>
    <!-- Login Page -->
    <div id="loginPage" class="login-container">
        <div class="login-card">
            <h1>🕷️ SpiderPrint</h1>
            <p>Dashboard Administrativo</p>
            
            <div id="errorMessage" class="error-message"></div>
            
            <form id="loginForm">
                <div class="form-group">
                    <label for="loginUsername">Usuário:</label>
                    <input type="text" id="loginUsername" name="username" required>
                </div>
                <div class="form-group">
                    <label for="loginPassword">Senha:</label>
                    <input type="password" id="loginPassword" name="password" required>
                </div>
                <button type="submit" class="btn">🔐 Entrar</button>
            </form>
        </div>
    </div>
    
    <!-- Dashboard -->
    <div id="dashboardPage" class="dashboard-container">
        <div class="header">
            <div>
                <h1>🕷️ SpiderPrint</h1>
                <p>Dashboard Administrativo - Sistema Completo</p>
            </div>
            <div class="header-actions">
                <span class="user-info">👤 <span id="currentUser">Admin</span></span>
                <button class="btn-logout" onclick="logout()">🚪 Sair</button>
            </div>
        </div>
        
        <div class="tabs">
            <div class="tab-buttons">
                <button class="tab-button active" onclick="showTab('dashboard')">📊 Dashboard</button>
                <button class="tab-button" onclick="showTab('users')">👥 Usuários</button>
                <button class="tab-button" onclick="showTab('staff')">👨‍💼 Staff</button>
                <button class="tab-button" onclick="showTab('logs')">📋 Logs</button>
                <button class="tab-button" onclick="showTab('backup')">💾 Backup</button>
                <button class="tab-button" onclick="showTab('settings')">⚙️ Configurações</button>
            </div>
            
            <!-- Dashboard Tab -->
            <div id="dashboard" class="tab-content active">
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
                        <div class="stat-number" id="todayLogins">0</div>
                        <div class="stat-label">Logins Hoje</div>
                    </div>
                    <div class="stat-card">
                        <div class="stat-number" id="activeLicenses">0</div>
                        <div class="stat-label">Licenças Ativas</div>
                    </div>
                    <div class="stat-card">
                        <div class="stat-number" id="expiringLicenses">0</div>
                        <div class="stat-label">Expirando em 7 dias</div>
                    </div>
                    <div class="stat-card">
                        <div class="stat-number" id="totalStaff">0</div>
                        <div class="stat-label">Staff Ativo</div>
                    </div>
                </div>
            </div>
            
            <!-- Users Tab -->
            <div id="users" class="tab-content">
                <div class="table-container">
                    <div class="table-header">
                        <h3>👥 Gerenciar Usuários</h3>
                        <button class="btn btn-success" onclick="openUserModal()">+ Novo Usuário</button>
                    </div>
                    <div style="padding: 15px;">
                        <div class="search-filter">
                            <input type="text" class="search-input" id="userSearch" placeholder="🔍 Buscar usuários..." onkeyup="filterUsers()">
                            <select class="filter-select" id="userLevelFilter" onchange="filterUsers()">
                                <option value="">Todos os Níveis</option>
                                <option value="Básico">Básico</option>
                                <option value="Avançado">Avançado</option>
                                <option value="Completo">Completo</option>
                                <option value="Admin">Admin</option>
                            </select>
                            <select class="filter-select" id="userStatusFilter" onchange="filterUsers()">
                                <option value="">Todos os Status</option>
                                <option value="active">Ativo</option>
                                <option value="inactive">Inativo</option>
                                <option value="expired">Expirado</option>
                            </select>
                            <button class="btn btn-info btn-sm" onclick="exportUsers()">📊 Exportar CSV</button>
                        </div>
                        <div style="overflow-x: auto;">
                            <table class="data-table">
                                <thead>
                                    <tr>
                                        <th onclick="sortUsers('username')">👤 Usuário</th>
                                        <th onclick="sortUsers('email')">📧 Email</th>
                                        <th onclick="sortUsers('access_level')">🎯 Nível</th>
                                        <th onclick="sortUsers('license_type')">📄 Licença</th>
                                        <th onclick="sortUsers('expires_at')">⏰ Expira</th>
                                        <th onclick="sortUsers('is_active')">📊 Status</th>
                                        <th>🔧 Hardware</th>
                                        <th>⚡ Ações</th>
                                    </tr>
                                </thead>
                                <tbody id="usersTableBody">
                                    <!-- Usuários serão carregados aqui -->
                                </tbody>
                            </table>
                        </div>
                    </div>
                </div>
            </div>
            
            <!-- Staff Tab -->
            <div id="staff" class="tab-content">
                <div class="table-container">
                    <div class="table-header">
                        <h3>👨‍💼 Gerenciar Staff (Vendedores/Técnicos)</h3>
                        <button class="btn btn-success" onclick="openStaffModal()">+ Novo Staff</button>
                    </div>
                    <div style="padding: 15px;">
                        <div class="search-filter">
                            <input type="text" class="search-input" id="staffSearch" placeholder="🔍 Buscar staff..." onkeyup="filterStaff()">
                            <select class="filter-select" id="staffTypeFilter" onchange="filterStaff()">
                                <option value="">Todos os Tipos</option>
                                <option value="Vendedor">Vendedor</option>
                                <option value="Técnico">Técnico</option>
                            </select>
                        </div>
                        <div style="overflow-x: auto;">
                            <table class="data-table">
                                <thead>
                                    <tr>
                                        <th>👤 Usuário</th>
                                        <th>📧 Email</th>
                                        <th>🏷️ Tipo</th>
                                        <th>📅 Criado em</th>
                                        <th>📊 Status</th>
                                        <th>🎯 Acessos Criados</th>
                                        <th>⚡ Ações</th>
                                    </tr>
                                </thead>
                                <tbody id="staffTableBody">
                                    <!-- Staff será carregado aqui -->
                                </tbody>
                            </table>
                        </div>
                    </div>
                </div>
            </div>
            
            <!-- Logs Tab -->
            <div id="logs" class="tab-content">
                <div class="table-container">
                    <div class="table-header">
                        <h3>📋 Logs de Acesso</h3>
                        <div>
                            <button class="btn btn-info btn-sm" onclick="exportLogs()">📊 Exportar CSV</button>
                            <button class="btn btn-warning btn-sm" onclick="clearOldLogs()">🗑️ Limpar Antigos</button>
                        </div>
                    </div>
                    <div style="padding: 15px;">
                        <div class="search-filter">
                            <input type="text" class="search-input" id="logSearch" placeholder="🔍 Buscar logs..." onkeyup="filterLogs()">
                            <input type="date" class="filter-select" id="logDateFilter" onchange="filterLogs()">
                            <select class="filter-select" id="logActionFilter" onchange="filterLogs()">
                                <option value="">Todas as Ações</option>
                                <option value="login">Login</option>
                                <option value="logout">Logout</option>
                                <option value="created">Criado</option>
                                <option value="updated">Atualizado</option>
                                <option value="deleted">Excluído</option>
                            </select>
                        </div>
                        <div style="overflow-x: auto; max-height: 500px;">
                            <table class="data-table">
                                <thead>
                                    <tr>
                                        <th>⏰ Data/Hora</th>
                                        <th>👤 Usuário</th>
                                        <th>⚡ Ação</th>
                                        <th>🌐 IP</th>
                                        <th>🔧 Hardware</th>
                                        <th>📋 Detalhes</th>
                                    </tr>
                                </thead>
                                <tbody id="logsTableBody">
                                    <!-- Logs serão carregados aqui -->
                                </tbody>
                            </table>
                        </div>
                    </div>
                </div>
            </div>
            
            <!-- Backup Tab -->
            <div id="backup" class="tab-content">
                <div class="backup-section">
                    <h3>💾 Sistema de Backup</h3>
                    <div class="backup-actions">
                        <button class="btn btn-success" onclick="createBackup()">💾 Criar Backup Agora</button>
                        <button class="btn btn-info" onclick="refreshBackups()">🔄 Atualizar Lista</button>
                    </div>
                    
                    <div class="upload-area" id="uploadArea">
                        <p>📁 Arraste um arquivo de backup (.db) aqui ou</p>
                        <input type="file" id="backupFile" accept=".db" style="display: none;" onchange="uploadBackup()">
                        <button class="btn" onclick="document.getElementById('backupFile').click()">📂 Selecionar Arquivo</button>
                    </div>
                    
                    <div class="table-container">
                        <div class="table-header">
                            <h3>📋 Backups Disponíveis</h3>
                        </div>
                        <div class="backup-list" id="backupList">
                            <!-- Lista de backups será carregada aqui -->
                        </div>
                    </div>
                </div>
            </div>
            
            <!-- Settings Tab -->
            <div id="settings" class="tab-content">
                <div class="backup-section">
                    <h3>⚙️ Configurações do Sistema</h3>
                    
                    <div style="margin-bottom: 30px;">
                        <h4>🔑 Trocar Senha do Admin</h4>
                        <form id="changePasswordForm" style="max-width: 400px;">
                            <div class="form-group">
                                <label>Senha Atual:</label>
                                <input type="password" id="currentPassword" required>
                            </div>
                            <div class="form-group">
                                <label>Nova Senha:</label>
                                <input type="password" id="newPassword" required minlength="8">
                            </div>
                            <div class="form-group">
                                <label>Confirmar Nova Senha:</label>
                                <input type="password" id="confirmPassword" required minlength="8">
                            </div>
                            <button type="submit" class="btn btn-warning">🔄 Alterar Senha</button>
                        </form>
                    </div>
                    
                    <div>
                        <h4>🌎 Informações do Sistema</h4>
                        <p><strong>Fuso Horário:</strong> Brasil (UTC-3)</p>
                        <p><strong>Versão:</strong> SpiderPrint v2.0</p>
                        <p><strong>Banco de Dados:</strong> SQLite</p>
                    </div>
                </div>
            </div>
        </div>
    </div>
    
    <!-- Modal Usuário -->
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
                    <label for="accessLevel">Nível de Acesso:</label>
                    <select id="accessLevel" name="accessLevel">
                        <option value="Básico">Básico</option>
                        <option value="Avançado">Avançado</option>
                        <option value="Completo">Completo</option>
                        <option value="Admin">Admin (Vitalício)</option>
                    </select>
                </div>
                <div class="form-group" id="durationGroup">
                    <label for="duration">Duração da Licença (dias):</label>
                    <input type="number" id="duration" name="duration" value="30" min="1">
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
                    <button type="submit" class="btn btn-success" id="userSubmitBtn">Criar Usuário</button>
                </div>
            </form>
        </div>
    </div>
    
    <!-- Modal Staff -->
    <div id="staffModal" class="modal">
        <div class="modal-content">
            <span class="close" onclick="closeStaffModal()">&times;</span>
            <h2 id="staffModalTitle">Criar Novo Staff</h2>
            <form id="staffForm">
                <input type="hidden" id="staffId" name="staffId">
                <div class="form-group">
                    <label for="staffUsername">Usuário:</label>
                    <input type="text" id="staffUsername" name="username" required>
                </div>
                <div class="form-group">
                    <label for="staffEmail">Email:</label>
                    <input type="email" id="staffEmail" name="email" required>
                </div>
                <div class="form-group">
                    <label for="staffPassword">Senha:</label>
                    <input type="password" id="staffPassword" name="password" required minlength="6">
                </div>
                <div class="form-group">
                    <label for="staffType">Tipo de Staff:</label>
                    <select id="staffType" name="staffType" required>
                        <option value="">Selecione...</option>
                        <option value="Vendedor">Vendedor</option>
                        <option value="Técnico">Técnico</option>
                    </select>
                </div>
                <div style="text-align: right; margin-top: 30px;">
                    <button type="button" class="btn" onclick="closeStaffModal()">Cancelar</button>
                    <button type="submit" class="btn btn-success" id="staffSubmitBtn">Criar Staff</button>
                </div>
            </form>
        </div>
    </div>
    
    <script>
        let currentUser = null;
        let editingUserId = null;
        let editingStaffId = null;
        let usersData = [];
        let staffData = [];
        let logsData = [];
        
        // Login
        document.getElementById('loginForm').addEventListener('submit', function(e) {
            e.preventDefault();
            
            const username = document.getElementById('loginUsername').value;
            const password = document.getElementById('loginPassword').value;
            
            fetch('/api/admin/login', {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/json',
                },
                body: JSON.stringify({ username, password })
            })
            .then(response => response.json())
            .then(data => {
                if (data.success) {
                    currentUser = data.username;
                    // Salvar sessão no localStorage
                    localStorage.setItem('spiderprint_admin_session', JSON.stringify({
                        username: data.username,
                        loginTime: Date.now()
                    }));
                    
                    document.getElementById('currentUser').textContent = currentUser;
                    document.getElementById('loginPage').style.display = 'none';
                    document.getElementById('dashboardPage').style.display = 'block';
                    loadAllData();
                } else {
                    showError(data.error || 'Credenciais inválidas');
                }
            })
            .catch(error => {
                console.error('Erro:', error);
                showError('Erro de conexão');
            });
        });
        
        // Verificar sessão salva ao carregar a página
        function checkSavedSession() {
            const savedSession = localStorage.getItem('spiderprint_admin_session');
            if (savedSession) {
                try {
                    const session = JSON.parse(savedSession);
                    const sessionAge = Date.now() - session.loginTime;
                    
                    // Sessão válida por 24 horas (86400000 ms)
                    if (sessionAge < 86400000) {
                        currentUser = session.username;
                        document.getElementById('currentUser').textContent = currentUser;
                        document.getElementById('loginPage').style.display = 'none';
                        document.getElementById('dashboardPage').style.display = 'block';
                        loadAllData();
                        return true;
                    } else {
                        // Sessão expirada
                        localStorage.removeItem('spiderprint_admin_session');
                    }
                } catch (e) {
                    localStorage.removeItem('spiderprint_admin_session');
                }
            }
            return false;
        }
        
        function showError(message) {
            const errorDiv = document.getElementById('errorMessage');
            errorDiv.textContent = message;
            errorDiv.style.display = 'block';
            setTimeout(() => {
                errorDiv.style.display = 'none';
            }, 5000);
        }
        
        function logout() {
            currentUser = null;
            // Limpar sessão salva
            localStorage.removeItem('spiderprint_admin_session');
            document.getElementById('loginPage').style.display = 'flex';
            document.getElementById('dashboardPage').style.display = 'none';
            document.getElementById('loginForm').reset();
        }
        
        // Tabs
        function showTab(tabName) {
            // Hide all tabs
            const tabs = document.querySelectorAll('.tab-content');
            tabs.forEach(tab => tab.classList.remove('active'));
            
            // Hide all tab buttons
            const buttons = document.querySelectorAll('.tab-button');
            buttons.forEach(btn => btn.classList.remove('active'));
            
            // Show selected tab
            document.getElementById(tabName).classList.add('active');
            event.target.classList.add('active');
            
            // Load data for specific tabs
            if (tabName === 'users') {
                loadUsers();
            } else if (tabName === 'staff') {
                loadStaff();
            } else if (tabName === 'logs') {
                loadLogs();
            } else if (tabName === 'backup') {
                loadBackups();
            }
        }
        
        // Load all data
        function loadAllData() {
            loadStats();
            loadUsers();
            loadStaff();
            loadLogs();
        }
        
        // Stats
        function loadStats() {
            fetch('/api/stats')
                .then(response => response.json())
                .then(data => {
                    document.getElementById('totalUsers').textContent = data.total_users || 0;
                    document.getElementById('activeUsers').textContent = data.active_users || 0;
                    document.getElementById('todayLogins').textContent = data.today_logins || 0;
                    document.getElementById('activeLicenses').textContent = data.active_licenses || 0;
                    document.getElementById('expiringLicenses').textContent = data.expiring_soon || 0;
                    document.getElementById('totalStaff').textContent = data.total_staff || 0;
                })
                .catch(error => console.error('Erro ao carregar estatísticas:', error));
        }
        
        // Users
        function loadUsers() {
            fetch('/api/users')
                .then(response => response.json())
                .then(data => {
                    usersData = data;
                    renderUsers(data);
                })
                .catch(error => console.error('Erro ao carregar usuários:', error));
        }
        
        function renderUsers(users) {
            const tbody = document.getElementById('usersTableBody');
            if (!users || users.length === 0) {
                tbody.innerHTML = '<tr><td colspan="8" style="text-align: center; color: #666;">Nenhum usuário encontrado</td></tr>';
                return;
            }
            
            tbody.innerHTML = users.map(user => {
                const isExpired = user.expires_at && new Date(user.expires_at) < new Date();
                const statusClass = !user.is_active ? 'status-inactive' : (isExpired ? 'status-expired' : 'status-active');
                const statusText = !user.is_active ? 'Inativo' : (isExpired ? 'Expirado' : 'Ativo');
                
                const hardwareDisplay = user.hardware_id ? 
                    `<div class="hardware-id">${user.hardware_id.substring(0, 12)}...</div>` : 
                    '<span style="color: #999;">Não vinculado</span>';
                
                const expiresDisplay = user.expires_at ? 
                    new Date(user.expires_at).toLocaleDateString('pt-BR') : 
                    '<span style="color: #28a745;">Nunca</span>';
                
                return `
                    <tr>
                        <td><strong>${user.username}</strong></td>
                        <td>${user.email}</td>
                        <td><span class="hardware-id">${user.access_level || 'Básico'}</span></td>
                        <td>${user.license_type}</td>
                        <td>${expiresDisplay}</td>
                        <td><span class="${statusClass}">${statusText}</span></td>
                        <td>${hardwareDisplay}</td>
                        <td>
                            <button class="btn btn-sm btn-info" onclick="openUserModal(${user.id})" title="Editar usuário">✏️ Editar</button>
                            <button class="btn btn-sm ${user.is_active ? 'btn-warning' : 'btn-success'}" 
                                    onclick="toggleUserStatus(${user.id}, ${user.is_active})"
                                    title="${user.is_active ? 'Desativar usuário' : 'Ativar usuário'}">
                                ${user.is_active ? '⏸️ Desativar' : '▶️ Ativar'}
                            </button>
                            ${user.hardware_id ? `<button class="btn btn-sm btn-warning" onclick="removeHardware(${user.id})" title="Remover hardware vinculado">🔧 Hardware</button>` : ''}
                            <button class="btn btn-sm btn-danger" onclick="deleteUser(${user.id}, '${user.username}')" title="Excluir usuário">🗑️ Excluir</button>
                        </td>
                    </tr>
                `;
            }).join('');
        }
        
        function filterUsers() {
            const search = document.getElementById('userSearch').value.toLowerCase();
            const levelFilter = document.getElementById('userLevelFilter').value;
            const statusFilter = document.getElementById('userStatusFilter').value;
            
            let filtered = usersData.filter(user => {
                const matchesSearch = user.username.toLowerCase().includes(search) || 
                                    user.email.toLowerCase().includes(search);
                
                const matchesLevel = !levelFilter || user.access_level === levelFilter;
                
                let matchesStatus = true;
                if (statusFilter === 'active') {
                    matchesStatus = user.is_active && (!user.expires_at || new Date(user.expires_at) > new Date());
                } else if (statusFilter === 'inactive') {
                    matchesStatus = !user.is_active;
                } else if (statusFilter === 'expired') {
                    matchesStatus = user.expires_at && new Date(user.expires_at) < new Date();
                }
                
                return matchesSearch && matchesLevel && matchesStatus;
            });
            
            renderUsers(filtered);
        }
        
        function sortUsers(column) {
            usersData.sort((a, b) => {
                if (a[column] < b[column]) return -1;
                if (a[column] > b[column]) return 1;
                return 0;
            });
            renderUsers(usersData);
        }
        
        function exportUsers() {
            const csv = [
                ['Usuário', 'Email', 'Nível', 'Licença', 'Expira', 'Status', 'Hardware ID'],
                ...usersData.map(user => [
                    user.username,
                    user.email,
                    user.access_level || 'Básico',
                    user.license_type,
                    user.expires_at || 'Nunca',
                    user.is_active ? 'Ativo' : 'Inativo',
                    user.hardware_id || 'Não vinculado'
                ])
            ].map(row => row.join(',')).join('\\n');
            
            const blob = new Blob([csv], { type: 'text/csv' });
            const url = window.URL.createObjectURL(blob);
            const a = document.createElement('a');
            a.href = url;
            a.download = `usuarios_${new Date().toISOString().split('T')[0]}.csv`;
            a.click();
        }
        
        // User Modal
        function openUserModal(userId = null) {
            editingUserId = userId;
            const modal = document.getElementById('userModal');
            const title = document.getElementById('userModalTitle');
            const submitBtn = document.getElementById('userSubmitBtn');
            const passwordHelp = document.getElementById('passwordHelp');
            const passwordField = document.getElementById('password');
            const durationGroup = document.getElementById('durationGroup');
            const accessLevel = document.getElementById('accessLevel');
            
            if (userId) {
                title.textContent = 'Editar Usuário';
                submitBtn.textContent = 'Salvar Alterações';
                passwordHelp.style.display = 'block';
                passwordField.required = false;
                loadUserForEdit(userId);
            } else {
                title.textContent = 'Criar Novo Usuário';
                submitBtn.textContent = 'Criar Usuário';
                passwordHelp.style.display = 'none';
                passwordField.required = true;
                document.getElementById('userForm').reset();
                document.getElementById('duration').value = 30;
            }
            
            // Handle Admin level
            accessLevel.addEventListener('change', function() {
                if (this.value === 'Admin') {
                    durationGroup.style.display = 'none';
                    document.getElementById('licenseType').value = 'Vitalícia';
                } else {
                    durationGroup.style.display = 'block';
                }
            });
            
            modal.style.display = 'block';
        }
        
        function closeUserModal() {
            document.getElementById('userModal').style.display = 'none';
            document.getElementById('userForm').reset();
            editingUserId = null;
        }
        
        function loadUserForEdit(userId) {
            const user = usersData.find(u => u.id === userId);
            if (user) {
                document.getElementById('userId').value = user.id;
                document.getElementById('username').value = user.username;
                document.getElementById('email').value = user.email;
                document.getElementById('accessLevel').value = user.access_level || 'Básico';
                document.getElementById('licenseType').value = user.license_type;
                
                if (user.access_level === 'Admin') {
                    document.getElementById('durationGroup').style.display = 'none';
                } else if (user.expires_at) {
                    const expiresAt = new Date(user.expires_at);
                    const now = new Date();
                    const daysRemaining = Math.ceil((expiresAt - now) / (1000 * 60 * 60 * 24));
                    document.getElementById('duration').value = Math.max(1, daysRemaining);
                }
            }
        }
        
        // User Form Submit
        document.getElementById('userForm').addEventListener('submit', function(e) {
            e.preventDefault();
            
            const formData = new FormData(e.target);
            const userData = {
                username: formData.get('username'),
                email: formData.get('email'),
                access_level: formData.get('accessLevel'),
                license_type: formData.get('licenseType')
            };
            
            // Add duration only if not Admin
            if (userData.access_level !== 'Admin') {
                userData.duration = parseInt(formData.get('duration'));
            }
            
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
            .then(response => response.json())
            .then(data => {
                if (data.error) {
                    alert('Erro: ' + data.error);
                } else {
                    alert(isEditing ? 'Usuário editado com sucesso!' : 'Usuário criado com sucesso!');
                    closeUserModal();
                    // Atualizar dados imediatamente
                    loadUsers();
                    loadStats();
                    // Forçar atualização após um pequeno delay para garantir que o backend processou
                    setTimeout(() => {
                        loadUsers();
                        loadStats();
                    }, 1000);
                }
            })
            .catch(error => {
                console.error('Erro:', error);
                alert('Erro ao salvar usuário');
            });
        });
        
        function toggleUserStatus(userId, currentStatus) {
            const action = currentStatus ? 'desativar' : 'ativar';
            if (confirm(`Tem certeza que deseja ${action} este usuário?`)) {
                fetch(`/api/users/${userId}/status`, {
                    method: 'PUT',
                    headers: {
                        'Content-Type': 'application/json',
                    },
                    body: JSON.stringify({ is_active: !currentStatus })
                })
                .then(response => response.json())
                .then(data => {
                    if (data.error) {
                        alert('Erro: ' + data.error);
                    } else {
                        // Atualizar dados imediatamente
                        loadUsers();
                        loadStats();
                        // Forçar atualização após delay
                        setTimeout(() => {
                            loadUsers();
                            loadStats();
                        }, 1000);
                    }
                })
                .catch(error => {
                    console.error('Erro:', error);
                    alert('Erro ao alterar status');
                });
            }
        }
        
        function removeHardware(userId) {
            if (confirm('Tem certeza que deseja remover o hardware ID deste usuário? Isso permitirá que ele use o software em outro computador.')) {
                fetch(`/api/hardware/remove/${userId}`, {
                    method: 'POST',
                    headers: {
                        'Content-Type': 'application/json',
                    }
                })
                .then(response => response.json())
                .then(data => {
                    if (data.error) {
                        alert('Erro: ' + data.error);
                    } else {
                        alert('Hardware ID removido com sucesso!');
                        // Atualizar dados imediatamente
                        loadUsers();
                        loadStats();
                        // Forçar atualização após delay
                        setTimeout(() => {
                            loadUsers();
                            loadStats();
                        }, 1000);
                    }
                })
                .catch(error => {
                    console.error('Erro:', error);
                    alert('Erro ao remover hardware ID');
                });
            }
        }
        
        function deleteUser(userId, username) {
            if (confirm(`Tem certeza que deseja excluir o usuário "${username}"? Esta ação não pode ser desfeita.`)) {
                fetch(`/api/users/${userId}`, {
                    method: 'DELETE'
                })
                .then(response => response.json())
                .then(data => {
                    if (data.error) {
                        alert('Erro: ' + data.error);
                    } else {
                        alert('Usuário excluído com sucesso!');
                        loadUsers();
                        loadStats();
                    }
                })
                .catch(error => {
                    console.error('Erro:', error);
                    alert('Erro ao excluir usuário');
                });
            }
        }
        
        // Staff Management
        function loadStaff() {
            fetch('/api/staff')
                .then(response => response.json())
                .then(data => {
                    staffData = data;
                    renderStaff(data);
                })
                .catch(error => console.error('Erro ao carregar staff:', error));
        }
        
        function renderStaff(staff) {
            const tbody = document.getElementById('staffTableBody');
            if (!staff || staff.length === 0) {
                tbody.innerHTML = '<tr><td colspan="7" style="text-align: center; color: #666;">Nenhum staff encontrado</td></tr>';
                return;
            }
            
            tbody.innerHTML = staff.map(member => {
                const statusClass = member.is_active ? 'status-active' : 'status-inactive';
                const statusText = member.is_active ? 'Ativo' : 'Inativo';
                
                return `
                    <tr>
                        <td><strong>${member.username}</strong></td>
                        <td>${member.email}</td>
                        <td><span class="hardware-id">${member.staff_type}</span></td>
                        <td>${new Date(member.created_at).toLocaleDateString('pt-BR')}</td>
                        <td><span class="${statusClass}">${statusText}</span></td>
                        <td>${member.created_users || 0}</td>
                        <td>
                            <button class="btn btn-sm btn-info" onclick="openStaffModal(${member.id})" title="Editar staff">✏️ Editar</button>
                            <button class="btn btn-sm ${member.is_active ? 'btn-warning' : 'btn-success'}" 
                                    onclick="toggleStaffStatus(${member.id}, ${member.is_active})"
                                    title="${member.is_active ? 'Desativar staff' : 'Ativar staff'}">
                                ${member.is_active ? '⏸️ Desativar' : '▶️ Ativar'}
                            </button>
                            <button class="btn btn-sm btn-danger" onclick="deleteStaff(${member.id}, '${member.username}')" title="Excluir staff">🗑️ Excluir</button>
                        </td>
                    </tr>
                `;
            }).join('');
        }
        
        function filterStaff() {
            const search = document.getElementById('staffSearch').value.toLowerCase();
            const typeFilter = document.getElementById('staffTypeFilter').value;
            
            let filtered = staffData.filter(member => {
                const matchesSearch = member.username.toLowerCase().includes(search) || 
                                    member.email.toLowerCase().includes(search);
                const matchesType = !typeFilter || member.staff_type === typeFilter;
                
                return matchesSearch && matchesType;
            });
            
            renderStaff(filtered);
        }
        
        function openStaffModal(staffId = null) {
            editingStaffId = staffId;
            const modal = document.getElementById('staffModal');
            const title = document.getElementById('staffModalTitle');
            const submitBtn = document.getElementById('staffSubmitBtn');
            
            if (staffId) {
                title.textContent = 'Editar Staff';
                submitBtn.textContent = 'Salvar Alterações';
                loadStaffForEdit(staffId);
            } else {
                title.textContent = 'Criar Novo Staff';
                submitBtn.textContent = 'Criar Staff';
                document.getElementById('staffForm').reset();
            }
            
            modal.style.display = 'block';
        }
        
        function closeStaffModal() {
            document.getElementById('staffModal').style.display = 'none';
            document.getElementById('staffForm').reset();
            editingStaffId = null;
        }
        
        function loadStaffForEdit(staffId) {
            const member = staffData.find(s => s.id === staffId);
            if (member) {
                document.getElementById('staffId').value = member.id;
                document.getElementById('staffUsername').value = member.username;
                document.getElementById('staffEmail').value = member.email;
                document.getElementById('staffType').value = member.staff_type;
                document.getElementById('staffPassword').required = false;
            }
        }
        
        document.getElementById('staffForm').addEventListener('submit', function(e) {
            e.preventDefault();
            
            const formData = new FormData(e.target);
            const staffData = {
                username: formData.get('username'),
                email: formData.get('email'),
                staff_type: formData.get('staffType'),
                password: formData.get('password')
            };
            
            const isEditing = editingStaffId !== null;
            const url = isEditing ? `/api/staff/${editingStaffId}` : '/api/staff';
            const method = isEditing ? 'PUT' : 'POST';
            
            fetch(url, {
                method: method,
                headers: {
                    'Content-Type': 'application/json',
                },
                body: JSON.stringify(staffData)
            })
            .then(response => response.json())
            .then(data => {
                if (data.error) {
                    alert('Erro: ' + data.error);
                } else {
                    alert(isEditing ? 'Staff editado com sucesso!' : 'Staff criado com sucesso!');
                    closeStaffModal();
                    loadStaff();
                    loadStats();
                }
            })
            .catch(error => {
                console.error('Erro:', error);
                alert('Erro ao salvar staff');
            });
        });
        
        function toggleStaffStatus(staffId, currentStatus) {
            const action = currentStatus ? 'desativar' : 'ativar';
            if (confirm(`Tem certeza que deseja ${action} este staff?`)) {
                fetch(`/api/staff/${staffId}/status`, {
                    method: 'PUT',
                    headers: {
                        'Content-Type': 'application/json',
                    },
                    body: JSON.stringify({ is_active: !currentStatus })
                })
                .then(response => response.json())
                .then(data => {
                    if (data.error) {
                        alert('Erro: ' + data.error);
                    } else {
                        loadStaff();
                        loadStats();
                    }
                })
                .catch(error => {
                    console.error('Erro:', error);
                    alert('Erro ao alterar status');
                });
            }
        }
        
        function deleteStaff(staffId, username) {
            if (confirm(`Tem certeza que deseja excluir o staff "${username}"? Esta ação não pode ser desfeita.`)) {
                fetch(`/api/staff/${staffId}`, {
                    method: 'DELETE'
                })
                .then(response => response.json())
                .then(data => {
                    if (data.error) {
                        alert('Erro: ' + data.error);
                    } else {
                        alert('Staff excluído com sucesso!');
                        loadStaff();
                        loadStats();
                    }
                })
                .catch(error => {
                    console.error('Erro:', error);
                    alert('Erro ao excluir staff');
                });
            }
        }
        
        // Logs
        function loadLogs() {
            fetch('/api/logs?per_page=100')
                .then(response => response.json())
                .then(data => {
                    logsData = data;
                    renderLogs(data);
                })
                .catch(error => console.error('Erro ao carregar logs:', error));
        }
        
        function renderLogs(logs) {
            const tbody = document.getElementById('logsTableBody');
            if (!logs || logs.length === 0) {
                tbody.innerHTML = '<tr><td colspan="6" style="text-align: center; color: #666;">Nenhum log encontrado</td></tr>';
                return;
            }
            
            tbody.innerHTML = logs.map(log => {
                const actionColor = getActionColor(log.action);
                const hardwareDisplay = log.hardware_id ? 
                    `<div class="hardware-id">${log.hardware_id.substring(0, 12)}...</div>` : 
                    '<span style="color: #999;">-</span>';
                
                return `
                    <tr>
                        <td>${new Date(log.timestamp).toLocaleString('pt-BR')}</td>
                        <td><strong>${log.username}</strong></td>
                        <td><span style="color: ${actionColor};">${log.action}</span></td>
                        <td>${log.ip_address || '-'}</td>
                        <td>${hardwareDisplay}</td>
                        <td>${log.details || '-'}</td>
                    </tr>
                `;
            }).join('');
        }
        
        function getActionColor(action) {
            if (action.includes('login')) return '#28a745';
            if (action.includes('logout')) return '#6c757d';
            if (action.includes('criado') || action.includes('created')) return '#007bff';
            if (action.includes('editado') || action.includes('updated')) return '#ffc107';
            if (action.includes('excluído') || action.includes('deleted')) return '#dc3545';
            return '#333';
        }
        
        function filterLogs() {
            const search = document.getElementById('logSearch').value.toLowerCase();
            const dateFilter = document.getElementById('logDateFilter').value;
            const actionFilter = document.getElementById('logActionFilter').value;
            
            let filtered = logsData.filter(log => {
                const matchesSearch = log.username.toLowerCase().includes(search) || 
                                    log.action.toLowerCase().includes(search) ||
                                    (log.details && log.details.toLowerCase().includes(search));
                
                const matchesDate = !dateFilter || log.timestamp.startsWith(dateFilter);
                const matchesAction = !actionFilter || log.action.toLowerCase().includes(actionFilter);
                
                return matchesSearch && matchesDate && matchesAction;
            });
            
            renderLogs(filtered);
        }
        
        function exportLogs() {
            const csv = [
                ['Data/Hora', 'Usuário', 'Ação', 'IP', 'Hardware', 'Detalhes'],
                ...logsData.map(log => [
                    new Date(log.timestamp).toLocaleString('pt-BR'),
                    log.username,
                    log.action,
                    log.ip_address || '',
                    log.hardware_id || '',
                    log.details || ''
                ])
            ].map(row => row.join(',')).join('\\n');
            
            const blob = new Blob([csv], { type: 'text/csv' });
            const url = window.URL.createObjectURL(blob);
            const a = document.createElement('a');
            a.href = url;
            a.download = `logs_${new Date().toISOString().split('T')[0]}.csv`;
            a.click();
        }
        
        function clearOldLogs() {
            if (confirm('Tem certeza que deseja limpar logs antigos (mais de 30 dias)? Esta ação não pode ser desfeita.')) {
                fetch('/api/logs/cleanup', {
                    method: 'POST'
                })
                .then(response => response.json())
                .then(data => {
                    if (data.error) {
                        alert('Erro: ' + data.error);
                    } else {
                        alert(`${data.deleted_count} logs antigos foram removidos.`);
                        loadLogs();
                    }
                })
                .catch(error => {
                    console.error('Erro:', error);
                    alert('Erro ao limpar logs');
                });
            }
        }
        
        // Backup
        function loadBackups() {
            fetch('/api/backup/list')
                .then(response => response.json())
                .then(data => {
                    renderBackups(data.backups || []);
                })
                .catch(error => console.error('Erro ao carregar backups:', error));
        }
        
        function renderBackups(backups) {
            const container = document.getElementById('backupList');
            if (!backups || backups.length === 0) {
                container.innerHTML = '<p style="text-align: center; color: #666; padding: 20px;">Nenhum backup encontrado</p>';
                return;
            }
            
            container.innerHTML = backups.map(backup => `
                <div class="backup-item">
                    <div class="backup-info">
                        <div class="backup-name">${backup.name}</div>
                        <div class="backup-details">
                            📅 ${new Date(backup.created_at).toLocaleString('pt-BR')} | 
                            📊 ${(backup.size / 1024).toFixed(1)} KB
                        </div>
                    </div>
                    <div class="backup-actions-btn">
                        <button class="btn btn-sm btn-info" onclick="downloadBackup('${backup.name}')">📥 Download</button>
                        <button class="btn btn-sm btn-warning" onclick="restoreBackup('${backup.name}')">🔄 Restaurar</button>
                        <button class="btn btn-sm btn-danger" onclick="deleteBackup('${backup.name}')">🗑️ Excluir</button>
                    </div>
                </div>
            `).join('');
        }
        
        function createBackup() {
            if (confirm('Criar um novo backup do banco de dados?')) {
                fetch('/api/backup/create', {
                    method: 'POST'
                })
                .then(response => response.json())
                .then(data => {
                    if (data.error) {
                        alert('Erro: ' + data.error);
                    } else {
                        alert('Backup criado com sucesso!');
                        loadBackups();
                    }
                })
                .catch(error => {
                    console.error('Erro:', error);
                    alert('Erro ao criar backup');
                });
            }
        }
        
        function downloadBackup(filename) {
            window.open(`/api/backup/download/${filename}`, '_blank');
        }
        
        function restoreBackup(filename) {
            if (confirm(`Tem certeza que deseja restaurar o backup "${filename}"? O banco atual será substituído e um backup automático será criado.`)) {
                fetch('/api/backup/restore', {
                    method: 'POST',
                    headers: {
                        'Content-Type': 'application/json',
                    },
                    body: JSON.stringify({ filename: filename })
                })
                .then(response => response.json())
                .then(data => {
                    if (data.error) {
                        alert('Erro: ' + data.error);
                    } else {
                        alert('Backup restaurado com sucesso! A página será recarregada.');
                        location.reload();
                    }
                })
                .catch(error => {
                    console.error('Erro:', error);
                    alert('Erro ao restaurar backup');
                });
            }
        }
        
        function deleteBackup(filename) {
            if (confirm(`Tem certeza que deseja excluir o backup "${filename}"? Esta ação não pode ser desfeita.`)) {
                fetch(`/api/backup/delete/${filename}`, {
                    method: 'DELETE'
                })
                .then(response => response.json())
                .then(data => {
                    if (data.error) {
                        alert('Erro: ' + data.error);
                    } else {
                        alert('Backup excluído com sucesso!');
                        loadBackups();
                    }
                })
                .catch(error => {
                    console.error('Erro:', error);
                    alert('Erro ao excluir backup');
                });
            }
        }
        
        function refreshBackups() {
            loadBackups();
        }
        
        function uploadBackup() {
            const fileInput = document.getElementById('backupFile');
            const file = fileInput.files[0];
            
            if (!file) return;
            
            if (!file.name.endsWith('.db')) {
                alert('Por favor, selecione um arquivo .db válido');
                return;
            }
            
            if (confirm(`Tem certeza que deseja restaurar o backup "${file.name}"? O banco atual será substituído.`)) {
                const formData = new FormData();
                formData.append('backup', file);
                
                fetch('/api/backup/upload', {
                    method: 'POST',
                    body: formData
                })
                .then(response => response.json())
                .then(data => {
                    if (data.error) {
                        alert('Erro: ' + data.error);
                    } else {
                        alert('Backup restaurado com sucesso! A página será recarregada.');
                        location.reload();
                    }
                })
                .catch(error => {
                    console.error('Erro:', error);
                    alert('Erro ao fazer upload do backup');
                });
            }
            
            fileInput.value = '';
        }
        
        // Drag and drop for backup upload
        const uploadArea = document.getElementById('uploadArea');
        
        uploadArea.addEventListener('dragover', function(e) {
            e.preventDefault();
            uploadArea.classList.add('dragover');
        });
        
        uploadArea.addEventListener('dragleave', function(e) {
            e.preventDefault();
            uploadArea.classList.remove('dragover');
        });
        
        uploadArea.addEventListener('drop', function(e) {
            e.preventDefault();
            uploadArea.classList.remove('dragover');
            
            const files = e.dataTransfer.files;
            if (files.length > 0) {
                const file = files[0];
                if (file.name.endsWith('.db')) {
                    document.getElementById('backupFile').files = files;
                    uploadBackup();
                } else {
                    alert('Por favor, arraste apenas arquivos .db');
                }
            }
        });
        
        // Settings
        document.getElementById('changePasswordForm').addEventListener('submit', function(e) {
            e.preventDefault();
            
            const currentPassword = document.getElementById('currentPassword').value;
            const newPassword = document.getElementById('newPassword').value;
            const confirmPassword = document.getElementById('confirmPassword').value;
            
            if (newPassword !== confirmPassword) {
                alert('As senhas não coincidem');
                return;
            }
            
            if (newPassword.length < 8) {
                alert('A nova senha deve ter pelo menos 8 caracteres');
                return;
            }
            
            fetch('/api/admin/change-password', {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/json',
                },
                body: JSON.stringify({
                    current_password: currentPassword,
                    new_password: newPassword
                })
            })
            .then(response => response.json())
            .then(data => {
                if (data.error) {
                    alert('Erro: ' + data.error);
                } else {
                    alert('Senha alterada com sucesso!');
                    document.getElementById('changePasswordForm').reset();
                }
            })
            .catch(error => {
                console.error('Erro:', error);
                alert('Erro ao alterar senha');
            });
        });
        
        // Inicializar página
        document.addEventListener('DOMContentLoaded', function() {
            // Verificar se há sessão salva
            if (!checkSavedSession()) {
                // Se não há sessão, mostrar página de login
                document.getElementById('loginPage').style.display = 'flex';
                document.getElementById('dashboardPage').style.display = 'none';
            }
        });
        
        // Atualização automática a cada 30 segundos (apenas se logado)
        setInterval(function() {
            if (currentUser && document.getElementById('dashboardPage').style.display !== 'none') {
                loadStats();
                // Recarregar dados da aba ativa
                const activeTab = document.querySelector('.tab-content.active');
                if (activeTab) {
                    const tabId = activeTab.id;
                    if (tabId === 'users') {
                        loadUsers();
                    } else if (tabId === 'staff') {
                        loadStaff();
                    } else if (tabId === 'logs') {
                        loadLogs();
                    }
                }
            }
        }, 30000);
    </script>
</body>
</html>
    '''
    return html

# APIs

@app.route('/api/admin/login', methods=['POST'])
def admin_login():
    """Login do admin"""
    try:
        data = request.get_json()
        username = data.get('username')
        password = data.get('password')
        
        if not username or not password:
            return jsonify({'error': 'Username e senha são obrigatórios'}), 400
        
        # Verificar credenciais do admin
        if username == ADMIN_USERNAME and password == ADMIN_PASSWORD:
            # Log do login
            conn = sqlite3.connect(DATABASE)
            cursor = conn.cursor()
            cursor.execute("""
                INSERT INTO access_logs (username, action, ip_address, details)
                VALUES (?, ?, ?, ?)
            """, (username, 'admin login', request.remote_addr, 'Dashboard administrativo'))
            conn.commit()
            conn.close()
            
            return jsonify({
                'success': True,
                'username': username,
                'message': 'Login realizado com sucesso'
            })
        else:
            return jsonify({'error': 'Credenciais inválidas'}), 401
            
    except Exception as e:
        return jsonify({'error': f'Erro interno: {str(e)}'}), 500

@app.route('/api/admin/change-password', methods=['POST'])
def change_admin_password():
    """Trocar senha do admin"""
    try:
        data = request.get_json()
        current_password = data.get('current_password')
        new_password = data.get('new_password')
        
        if not current_password or not new_password:
            return jsonify({'error': 'Senha atual e nova senha são obrigatórias'}), 400
        
        if current_password != ADMIN_PASSWORD:
            return jsonify({'error': 'Senha atual incorreta'}), 401
        
        if len(new_password) < 8:
            return jsonify({'error': 'Nova senha deve ter pelo menos 8 caracteres'}), 400
        
        # Atualizar senha no banco
        conn = sqlite3.connect(DATABASE)
        cursor = conn.cursor()
        new_hash = hash_password(new_password)
        cursor.execute("""
            UPDATE users SET password_hash = ? WHERE username = ?
        """, (new_hash, ADMIN_USERNAME))
        
        # Log da alteração
        cursor.execute("""
            INSERT INTO access_logs (username, action, ip_address, details)
            VALUES (?, ?, ?, ?)
        """, (ADMIN_USERNAME, 'password changed', request.remote_addr, 'Senha alterada via dashboard'))
        
        conn.commit()
        conn.close()
        
        # Nota: A senha foi atualizada no banco de dados
        # Para esta sessão, a variável global permanece inalterada
        
        return jsonify({'message': 'Senha alterada com sucesso'})
        
    except Exception as e:
        return jsonify({'error': f'Erro interno: {str(e)}'}), 500

@app.route('/api/stats')
def get_stats():
    """Estatísticas do sistema"""
    try:
        conn = sqlite3.connect(DATABASE)
        cursor = conn.cursor()
        
        # Total de usuários
        cursor.execute("SELECT COUNT(*) FROM users WHERE user_type != 'Admin'")
        total_users = cursor.fetchone()[0]
        
        # Usuários ativos (não expirados)
        cursor.execute("""
            SELECT COUNT(*) FROM users 
            WHERE (expires_at > datetime('now') OR expires_at IS NULL) 
            AND is_active = 1 AND user_type != 'Admin'
        """)
        active_users = cursor.fetchone()[0]
        
        # Logins hoje (horário Brasil)
        brazil_today = get_brazil_time().strftime('%Y-%m-%d')
        cursor.execute("""
            SELECT COUNT(*) FROM access_logs 
            WHERE date(timestamp) = ? AND action LIKE '%login%'
        """, (brazil_today,))
        today_logins = cursor.fetchone()[0]
        
        # Licenças ativas
        cursor.execute("""
            SELECT COUNT(*) FROM users 
            WHERE (expires_at > datetime('now') OR expires_at IS NULL) 
            AND is_active = 1 AND user_type != 'Admin'
        """)
        active_licenses = cursor.fetchone()[0]
        
        # Expirando em 7 dias
        cursor.execute("""
            SELECT COUNT(*) FROM users 
            WHERE expires_at BETWEEN datetime('now') AND datetime('now', '+7 days')
            AND is_active = 1 AND user_type != 'Admin'
        """)
        expiring_soon = cursor.fetchone()[0]
        
        # Total de staff
        cursor.execute("SELECT COUNT(*) FROM staff WHERE is_active = 1")
        total_staff = cursor.fetchone()[0]
        
        conn.close()
        
        return jsonify({
            'total_users': total_users,
            'active_users': active_users,
            'today_logins': today_logins,
            'active_licenses': active_licenses,
            'expiring_soon': expiring_soon,
            'total_staff': total_staff
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
            SELECT id, username, email, created_at, expires_at, license_type, 
                   access_level, user_type, is_active, last_login, hardware_id, created_by
            FROM users
            WHERE user_type != 'Admin'
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
                'access_level': row[6],
                'user_type': row[7],
                'is_active': row[8],
                'last_login': row[9],
                'hardware_id': row[10],
                'created_by': row[11]
            })
        
        conn.close()
        return jsonify(users)
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/api/users/<int:user_id>', methods=['GET'])
def get_user(user_id):
    """Obter dados de um usuário específico"""
    try:
        conn = sqlite3.connect(DATABASE)
        cursor = conn.cursor()
        
        cursor.execute("""
            SELECT id, username, email, created_at, expires_at, license_type, 
                   access_level, user_type, is_active, last_login, hardware_id
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
            'access_level': row[6],
            'user_type': row[7],
            'is_active': row[8],
            'last_login': row[9],
            'hardware_id': row[10]
        }
        
        conn.close()
        return jsonify(user)
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
        access_level = data.get('access_level', 'Básico')
        license_type = data.get('license_type', 'Trial')
        duration = data.get('duration', 30)
        
        # Validações básicas
        if len(username) < 3:
            return jsonify({'error': 'Username deve ter pelo menos 3 caracteres'}), 400
        
        if len(password) < 6:
            return jsonify({'error': 'Senha deve ter pelo menos 6 caracteres'}), 400
        
        if '@' not in email:
            return jsonify({'error': 'Email inválido'}), 400
        
        # Calcular data de expiração (horário Brasil)
        expires_at = None
        if access_level != 'Admin' and license_type != 'Vitalícia' and duration > 0:
            expires_at = (get_brazil_time() + datetime.timedelta(days=duration)).isoformat()
        
        conn = sqlite3.connect(DATABASE)
        cursor = conn.cursor()
        
        # Verificar se usuário já existe
        cursor.execute("SELECT id FROM users WHERE username = ? OR email = ?", (username, email))
        if cursor.fetchone():
            conn.close()
            return jsonify({'error': 'Usuário ou email já existe'}), 400
        
        # Definir tipo de usuário
        user_type = 'Admin' if access_level == 'Admin' else 'Cliente'
        
        # Criar usuário
        password_hash = hash_password(password)
        cursor.execute("""
            INSERT INTO users (username, email, password_hash, expires_at, license_type, 
                             access_level, user_type, created_by)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?)
        """, (username, email, password_hash, expires_at, license_type, access_level, user_type, 'admin'))
        
        user_id = cursor.lastrowid
        
        # Log da criação
        cursor.execute("""
            INSERT INTO access_logs (username, action, ip_address, details)
            VALUES (?, ?, ?, ?)
        """, ('admin', 'user created', request.remote_addr, f'Usuário {username} criado'))
        
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
    try:
        data = request.get_json()
        
        # Validar dados obrigatórios
        if not data or not all(k in data for k in ('username', 'email')):
            return jsonify({'error': 'Dados obrigatórios: username, email'}), 400
        
        username = data['username'].strip()
        email = data['email'].strip()
        password = data.get('password', '').strip()
        access_level = data.get('access_level', 'Básico')
        license_type = data.get('license_type', 'Trial')
        duration = data.get('duration', 30)
        
        # Validações básicas
        if len(username) < 3:
            return jsonify({'error': 'Username deve ter pelo menos 3 caracteres'}), 400
        
        if password and len(password) < 6:
            return jsonify({'error': 'Senha deve ter pelo menos 6 caracteres'}), 400
        
        if '@' not in email:
            return jsonify({'error': 'Email inválido'}), 400
        
        # Calcular data de expiração (horário Brasil)
        expires_at = None
        if access_level != 'Admin' and license_type != 'Vitalícia' and duration > 0:
            expires_at = (get_brazil_time() + datetime.timedelta(days=duration)).isoformat()
        
        conn = sqlite3.connect(DATABASE)
        cursor = conn.cursor()
        
        # Verificar se usuário existe
        cursor.execute("SELECT username FROM users WHERE id = ?", (user_id,))
        old_user = cursor.fetchone()
        if not old_user:
            conn.close()
            return jsonify({'error': 'Usuário não encontrado'}), 404
        
        # Verificar se username/email já existe em outro usuário
        cursor.execute("SELECT id FROM users WHERE (username = ? OR email = ?) AND id != ?", (username, email, user_id))
        if cursor.fetchone():
            conn.close()
            return jsonify({'error': 'Usuário ou email já existe'}), 400
        
        # Definir tipo de usuário
        user_type = 'Admin' if access_level == 'Admin' else 'Cliente'
        
        # Atualizar usuário
        if password:
            # Atualizar com nova senha
            password_hash = hash_password(password)
            cursor.execute("""
                UPDATE users 
                SET username = ?, email = ?, password_hash = ?, expires_at = ?, 
                    license_type = ?, access_level = ?, user_type = ?
                WHERE id = ?
            """, (username, email, password_hash, expires_at, license_type, access_level, user_type, user_id))
        else:
            # Atualizar sem alterar senha
            cursor.execute("""
                UPDATE users 
                SET username = ?, email = ?, expires_at = ?, license_type = ?, 
                    access_level = ?, user_type = ?
                WHERE id = ?
            """, (username, email, expires_at, license_type, access_level, user_type, user_id))
        
        # Log da edição
        cursor.execute("""
            INSERT INTO access_logs (username, action, ip_address, details)
            VALUES (?, ?, ?, ?)
        """, ('admin', 'user updated', request.remote_addr, f'Usuário {old_user[0]} editado para {username}'))
        
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
        action = 'user activated' if is_active else 'user deactivated'
        cursor.execute("""
            INSERT INTO access_logs (username, action, ip_address, details)
            VALUES (?, ?, ?, ?)
        """, ('admin', action, request.remote_addr, f'Usuário {user[0]} {action}'))
        
        conn.commit()
        conn.close()
        
        return jsonify({
            'message': f'Usuário {"ativado" if is_active else "desativado"} com sucesso',
            'is_active': is_active
        })
        
    except Exception as e:
        return jsonify({'error': f'Erro interno: {str(e)}'}), 500

@app.route('/api/users/<int:user_id>', methods=['DELETE'])
def delete_user(user_id):
    """Excluir usuário"""
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
            INSERT INTO access_logs (username, action, ip_address, details)
            VALUES (?, ?, ?, ?)
        """, ('admin', 'user deleted', request.remote_addr, f'Usuário {user[0]} excluído'))
        
        conn.commit()
        conn.close()
        
        return jsonify({'message': 'Usuário excluído com sucesso'})
        
    except Exception as e:
        return jsonify({'error': f'Erro interno: {str(e)}'}), 500

@app.route('/api/hardware/remove/<int:user_id>', methods=['POST'])
def remove_hardware(user_id):
    """Remover hardware ID de um usuário"""
    try:
        conn = sqlite3.connect(DATABASE)
        cursor = conn.cursor()
        
        # Verificar se usuário existe
        cursor.execute("SELECT username, hardware_id FROM users WHERE id = ?", (user_id,))
        user = cursor.fetchone()
        if not user:
            conn.close()
            return jsonify({'error': 'Usuário não encontrado'}), 404
        
        if not user[1]:
            conn.close()
            return jsonify({'error': 'Usuário não possui hardware vinculado'}), 400
        
        # Remover hardware ID
        cursor.execute("UPDATE users SET hardware_id = NULL WHERE id = ?", (user_id,))
        
        # Log da ação
        cursor.execute("""
            INSERT INTO access_logs (username, action, ip_address, details)
            VALUES (?, ?, ?, ?)
        """, ('admin', 'hardware removed', request.remote_addr, f'Hardware removido do usuário {user[0]}'))
        
        conn.commit()
        conn.close()
        
        return jsonify({'message': 'Hardware ID removido com sucesso'})
        
    except Exception as e:
        return jsonify({'error': f'Erro interno: {str(e)}'}), 500

# Staff APIs

@app.route('/api/staff', methods=['GET'])
def get_staff():
    """Listar staff"""
    try:
        conn = sqlite3.connect(DATABASE)
        cursor = conn.cursor()
        
        cursor.execute("""
            SELECT s.id, s.username, s.email, s.staff_type, s.created_at, s.is_active, s.created_by,
                   COUNT(u.id) as created_users
            FROM staff s
            LEFT JOIN users u ON u.created_by = s.username
            GROUP BY s.id, s.username, s.email, s.staff_type, s.created_at, s.is_active, s.created_by
            ORDER BY s.created_at DESC
        """)
        
        staff = []
        for row in cursor.fetchall():
            staff.append({
                'id': row[0],
                'username': row[1],
                'email': row[2],
                'staff_type': row[3],
                'created_at': row[4],
                'is_active': row[5],
                'created_by': row[6],
                'created_users': row[7]
            })
        
        conn.close()
        return jsonify(staff)
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/api/staff', methods=['POST'])
def create_staff():
    """Criar novo staff"""
    try:
        data = request.get_json()
        
        # Validar dados obrigatórios
        if not data or not all(k in data for k in ('username', 'email', 'password', 'staff_type')):
            return jsonify({'error': 'Dados obrigatórios: username, email, password, staff_type'}), 400
        
        username = data['username'].strip()
        email = data['email'].strip()
        password = data['password']
        staff_type = data['staff_type']
        
        # Validações básicas
        if len(username) < 3:
            return jsonify({'error': 'Username deve ter pelo menos 3 caracteres'}), 400
        
        if len(password) < 6:
            return jsonify({'error': 'Senha deve ter pelo menos 6 caracteres'}), 400
        
        if '@' not in email:
            return jsonify({'error': 'Email inválido'}), 400
        
        if staff_type not in ['Vendedor', 'Técnico']:
            return jsonify({'error': 'Tipo de staff deve ser Vendedor ou Técnico'}), 400
        
        conn = sqlite3.connect(DATABASE)
        cursor = conn.cursor()
        
        # Verificar se staff já existe
        cursor.execute("SELECT id FROM staff WHERE username = ? OR email = ?", (username, email))
        if cursor.fetchone():
            conn.close()
            return jsonify({'error': 'Usuário ou email já existe'}), 400
        
        # Criar staff
        password_hash = hash_password(password)
        cursor.execute("""
            INSERT INTO staff (username, email, password_hash, staff_type, created_by)
            VALUES (?, ?, ?, ?, ?)
        """, (username, email, password_hash, staff_type, 'admin'))
        
        staff_id = cursor.lastrowid
        
        # Log da criação
        cursor.execute("""
            INSERT INTO access_logs (username, action, ip_address, details)
            VALUES (?, ?, ?, ?)
        """, ('admin', 'staff created', request.remote_addr, f'Staff {username} ({staff_type}) criado'))
        
        conn.commit()
        conn.close()
        
        return jsonify({
            'id': staff_id,
            'username': username,
            'email': email,
            'staff_type': staff_type,
            'message': 'Staff criado com sucesso'
        }), 201
        
    except Exception as e:
        return jsonify({'error': f'Erro interno: {str(e)}'}), 500

@app.route('/api/staff/<int:staff_id>', methods=['PUT'])
def update_staff(staff_id):
    """Editar staff existente"""
    try:
        data = request.get_json()
        
        # Validar dados obrigatórios
        if not data or not all(k in data for k in ('username', 'email', 'staff_type')):
            return jsonify({'error': 'Dados obrigatórios: username, email, staff_type'}), 400
        
        username = data['username'].strip()
        email = data['email'].strip()
        password = data.get('password', '').strip()
        staff_type = data['staff_type']
        
        # Validações básicas
        if len(username) < 3:
            return jsonify({'error': 'Username deve ter pelo menos 3 caracteres'}), 400
        
        if password and len(password) < 6:
            return jsonify({'error': 'Senha deve ter pelo menos 6 caracteres'}), 400
        
        if '@' not in email:
            return jsonify({'error': 'Email inválido'}), 400
        
        if staff_type not in ['Vendedor', 'Técnico']:
            return jsonify({'error': 'Tipo de staff deve ser Vendedor ou Técnico'}), 400
        
        conn = sqlite3.connect(DATABASE)
        cursor = conn.cursor()
        
        # Verificar se staff existe
        cursor.execute("SELECT username FROM staff WHERE id = ?", (staff_id,))
        old_staff = cursor.fetchone()
        if not old_staff:
            conn.close()
            return jsonify({'error': 'Staff não encontrado'}), 404
        
        # Verificar se username/email já existe em outro staff
        cursor.execute("SELECT id FROM staff WHERE (username = ? OR email = ?) AND id != ?", (username, email, staff_id))
        if cursor.fetchone():
            conn.close()
            return jsonify({'error': 'Usuário ou email já existe'}), 400
        
        # Atualizar staff
        if password:
            # Atualizar com nova senha
            password_hash = hash_password(password)
            cursor.execute("""
                UPDATE staff 
                SET username = ?, email = ?, password_hash = ?, staff_type = ?
                WHERE id = ?
            """, (username, email, password_hash, staff_type, staff_id))
        else:
            # Atualizar sem alterar senha
            cursor.execute("""
                UPDATE staff 
                SET username = ?, email = ?, staff_type = ?
                WHERE id = ?
            """, (username, email, staff_type, staff_id))
        
        # Log da edição
        cursor.execute("""
            INSERT INTO access_logs (username, action, ip_address, details)
            VALUES (?, ?, ?, ?)
        """, ('admin', 'staff updated', request.remote_addr, f'Staff {old_staff[0]} editado para {username}'))
        
        conn.commit()
        conn.close()
        
        return jsonify({
            'id': staff_id,
            'username': username,
            'email': email,
            'staff_type': staff_type,
            'message': 'Staff atualizado com sucesso'
        })
        
    except Exception as e:
        return jsonify({'error': f'Erro interno: {str(e)}'}), 500

@app.route('/api/staff/<int:staff_id>/status', methods=['PUT'])
def update_staff_status(staff_id):
    """Ativar/Desativar staff"""
    try:
        data = request.get_json()
        
        if not data or 'is_active' not in data:
            return jsonify({'error': 'Campo obrigatório: is_active'}), 400
        
        is_active = bool(data['is_active'])
        
        conn = sqlite3.connect(DATABASE)
        cursor = conn.cursor()
        
        # Verificar se staff existe
        cursor.execute("SELECT username FROM staff WHERE id = ?", (staff_id,))
        staff = cursor.fetchone()
        if not staff:
            conn.close()
            return jsonify({'error': 'Staff não encontrado'}), 404
        
        # Atualizar status
        cursor.execute("UPDATE staff SET is_active = ? WHERE id = ?", (is_active, staff_id))
        
        # Log da ação
        action = 'staff activated' if is_active else 'staff deactivated'
        cursor.execute("""
            INSERT INTO access_logs (username, action, ip_address, details)
            VALUES (?, ?, ?, ?)
        """, ('admin', action, request.remote_addr, f'Staff {staff[0]} {action}'))
        
        conn.commit()
        conn.close()
        
        return jsonify({
            'message': f'Staff {"ativado" if is_active else "desativado"} com sucesso',
            'is_active': is_active
        })
        
    except Exception as e:
        return jsonify({'error': f'Erro interno: {str(e)}'}), 500

@app.route('/api/staff/<int:staff_id>', methods=['DELETE'])
def delete_staff(staff_id):
    """Excluir staff"""
    try:
        conn = sqlite3.connect(DATABASE)
        cursor = conn.cursor()
        
        # Verificar se staff existe
        cursor.execute("SELECT username FROM staff WHERE id = ?", (staff_id,))
        staff = cursor.fetchone()
        if not staff:
            conn.close()
            return jsonify({'error': 'Staff não encontrado'}), 404
        
        # Excluir staff
        cursor.execute("DELETE FROM staff WHERE id = ?", (staff_id,))
        
        # Log da ação
        cursor.execute("""
            INSERT INTO access_logs (username, action, ip_address, details)
            VALUES (?, ?, ?, ?)
        """, ('admin', 'staff deleted', request.remote_addr, f'Staff {staff[0]} excluído'))
        
        conn.commit()
        conn.close()
        
        return jsonify({'message': 'Staff excluído com sucesso'})
        
    except Exception as e:
        return jsonify({'error': f'Erro interno: {str(e)}'}), 500

# Logs APIs

@app.route('/api/logs')
def get_logs():
    """Logs de acesso"""
    try:
        per_page = request.args.get('per_page', 100, type=int)
        
        conn = sqlite3.connect(DATABASE)
        cursor = conn.cursor()
        
        cursor.execute("""
            SELECT username, action, timestamp, ip_address, hardware_id, details
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
                'hardware_id': row[4],
                'details': row[5]
            })
        
        conn.close()
        return jsonify(logs)
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/api/logs/cleanup', methods=['POST'])
def cleanup_logs():
    """Limpar logs antigos (mais de 30 dias)"""
    try:
        conn = sqlite3.connect(DATABASE)
        cursor = conn.cursor()
        
        # Contar logs que serão removidos
        cursor.execute("""
            SELECT COUNT(*) FROM access_logs 
            WHERE timestamp < datetime('now', '-30 days')
        """)
        count_to_delete = cursor.fetchone()[0]
        
        # Remover logs antigos
        cursor.execute("""
            DELETE FROM access_logs 
            WHERE timestamp < datetime('now', '-30 days')
        """)
        
        # Log da limpeza
        cursor.execute("""
            INSERT INTO access_logs (username, action, ip_address, details)
            VALUES (?, ?, ?, ?)
        """, ('admin', 'logs cleanup', request.remote_addr, f'{count_to_delete} logs antigos removidos'))
        
        conn.commit()
        conn.close()
        
        return jsonify({
            'message': 'Logs antigos removidos com sucesso',
            'deleted_count': count_to_delete
        })
        
    except Exception as e:
        return jsonify({'error': f'Erro interno: {str(e)}'}), 500

# Backup APIs

@app.route('/api/backup/create', methods=['POST'])
def create_backup():
    """Criar backup do banco de dados"""
    try:
        # Criar diretório de backups se não existir
        backup_dir = 'backups'
        if not os.path.exists(backup_dir):
            os.makedirs(backup_dir)
        
        # Nome do backup com timestamp (horário Brasil)
        timestamp = get_brazil_time().strftime('%Y-%m-%d_%H-%M-%S')
        backup_filename = f'backup_{timestamp}.db'
        backup_path = os.path.join(backup_dir, backup_filename)
        
        # Copiar banco de dados
        shutil.copy2(DATABASE, backup_path)
        
        # Log da criação
        conn = sqlite3.connect(DATABASE)
        cursor = conn.cursor()
        cursor.execute("""
            INSERT INTO access_logs (username, action, ip_address, details)
            VALUES (?, ?, ?, ?)
        """, ('admin', 'backup created', request.remote_addr, f'Backup {backup_filename} criado'))
        conn.commit()
        conn.close()
        
        return jsonify({
            'message': 'Backup criado com sucesso',
            'filename': backup_filename,
            'path': backup_path
        })
        
    except Exception as e:
        return jsonify({'error': f'Erro ao criar backup: {str(e)}'}), 500

@app.route('/api/backup/list')
def list_backups():
    """Listar backups disponíveis"""
    try:
        backup_dir = 'backups'
        if not os.path.exists(backup_dir):
            return jsonify({'backups': []})
        
        backups = []
        for filename in os.listdir(backup_dir):
            if filename.endswith('.db'):
                filepath = os.path.join(backup_dir, filename)
                stat = os.stat(filepath)
                backups.append({
                    'name': filename,
                    'size': stat.st_size,
                    'created_at': datetime.datetime.fromtimestamp(stat.st_mtime).isoformat()
                })
        
        # Ordenar por data de criação (mais recente primeiro)
        backups.sort(key=lambda x: x['created_at'], reverse=True)
        
        return jsonify({'backups': backups})
        
    except Exception as e:
        return jsonify({'error': f'Erro ao listar backups: {str(e)}'}), 500

@app.route('/api/backup/download/<filename>')
def download_backup(filename):
    """Download de backup"""
    try:
        backup_dir = 'backups'
        backup_path = os.path.join(backup_dir, filename)
        
        if not os.path.exists(backup_path) or not filename.endswith('.db'):
            return jsonify({'error': 'Backup não encontrado'}), 404
        
        # Log do download
        conn = sqlite3.connect(DATABASE)
        cursor = conn.cursor()
        cursor.execute("""
            INSERT INTO access_logs (username, action, ip_address, details)
            VALUES (?, ?, ?, ?)
        """, ('admin', 'backup downloaded', request.remote_addr, f'Backup {filename} baixado'))
        conn.commit()
        conn.close()
        
        return send_file(backup_path, as_attachment=True, download_name=filename)
        
    except Exception as e:
        return jsonify({'error': f'Erro ao baixar backup: {str(e)}'}), 500

@app.route('/api/backup/restore', methods=['POST'])
def restore_backup():
    """Restaurar backup"""
    try:
        data = request.get_json()
        filename = data.get('filename')
        
        if not filename:
            return jsonify({'error': 'Nome do arquivo é obrigatório'}), 400
        
        backup_dir = 'backups'
        backup_path = os.path.join(backup_dir, filename)
        
        if not os.path.exists(backup_path) or not filename.endswith('.db'):
            return jsonify({'error': 'Backup não encontrado'}), 404
        
        # Criar backup do banco atual antes de restaurar
        current_backup_name = f'backup_before_restore_{get_brazil_time().strftime("%Y-%m-%d_%H-%M-%S")}.db'
        current_backup_path = os.path.join(backup_dir, current_backup_name)
        shutil.copy2(DATABASE, current_backup_path)
        
        # Restaurar backup
        shutil.copy2(backup_path, DATABASE)
        
        # Log da restauração (no banco restaurado)
        conn = sqlite3.connect(DATABASE)
        cursor = conn.cursor()
        cursor.execute("""
            INSERT INTO access_logs (username, action, ip_address, details)
            VALUES (?, ?, ?, ?)
        """, ('admin', 'backup restored', request.remote_addr, f'Backup {filename} restaurado'))
        conn.commit()
        conn.close()
        
        return jsonify({
            'message': 'Backup restaurado com sucesso',
            'restored_from': filename,
            'current_backup': current_backup_name
        })
        
    except Exception as e:
        return jsonify({'error': f'Erro ao restaurar backup: {str(e)}'}), 500

@app.route('/api/backup/upload', methods=['POST'])
def upload_backup():
    """Upload e restauração de backup"""
    try:
        if 'backup' not in request.files:
            return jsonify({'error': 'Nenhum arquivo enviado'}), 400
        
        file = request.files['backup']
        if file.filename == '':
            return jsonify({'error': 'Nenhum arquivo selecionado'}), 400
        
        if not file.filename.endswith('.db'):
            return jsonify({'error': 'Arquivo deve ter extensão .db'}), 400
        
        # Salvar arquivo temporariamente
        temp_dir = tempfile.gettempdir()
        temp_path = os.path.join(temp_dir, secure_filename(file.filename))
        file.save(temp_path)
        
        try:
            # Verificar se é um banco SQLite válido
            test_conn = sqlite3.connect(temp_path)
            test_conn.execute("SELECT name FROM sqlite_master WHERE type='table';")
            test_conn.close()
        except:
            os.remove(temp_path)
            return jsonify({'error': 'Arquivo não é um banco SQLite válido'}), 400
        
        # Criar backup do banco atual
        backup_dir = 'backups'
        if not os.path.exists(backup_dir):
            os.makedirs(backup_dir)
        
        current_backup_name = f'backup_before_upload_{get_brazil_time().strftime("%Y-%m-%d_%H-%M-%S")}.db'
        current_backup_path = os.path.join(backup_dir, current_backup_name)
        shutil.copy2(DATABASE, current_backup_path)
        
        # Restaurar backup enviado
        shutil.copy2(temp_path, DATABASE)
        os.remove(temp_path)
        
        # Log da restauração
        conn = sqlite3.connect(DATABASE)
        cursor = conn.cursor()
        cursor.execute("""
            INSERT INTO access_logs (username, action, ip_address, details)
            VALUES (?, ?, ?, ?)
        """, ('admin', 'backup uploaded', request.remote_addr, f'Backup {file.filename} enviado e restaurado'))
        conn.commit()
        conn.close()
        
        return jsonify({
            'message': 'Backup enviado e restaurado com sucesso',
            'uploaded_file': file.filename,
            'current_backup': current_backup_name
        })
        
    except Exception as e:
        return jsonify({'error': f'Erro ao enviar backup: {str(e)}'}), 500

@app.route('/api/backup/delete/<filename>', methods=['DELETE'])
def delete_backup(filename):
    """Excluir backup"""
    try:
        backup_dir = 'backups'
        backup_path = os.path.join(backup_dir, filename)
        
        if not os.path.exists(backup_path) or not filename.endswith('.db'):
            return jsonify({'error': 'Backup não encontrado'}), 404
        
        # Remover arquivo
        os.remove(backup_path)
        
        # Log da exclusão
        conn = sqlite3.connect(DATABASE)
        cursor = conn.cursor()
        cursor.execute("""
            INSERT INTO access_logs (username, action, ip_address, details)
            VALUES (?, ?, ?, ?)
        """, ('admin', 'backup deleted', request.remote_addr, f'Backup {filename} excluído'))
        conn.commit()
        conn.close()
        
        return jsonify({'message': 'Backup excluído com sucesso'})
        
    except Exception as e:
        return jsonify({'error': f'Erro ao excluir backup: {str(e)}'}), 500

# API de autenticação original (para o SpiderPrint)

@app.route('/api/auth/login', methods=['POST'])
def login():
    """Autenticação de usuário para o SpiderPrint"""
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
            SELECT id, username, password_hash, expires_at, is_active, access_level, 
                   license_type, user_type, hardware_id
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
        is_admin_special = user[5] == 'Admin' or user[6] == 'Admin' or user[7] == 'Admin'
        
        if not is_admin_special:
            # Verificar expiração (apenas para não-admins)
            if user[3]:  # Se tem data de expiração
                expires_at = datetime.datetime.fromisoformat(user[3])
                if expires_at < get_brazil_time():
                    conn.close()
                    return jsonify({'error': 'Licença expirada'}), 401
            
            # Verificar hardware ID (apenas para não-admins)
            if user[8] and user[8] != hardware_id:
                conn.close()
                return jsonify({'error': 'Hardware não autorizado'}), 401
        
        # Atualizar último login e hardware_id (se não for admin especial)
        if not is_admin_special:
            cursor.execute("""
                UPDATE users 
                SET last_login = ?, hardware_id = ?
                WHERE id = ?
            """, (get_brazil_time().isoformat(), hardware_id, user[0]))
        else:
            cursor.execute("""
                UPDATE users 
                SET last_login = ?
                WHERE id = ?
            """, (get_brazil_time().isoformat(), user[0]))
        
        # Log de acesso
        cursor.execute("""
            INSERT INTO access_logs (username, action, ip_address, hardware_id, details)
            VALUES (?, ?, ?, ?, ?)
        """, (username, 'login', request.remote_addr, hardware_id, 
              f'Login via SpiderPrint - Nível: {user[5]}'))
        
        conn.commit()
        conn.close()
        
        # Determinar nível de acesso
        access_level = user[5] or 'Básico'
        
        return jsonify({
            'success': True,
            'message': 'Login realizado com sucesso',
            'username': username,
            'access_level': access_level,
            'license_type': user[6],
            'expires_at': user[3],
            'is_admin_special': is_admin_special
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
    create_admin_if_not_exists()
    
    print("🕷️ SpiderPrint Enhanced Server iniciado!")
    print(f"📊 Dashboard: http://localhost:5000")
    print(f"👤 Admin: {ADMIN_USERNAME}")
    print(f"🔑 Senha: {ADMIN_PASSWORD}")
    print("🇧🇷 Fuso horário: Brasil (UTC-3)")
    
    # Configuração para produção
    port = int(os.environ.get('PORT', 5000))
    app.run(host='0.0.0.0', port=port, debug=False)

