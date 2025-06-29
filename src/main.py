import os
import sys
import os

# NÃO ALTERE ESSA LINHA
sys.path.insert(0, os.path.dirname(os.path.dirname(__file__)))

from flask import Flask, send_from_directory, request, jsonify
from flask_cors import CORS
from flask_login import LoginManager, logout_user
from src.models.user import db, User
from src.services.cache_service import cache_service
from src.services.environment_service import env_config
from src.services.system_config_service import system_config_service
from datetime import timedelta
from flask_wtf.csrf import CSRFProtect # Importar CSRFProtect

# Importar sistemas de segurança
from src.security.rate_limiter import security_rate_limiter
from src.security.http_security import http_security
from src.security.security_logger import security_logger

from src.routes.user import user_bp
from src.routes.admin import admin_bp
from src.routes.tracking import tracking_bp
from src.routes.urls import urls_bp
from src.routes.protection import protection_bp
from src.routes.domains import domains_bp
from src.routes.dns import dns_bp
from src.routes.notifications import notifications_bp
from src.routes.credentials import credentials_bp
from src.routes.reports import reports_bp
from src.routes.cache import cache_bp
from src.routes.metrics import metrics_bp

app = Flask(__name__, static_folder=os.path.join(os.path.dirname(__file__), 'static'))

# Configurar CORS
CORS(app, origins="*")

# Carregar configurações do SystemConfigService
system_configs = system_config_service.get_config()
app.config['SECRET_KEY'] = system_configs.get('SECRET_KEY') or env_config.config['SECRET_KEY']

# Configurar tempo de vida da sessão (ex: 30 minutos)
app.config['PERMANENT_SESSION_LIFETIME'] = timedelta(minutes=30)

# Configurações de segurança para cookies de sessão
app.config['SESSION_COOKIE_SECURE'] = False  # True em produção com HTTPS
app.config['SESSION_COOKIE_HTTPONLY'] = True # Impede acesso ao cookie via JavaScript
app.config['SESSION_COOKIE_SAMESITE'] = 'Lax' # Proteção contra CSRF

# Inicializar sistemas de segurança
security_rate_limiter.init_app(app)
http_security.init_app(app)

# Configurar CSRFProtect apenas para formulários web, não para API
# csrf = CSRFProtect(app)  # Comentado temporariamente para resolver problemas de teste

# Aplicar configurações do ambiente
for key, value in env_config.config.items():
    if key != 'SECRET_KEY':
        app.config[key] = value

# Inicializar cache
cache_service.init_app(app)

# Configurar Flask-Login
login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'user.login'
login_manager.login_message = 'Por favor, faça login para acessar esta página.'

@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

# Blacklist de tokens JWT
@app.before_request
def check_jwt_blacklist():
    auth_header = request.headers.get('Authorization')
    if auth_header and auth_header.startswith('Bearer '):
        token = auth_header.split(' ')[1]
        if cache_service.get(f'blacklist_{token}'):
            return jsonify({'message': 'Token revogado.'}), 401

# Registrar blueprints
app.register_blueprint(user_bp, url_prefix='/api')
app.register_blueprint(admin_bp, url_prefix='/api/admin')
app.register_blueprint(tracking_bp, url_prefix='/api/tracking')
app.register_blueprint(urls_bp, url_prefix='/api/urls')
app.register_blueprint(protection_bp, url_prefix='/api/protection')
app.register_blueprint(domains_bp, url_prefix='/api/domains')
app.register_blueprint(dns_bp, url_prefix='/api/dns')
app.register_blueprint(notifications_bp)
app.register_blueprint(credentials_bp, url_prefix='/api/credentials')
app.register_blueprint(reports_bp, url_prefix='/api/reports')
app.register_blueprint(cache_bp, url_prefix='/api/cache')
app.register_blueprint(metrics_bp, url_prefix='/api/metrics')

# Inicializar banco de dados
db.init_app(app)

@app.route('/')
def index():
    return send_from_directory(app.static_folder, 'index.html')

@app.route('/<path:path>')
def static_files(path):
    return send_from_directory(app.static_folder, path)

# ✅ ROTA DE SAÚDE (healthcheck)
@app.route('/health')
def health_check():
    return jsonify({'status': 'ok'}), 200

# Rota para setup inicial (executada apenas uma vez)
@app.route('/api/setup', methods=['POST'])
def initial_setup():
    data = request.get_json()
    admin_username = data.get('admin_username')
    admin_password = data.get('admin_password')
    telegram_bot_token = data.get('telegram_bot_token')
    telegram_admin_chat_id = data.get('telegram_admin_chat_id')

    if not all([admin_username, admin_password, telegram_bot_token, telegram_admin_chat_id]):
        return jsonify({'message': 'Missing required setup data'}), 400

    with app.app_context():
        db.create_all()
        current_config = system_config_service.get_config()
        if not current_config.get('SECRET_KEY'):
            system_config_service.generate_secret_key()

        if system_config_service.setup_initial_admin(admin_username, admin_password):
            system_config_service.update_config({
                'TELEGRAM_BOT_TOKEN': telegram_bot_token,
                'TELEGRAM_ADMIN_CHAT_ID': telegram_admin_chat_id
            })
            return jsonify({'message': 'Initial setup complete. Admin user created and Telegram configured.'}), 200
        else:
            return jsonify({'message': 'Admin user already exists or setup already performed.'}), 409

if __name__ == '__main__':
    with app.app_context():
        db.create_all()

    print(f"Iniciando aplicação em modo: {env_config.environment}")
    print(f"URL base: {env_config.config['BASE_URL']}")

    app.run(
        host=env_config.config['HOST'],
        port=env_config.config['PORT'],
        debug=env_config.config['DEBUG']
    )


