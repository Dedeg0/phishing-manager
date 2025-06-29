from flask import Blueprint, request, jsonify, session
from flask_login import login_user, logout_user, login_required, current_user
from werkzeug.security import check_password_hash
from src.models.user import db, User, Log
from src.services.telegram_service import telegram_service
from datetime import datetime
import jwt
import os
from src.services.cache_service import cache_service # Importar cache_service
from markupsafe import escape # Para proteção contra XSS

user_bp = Blueprint("user", __name__)

def log_action(action, details=None, user_id=None):
    """Registra uma ação no sistema de logs"""
    log = Log(
        user_id=user_id or (current_user.id if current_user.is_authenticated else None),
        action=action,
        details=details
    )
    db.session.add(log)
    db.session.commit()

def generate_token(user):
    """Gera um token JWT para o usuário"""
    payload = {
        "user_id": user.id,
        "username": user.username,
        "is_admin": user.is_admin,
        "exp": datetime.utcnow().timestamp() + 3600  # Token expira em 1 hora
    }
    # Usar app.config["SECRET_KEY"] se disponível (para testes), caso contrário, usar variável de ambiente
    from flask import current_app
    secret_key = current_app.config.get("SECRET_KEY", os.environ.get("SECRET_KEY", "asdf#FGSgvasgf$5$WGT"))
    return jwt.encode(payload, secret_key, algorithm="HS256")

def verify_token(token):
    """Verifica e decodifica um token JWT"""
    try:
        payload = jwt.decode(token, os.environ.get("SECRET_KEY", "asdf#FGSgvasgf$5$WGT"), algorithms=["HS256"])
        return payload
    except jwt.ExpiredSignatureError:
        return None
    except jwt.InvalidTokenError:
        return None

@user_bp.route("/login", methods=["POST"])
def login():
    """Endpoint para login de usuários e administradores"""
    try:
        data = request.get_json(silent=True)
        if data is None:
            # Se get_json() retornar None, pode ser que o Content-Type não seja application/json
            # ou o corpo da requisição esteja vazio/malformado.
            # Tentamos ler como form data ou raw data para depuração.
            if request.form:
                data = request.form.to_dict()
            elif request.data:
                # Se houver raw data, mas não JSON, pode ser um problema de Content-Type
                print(f"Login: Raw data present but not JSON: {request.data}")
                return jsonify({"error": "Formato de requisição inválido. Esperado JSON."}), 400
            else:
                return jsonify({"error": "Dados de requisição ausentes ou formato inválido"}), 400
    except Exception as e:
        print(f"Login: Error parsing JSON/data: {e}")
        return jsonify({"error": "Dados de requisição inválidos"}), 400

    username = data.get("username")
    password = data.get("password")
    otp_code = data.get("otp_code")

    if not username or not password:
        return jsonify({"error": "Username e password são obrigatórios"}), 400
    
    # Buscar usuário no banco de dados (protegido contra SQL Injection pelo SQLAlchemy)
    user = User.query.filter_by(username=username).first()
    
    if not user or not user.check_password(password):
        log_action("LOGIN_FAILED", f"Tentativa de login falhada para username: {escape(username)}")
        return jsonify({"error": "Credenciais inválidas"}), 401
    
    # Verificar se o usuário está banido ou inativo
    if user.is_banned:
        log_action("LOGIN_BLOCKED_BANNED", f"Usuário banido tentou fazer login: {escape(username)}", user.id)
        return jsonify({"error": "Conta banida"}), 403
    
    if not user.is_active:
        log_action("LOGIN_BLOCKED_INACTIVE", f"Usuário inativo tentou fazer login: {escape(username)}", user.id)
        return jsonify({"error": "Conta inativa"}), 403
    
    # Verificar se OTP é necessário
    if user.is_otp_required():
        if not otp_code:
            # Gerar e enviar novo código OTP
            otp = user.generate_otp()
            success, error_msg = telegram_service.send_otp(user, otp)
            
            if not success:
                log_action("OTP_SEND_FAILED", f"Falha ao enviar OTP para {escape(username)}: {escape(error_msg)}", user.id)
                return jsonify({"error": f"Falha ao enviar código OTP: {escape(error_msg)}"}), 500
            
            return jsonify({
                "otp_required": True,
                "message": "Código OTP enviado para seu Telegram. Insira o código para continuar."
            }), 200
        else:
            # Verificar código OTP fornecido
            if not user.verify_otp(otp_code):
                log_action("OTP_VERIFICATION_FAILED", f"Código OTP inválido para {escape(username)}", user.id)
                return jsonify({"error": "Código OTP inválido ou expirado"}), 401
    
    # Fazer login do usuário
    login_user(user)
    
    # Gerar token JWT
    token = generate_token(user)
    
    # Registrar login bem-sucedido
    log_action("LOGIN_SUCCESS", f"Login bem-sucedido para: {escape(username)}", user.id)
    
    return jsonify({
        "message": "Login realizado com sucesso",
        "token": token,
        "user": user.to_dict()
    }), 200

@user_bp.route("/logout", methods=["POST"])
@login_required
def logout():
    """Endpoint para logout"""
    username = current_user.username
    user_id = current_user.id
    
    # Invalida o token JWT adicionando-o à blacklist
    auth_header = request.headers.get("Authorization")
    if auth_header and auth_header.startswith("Bearer "):
        token = auth_header.split(" ")[1]
        # O tempo de expiração do token na blacklist deve ser o mesmo do token original
        # Para simplificar, vamos assumir que o token expira em 1 hora (3600 segundos)
        cache_service.set(f"blacklist_{token}", "true", ex=3600)

    logout_user()
    
    log_action("LOGOUT", f"Logout realizado para: {escape(username)}", user_id)
    
    return jsonify({"message": "Logout realizado com sucesso"}), 200

@user_bp.route("/register", methods=["POST"])
def register():
    """Endpoint para registro de novos usuários"""
    try:
        data = request.get_json(silent=True)
        if data is None:
            if request.form:
                data = request.form.to_dict()
            elif request.data:
                print(f"Register: Raw data present but not JSON: {request.data}")
                return jsonify({"error": "Formato de requisição inválido. Esperado JSON."}), 400
            else:
                return jsonify({"error": "Dados de requisição ausentes ou formato inválido"}), 400
    except Exception as e:
        print(f"Register: Error parsing JSON/data: {e}")
        return jsonify({"error": "Dados de requisição inválidos"}), 400
    
    if not data or not data.get("username") or not data.get("email") or not data.get("password"):
        return jsonify({"error": "Username, email e password são obrigatórios"}), 400
    
    username = data.get("username")
    email = data.get("email")
    password = data.get("password")
    
    # Verificar se o usuário já existe (protegido contra SQL Injection pelo SQLAlchemy)
    if User.query.filter_by(username=username).first():
        return jsonify({"error": "Username já existe"}), 409
    
    if User.query.filter_by(email=email).first():
        return jsonify({"error": "Email já está em uso"}), 409
    
    # Criar novo usuário
    user = User(
        username=username,
        email=email,
        credits=10  # Créditos iniciais
    )
    user.set_password(password)
    
    db.session.add(user)
    db.session.commit()
    
    log_action("USER_REGISTERED", f"Novo usuário registrado: {escape(username)}", user.id)
    
    return jsonify({
        "message": "Usuário registrado com sucesso",
        "user": user.to_dict()
    }), 201

@user_bp.route("/profile", methods=["GET"])
@login_required
def get_profile():
    """Endpoint para obter perfil do usuário atual"""
    return jsonify({
        "user": current_user.to_dict()
    }), 200

@user_bp.route("/verify-token", methods=["POST"])
def verify_user_token():
    """Endpoint para verificar validade de um token JWT"""
    data = request.get_json()
    token = data.get("token") if data else None
    
    if not token:
        return jsonify({"error": "Token não fornecido"}), 400
    
    payload = verify_token(token)
    if not payload:
        return jsonify({"error": "Token inválido ou expirado"}), 401
    
    # Buscar usuário para verificar se ainda está ativo (protegido contra SQL Injection pelo SQLAlchemy)
    user = User.query.get(payload["user_id"])
    if not user or user.is_banned or not user.is_active:
        return jsonify({"error": "Usuário inválido"}), 401
    
    return jsonify({
        "valid": True,
        "user": user.to_dict()
    }), 200

@user_bp.route("/change-password", methods=["POST"])
@login_required
def change_password():
    """Endpoint para alterar senha do usuário atual"""
    data = request.get_json()
    
    if not data or not data.get("current_password") or not data.get("new_password"):
        return jsonify({"error": "Senha atual e nova senha são obrigatórias"}), 400
    
    current_password = data.get("current_password")
    new_password = data.get("new_password")
    
    # Verificar senha atual
    if not current_user.check_password(current_password):
        log_action("PASSWORD_CHANGE_FAILED", "Senha atual incorreta", current_user.id)
        return jsonify({"error": "Senha atual incorreta"}), 400
    
    # Alterar senha
    current_user.set_password(new_password)
    db.session.commit()
    
    log_action("PASSWORD_CHANGED", "Senha alterada com sucesso", current_user.id)
    
    return jsonify({"message": "Senha alterada com sucesso"}), 200

# ==================== ROTAS PARA OTP E TELEGRAM ====================

@user_bp.route("/telegram/configure", methods=["POST"])
@login_required
def configure_telegram():
    """Endpoint para configurar integração com Telegram"""
    data = request.get_json()
    
    if not data or not data.get("chat_id"):
        return jsonify({"error": "Chat ID do Telegram é obrigatório"}), 400
    
    chat_id = data.get("chat_id")
    telegram_username = data.get("telegram_username", "")
    
    # Verificar se o chat_id é válido
    success, error_msg = telegram_service.verify_chat_id(chat_id)
    
    if not success:
        log_action("TELEGRAM_CONFIG_FAILED", f"Falha ao configurar Telegram: {escape(error_msg)}", current_user.id)
        return jsonify({"error": f"Falha ao verificar chat ID: {escape(error_msg)}"}), 400
    
    # Salvar configuração do Telegram
    current_user.telegram_chat_id = chat_id
    current_user.telegram_username = telegram_username
    db.session.commit()
    
    log_action("TELEGRAM_CONFIGURED", f"Telegram configurado para chat_id: {escape(chat_id)}", current_user.id)
    
    return jsonify({
        "message": "Telegram configurado com sucesso",
        "user": current_user.to_dict()
    }), 200

@user_bp.route("/telegram/remove", methods=["POST"])
@login_required
def remove_telegram():
    """Endpoint para remover configuração do Telegram"""
    current_user.telegram_chat_id = None
    current_user.telegram_username = None
    current_user.otp_enabled = False  # Desabilitar OTP também
    db.session.commit()
    
    log_action("TELEGRAM_REMOVED", "Configuração do Telegram removida", current_user.id)
    
    return jsonify({
        "message": "Configuração do Telegram removida com sucesso",
        "user": current_user.to_dict()
    }), 200

@user_bp.route("/otp/enable", methods=["POST"])
@login_required
def enable_otp():
    """Endpoint para habilitar OTP"""
    if not current_user.telegram_chat_id:
        return jsonify({"error": "Configure o Telegram primeiro antes de habilitar OTP"}), 400
    
    current_user.otp_enabled = True
    db.session.commit()
    
    log_action("OTP_ENABLED", "OTP habilitado pelo usuário", current_user.id)
    
    return jsonify({
        "message": "OTP habilitado com sucesso",
        "user": current_user.to_dict()
    }), 200

@user_bp.route("/otp/disable", methods=["POST"])
@login_required
def disable_otp():
    """Endpoint para desabilitar OTP"""
    current_user.otp_enabled = False
    current_user.clear_otp()  # Limpar qualquer OTP pendente
    db.session.commit()
    
    log_action("OTP_DISABLED", "OTP desabilitado pelo usuário", current_user.id)
    
    return jsonify({
        "message": "OTP desabilitado com sucesso",
        "user": current_user.to_dict()
    }), 200

@user_bp.route("/otp/test", methods=["POST"])
@login_required
def test_otp():
    """Endpoint para testar envio de OTP"""
    if not current_user.telegram_chat_id:
        return jsonify({"error": "Configure o Telegram primeiro"}), 400
    
    # Gerar código OTP de teste
    otp = current_user.generate_otp()
    success, error_msg = telegram_service.send_otp(current_user, otp)
    
    if not success:
        return jsonify({"error": f"Falha ao enviar OTP de teste: {escape(error_msg)}"}), 500
    
    log_action("OTP_TEST_SENT", "Código OTP de teste enviado", current_user.id)
    
    return jsonify({
        "message": "Código OTP de teste enviado com sucesso para seu Telegram"
    }), 200

@user_bp.route("/telegram/bot-info", methods=["GET"])
@login_required
def get_bot_info():
    """Endpoint para obter informações do bot do Telegram"""
    bot_info, error_msg = telegram_service.get_bot_info()
    
    if not bot_info:
        return jsonify({"error": escape(error_msg)}), 500
    
    return jsonify({
        "bot_info": bot_info,
        "configured": telegram_service.is_configured()
    }), 200

# Decorador para verificar se o usuário é administrador
def admin_required(f):
    """Decorador para rotas que requerem privilégios de administrador"""
    def decorated_function(*args, **kwargs):
        if not current_user.is_authenticated or not current_user.is_admin:
            return jsonify({"error": "Acesso negado. Privilégios de administrador necessários."}), 403
        return f(*args, **kwargs)
    decorated_function.__name__ = f.__name__
    return decorated_function

@user_bp.route("/admin/users", methods=["GET"])
@login_required
@admin_required
def admin_get_users():
    """Endpoint para administradores listarem todos os usuários"""
    users = User.query.all()
    return jsonify({
        "users": [user.to_dict() for user in users]
    }), 200

@user_bp.route("/admin/users/<int:user_id>/ban", methods=["POST"])
@login_required
@admin_required
def admin_ban_user(user_id):
    """Endpoint para administradores banirem usuários"""
    user = User.query.get_or_404(user_id)
    
    if user.is_admin:
        return jsonify({"error": "Não é possível banir um administrador"}), 400
    
    user.is_banned = True
    db.session.commit()
    
    log_action("USER_BANNED", f"Usuário {escape(user.username)} foi banido pelo admin {escape(current_user.username)}", current_user.id)
    
    return jsonify({"message": f"Usuário {escape(user.username)} foi banido"}), 200

@user_bp.route("/admin/users/<int:user_id>/unban", methods=["POST"])
@login_required
@admin_required
def admin_unban_user(user_id):
    """Endpoint para administradores desbanirem usuários"""
    user = User.query.get_or_404(user_id)
    
    user.is_banned = False
    db.session.commit()
    
    log_action("USER_UNBANNED", f"Usuário {escape(user.username)} foi desbanido pelo admin {escape(current_user.username)}", current_user.id)
    
    return jsonify({"message": f"Usuário {escape(user.username)} foi desbanido"}), 200

@user_bp.route("/admin/users/<int:user_id>/credits", methods=["POST"])
@login_required
@admin_required
def admin_manage_credits(user_id):
    """Endpoint para administradores gerenciarem créditos de usuários"""
    data = request.get_json()
    user = User.query.get_or_404(user_id)
    
    if not data or "credits" not in data:
        return jsonify({"error": "Quantidade de créditos é obrigatória"}), 400


    
    credits = data.get("credits")
    
    # Validar se credits é um número válido
    try:
        credits = int(credits)
        if credits < 0:
            return jsonify({"error": "Quantidade de créditos deve ser um número positivo"}), 400
    except (ValueError, TypeError):
        return jsonify({"error": "Quantidade de créditos deve ser um número válido"}), 400
    
    # Atualizar créditos do usuário
    user.credits = credits
    db.session.commit()
    
    log_action("CREDITS_UPDATED", f"Créditos do usuário {escape(user.username)} atualizados para {credits} pelo admin {escape(current_user.username)}", current_user.id)
    
    return jsonify({
        "message": f"Créditos do usuário {escape(user.username)} atualizados para {credits}",
        "user": user.to_dict()
    }), 200

# ==================== ROTAS ADMINISTRATIVAS ADICIONAIS ====================

@user_bp.route("/admin/users/create", methods=["POST"])
@login_required
@admin_required
def admin_create_user():
    """Endpoint para administradores criarem novos usuários"""
    data = request.get_json()
    
    if not data or not all(key in data for key in ["username", "email", "password"]):
        return jsonify({"error": "Username, email e password são obrigatórios"}), 400
    
    username = data.get("username")
    email = data.get("email")
    password = data.get("password")
    is_admin = data.get("is_admin", False)
    credits = data.get("credits", 10)
    
    # Verificar se o usuário já existe
    if User.query.filter_by(username=username).first():
        return jsonify({"error": "Username já existe"}), 409
    
    if User.query.filter_by(email=email).first():
        return jsonify({"error": "Email já está em uso"}), 409
    
    # Criar novo usuário
    user = User(
        username=username,
        email=email,
        is_admin=is_admin,
        credits=credits
    )
    user.set_password(password)
    
    db.session.add(user)
    db.session.commit()
    
    log_action("USER_CREATED_BY_ADMIN", f"Usuário {escape(username)} criado pelo admin {escape(current_user.username)}", current_user.id)
    
    return jsonify({
        "message": f"Usuário {escape(username)} criado com sucesso",
        "user": user.to_dict()
    }), 201

@user_bp.route("/admin/users/<int:user_id>/edit", methods=["PUT"])
@login_required
@admin_required
def admin_edit_user(user_id):
    """Endpoint para administradores editarem usuários"""
    data = request.get_json()
    user = User.query.get_or_404(user_id)
    
    if not data:
        return jsonify({"error": "Dados para atualização são obrigatórios"}), 400
    
    # Atualizar campos permitidos
    if "email" in data:
        new_email = data["email"]
        # Verificar se o email já está em uso por outro usuário
        existing_user = User.query.filter_by(email=new_email).first()
        if existing_user and existing_user.id != user.id:
            return jsonify({"error": "Email já está em uso por outro usuário"}), 409
        user.email = new_email
    
    if "credits" in data:
        try:
            credits = int(data["credits"])
            if credits < 0:
                return jsonify({"error": "Créditos devem ser um número positivo"}), 400
            user.credits = credits
        except (ValueError, TypeError):
            return jsonify({"error": "Créditos devem ser um número válido"}), 400
    
    if "is_admin" in data:
        # Não permitir que um admin remova seus próprios privilégios
        if user.id == current_user.id and not data["is_admin"]:
            return jsonify({"error": "Você não pode remover seus próprios privilégios de administrador"}), 400
        user.is_admin = bool(data["is_admin"])
    
    if "is_active" in data:
        user.is_active = bool(data["is_active"])
    
    if "is_banned" in data:
        # Não permitir banir administradores
        if user.is_admin and data["is_banned"]:
            return jsonify({"error": "Não é possível banir um administrador"}), 400
        user.is_banned = bool(data["is_banned"])
    
    db.session.commit()
    
    log_action("USER_EDITED_BY_ADMIN", f"Usuário {escape(user.username)} editado pelo admin {escape(current_user.username)}", current_user.id)
    
    return jsonify({
        "message": f"Usuário {escape(user.username)} atualizado com sucesso",
        "user": user.to_dict()
    }), 200

@user_bp.route("/admin/users/<int:user_id>/delete", methods=["DELETE"])
@login_required
@admin_required
def admin_delete_user(user_id):
    """Endpoint para administradores deletarem usuários"""
    user = User.query.get_or_404(user_id)
    
    # Não permitir que um admin delete a si mesmo
    if user.id == current_user.id:
        return jsonify({"error": "Você não pode deletar sua própria conta"}), 400
    
    # Não permitir deletar outros administradores
    if user.is_admin:
        return jsonify({"error": "Não é possível deletar um administrador"}), 400
    
    username = user.username
    db.session.delete(user)
    db.session.commit()
    
    log_action("USER_DELETED_BY_ADMIN", f"Usuário {escape(username)} deletado pelo admin {escape(current_user.username)}", current_user.id)
    
    return jsonify({
        "message": f"Usuário {escape(username)} deletado com sucesso"
    }), 200

@user_bp.route("/admin/logs", methods=["GET"])
@login_required
@admin_required
def admin_get_logs():
    """Endpoint para administradores visualizarem logs do sistema"""
    page = request.args.get('page', 1, type=int)
    per_page = request.args.get('per_page', 50, type=int)
    
    # Limitar per_page para evitar sobrecarga
    per_page = min(per_page, 100)
    
    logs = Log.query.order_by(Log.timestamp.desc()).paginate(
        page=page, per_page=per_page, error_out=False
    )
    
    return jsonify({
        "logs": [log.to_dict() for log in logs.items],
        "total": logs.total,
        "pages": logs.pages,
        "current_page": page,
        "per_page": per_page
    }), 200

@user_bp.route("/admin/stats", methods=["GET"])
@login_required
@admin_required
def admin_get_stats():
    """Endpoint para administradores obterem estatísticas do sistema"""
    total_users = User.query.count()
    active_users = User.query.filter_by(is_active=True, is_banned=False).count()
    banned_users = User.query.filter_by(is_banned=True).count()
    admin_users = User.query.filter_by(is_admin=True).count()
    
    # Estatísticas de logs (últimos 30 dias)
    from datetime import datetime, timedelta
    thirty_days_ago = datetime.utcnow() - timedelta(days=30)
    recent_logins = Log.query.filter(
        Log.action == 'LOGIN_SUCCESS',
        Log.timestamp >= thirty_days_ago
    ).count()
    
    return jsonify({
        "users": {
            "total": total_users,
            "active": active_users,
            "banned": banned_users,
            "admins": admin_users
        },
        "activity": {
            "recent_logins": recent_logins
        }
    }), 200

