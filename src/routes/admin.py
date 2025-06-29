from flask import Blueprint, request, jsonify
from flask_login import login_required, current_user
from src.models.user import db, User, Domain, Script, GeneratedURL, Log, UserDomain
from src.routes.user import admin_required, log_action
from src.services.system_config_service import system_config_service
from datetime import datetime
from markupsafe import escape # Importar escape para proteção XSS

admin_bp = Blueprint("admin", __name__)

# ==================== GERENCIAMENTO DE USUÁRIOS ====================

@admin_bp.route("/users/create", methods=["POST"])
@login_required
@admin_required
def create_user():
    """Endpoint para administradores criarem novos usuários"""
    data = request.get_json()
    
    if not data or not data.get("username") or not data.get("email") or not data.get("password"):
        return jsonify({"error": "Username, email e password são obrigatórios"}), 400
    
    username = escape(data.get("username")) # Proteção XSS
    email = escape(data.get("email"))       # Proteção XSS
    password = data.get("password")
    is_admin = data.get("is_admin", False)
    credits = data.get("credits", 10)
    
    # Verificar se o usuário já existe (protegido contra SQL Injection pelo SQLAlchemy)
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
    
    log_action("USER_CREATED_BY_ADMIN", f"Usuário {username} criado pelo admin {current_user.username}" , current_user.id)
    
    return jsonify({
        "message": f"Usuário {username} criado com sucesso",
        "user": user.to_dict()
    }), 201

@admin_bp.route("/users/<int:user_id>/edit", methods=["PUT"])
@login_required
@admin_required
def edit_user(user_id):
    """Endpoint para administradores editarem usuários"""
    user = User.query.get_or_404(user_id)
    data = request.get_json()
    
    if not data:
        return jsonify({"error": "Dados não fornecidos"}), 400
    
    # Campos que podem ser editados
    if "email" in data:
        new_email = escape(data["email"]) # Proteção XSS
        # Verificar se o email já está em uso por outro usuário (protegido contra SQL Injection pelo SQLAlchemy)
        existing_user = User.query.filter_by(email=new_email).first()
        if existing_user and existing_user.id != user.id:
            return jsonify({"error": "Email já está em uso"}), 409
        user.email = new_email
    
    if "is_admin" in data and not user.id == current_user.id:  # Admin não pode remover próprios privilégios
        user.is_admin = data["is_admin"]
    
    if "credits" in data:
        old_credits = user.credits
        user.credits = data["credits"]
        log_action("CREDITS_CHANGED", f"Créditos do usuário {escape(user.username)} alterados de {old_credits} para {data.get('credits')}" , current_user.id)
    
    if "password" in data and data["password"]:
        user.set_password(data["password"])

    db.session.commit()
    log_action("USER_UPDATED_BY_ADMIN", f"Usuário {escape(user.username)} atualizado pelo admin {escape(current_user.username)}", current_user.id)
    return jsonify({"message": f"Usuário {escape(user.username)} atualizado com sucesso", "user": user.to_dict()}), 200

@admin_bp.route("/users/<int:user_id>/delete", methods=["DELETE"])
@login_required
@admin_required
def delete_user(user_id):
    """Endpoint para administradores deletarem usuários"""
    user = User.query.get_or_404(user_id)
    
    if user.id == current_user.id:
        return jsonify({"error": "Você não pode deletar sua própria conta de administrador."}), 400

    username = escape(user.username) # Proteção XSS
    db.session.delete(user)
    db.session.commit()
    log_action("USER_DELETED_BY_ADMIN", f"Usuário {username} deletado pelo admin {escape(current_user.username)}", current_user.id)
    return jsonify({"message": f"Usuário {username} deletado com sucesso"}), 200

@admin_bp.route("/users", methods=["GET"])
@login_required
@admin_required
def list_users():
    """Endpoint para administradores listarem todos os usuários"""
    users = User.query.all()
    return jsonify([user.to_dict() for user in users]), 200

@admin_bp.route("/users/<int:user_id>/ban", methods=["PUT"])
@login_required
@admin_required
def ban_user(user_id):
    """Endpoint para administradores banirem um usuário"""
    user = User.query.get_or_404(user_id)
    if user.id == current_user.id:
        return jsonify({"error": "Você não pode banir a si mesmo."}), 400
    user.is_banned = True
    db.session.commit()
    log_action("USER_BANNED_BY_ADMIN", f"Usuário {escape(user.username)} banido pelo admin {escape(current_user.username)}", current_user.id)
    return jsonify({"message": f"Usuário {escape(user.username)} banido com sucesso"}), 200

@admin_bp.route("/users/<int:user_id>/unban", methods=["PUT"])
@login_required
@admin_required
def unban_user(user_id):
    """Endpoint para administradores desbanirem um usuário"""
    user = User.query.get_or_404(user_id)
    user.is_banned = False
    db.session.commit()
    log_action("USER_UNBANNED_BY_ADMIN", f"Usuário {escape(user.username)} desbanido pelo admin {escape(current_user.username)}", current_user.id)
    return jsonify({"message": f"Usuário {escape(user.username)} desbanido com sucesso"}), 200

# ==================== GERENCIAMENTO DE DOMÍNIOS ====================

@admin_bp.route("/domains/create", methods=["POST"])
@login_required
@admin_required
def create_domain():
    """Endpoint para administradores criarem novos domínios"""
    data = request.get_json()
    if not data or not data.get("domain_name"):
        return jsonify({"error": "Nome do domínio é obrigatório"}), 400
    
    domain_name = escape(data.get("domain_name")) # Proteção XSS
    if Domain.query.filter_by(domain_name=domain_name).first():
        return jsonify({"error": "Domínio já existe"}), 409
    
    domain = Domain(domain_name=domain_name)
    db.session.add(domain)
    db.session.commit()
    log_action("DOMAIN_CREATED_BY_ADMIN", f"Domínio {domain_name} criado pelo admin {escape(current_user.username)}", current_user.id)
    return jsonify({"message": f"Domínio {domain_name} criado com sucesso", "domain": domain.to_dict()}), 201

@admin_bp.route("/domains/<int:domain_id>/edit", methods=["PUT"])
@login_required
@admin_required
def edit_domain(domain_id):
    """Endpoint para administradores editarem domínios"""
    domain = Domain.query.get_or_404(domain_id)
    data = request.get_json()
    
    if not data or not data.get("domain_name"):
        return jsonify({"error": "Nome do domínio é obrigatório"}), 400
    
    new_domain_name = escape(data.get("domain_name")) # Proteção XSS
    if Domain.query.filter_by(domain_name=new_domain_name).first() and new_domain_name != domain.domain_name:
        return jsonify({"error": "Novo nome de domínio já existe"}), 409
    
    old_domain_name = escape(domain.domain_name) # Proteção XSS
    domain.domain_name = new_domain_name
    db.session.commit()
    log_action("DOMAIN_UPDATED_BY_ADMIN", f"Domínio {old_domain_name} atualizado para {new_domain_name} pelo admin {escape(current_user.username)}", current_user.id)
    return jsonify({"message": f"Domínio {old_domain_name} atualizado para {new_domain_name} com sucesso", "domain": domain.to_dict()}), 200

@admin_bp.route("/domains/<int:domain_id>/delete", methods=["DELETE"])
@login_required
@admin_required
def delete_domain(domain_id):
    """Endpoint para administradores deletarem domínios"""
    domain = Domain.query.get_or_404(domain_id)
    domain_name = escape(domain.domain_name) # Proteção XSS
    db.session.delete(domain)
    db.session.commit()
    log_action("DOMAIN_DELETED_BY_ADMIN", f"Domínio {domain_name} deletado pelo admin {escape(current_user.username)}", current_user.id)
    return jsonify({"message": f"Domínio {domain_name} deletado com sucesso"}), 200

@admin_bp.route("/domains", methods=["GET"])
@login_required
@admin_required
def list_domains():
    """Endpoint para administradores listarem todos os domínios"""
    domains = Domain.query.all()
    return jsonify([domain.to_dict() for domain in domains]), 200

@admin_bp.route("/domains/<int:domain_id>/assign/<int:user_id>", methods=["PUT"])
@login_required
@admin_required
def assign_domain_to_user(domain_id, user_id):
    """Endpoint para administradores atribuírem um domínio a um usuário"""
    domain = Domain.query.get_or_404(domain_id)
    user = User.query.get_or_404(user_id)

    if UserDomain.query.filter_by(user_id=user.id, domain_id=domain.id).first():
        return jsonify({"error": "Domínio já atribuído a este usuário"}), 409

    user_domain = UserDomain(user_id=user.id, domain_id=domain.id)
    db.session.add(user_domain)
    db.session.commit()
    log_action("DOMAIN_ASSIGNED_BY_ADMIN", f"Domínio {escape(domain.domain_name)} atribuído ao usuário {escape(user.username)} pelo admin {escape(current_user.username)}", current_user.id)
    return jsonify({"message": f"Domínio {escape(domain.domain_name)} atribuído ao usuário {escape(user.username)} com sucesso"}), 200

@admin_bp.route("/domains/<int:domain_id>/unassign/<int:user_id>", methods=["PUT"])
@login_required
@admin_required
def unassign_domain_from_user(domain_id, user_id):
    """Endpoint para administradores desatribuírem um domínio de um usuário"""
    user_domain = UserDomain.query.filter_by(user_id=user_id, domain_id=domain_id).first_or_404()
    domain_name = escape(user_domain.domain.domain_name) # Proteção XSS
    username = escape(user_domain.user.username)         # Proteção XSS
    db.session.delete(user_domain)
    db.session.commit()
    log_action("DOMAIN_UNASSIGNED_BY_ADMIN", f"Domínio {domain_name} desatribuído do usuário {username} pelo admin {escape(current_user.username)}", current_user.id)
    return jsonify({"message": f"Domínio {domain_name} desatribuído do usuário {username} com sucesso"}), 200

# ==================== GERENCIAMENTO DE SCRIPTS ====================

@admin_bp.route("/scripts/create", methods=["POST"])
@login_required
@admin_required
def create_script():
    """Endpoint para administradores criarem novos scripts"""
    data = request.get_json()
    if not data or not data.get("script_name") or not data.get("script_content"):
        return jsonify({"error": "Nome e conteúdo do script são obrigatórios"}), 400
    
    script_name = escape(data.get("script_name")) # Proteção XSS
    script_content = escape(data.get("script_content")) # Proteção XSS
    if Script.query.filter_by(script_name=script_name).first():
        return jsonify({"error": "Script já existe"}), 409
    
    script = Script(script_name=script_name, script_content=script_content)
    db.session.add(script)
    db.session.commit()
    log_action("SCRIPT_CREATED_BY_ADMIN", f"Script {script_name} criado pelo admin {escape(current_user.username)}", current_user.id)
    return jsonify({"message": f"Script {script_name} criado com sucesso", "script": script.to_dict()}), 201

@admin_bp.route("/scripts/<int:script_id>/edit", methods=["PUT"])
@login_required
@admin_required
def edit_script(script_id):
    """Endpoint para administradores editarem scripts"""
    script = Script.query.get_or_404(script_id)
    data = request.get_json()
    
    if not data:
        return jsonify({"error": "Dados não fornecidos"}), 400
    
    if "script_name" in data:
        new_script_name = escape(data.get("script_name")) # Proteção XSS
        if Script.query.filter_by(script_name=new_script_name).first() and new_script_name != script.script_name:
            return jsonify({"error": "Novo nome de script já existe"}), 409
        script.script_name = new_script_name
    
    if "script_content" in data:
        script.script_content = escape(data.get("script_content")) # Proteção XSS
    
    db.session.commit()
    log_action("SCRIPT_UPDATED_BY_ADMIN", f"Script {escape(script.script_name)} atualizado pelo admin {escape(current_user.username)}", current_user.id)
    return jsonify({"message": f"Script {escape(script.script_name)} atualizado com sucesso", "script": script.to_dict()}), 200

@admin_bp.route("/scripts/<int:script_id>/delete", methods=["DELETE"])
@login_required
@admin_required
def delete_script(script_id):
    """Endpoint para administradores deletarem scripts"""
    script = Script.query.get_or_404(script_id)
    script_name = escape(script.script_name) # Proteção XSS
    db.session.delete(script)
    db.session.commit()
    log_action("SCRIPT_DELETED_BY_ADMIN", f"Script {script_name} deletado pelo admin {escape(current_user.username)}", current_user.id)
    return jsonify({"message": f"Script {script_name} deletado com sucesso"}), 200

@admin_bp.route("/scripts", methods=["GET"])
@login_required
@admin_required
def list_scripts():
    """Endpoint para administradores listarem todos os scripts"""
    scripts = Script.query.all()
    return jsonify([script.to_dict() for script in scripts]), 200

# ==================== GERENCIAMENTO DE CONFIGURAÇÕES DO SISTEMA ====================

@admin_bp.route("/system-config", methods=["GET"])
@login_required
@admin_required
def get_system_config():
    """Endpoint para administradores obterem as configurações do sistema."""
    config = system_config_service.get_config()
    # Não retornar a SECRET_KEY diretamente por segurança
    config_display = {k: v for k, v in config.items() if k != "SECRET_KEY"}
    return jsonify(config_display), 200

@admin_bp.route("/system-config", methods=["PUT"])
@login_required
@admin_required
def update_system_config():
    """Endpoint para administradores atualizarem as configurações do sistema."""
    data = request.get_json()
    
    if not data:
        return jsonify({"error": "Dados não fornecidos"}), 400

    # Validar se a senha do administrador atual foi fornecida para alterações sensíveis
    admin_password = data.pop("admin_password", None)
    if not admin_password or not current_user.check_password(admin_password):
        return jsonify({"error": "Senha do administrador inválida ou não fornecida."}), 401

    # Gerar nova SECRET_KEY se solicitado
    if data.get("generate_new_secret_key"):
        new_secret_key = system_config_service.generate_secret_key()
        data["SECRET_KEY"] = new_secret_key
        del data["generate_new_secret_key"]

    system_config_service.update_config(data)
    log_action("SYSTEM_CONFIG_UPDATED", f"Configurações do sistema atualizadas pelo admin {escape(current_user.username)}", current_user.id)
    
    config_display = {k: v for k, v in system_config_service.get_config().items() if k != "SECRET_KEY"}
    return jsonify({
        "message": "Configurações do sistema atualizadas com sucesso.",
        "config": config_display
    }), 200












