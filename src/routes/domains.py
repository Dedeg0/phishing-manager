from flask import Blueprint, request, jsonify
from flask_login import login_required, current_user
from src.models.user import db, Domain, UserDomain, DomainRequest, User
from src.services.notification_service import NotificationService
from src.routes.user import log_action
from datetime import datetime, timedelta
import requests
import json

domains_bp = Blueprint('domains', __name__)

@domains_bp.route('/available', methods=['GET'])
@login_required
def get_available_domains():
    """Lista domínios disponíveis para o usuário"""
    # Domínios que o usuário já tem acesso
    user_domain_ids = [ud.domain_id for ud in current_user.user_domains]
    
    # Domínios disponíveis (ativos e que o usuário não tem acesso)
    available_domains = Domain.query.filter(
        Domain.is_active == True,
        ~Domain.id.in_(user_domain_ids)
    ).all()
    
    # Filtrar domínios baseado em critérios
    filtered_domains = []
    for domain in available_domains:
        # Verificar se o domínio não atingiu o limite de usuários
        current_users = len(domain.user_domains)
        if current_users < domain.max_users:
            domain_dict = domain.to_dict()
            domain_dict['current_users'] = current_users
            domain_dict['can_request'] = True
            
            # Verificar se já existe uma solicitação pendente
            existing_request = DomainRequest.query.filter_by(
                user_id=current_user.id,
                domain_id=domain.id,
                status='pending'
            ).first()
            
            if existing_request:
                domain_dict['can_request'] = False
                domain_dict['pending_request'] = existing_request.to_dict()
            
            filtered_domains.append(domain_dict)
    
    return jsonify({
        'available_domains': filtered_domains,
        'total': len(filtered_domains)
    }), 200

@domains_bp.route('/my-domains', methods=['GET'])
@login_required
def get_my_domains():
    """Lista domínios que o usuário tem acesso"""
    user_domains = []
    
    for user_domain in current_user.user_domains:
        domain_dict = user_domain.domain.to_dict()
        domain_dict['access_info'] = user_domain.to_dict()
        
        # Verificar se o acesso expirou
        if user_domain.expires_at and datetime.utcnow() > user_domain.expires_at:
            domain_dict['access_info']['is_expired'] = True
        else:
            domain_dict['access_info']['is_expired'] = False
        
        user_domains.append(domain_dict)
    
    return jsonify({
        'my_domains': user_domains,
        'total': len(user_domains)
    }), 200

@domains_bp.route('/request-access', methods=['POST'])
@login_required
def request_domain_access():
    """Solicita acesso a um domínio"""
    data = request.get_json()
    
    if not data or not data.get('domain_id'):
        return jsonify({'error': 'Domain ID é obrigatório'}), 400
    
    domain_id = data.get('domain_id')
    reason = data.get('reason', '')
    requested_duration_days = data.get('duration_days')
    priority = data.get('priority', 'normal')
    
    # Verificar se o domínio existe e está ativo
    domain = Domain.query.filter_by(id=domain_id, is_active=True).first()
    if not domain:
        return jsonify({'error': 'Domínio não encontrado ou inativo'}), 404
    
    # Verificar se o usuário já tem acesso
    existing_access = UserDomain.query.filter_by(
        user_id=current_user.id,
        domain_id=domain_id
    ).first()
    
    if existing_access:
        return jsonify({'error': 'Você já tem acesso a este domínio'}), 400
    
    # Verificar se já existe uma solicitação pendente
    existing_request = DomainRequest.query.filter_by(
        user_id=current_user.id,
        domain_id=domain_id,
        status='pending'
    ).first()
    
    if existing_request:
        return jsonify({'error': 'Já existe uma solicitação pendente para este domínio'}), 400
    
    # Verificar se o domínio não atingiu o limite de usuários
    current_users = len(domain.user_domains)
    if current_users >= domain.max_users:
        return jsonify({'error': 'Domínio atingiu o limite máximo de usuários'}), 400
    
    # Validar prioridade
    valid_priorities = ['low', 'normal', 'high', 'urgent']
    if priority not in valid_priorities:
        priority = 'normal'
    
    # Criar solicitação
    domain_request = DomainRequest(
        user_id=current_user.id,
        domain_id=domain_id,
        reason=reason,
        requested_duration_days=requested_duration_days,
        priority=priority
    )
    
    db.session.add(domain_request)
    db.session.commit()
    
    # Registrar no log
    log_action('DOMAIN_ACCESS_REQUESTED', f'Solicitação de acesso ao domínio {domain.domain_name}', current_user.id)
    
    # Notificar administradores
    try:
        notification_service.notify_system_alert(
            'DOMAIN_REQUEST',
            f'Nova solicitação de domínio',
            f'Usuário: {current_user.username}\nDomínio: {domain.domain_name}\nPrioridade: {priority}'
        )
    except Exception as e:
        print(f"Erro ao enviar notificação: {e}")
    
    return jsonify({
        'message': 'Solicitação de acesso enviada com sucesso',
        'request': domain_request.to_dict()
    }), 201

@domains_bp.route('/requests', methods=['GET'])
@login_required
def get_domain_requests():
    """Lista solicitações de domínio (usuário vê suas próprias, admin vê todas)"""
    page = request.args.get('page', 1, type=int)
    per_page = request.args.get('per_page', 20, type=int)
    status = request.args.get('status')  # Filtro opcional
    priority = request.args.get('priority')  # Filtro opcional
    
    # Construir query baseado no tipo de usuário
    if current_user.is_admin:
        query = DomainRequest.query
    else:
        query = DomainRequest.query.filter_by(user_id=current_user.id)
    
    # Aplicar filtros
    if status:
        query = query.filter_by(status=status)
    
    if priority:
        query = query.filter_by(priority=priority)
    
    # Ordenar por prioridade e data
    priority_order = db.case(
        (DomainRequest.priority == 'urgent', 1),
        (DomainRequest.priority == 'high', 2),
        (DomainRequest.priority == 'normal', 3),
        (DomainRequest.priority == 'low', 4),
        else_=5
    )
    
    requests_paginated = query.order_by(
        priority_order,
        DomainRequest.requested_at.desc()
    ).paginate(page=page, per_page=per_page, error_out=False)
    
    return jsonify({
        'requests': [req.to_dict() for req in requests_paginated.items],
        'total': requests_paginated.total,
        'pages': requests_paginated.pages,
        'current_page': page,
        'has_next': requests_paginated.has_next,
        'has_prev': requests_paginated.has_prev
    }), 200

@domains_bp.route('/requests/<int:request_id>/review', methods=['POST'])
@login_required
def review_domain_request(request_id):
    """Aprovar ou rejeitar solicitação de domínio (apenas admins)"""
    if not current_user.is_admin:
        return jsonify({'error': 'Acesso negado'}), 403
    
    domain_request = DomainRequest.query.get_or_404(request_id)
    
    if domain_request.status != 'pending':
        return jsonify({'error': 'Esta solicitação já foi revisada'}), 400
    
    data = request.get_json()
    action = data.get('action')  # 'approve' ou 'reject'
    admin_response = data.get('response', '')
    duration_days = data.get('duration_days')  # Para aprovações
    
    if action not in ['approve', 'reject']:
        return jsonify({'error': 'Ação inválida. Use "approve" ou "reject"'}), 400
    
    # Atualizar solicitação
    domain_request.status = 'approved' if action == 'approve' else 'rejected'
    domain_request.reviewed_at = datetime.utcnow()
    domain_request.reviewed_by = current_user.id
    domain_request.admin_response = admin_response
    
    if action == 'approve':
        # Verificar se o domínio ainda está disponível
        domain = domain_request.domain
        current_users = len(domain.user_domains)
        
        if current_users >= domain.max_users:
            return jsonify({'error': 'Domínio atingiu o limite máximo de usuários'}), 400
        
        # Verificar se o usuário ainda não tem acesso
        existing_access = UserDomain.query.filter_by(
            user_id=domain_request.user_id,
            domain_id=domain_request.domain_id
        ).first()
        
        if existing_access:
            return jsonify({'error': 'Usuário já tem acesso a este domínio'}), 400
        
        # Criar acesso ao domínio
        expires_at = None
        if duration_days:
            expires_at = datetime.utcnow() + timedelta(days=duration_days)
        elif domain_request.requested_duration_days:
            expires_at = datetime.utcnow() + timedelta(days=domain_request.requested_duration_days)
        
        user_domain = UserDomain(
            user_id=domain_request.user_id,
            domain_id=domain_request.domain_id,
            granted_by=current_user.id,
            expires_at=expires_at
        )
        
        db.session.add(user_domain)
        
        # Registrar no log
        log_action('DOMAIN_ACCESS_GRANTED', f'Acesso ao domínio {domain.domain_name} concedido para usuário {domain_request.user.username}', current_user.id)
        
        # Notificar usuário
        try:
            if domain_request.user.receive_notifications and domain_request.user.get_notification_chat_id():
                message = f"""
✅ <b>Solicitação de Domínio Aprovada!</b>

🌐 <b>Domínio:</b> {domain.domain_name}
⏰ <b>Válido até:</b> {expires_at.strftime('%d/%m/%Y %H:%M') if expires_at else 'Permanente'}
💬 <b>Resposta do Admin:</b> {admin_response or 'Aprovado'}

Agora você pode usar este domínio para gerar URLs!
                """
                notification_service.send_message(domain_request.user.get_notification_chat_id(), message)
        except Exception as e:
            print(f"Erro ao enviar notificação: {e}")
    
    else:  # reject
        # Registrar no log
        log_action('DOMAIN_ACCESS_REJECTED', f'Solicitação de acesso ao domínio {domain_request.domain.domain_name} rejeitada para usuário {domain_request.user.username}', current_user.id)
        
        # Notificar usuário
        try:
            if domain_request.user.receive_notifications and domain_request.user.get_notification_chat_id():
                message = f"""
❌ <b>Solicitação de Domínio Rejeitada</b>

🌐 <b>Domínio:</b> {domain_request.domain.domain_name}
💬 <b>Motivo:</b> {admin_response or 'Não especificado'}

Você pode fazer uma nova solicitação com mais detalhes.
                """
                notification_service.send_message(domain_request.user.get_notification_chat_id(), message)
        except Exception as e:
            print(f"Erro ao enviar notificação: {e}")
    
    db.session.commit()
    
    return jsonify({
        'message': f'Solicitação {action}da com sucesso',
        'request': domain_request.to_dict()
    }), 200

@domains_bp.route('/manage', methods=['GET'])
@login_required
def list_all_domains():
    """Lista todos os domínios para gerenciamento (apenas admins)"""
    if not current_user.is_admin:
        return jsonify({'error': 'Acesso negado'}), 403
    
    page = request.args.get('page', 1, type=int)
    per_page = request.args.get('per_page', 20, type=int)
    active_only = request.args.get('active_only', 'false').lower() == 'true'
    
    query = Domain.query
    if active_only:
        query = query.filter_by(is_active=True)
    
    domains = query.order_by(Domain.created_at.desc()).paginate(
        page=page, per_page=per_page, error_out=False
    )
    
    # Adicionar estatísticas para cada domínio
    domains_with_stats = []
    for domain in domains.items:
        domain_dict = domain.to_dict()
        domain_dict['current_users'] = len(domain.user_domains)
        domain_dict['pending_requests'] = DomainRequest.query.filter_by(
            domain_id=domain.id,
            status='pending'
        ).count()
        domains_with_stats.append(domain_dict)
    
    return jsonify({
        'domains': domains_with_stats,
        'total': domains.total,
        'pages': domains.pages,
        'current_page': page,
        'has_next': domains.has_next,
        'has_prev': domains.has_prev
    }), 200

@domains_bp.route('/create', methods=['POST'])
@login_required
def create_domain():
    """Criar novo domínio (apenas admins)"""
    if not current_user.is_admin:
        return jsonify({'error': 'Acesso negado'}), 403
    
    data = request.get_json()
    
    if not data or not data.get('domain_name'):
        return jsonify({'error': 'Nome do domínio é obrigatório'}), 400
    
    domain_name = data.get('domain_name').lower().strip()
    
    # Verificar se o domínio já existe
    existing_domain = Domain.query.filter_by(domain_name=domain_name).first()
    if existing_domain:
        return jsonify({'error': 'Domínio já existe'}), 400
    
    # Criar domínio
    domain = Domain(
        domain_name=domain_name,
        max_users=data.get('max_users', 100),
        requires_approval=data.get('requires_approval', True),
        is_premium=data.get('is_premium', False),
        cost_per_use=data.get('cost_per_use', 1),
        rate_limit_per_hour=data.get('rate_limit_per_hour', 1000),
        status_check_url=data.get('status_check_url')
    )
    
    # Configurações de segurança
    if data.get('allowed_countries'):
        domain.allowed_countries = json.dumps(data.get('allowed_countries'))
    
    if data.get('blocked_ips'):
        domain.blocked_ips = json.dumps(data.get('blocked_ips'))
    
    db.session.add(domain)
    db.session.commit()
    
    # Registrar no log
    log_action('DOMAIN_CREATED', f'Domínio {domain_name} criado', current_user.id)
    
    return jsonify({
        'message': 'Domínio criado com sucesso',
        'domain': domain.to_dict()
    }), 201

@domains_bp.route('/<int:domain_id>', methods=['PUT'])
@login_required
def update_domain(domain_id):
    """Atualizar configurações de domínio (apenas admins)"""
    if not current_user.is_admin:
        return jsonify({'error': 'Acesso negado'}), 403
    
    domain = Domain.query.get_or_404(domain_id)
    data = request.get_json()
    
    if not data:
        return jsonify({'error': 'Dados são obrigatórios'}), 400
    
    # Atualizar campos permitidos
    updatable_fields = [
        'is_active', 'max_users', 'requires_approval', 'is_premium',
        'cost_per_use', 'rate_limit_per_hour', 'status_check_url'
    ]
    
    for field in updatable_fields:
        if field in data:
            setattr(domain, field, data[field])
    
    # Configurações de segurança
    if 'allowed_countries' in data:
        domain.allowed_countries = json.dumps(data['allowed_countries']) if data['allowed_countries'] else None
    
    if 'blocked_ips' in data:
        domain.blocked_ips = json.dumps(data['blocked_ips']) if data['blocked_ips'] else None
    
    db.session.commit()
    
    # Registrar no log
    log_action('DOMAIN_UPDATED', f'Domínio {domain.domain_name} atualizado', current_user.id)
    
    return jsonify({
        'message': 'Domínio atualizado com sucesso',
        'domain': domain.to_dict()
    }), 200

@domains_bp.route('/<int:domain_id>/check-status', methods=['POST'])
@login_required
def check_domain_status(domain_id):
    """Verificar status de um domínio (apenas admins)"""
    if not current_user.is_admin:
        return jsonify({'error': 'Acesso negado'}), 403
    
    domain = Domain.query.get_or_404(domain_id)
    
    if not domain.status_check_url:
        return jsonify({'error': 'URL de verificação não configurada'}), 400
    
    try:
        # Fazer requisição para verificar status
        response = requests.get(domain.status_check_url, timeout=10)
        is_online = response.status_code == 200
        
        # Atualizar status no banco
        domain.is_online = is_online
        domain.last_status_check = datetime.utcnow()
        db.session.commit()
        
        # Registrar no log
        status_text = 'online' if is_online else 'offline'
        log_action('DOMAIN_STATUS_CHECKED', f'Domínio {domain.domain_name} está {status_text}', current_user.id)
        
        return jsonify({
            'domain_name': domain.domain_name,
            'is_online': is_online,
            'status_code': response.status_code,
            'checked_at': domain.last_status_check.isoformat()
        }), 200
        
    except requests.RequestException as e:
        # Erro na verificação - considerar offline
        domain.is_online = False
        domain.last_status_check = datetime.utcnow()
        db.session.commit()
        
        log_action('DOMAIN_STATUS_CHECK_FAILED', f'Falha ao verificar domínio {domain.domain_name}: {str(e)}', current_user.id)
        
        return jsonify({
            'domain_name': domain.domain_name,
            'is_online': False,
            'error': str(e),
            'checked_at': domain.last_status_check.isoformat()
        }), 200

@domains_bp.route('/<int:domain_id>/users', methods=['GET'])
@login_required
def get_domain_users(domain_id):
    """Listar usuários com acesso a um domínio (apenas admins)"""
    if not current_user.is_admin:
        return jsonify({'error': 'Acesso negado'}), 403
    
    domain = Domain.query.get_or_404(domain_id)
    
    users_with_access = []
    for user_domain in domain.user_domains:
        user_dict = user_domain.user.to_dict()
        user_dict['access_info'] = user_domain.to_dict()
        users_with_access.append(user_dict)
    
    return jsonify({
        'domain': domain.to_dict(),
        'users': users_with_access,
        'total_users': len(users_with_access)
    }), 200

@domains_bp.route('/<int:domain_id>/revoke-access/<int:user_id>', methods=['DELETE'])
@login_required
def revoke_domain_access(domain_id, user_id):
    """Revogar acesso de usuário a um domínio (apenas admins)"""
    if not current_user.is_admin:
        return jsonify({'error': 'Acesso negado'}), 403
    
    user_domain = UserDomain.query.filter_by(
        domain_id=domain_id,
        user_id=user_id
    ).first()
    
    if not user_domain:
        return jsonify({'error': 'Usuário não tem acesso a este domínio'}), 404
    
    domain_name = user_domain.domain.domain_name
    username = user_domain.user.username
    
    db.session.delete(user_domain)
    db.session.commit()
    
    # Registrar no log
    log_action('DOMAIN_ACCESS_REVOKED', f'Acesso ao domínio {domain_name} revogado para usuário {username}', current_user.id)
    
    # Notificar usuário
    try:
        user = User.query.get(user_id)
        if user and user.receive_notifications and user.get_notification_chat_id():
            message = f"""
🚫 <b>Acesso ao Domínio Revogado</b>

🌐 <b>Domínio:</b> {domain_name}
⏰ <b>Revogado em:</b> {datetime.utcnow().strftime('%d/%m/%Y %H:%M')}

Seu acesso a este domínio foi removido por um administrador.
            """
            notification_service.send_message(user.get_notification_chat_id(), message)
    except Exception as e:
        print(f"Erro ao enviar notificação: {e}")
    
    return jsonify({'message': f'Acesso ao domínio revogado para usuário {username}'}), 200

@domains_bp.route('/stats', methods=['GET'])
@login_required
def get_domain_stats():
    """Obter estatísticas gerais de domínios (apenas admins)"""
    if not current_user.is_admin:
        return jsonify({'error': 'Acesso negado'}), 403
    
    # Estatísticas gerais
    total_domains = Domain.query.count()
    active_domains = Domain.query.filter_by(is_active=True).count()
    premium_domains = Domain.query.filter_by(is_premium=True).count()
    
    # Solicitações pendentes
    pending_requests = DomainRequest.query.filter_by(status='pending').count()
    
    # Domínios mais utilizados
    most_used_domains = db.session.query(
        Domain.domain_name,
        db.func.count(UserDomain.user_id).label('user_count')
    ).join(UserDomain).group_by(Domain.id).order_by(
        db.func.count(UserDomain.user_id).desc()
    ).limit(10).all()
    
    # Solicitações por status
    request_stats = db.session.query(
        DomainRequest.status,
        db.func.count(DomainRequest.id).label('count')
    ).group_by(DomainRequest.status).all()
    
    # Domínios online/offline
    online_domains = Domain.query.filter_by(is_online=True).count()
    offline_domains = Domain.query.filter_by(is_online=False).count()
    
    return jsonify({
        'general_stats': {
            'total_domains': total_domains,
            'active_domains': active_domains,
            'premium_domains': premium_domains,
            'pending_requests': pending_requests,
            'online_domains': online_domains,
            'offline_domains': offline_domains
        },
        'most_used_domains': [
            {'domain_name': domain[0], 'user_count': domain[1]}
            for domain in most_used_domains
        ],
        'request_stats': [
            {'status': status[0], 'count': status[1]}
            for status in request_stats
        ]
    }), 200

