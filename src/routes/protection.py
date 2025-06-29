from flask import Blueprint, request, jsonify
from flask_login import login_required, current_user
from src.models.user import db, URLCleaning, BlacklistedIP, SuspiciousActivity, User
from src.services.anti_redpage_service import AntiRedpageService
from src.services.notification_service import NotificationService
from src.routes.user import log_action
from datetime import datetime, timedelta
import json

protection_bp = Blueprint('protection', __name__)

@protection_bp.route('/clean-url', methods=['POST'])
@login_required
def clean_url():
    """Endpoint para adicionar uma URL para limpeza"""
    data = request.get_json()
    
    if not data or not data.get('url'):
        return jsonify({'error': 'URL é obrigatória'}), 400
    
    url = data.get('url')
    cleaning_type = data.get('cleaning_type', 'full_clean')  # redpage_removal, bot_protection, full_clean
    
    # Validar tipo de limpeza
    valid_types = ['redpage_removal', 'bot_protection', 'full_clean']
    if cleaning_type not in valid_types:
        return jsonify({'error': f'Tipo de limpeza inválido. Use: {valid_types}'}), 400
    
    # Verificar se o usuário tem créditos suficientes (limpeza custa 1 crédito)
    if current_user.credits <= 0:
        return jsonify({'error': 'Créditos insuficientes para limpeza de URL'}), 400
    
    # Criar registro de limpeza
    url_cleaning = URLCleaning(
        user_id=current_user.id,
        original_url=url,
        cleaning_type=cleaning_type,
        status='processing'
    )
    
    # Debitar crédito
    current_user.credits -= 1
    
    db.session.add(url_cleaning)
    db.session.commit()
    
    try:
        # Executar limpeza
        cleaning_result = anti_redpage_service.clean_url(url, cleaning_type)
        
        # Atualizar registro com resultados
        url_cleaning.cleaned_url = cleaning_result['cleaned_url']
        url_cleaning.issues_found = json.dumps(cleaning_result['issues_found'])
        url_cleaning.actions_taken = json.dumps(cleaning_result['actions_taken'])
        url_cleaning.status = 'completed'
        url_cleaning.completed_at = datetime.utcnow()
        
        db.session.commit()
        
        # Registrar no log
        log_action('URL_CLEANED', f'URL limpa: {url} -> {cleaning_result["cleaned_url"]}', current_user.id)
        
        # Enviar notificação se configurado
        if current_user.receive_notifications and current_user.get_notification_chat_id():
            message = f"""
🧹 <b>URL Limpa com Sucesso!</b>

🔗 <b>URL Original:</b>
<code>{url}</code>

✨ <b>URL Limpa:</b>
<code>{cleaning_result['cleaned_url']}</code>

🔍 <b>Problemas Encontrados:</b>
{chr(10).join(f"• {issue}" for issue in cleaning_result['issues_found']) if cleaning_result['issues_found'] else "• Nenhum problema detectado"}

⚡ <b>Ações Realizadas:</b>
{chr(10).join(f"• {action}" for action in cleaning_result['actions_taken']) if cleaning_result['actions_taken'] else "• Nenhuma ação necessária"}

💳 <b>Créditos Restantes:</b> {current_user.credits}
            """
            notification_service.send_message(current_user.get_notification_chat_id(), message)
        
        return jsonify({
            'message': 'URL limpa com sucesso',
            'cleaning_id': url_cleaning.id,
            'original_url': url,
            'cleaned_url': cleaning_result['cleaned_url'],
            'issues_found': cleaning_result['issues_found'],
            'actions_taken': cleaning_result['actions_taken'],
            'is_clean': cleaning_result['is_clean'],
            'remaining_credits': current_user.credits
        }), 200
        
    except Exception as e:
        # Erro na limpeza
        url_cleaning.status = 'failed'
        url_cleaning.issues_found = json.dumps([f"Erro na limpeza: {str(e)}"])
        url_cleaning.completed_at = datetime.utcnow()
        
        # Devolver crédito em caso de erro
        current_user.credits += 1
        
        db.session.commit()
        
        return jsonify({'error': f'Erro na limpeza da URL: {str(e)}'}), 500

@protection_bp.route('/my-cleanings', methods=['GET'])
@login_required
def get_my_cleanings():
    """Endpoint para listar limpezas do usuário"""
    page = request.args.get('page', 1, type=int)
    per_page = request.args.get('per_page', 20, type=int)
    
    cleanings = URLCleaning.query.filter_by(user_id=current_user.id).order_by(
        URLCleaning.created_at.desc()
    ).paginate(page=page, per_page=per_page, error_out=False)
    
    # Processar dados para resposta
    cleanings_data = []
    for cleaning in cleanings.items:
        cleaning_dict = cleaning.to_dict()
        
        # Decodificar JSON fields
        try:
            cleaning_dict['issues_found'] = json.loads(cleaning.issues_found) if cleaning.issues_found else []
            cleaning_dict['actions_taken'] = json.loads(cleaning.actions_taken) if cleaning.actions_taken else []
        except:
            cleaning_dict['issues_found'] = []
            cleaning_dict['actions_taken'] = []
        
        cleanings_data.append(cleaning_dict)
    
    return jsonify({
        'cleanings': cleanings_data,
        'total': cleanings.total,
        'pages': cleanings.pages,
        'current_page': page,
        'has_next': cleanings.has_next,
        'has_prev': cleanings.has_prev
    }), 200

@protection_bp.route('/analyze-visitor', methods=['POST'])
def analyze_visitor():
    """Endpoint para analisar um visitante em busca de comportamento de bot"""
    data = request.get_json()
    
    if not data:
        return jsonify({'error': 'Dados de análise são obrigatórios'}), 400
    
    # Extrair dados do request
    request_data = {
        'user_agent': data.get('user_agent', ''),
        'headers': data.get('headers', {}),
        'fingerprint': data.get('fingerprint', {})
    }
    
    visitor_data = data.get('visitor_data', {})
    
    # Executar análise
    analysis_result = anti_bot_service.analyze_visitor(request_data, visitor_data)
    
    # Se detectado como bot, registrar atividade suspeita
    if analysis_result['is_bot']:
        ip_address = data.get('ip_address', 'unknown')
        
        suspicious_activity = SuspiciousActivity(
            ip_address=ip_address,
            user_agent=request_data['user_agent'],
            activity_type='bot_detected',
            severity=analysis_result['risk_level'],
            details=json.dumps({
                'bot_score': analysis_result['bot_score'],
                'indicators': analysis_result['indicators'],
                'confidence': analysis_result['confidence']
            })
        )
        
        db.session.add(suspicious_activity)
        db.session.commit()
        
        # Notificar administradores se for crítico
        if analysis_result['risk_level'] == 'critical':
            notification_service.notify_system_alert(
                'BOT_DETECTED',
                f'Bot crítico detectado: {ip_address}',
                f"Score: {analysis_result['bot_score']:.2f}, Indicadores: {len(analysis_result['indicators'])}"
            )
    
    return jsonify(analysis_result), 200

@protection_bp.route('/protection-challenge', methods=['POST'])
def get_protection_challenge():
    """Endpoint para obter um desafio de proteção anti-bot"""
    data = request.get_json()
    challenge_type = data.get('type', 'javascript') if data else 'javascript'
    
    challenge = anti_bot_service.generate_challenge(challenge_type)
    
    return jsonify(challenge), 200

@protection_bp.route('/blacklist-ip', methods=['POST'])
@login_required
def blacklist_ip():
    """Endpoint para adicionar IP à blacklist (apenas admins)"""
    if not current_user.is_admin:
        return jsonify({'error': 'Acesso negado'}), 403
    
    data = request.get_json()
    
    if not data or not data.get('ip_address'):
        return jsonify({'error': 'IP address é obrigatório'}), 400
    
    ip_address = data.get('ip_address')
    reason = data.get('reason', 'Adicionado manualmente')
    expires_hours = data.get('expires_hours')  # Opcional
    
    # Verificar se já existe
    existing = BlacklistedIP.query.filter_by(ip_address=ip_address, is_active=True).first()
    if existing:
        return jsonify({'error': 'IP já está na blacklist'}), 400
    
    # Criar entrada na blacklist
    blacklisted_ip = BlacklistedIP(
        ip_address=ip_address,
        reason=reason,
        added_by=current_user.id,
        expires_at=datetime.utcnow() + timedelta(hours=expires_hours) if expires_hours else None
    )
    
    db.session.add(blacklisted_ip)
    db.session.commit()
    
    log_action('IP_BLACKLISTED', f'IP {ip_address} adicionado à blacklist: {reason}', current_user.id)
    
    return jsonify({
        'message': f'IP {ip_address} adicionado à blacklist',
        'blacklist_entry': blacklisted_ip.to_dict()
    }), 201

@protection_bp.route('/blacklist', methods=['GET'])
@login_required
def get_blacklist():
    """Endpoint para listar IPs na blacklist (apenas admins)"""
    if not current_user.is_admin:
        return jsonify({'error': 'Acesso negado'}), 403
    
    page = request.args.get('page', 1, type=int)
    per_page = request.args.get('per_page', 50, type=int)
    active_only = request.args.get('active_only', 'true').lower() == 'true'
    
    query = BlacklistedIP.query
    if active_only:
        query = query.filter_by(is_active=True)
    
    blacklist = query.order_by(BlacklistedIP.created_at.desc()).paginate(
        page=page, per_page=per_page, error_out=False
    )
    
    return jsonify({
        'blacklist': [entry.to_dict() for entry in blacklist.items],
        'total': blacklist.total,
        'pages': blacklist.pages,
        'current_page': page,
        'has_next': blacklist.has_next,
        'has_prev': blacklist.has_prev
    }), 200

@protection_bp.route('/blacklist/<int:entry_id>', methods=['DELETE'])
@login_required
def remove_from_blacklist(entry_id):
    """Endpoint para remover IP da blacklist (apenas admins)"""
    if not current_user.is_admin:
        return jsonify({'error': 'Acesso negado'}), 403
    
    blacklist_entry = BlacklistedIP.query.get_or_404(entry_id)
    
    blacklist_entry.is_active = False
    db.session.commit()
    
    log_action('IP_UNBLACKLISTED', f'IP {blacklist_entry.ip_address} removido da blacklist', current_user.id)
    
    return jsonify({'message': f'IP {blacklist_entry.ip_address} removido da blacklist'}), 200

@protection_bp.route('/suspicious-activities', methods=['GET'])
@login_required
def get_suspicious_activities():
    """Endpoint para listar atividades suspeitas (apenas admins)"""
    if not current_user.is_admin:
        return jsonify({'error': 'Acesso negado'}), 403
    
    page = request.args.get('page', 1, type=int)
    per_page = request.args.get('per_page', 50, type=int)
    severity = request.args.get('severity')  # Filtro opcional
    resolved = request.args.get('resolved')  # true/false
    
    query = SuspiciousActivity.query
    
    if severity:
        query = query.filter_by(severity=severity)
    
    if resolved is not None:
        is_resolved = resolved.lower() == 'true'
        query = query.filter_by(is_resolved=is_resolved)
    
    activities = query.order_by(SuspiciousActivity.detected_at.desc()).paginate(
        page=page, per_page=per_page, error_out=False
    )
    
    # Processar dados para resposta
    activities_data = []
    for activity in activities.items:
        activity_dict = activity.to_dict()
        
        # Decodificar detalhes JSON
        try:
            activity_dict['details'] = json.loads(activity.details) if activity.details else {}
        except:
            activity_dict['details'] = {}
        
        activities_data.append(activity_dict)
    
    return jsonify({
        'activities': activities_data,
        'total': activities.total,
        'pages': activities.pages,
        'current_page': page,
        'has_next': activities.has_next,
        'has_prev': activities.has_prev
    }), 200

@protection_bp.route('/suspicious-activities/<int:activity_id>/resolve', methods=['POST'])
@login_required
def resolve_suspicious_activity(activity_id):
    """Endpoint para marcar atividade suspeita como resolvida (apenas admins)"""
    if not current_user.is_admin:
        return jsonify({'error': 'Acesso negado'}), 403
    
    activity = SuspiciousActivity.query.get_or_404(activity_id)
    
    activity.is_resolved = True
    activity.resolved_at = datetime.utcnow()
    db.session.commit()
    
    log_action('SUSPICIOUS_ACTIVITY_RESOLVED', f'Atividade suspeita {activity_id} resolvida', current_user.id)
    
    return jsonify({'message': 'Atividade suspeita marcada como resolvida'}), 200

@protection_bp.route('/url-protection/<unique_suffix>', methods=['POST'])
@login_required
def update_url_protection(unique_suffix):
    """Endpoint para atualizar configurações de proteção de uma URL"""
    generated_url = GeneratedURL.query.filter_by(unique_suffix=unique_suffix).first()
    
    if not generated_url:
        return jsonify({'error': 'URL não encontrada'}), 404
    
    # Verificar permissão
    if not current_user.is_admin and generated_url.user_id != current_user.id:
        return jsonify({'error': 'Acesso negado'}), 403
    
    data = request.get_json()
    
    if 'is_protected' in data:
        generated_url.is_protected = data['is_protected']
    
    if 'protection_level' in data:
        valid_levels = ['low', 'medium', 'high']
        if data['protection_level'] in valid_levels:
            generated_url.protection_level = data['protection_level']
        else:
            return jsonify({'error': f'Nível de proteção inválido. Use: {valid_levels}'}), 400
    
    db.session.commit()
    
    log_action('URL_PROTECTION_UPDATED', f'Proteção da URL {generated_url.full_url} atualizada', current_user.id)
    
    return jsonify({
        'message': 'Configurações de proteção atualizadas',
        'url': generated_url.to_dict()
    }), 200

@protection_bp.route('/protection-stats', methods=['GET'])
@login_required
def get_protection_stats():
    """Endpoint para obter estatísticas de proteção"""
    if not current_user.is_admin:
        return jsonify({'error': 'Acesso negado'}), 403
    
    # Estatísticas gerais
    total_cleanings = URLCleaning.query.count()
    successful_cleanings = URLCleaning.query.filter_by(status='completed').count()
    failed_cleanings = URLCleaning.query.filter_by(status='failed').count()
    
    total_blacklisted = BlacklistedIP.query.filter_by(is_active=True).count()
    total_suspicious = SuspiciousActivity.query.count()
    unresolved_suspicious = SuspiciousActivity.query.filter_by(is_resolved=False).count()
    
    # Estatísticas por período (últimos 7 dias)
    week_ago = datetime.utcnow() - timedelta(days=7)
    recent_cleanings = URLCleaning.query.filter(URLCleaning.created_at >= week_ago).count()
    recent_suspicious = SuspiciousActivity.query.filter(SuspiciousActivity.detected_at >= week_ago).count()
    
    # Estatísticas por tipo de limpeza
    cleaning_types = db.session.query(
        URLCleaning.cleaning_type,
        db.func.count(URLCleaning.id).label('count')
    ).group_by(URLCleaning.cleaning_type).all()
    
    # Estatísticas por severidade de atividades suspeitas
    severity_stats = db.session.query(
        SuspiciousActivity.severity,
        db.func.count(SuspiciousActivity.id).label('count')
    ).group_by(SuspiciousActivity.severity).all()
    
    return jsonify({
        'general_stats': {
            'total_cleanings': total_cleanings,
            'successful_cleanings': successful_cleanings,
            'failed_cleanings': failed_cleanings,
            'success_rate': (successful_cleanings / total_cleanings * 100) if total_cleanings > 0 else 0,
            'total_blacklisted_ips': total_blacklisted,
            'total_suspicious_activities': total_suspicious,
            'unresolved_suspicious': unresolved_suspicious
        },
        'recent_stats': {
            'cleanings_last_week': recent_cleanings,
            'suspicious_activities_last_week': recent_suspicious
        },
        'cleaning_types': [{'type': ct[0], 'count': ct[1]} for ct in cleaning_types],
        'severity_distribution': [{'severity': ss[0], 'count': ss[1]} for ss in severity_stats]
    }), 200

