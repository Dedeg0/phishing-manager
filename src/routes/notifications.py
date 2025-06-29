from flask import Blueprint, request, jsonify
from flask_login import login_required, current_user
from src.services.notification_service import NotificationService
from src.models.user import db

notifications_bp = Blueprint('notifications', __name__, url_prefix='/api/notifications')

@notifications_bp.route('/', methods=['GET'])
@login_required
def get_notifications():
    """Obtém notificações do usuário atual"""
    try:
        # Parâmetros de query
        include_read = request.args.get('include_read', 'true').lower() == 'true'
        include_dismissed = request.args.get('include_dismissed', 'false').lower() == 'true'
        limit = min(int(request.args.get('limit', 50)), 100)  # Máximo 100
        
        notifications = NotificationService.get_user_notifications(
            user_id=current_user.id,
            include_read=include_read,
            include_dismissed=include_dismissed,
            limit=limit
        )
        
        return jsonify({
            'success': True,
            'notifications': [n.to_dict() for n in notifications],
            'count': len(notifications)
        })
        
    except Exception as e:
        return jsonify({
            'success': False,
            'message': f'Erro ao buscar notificações: {str(e)}'
        }), 500

@notifications_bp.route('/unread-count', methods=['GET'])
@login_required
def get_unread_count():
    """Obtém contagem de notificações não lidas"""
    try:
        count = NotificationService.get_unread_count(current_user.id)
        
        return jsonify({
            'success': True,
            'unread_count': count
        })
        
    except Exception as e:
        return jsonify({
            'success': False,
            'message': f'Erro ao contar notificações: {str(e)}'
        }), 500

@notifications_bp.route('/<int:notification_id>/read', methods=['POST'])
@login_required
def mark_as_read(notification_id):
    """Marca notificação como lida"""
    try:
        success = NotificationService.mark_as_read(notification_id, current_user.id)
        
        if success:
            return jsonify({
                'success': True,
                'message': 'Notificação marcada como lida'
            })
        else:
            return jsonify({
                'success': False,
                'message': 'Notificação não encontrada'
            }), 404
            
    except Exception as e:
        return jsonify({
            'success': False,
            'message': f'Erro ao marcar como lida: {str(e)}'
        }), 500

@notifications_bp.route('/<int:notification_id>/dismiss', methods=['POST'])
@login_required
def dismiss_notification(notification_id):
    """Descarta notificação"""
    try:
        success = NotificationService.dismiss_notification(notification_id, current_user.id)
        
        if success:
            return jsonify({
                'success': True,
                'message': 'Notificação descartada'
            })
        else:
            return jsonify({
                'success': False,
                'message': 'Notificação não encontrada'
            }), 404
            
    except Exception as e:
        return jsonify({
            'success': False,
            'message': f'Erro ao descartar notificação: {str(e)}'
        }), 500

@notifications_bp.route('/mark-all-read', methods=['POST'])
@login_required
def mark_all_as_read():
    """Marca todas as notificações como lidas"""
    try:
        count = NotificationService.mark_all_as_read(current_user.id)
        
        return jsonify({
            'success': True,
            'message': f'{count} notificações marcadas como lidas',
            'marked_count': count
        })
        
    except Exception as e:
        return jsonify({
            'success': False,
            'message': f'Erro ao marcar todas como lidas: {str(e)}'
        }), 500

@notifications_bp.route('/create', methods=['POST'])
@login_required
def create_notification():
    """Cria uma nova notificação (para testes ou uso administrativo)"""
    try:
        data = request.get_json()
        
        if not data:
            return jsonify({
                'success': False,
                'message': 'Dados não fornecidos'
            }), 400
        
        # Validar campos obrigatórios
        required_fields = ['title', 'message']
        for field in required_fields:
            if field not in data:
                return jsonify({
                    'success': False,
                    'message': f'Campo obrigatório: {field}'
                }), 400
        
        # Criar notificação
        notification = NotificationService.create_notification(
            user_id=current_user.id,
            title=data['title'],
            message=data['message'],
            notification_type=data.get('type', 'info'),
            priority=data.get('priority', 'normal'),
            data=data.get('data'),
            action_url=data.get('action_url'),
            action_text=data.get('action_text'),
            expires_in_hours=data.get('expires_in_hours')
        )
        
        if notification:
            return jsonify({
                'success': True,
                'message': 'Notificação criada com sucesso',
                'notification': notification.to_dict()
            })
        else:
            return jsonify({
                'success': False,
                'message': 'Erro ao criar notificação'
            }), 500
            
    except Exception as e:
        return jsonify({
            'success': False,
            'message': f'Erro ao criar notificação: {str(e)}'
        }), 500

@notifications_bp.route('/test', methods=['POST'])
@login_required
def create_test_notifications():
    """Cria notificações de teste para demonstração"""
    try:
        # Criar diferentes tipos de notificações de teste
        test_notifications = [
            {
                'title': 'Nova URL Gerada',
                'message': 'Sua URL de phishing foi criada com sucesso',
                'type': 'success',
                'action_url': '/urls',
                'action_text': 'Ver URLs'
            },
            {
                'title': 'Visitante Capturado',
                'message': 'Dados capturados de 192.168.1.100',
                'type': 'info',
                'priority': 'high',
                'action_url': '/history',
                'action_text': 'Ver Histórico'
            },
            {
                'title': 'Bot Detectado',
                'message': 'Bot bloqueado tentando acessar sua URL',
                'type': 'warning',
                'priority': 'high',
                'action_url': '/protection',
                'action_text': 'Ver Proteções'
            },
            {
                'title': 'Créditos Baixos',
                'message': 'Você tem apenas 5 créditos restantes',
                'type': 'warning',
                'priority': 'high',
                'action_url': '/settings',
                'action_text': 'Gerenciar Conta'
            },
            {
                'title': 'Alerta de Segurança',
                'message': 'Atividade suspeita detectada em sua conta',
                'type': 'error',
                'priority': 'urgent',
                'action_url': '/security',
                'action_text': 'Ver Detalhes'
            }
        ]
        
        created_count = 0
        for notif_data in test_notifications:
            notification = NotificationService.create_notification(
                user_id=current_user.id,
                title=notif_data['title'],
                message=notif_data['message'],
                notification_type=notif_data['type'],
                priority=notif_data.get('priority', 'normal'),
                action_url=notif_data.get('action_url'),
                action_text=notif_data.get('action_text')
            )
            if notification:
                created_count += 1
        
        return jsonify({
            'success': True,
            'message': f'{created_count} notificações de teste criadas',
            'created_count': created_count
        })
        
    except Exception as e:
        return jsonify({
            'success': False,
            'message': f'Erro ao criar notificações de teste: {str(e)}'
        }), 500

# Rota para limpeza de notificações expiradas (pode ser chamada por cron job)
@notifications_bp.route('/cleanup', methods=['POST'])
def cleanup_expired():
    """Remove notificações expiradas (endpoint para manutenção)"""
    try:
        # Esta rota poderia ter autenticação de admin ou ser chamada internamente
        count = NotificationService.cleanup_expired_notifications()
        
        return jsonify({
            'success': True,
            'message': f'{count} notificações expiradas removidas',
            'cleaned_count': count
        })
        
    except Exception as e:
        return jsonify({
            'success': False,
            'message': f'Erro na limpeza: {str(e)}'
        }), 500

