import os
import socket
import platform
import psutil
from datetime import datetime
from flask import request
import json

class EnvironmentConfig:
    """Sistema de configuração e detecção de ambiente"""
    
    def __init__(self):
        self.environment = self.detect_environment()
        self.config = self.load_config()
        self.metrics = {}
    
    def detect_environment(self):
        """Detecta se está rodando em modo local ou online"""
        try:
            # Verificar variáveis de ambiente
            if os.getenv('FLASK_ENV') == 'production':
                return 'online'
            
            if os.getenv('DEPLOYMENT_MODE') == 'production':
                return 'online'
            
            # Verificar se está em um servidor conhecido
            hostname = socket.gethostname()
            if any(server in hostname.lower() for server in ['heroku', 'aws', 'azure', 'gcp', 'digitalocean', 'linode']):
                return 'online'
            
            # Verificar IP público
            try:
                import requests
                response = requests.get('https://api.ipify.org', timeout=5)
                public_ip = response.text.strip()
                
                # Se conseguiu obter IP público e não é localhost
                if public_ip and not public_ip.startswith('127.') and not public_ip.startswith('192.168.'):
                    return 'online'
            except:
                pass
            
            # Verificar se está rodando na porta padrão de produção
            if os.getenv('PORT') and int(os.getenv('PORT', 5000)) != 5000:
                return 'online'
            
            # Por padrão, assumir local
            return 'local'
            
        except Exception as e:
            print(f"Erro ao detectar ambiente: {e}")
            return 'local'
    
    def load_config(self):
        """Carrega configurações baseadas no ambiente"""
        base_config = {
            'SECRET_KEY': os.getenv('SECRET_KEY', 'dev-secret-key-change-in-production'),
            'DEBUG': False,
            'TESTING': False,
            'SQLALCHEMY_TRACK_MODIFICATIONS': False,
            'CACHE_TYPE': 'SimpleCache',
            'CACHE_DEFAULT_TIMEOUT': 300,
            'MAX_CONTENT_LENGTH': 16 * 1024 * 1024,  # 16MB
            'PERMANENT_SESSION_LIFETIME': 3600,  # 1 hora
        }
        
        if self.environment == 'local':
            local_config = {
                'DEBUG': True,
                'SQLALCHEMY_DATABASE_URI': f'sqlite:///{os.path.join(os.path.dirname(__file__), "..", "database", "app.db")}',
                'HOST': '127.0.0.1',
                'PORT': 5000,
                'BASE_URL': 'http://localhost:5000',
                'TELEGRAM_WEBHOOK_URL': None,  # Polling mode
                'LOG_LEVEL': 'DEBUG',
                'RATE_LIMIT': '1000 per hour',
                'ENABLE_METRICS': True,
                'ENABLE_PROFILING': True,
            }
            base_config.update(local_config)
            
        else:  # online
            online_config = {
                'DEBUG': False,
                'SQLALCHEMY_DATABASE_URI': os.getenv('DATABASE_URL', f'sqlite:///{os.path.join(os.path.dirname(__file__), "..", "database", "app.db")}'),
                'HOST': '0.0.0.0',
                'PORT': int(os.getenv('PORT', 5000)),
                'BASE_URL': os.getenv('BASE_URL', 'https://your-domain.com'),
                'TELEGRAM_WEBHOOK_URL': os.getenv('TELEGRAM_WEBHOOK_URL'),
                'LOG_LEVEL': 'INFO',
                'RATE_LIMIT': '100 per hour',
                'ENABLE_METRICS': True,
                'ENABLE_PROFILING': False,
                'CACHE_TYPE': os.getenv('CACHE_TYPE', 'SimpleCache'),
            }
            base_config.update(online_config)
        
        return base_config
    
    def get_system_metrics(self):
        """Obtém métricas do sistema"""
        try:
            cpu_percent = psutil.cpu_percent(interval=1)
            memory = psutil.virtual_memory()
            disk = psutil.disk_usage('/')
            
            metrics = {
                'timestamp': datetime.utcnow().isoformat(),
                'environment': self.environment,
                'system': {
                    'platform': platform.platform(),
                    'python_version': platform.python_version(),
                    'hostname': socket.gethostname(),
                    'cpu_count': psutil.cpu_count(),
                    'cpu_percent': cpu_percent,
                    'memory': {
                        'total': memory.total,
                        'available': memory.available,
                        'percent': memory.percent,
                        'used': memory.used
                    },
                    'disk': {
                        'total': disk.total,
                        'used': disk.used,
                        'free': disk.free,
                        'percent': (disk.used / disk.total) * 100
                    }
                },
                'network': self.get_network_info(),
                'process': self.get_process_info()
            }
            
            return metrics
            
        except Exception as e:
            return {
                'timestamp': datetime.utcnow().isoformat(),
                'environment': self.environment,
                'error': str(e)
            }
    
    def get_network_info(self):
        """Obtém informações de rede"""
        try:
            network_info = {
                'interfaces': [],
                'connections': len(psutil.net_connections()),
            }
            
            # Informações das interfaces de rede
            for interface, addrs in psutil.net_if_addrs().items():
                interface_info = {
                    'name': interface,
                    'addresses': []
                }
                
                for addr in addrs:
                    if addr.family == socket.AF_INET:  # IPv4
                        interface_info['addresses'].append({
                            'type': 'IPv4',
                            'address': addr.address,
                            'netmask': addr.netmask
                        })
                
                if interface_info['addresses']:
                    network_info['interfaces'].append(interface_info)
            
            return network_info
            
        except Exception as e:
            return {'error': str(e)}
    
    def get_process_info(self):
        """Obtém informações do processo atual"""
        try:
            process = psutil.Process()
            
            return {
                'pid': process.pid,
                'name': process.name(),
                'status': process.status(),
                'create_time': process.create_time(),
                'cpu_percent': process.cpu_percent(),
                'memory_info': {
                    'rss': process.memory_info().rss,
                    'vms': process.memory_info().vms,
                    'percent': process.memory_percent()
                },
                'num_threads': process.num_threads(),
                'connections': len(process.connections())
            }
            
        except Exception as e:
            return {'error': str(e)}
    
    def get_application_metrics(self, app):
        """Obtém métricas específicas da aplicação"""
        try:
            from src.models.user import User, GeneratedURL, Visitor, CapturedCredential, Notification
            
            metrics = {
                'timestamp': datetime.utcnow().isoformat(),
                'environment': self.environment,
                'database': {
                    'users': {
                        'total': User.query.count(),
                        'active': User.query.filter_by(is_active=True).count(),
                        'admins': User.query.filter_by(is_admin=True).count()
                    },
                    'urls': {
                        'total': GeneratedURL.query.count(),
                        'active': GeneratedURL.query.filter_by(is_active=True).count()
                    },
                    'visitors': {
                        'total': Visitor.query.count(),
                        'unique_ips': Visitor.query.distinct(Visitor.ip_address).count()
                    },
                    'credentials': {
                        'total': CapturedCredential.query.count()
                    },
                    'notifications': {
                        'total': Notification.query.count(),
                        'unread': Notification.query.filter_by(is_read=False).count()
                    }
                },
                'flask': {
                    'debug': app.debug,
                    'testing': app.testing,
                    'secret_key_set': bool(app.secret_key),
                    'blueprints': list(app.blueprints.keys()),
                    'url_rules': len(app.url_map._rules)
                }
            }
            
            return metrics
            
        except Exception as e:
            return {
                'timestamp': datetime.utcnow().isoformat(),
                'environment': self.environment,
                'error': str(e)
            }
    
    def get_health_status(self, app):
        """Verifica o status de saúde da aplicação"""
        health = {
            'timestamp': datetime.utcnow().isoformat(),
            'environment': self.environment,
            'status': 'healthy',
            'checks': {}
        }
        
        try:
            # Verificar banco de dados
            from src.models.user import db
            db.session.execute('SELECT 1')
            health['checks']['database'] = {'status': 'ok', 'message': 'Database connection successful'}
        except Exception as e:
            health['checks']['database'] = {'status': 'error', 'message': str(e)}
            health['status'] = 'unhealthy'
        
        try:
            # Verificar cache
            from src.services.cache_service import cache_service
            cache_info = cache_service.get_cache_info()
            health['checks']['cache'] = {'status': 'ok', 'message': f"Cache active: {cache_info['type']}"}
        except Exception as e:
            health['checks']['cache'] = {'status': 'error', 'message': str(e)}
            health['status'] = 'degraded' if health['status'] == 'healthy' else 'unhealthy'
        
        try:
            # Verificar sistema de arquivos
            import tempfile
            with tempfile.NamedTemporaryFile(delete=True) as tmp:
                tmp.write(b'test')
                tmp.flush()
            health['checks']['filesystem'] = {'status': 'ok', 'message': 'Filesystem writable'}
        except Exception as e:
            health['checks']['filesystem'] = {'status': 'error', 'message': str(e)}
            health['status'] = 'degraded' if health['status'] == 'healthy' else 'unhealthy'
        
        # Verificar recursos do sistema
        try:
            memory = psutil.virtual_memory()
            disk = psutil.disk_usage('/')
            
            if memory.percent > 90:
                health['checks']['memory'] = {'status': 'warning', 'message': f'High memory usage: {memory.percent}%'}
                health['status'] = 'degraded' if health['status'] == 'healthy' else health['status']
            else:
                health['checks']['memory'] = {'status': 'ok', 'message': f'Memory usage: {memory.percent}%'}
            
            if (disk.used / disk.total) * 100 > 90:
                health['checks']['disk'] = {'status': 'warning', 'message': f'High disk usage: {(disk.used / disk.total) * 100:.1f}%'}
                health['status'] = 'degraded' if health['status'] == 'healthy' else health['status']
            else:
                health['checks']['disk'] = {'status': 'ok', 'message': f'Disk usage: {(disk.used / disk.total) * 100:.1f}%'}
                
        except Exception as e:
            health['checks']['system_resources'] = {'status': 'error', 'message': str(e)}
        
        return health
    
    def log_request_metrics(self, request, response, duration):
        """Registra métricas de requisições"""
        try:
            metrics = {
                'timestamp': datetime.utcnow().isoformat(),
                'environment': self.environment,
                'request': {
                    'method': request.method,
                    'path': request.path,
                    'endpoint': request.endpoint,
                    'remote_addr': request.remote_addr,
                    'user_agent': request.headers.get('User-Agent', ''),
                    'content_length': request.content_length or 0
                },
                'response': {
                    'status_code': response.status_code,
                    'content_length': response.content_length or 0
                },
                'performance': {
                    'duration_ms': duration * 1000,
                    'duration_seconds': duration
                }
            }
            
            # Armazenar métricas (em produção, enviar para sistema de monitoramento)
            if not hasattr(self, 'request_metrics'):
                self.request_metrics = []
            
            self.request_metrics.append(metrics)
            
            # Manter apenas as últimas 1000 requisições
            if len(self.request_metrics) > 1000:
                self.request_metrics = self.request_metrics[-1000:]
            
            return metrics
            
        except Exception as e:
            print(f"Erro ao registrar métricas de requisição: {e}")
            return None
    
    def get_request_metrics_summary(self):
        """Obtém resumo das métricas de requisições"""
        if not hasattr(self, 'request_metrics') or not self.request_metrics:
            return {'message': 'Nenhuma métrica de requisição disponível'}
        
        try:
            metrics = self.request_metrics
            total_requests = len(metrics)
            
            # Calcular estatísticas
            durations = [m['performance']['duration_ms'] for m in metrics]
            status_codes = [m['response']['status_code'] for m in metrics]
            methods = [m['request']['method'] for m in metrics]
            
            summary = {
                'total_requests': total_requests,
                'avg_duration_ms': sum(durations) / len(durations) if durations else 0,
                'min_duration_ms': min(durations) if durations else 0,
                'max_duration_ms': max(durations) if durations else 0,
                'status_codes': {},
                'methods': {},
                'environment': self.environment
            }
            
            # Contar status codes
            for code in set(status_codes):
                summary['status_codes'][str(code)] = status_codes.count(code)
            
            # Contar métodos
            for method in set(methods):
                summary['methods'][method] = methods.count(method)
            
            return summary
            
        except Exception as e:
            return {'error': str(e)}
    
    def export_config(self):
        """Exporta configuração atual"""
        return {
            'environment': self.environment,
            'config': {k: v for k, v in self.config.items() if 'SECRET' not in k and 'PASSWORD' not in k},
            'system_info': {
                'platform': platform.platform(),
                'python_version': platform.python_version(),
                'hostname': socket.gethostname()
            }
        }

# Instância global
env_config = EnvironmentConfig()

