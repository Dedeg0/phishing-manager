"""
Sistema de segurança HTTP com headers de segurança e proteções
"""

from flask_talisman import Talisman
from flask import request, jsonify, current_app
from functools import wraps
import hashlib
import hmac
import time
from typing import Optional


class HTTPSecurityManager:
    """Gerenciador de segurança HTTP"""
    
    def __init__(self):
        self.talisman = None
        self.csrf_tokens = {}  # Cache de tokens CSRF
    
    def init_app(self, app):
        """Inicializa segurança HTTP com a aplicação Flask"""
        
        # Configuração do Content Security Policy
        csp = {
            'default-src': "'self'",
            'script-src': [
                "'self'",
                "'unsafe-inline'",  # Necessário para alguns frameworks JS
                "https://cdn.jsdelivr.net",
                "https://cdnjs.cloudflare.com"
            ],
            'style-src': [
                "'self'",
                "'unsafe-inline'",
                "https://cdn.jsdelivr.net",
                "https://cdnjs.cloudflare.com"
            ],
            'img-src': [
                "'self'",
                "data:",
                "https:"
            ],
            'font-src': [
                "'self'",
                "https://cdn.jsdelivr.net",
                "https://cdnjs.cloudflare.com"
            ],
            'connect-src': [
                "'self'",
                "https://api.telegram.org"  # Para integração com Telegram
            ],
            'frame-ancestors': "'none'",
            'base-uri': "'self'",
            'object-src': "'none'"
        }
        
        # Configurar Talisman
        self.talisman = Talisman(
            app,
            force_https=False,  # Configurar como True em produção
            strict_transport_security=True,
            strict_transport_security_max_age=31536000,  # 1 ano
            content_security_policy=csp,
            content_security_policy_nonce_in=['script-src', 'style-src'],
            referrer_policy='strict-origin-when-cross-origin',
            feature_policy={
                'geolocation': "'none'",
                'microphone': "'none'",
                'camera': "'none'",
                'payment': "'none'",
                'usb': "'none'"
            }
        )
        
        # Adicionar headers customizados
        @app.after_request
        def add_security_headers(response):
            # X-Content-Type-Options
            response.headers['X-Content-Type-Options'] = 'nosniff'
            
            # X-Frame-Options (redundante com CSP, mas boa prática)
            response.headers['X-Frame-Options'] = 'DENY'
            
            # X-XSS-Protection (legacy, mas ainda útil)
            response.headers['X-XSS-Protection'] = '1; mode=block'
            
            # Permissions Policy (substituto do Feature Policy)
            response.headers['Permissions-Policy'] = (
                'geolocation=(), microphone=(), camera=(), '
                'payment=(), usb=(), magnetometer=(), gyroscope=()'
            )
            
            # Server header (ocultar informações do servidor)
            response.headers['Server'] = 'Phishing Manager'
            
            # Cache control para rotas sensíveis
            if request.endpoint and any(sensitive in request.endpoint for sensitive in 
                                      ['login', 'admin', 'profile', 'password']):
                response.headers['Cache-Control'] = 'no-cache, no-store, must-revalidate'
                response.headers['Pragma'] = 'no-cache'
                response.headers['Expires'] = '0'
            
            return response
    
    def generate_csrf_token(self, user_id: str) -> str:
        """Gera token CSRF para um usuário"""
        timestamp = str(int(time.time()))
        secret_key = current_app.config.get('SECRET_KEY', 'default-secret')
        
        # Criar token baseado em user_id, timestamp e chave secreta
        token_data = f"{user_id}:{timestamp}"
        signature = hmac.new(
            secret_key.encode(),
            token_data.encode(),
            hashlib.sha256
        ).hexdigest()
        
        token = f"{token_data}:{signature}"
        
        # Armazenar token (com expiração de 1 hora)
        self.csrf_tokens[token] = time.time() + 3600
        
        return token
    
    def verify_csrf_token(self, token: str, user_id: str) -> bool:
        """Verifica token CSRF"""
        if not token:
            return False
        
        try:
            # Verificar se token existe e não expirou
            if token not in self.csrf_tokens:
                return False
            
            if time.time() > self.csrf_tokens[token]:
                # Token expirado
                del self.csrf_tokens[token]
                return False
            
            # Verificar assinatura
            parts = token.split(':')
            if len(parts) != 3:
                return False
            
            token_user_id, timestamp, signature = parts
            
            if token_user_id != str(user_id):
                return False
            
            secret_key = current_app.config.get('SECRET_KEY', 'default-secret')
            expected_signature = hmac.new(
                secret_key.encode(),
                f"{token_user_id}:{timestamp}".encode(),
                hashlib.sha256
            ).hexdigest()
            
            return hmac.compare_digest(signature, expected_signature)
            
        except Exception:
            return False
    
    def cleanup_expired_tokens(self):
        """Remove tokens CSRF expirados"""
        current_time = time.time()
        expired_tokens = [
            token for token, expiry in self.csrf_tokens.items()
            if current_time > expiry
        ]
        
        for token in expired_tokens:
            del self.csrf_tokens[token]


# Instância global do gerenciador de segurança HTTP
http_security = HTTPSecurityManager()


def require_csrf_token(f):
    """Decorator para exigir token CSRF válido"""
    @wraps(f)
    def decorated_function(*args, **kwargs):
        # Pular verificação CSRF para métodos GET
        if request.method == 'GET':
            return f(*args, **kwargs)
        
        # Obter token do header ou form data
        csrf_token = request.headers.get('X-CSRF-Token') or request.form.get('csrf_token')
        
        if not csrf_token:
            return jsonify({"error": "Token CSRF obrigatório"}), 400
        
        # Verificar token (assumindo que user_id está disponível)
        from flask_login import current_user
        if not current_user.is_authenticated:
            return jsonify({"error": "Autenticação obrigatória"}), 401
        
        if not http_security.verify_csrf_token(csrf_token, current_user.id):
            return jsonify({"error": "Token CSRF inválido"}), 403
        
        return f(*args, **kwargs)
    
    return decorated_function


def secure_headers(f):
    """Decorator para adicionar headers de segurança específicos"""
    @wraps(f)
    def decorated_function(*args, **kwargs):
        response = f(*args, **kwargs)
        
        # Adicionar headers específicos se necessário
        if hasattr(response, 'headers'):
            response.headers['X-API-Version'] = '1.0'
            response.headers['X-Rate-Limit-Remaining'] = '100'  # Placeholder
        
        return response
    
    return decorated_function


def validate_content_type(allowed_types=None):
    """Decorator para validar Content-Type da requisição"""
    if allowed_types is None:
        allowed_types = ['application/json']
    
    def decorator(f):
        @wraps(f)
        def decorated_function(*args, **kwargs):
            content_type = request.content_type
            
            if content_type not in allowed_types:
                return jsonify({
                    "error": f"Content-Type não suportado. Tipos aceitos: {', '.join(allowed_types)}"
                }), 415
            
            return f(*args, **kwargs)
        
        return decorated_function
    return decorator


def prevent_timing_attacks(f):
    """Decorator para prevenir ataques de timing"""
    @wraps(f)
    def decorated_function(*args, **kwargs):
        start_time = time.time()
        
        try:
            result = f(*args, **kwargs)
        except Exception as e:
            # Garantir tempo mínimo mesmo em caso de erro
            elapsed = time.time() - start_time
            if elapsed < 0.1:  # Mínimo 100ms
                time.sleep(0.1 - elapsed)
            raise e
        
        # Garantir tempo mínimo de resposta
        elapsed = time.time() - start_time
        if elapsed < 0.1:  # Mínimo 100ms
            time.sleep(0.1 - elapsed)
        
        return result
    
    return decorated_function


def validate_request_size(max_size_mb=10):
    """Decorator para validar tamanho da requisição"""
    def decorator(f):
        @wraps(f)
        def decorated_function(*args, **kwargs):
            content_length = request.content_length
            
            if content_length and content_length > max_size_mb * 1024 * 1024:
                return jsonify({
                    "error": f"Requisição muito grande. Máximo: {max_size_mb}MB"
                }), 413
            
            return f(*args, **kwargs)
        
        return decorated_function
    return decorator

