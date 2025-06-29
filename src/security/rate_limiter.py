"""
Sistema de rate limiting para prevenir ataques de força bruta e spam
"""

from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
from flask import request, jsonify, current_app
from functools import wraps
import time
from typing import Dict, Optional
from src.models.user import db, Log
from src.services.cache_service import cache_service


class SecurityRateLimiter:
    """Sistema de rate limiting com funcionalidades de segurança avançadas"""
    
    def __init__(self):
        self.limiter = None
        self.failed_attempts = {}  # Cache local para tentativas falhadas
        self.blocked_ips = set()   # IPs temporariamente bloqueados
    
    def init_app(self, app):
        """Inicializa o rate limiter com a aplicação Flask"""
        self.limiter = Limiter(
            app=app,
            key_func=get_remote_address,
            default_limits=["1000 per hour", "100 per minute"],
            storage_uri="memory://",
            strategy="fixed-window"
        )
        
        # Configurar handlers de erro
        @app.errorhandler(429)
        def ratelimit_handler(e):
            return jsonify({
                "error": "Muitas tentativas. Tente novamente mais tarde.",
                "retry_after": e.retry_after
            }), 429
    
    def get_client_identifier(self) -> str:
        """Obtém identificador único do cliente (IP + User-Agent)"""
        ip = get_remote_address()
        user_agent = request.headers.get('User-Agent', '')[:100]  # Limitar tamanho
        return f"{ip}:{hash(user_agent)}"
    
    def is_ip_blocked(self, ip: str = None) -> bool:
        """Verifica se um IP está bloqueado"""
        if ip is None:
            ip = get_remote_address()
        
        # Verificar cache local
        if ip in self.blocked_ips:
            return True
        
        # Verificar cache distribuído
        cache_key = f"blocked_ip:{ip}"
        return cache_service.get(cache_key) is not None
    
    def block_ip(self, ip: str = None, duration: int = 3600) -> None:
        """Bloqueia um IP temporariamente"""
        if ip is None:
            ip = get_remote_address()
        
        self.blocked_ips.add(ip)
        cache_key = f"blocked_ip:{ip}"
        cache_service.set(cache_key, "blocked", ex=duration)
        
        # Log do bloqueio
        self._log_security_event("IP_BLOCKED", f"IP {ip} bloqueado por {duration} segundos")
    
    def unblock_ip(self, ip: str) -> None:
        """Remove bloqueio de um IP"""
        self.blocked_ips.discard(ip)
        cache_key = f"blocked_ip:{ip}"
        cache_service.delete(cache_key)
        
        self._log_security_event("IP_UNBLOCKED", f"IP {ip} desbloqueado")
    
    def record_failed_attempt(self, identifier: str, attempt_type: str = "login") -> int:
        """Registra uma tentativa falhada e retorna o número total de tentativas"""
        cache_key = f"failed_attempts:{attempt_type}:{identifier}"
        
        # Obter tentativas atuais
        attempts = cache_service.get(cache_key) or 0
        attempts += 1
        
        # Armazenar com expiração de 1 hora
        cache_service.set(cache_key, attempts, ex=3600)
        
        # Log da tentativa falhada
        self._log_security_event(
            f"FAILED_{attempt_type.upper()}_ATTEMPT",
            f"Tentativa falhada #{attempts} para {identifier}"
        )
        
        return attempts
    
    def get_failed_attempts(self, identifier: str, attempt_type: str = "login") -> int:
        """Obtém número de tentativas falhadas para um identificador"""
        cache_key = f"failed_attempts:{attempt_type}:{identifier}"
        return cache_service.get(cache_key) or 0
    
    def clear_failed_attempts(self, identifier: str, attempt_type: str = "login") -> None:
        """Limpa tentativas falhadas para um identificador"""
        cache_key = f"failed_attempts:{attempt_type}:{identifier}"
        cache_service.delete(cache_key)
    
    def check_brute_force_protection(self, identifier: str, max_attempts: int = 5) -> bool:
        """
        Verifica proteção contra força bruta
        
        Returns:
            True se deve bloquear, False se pode continuar
        """
        attempts = self.get_failed_attempts(identifier)
        
        if attempts >= max_attempts:
            # Bloquear IP se muitas tentativas (apenas se em contexto de requisição)
            try:
                ip = get_remote_address()
                self.block_ip(ip, duration=1800)  # 30 minutos
                
                self._log_security_event(
                    "BRUTE_FORCE_DETECTED",
                    f"Ataque de força bruta detectado para {identifier}. IP {ip} bloqueado."
                )
            except RuntimeError:
                # Fora do contexto de requisição (ex: testes)
                self._log_security_event(
                    "BRUTE_FORCE_DETECTED",
                    f"Ataque de força bruta detectado para {identifier}."
                )
            
            return True
        
        return False
    
    def _log_security_event(self, action: str, details: str) -> None:
        """Registra evento de segurança no log"""
        try:
            # Obter IP apenas se em contexto de requisição
            try:
                ip_address = get_remote_address()
                user_agent = request.headers.get('User-Agent', '')[:255]
            except RuntimeError:
                # Fora do contexto de requisição
                ip_address = None
                user_agent = None
            
            log = Log(
                user_id=None,
                action=action,
                details=details,
                ip_address=ip_address,
                user_agent=user_agent
            )
            db.session.add(log)
            db.session.commit()
        except Exception as e:
            # Fallback para log do Flask se disponível
            try:
                current_app.logger.error(f"Erro ao registrar log de segurança: {e}")
            except RuntimeError:
                # Fora do contexto da aplicação também
                print(f"Erro ao registrar log de segurança: {e}")


# Instância global do rate limiter
security_rate_limiter = SecurityRateLimiter()


def rate_limit(limit: str):
    """Decorator para aplicar rate limiting a rotas específicas"""
    def decorator(f):
        @wraps(f)
        def decorated_function(*args, **kwargs):
            # Verificar se IP está bloqueado
            if security_rate_limiter.is_ip_blocked():
                return jsonify({
                    "error": "IP bloqueado devido a atividade suspeita"
                }), 403
            
            # Aplicar rate limiting padrão
            return security_rate_limiter.limiter.limit(limit)(f)(*args, **kwargs)
        
        return decorated_function
    return decorator


def brute_force_protection(max_attempts: int = 5, identifier_func=None):
    """
    Decorator para proteção contra força bruta
    
    Args:
        max_attempts: Número máximo de tentativas antes de bloquear
        identifier_func: Função para obter identificador único (padrão: IP + User-Agent)
    """
    def decorator(f):
        @wraps(f)
        def decorated_function(*args, **kwargs):
            # Obter identificador
            if identifier_func:
                identifier = identifier_func()
            else:
                identifier = security_rate_limiter.get_client_identifier()
            
            # Verificar proteção contra força bruta
            if security_rate_limiter.check_brute_force_protection(identifier, max_attempts):
                return jsonify({
                    "error": "Muitas tentativas falhadas. Acesso temporariamente bloqueado."
                }), 429
            
            return f(*args, **kwargs)
        
        return decorated_function
    return decorator


def login_rate_limit():
    """Rate limiting específico para login"""
    return rate_limit("10 per minute")


def registration_rate_limit():
    """Rate limiting específico para registro"""
    return rate_limit("5 per minute")


def api_rate_limit():
    """Rate limiting geral para API"""
    return rate_limit("100 per minute")


def admin_rate_limit():
    """Rate limiting para operações administrativas"""
    return rate_limit("50 per minute")


def password_reset_rate_limit():
    """Rate limiting para reset de senha"""
    return rate_limit("3 per hour")


def otp_rate_limit():
    """Rate limiting para solicitação de OTP"""
    return rate_limit("10 per hour")

