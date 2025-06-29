"""
Sistema de logs de segurança centralizado
"""

import json
from datetime import datetime
from flask import request, current_app
from flask_login import current_user
from src.models.user import db, Log
from typing import Dict, Any, Optional
import hashlib


class SecurityLogger:
    """Sistema de logs de segurança com categorização e análise de risco"""
    
    # Níveis de severidade
    SEVERITY_INFO = 'info'
    SEVERITY_WARNING = 'warning'
    SEVERITY_ERROR = 'error'
    SEVERITY_CRITICAL = 'critical'
    
    # Categorias de eventos
    CATEGORY_LOGIN = 'login'
    CATEGORY_ADMIN = 'admin'
    CATEGORY_SECURITY = 'security'
    CATEGORY_API = 'api'
    CATEGORY_2FA = '2fa'
    CATEGORY_PASSWORD = 'password'
    CATEGORY_RATE_LIMIT = 'rate_limit'
    CATEGORY_GENERAL = 'general'
    
    # Scores de risco por ação
    RISK_SCORES = {
        'LOGIN_SUCCESS': 0,
        'LOGIN_FAILED': 30,
        'LOGIN_BLOCKED_BANNED': 50,
        'LOGIN_BLOCKED_INACTIVE': 40,
        'BRUTE_FORCE_DETECTED': 90,
        'IP_BLOCKED': 80,
        'ACCOUNT_LOCKED': 70,
        'PASSWORD_CHANGED': 10,
        'PASSWORD_RESET_REQUESTED': 20,
        '2FA_ENABLED': 0,
        '2FA_DISABLED': 30,
        '2FA_FAILED': 40,
        'ADMIN_ACTION': 20,
        'ADMIN_USER_CREATED': 30,
        'ADMIN_USER_DELETED': 50,
        'ADMIN_PERMISSIONS_CHANGED': 60,
        'SUSPICIOUS_ACTIVITY': 70,
        'SECURITY_VIOLATION': 80,
        'CSRF_TOKEN_INVALID': 60,
        'RATE_LIMIT_EXCEEDED': 50,
        'UNAUTHORIZED_ACCESS': 70,
        'SQL_INJECTION_ATTEMPT': 95,
        'XSS_ATTEMPT': 85,
        'FILE_UPLOAD_BLOCKED': 60,
        'MALICIOUS_REQUEST': 80
    }
    
    def __init__(self):
        self.session_cache = {}  # Cache de sessões para correlação
    
    def log_security_event(
        self,
        action: str,
        details: str = None,
        user_id: int = None,
        severity: str = SEVERITY_INFO,
        category: str = CATEGORY_GENERAL,
        metadata: Dict[str, Any] = None,
        risk_score: int = None
    ) -> None:
        """
        Registra evento de segurança
        
        Args:
            action: Ação realizada
            details: Detalhes do evento
            user_id: ID do usuário (opcional)
            severity: Nível de severidade
            category: Categoria do evento
            metadata: Metadados adicionais
            risk_score: Score de risco (calculado automaticamente se não fornecido)
        """
        try:
            # Obter informações da requisição atual
            ip_address = self._get_client_ip()
            user_agent = request.headers.get('User-Agent', '')[:255] if request else None
            session_id = self._get_session_id()
            
            # Calcular score de risco se não fornecido
            if risk_score is None:
                risk_score = self.RISK_SCORES.get(action, 0)
            
            # Preparar metadados
            if metadata is None:
                metadata = {}
            
            # Adicionar informações contextuais aos metadados
            metadata.update({
                'request_method': request.method if request else None,
                'request_path': request.path if request else None,
                'request_args': dict(request.args) if request else None,
                'timestamp_iso': datetime.utcnow().isoformat(),
                'user_authenticated': current_user.is_authenticated if current_user else False
            })
            
            # Criar log
            log = Log(
                user_id=user_id or (current_user.id if current_user and current_user.is_authenticated else None),
                action=action,
                details=details,
                ip_address=ip_address,
                user_agent=user_agent,
                session_id=session_id,
                severity=severity,
                category=category,
                risk_score=risk_score,
                extra_data=json.dumps(metadata) if metadata else None
            )
            
            db.session.add(log)
            db.session.commit()
            
            # Log crítico também no arquivo de log do Flask
            if severity == self.SEVERITY_CRITICAL:
                current_app.logger.critical(f"SECURITY CRITICAL: {action} - {details}")
            elif severity == self.SEVERITY_ERROR:
                current_app.logger.error(f"SECURITY ERROR: {action} - {details}")
            elif severity == self.SEVERITY_WARNING:
                current_app.logger.warning(f"SECURITY WARNING: {action} - {details}")
            
            # Verificar se precisa de ação automática
            self._check_automatic_actions(action, risk_score, ip_address, user_id)
            
        except Exception as e:
            # Fallback para log do Flask se falhar
            current_app.logger.error(f"Erro ao registrar log de segurança: {e}")
    
    def log_login_attempt(self, username: str, success: bool, reason: str = None) -> None:
        """Registra tentativa de login"""
        if success:
            self.log_security_event(
                action='LOGIN_SUCCESS',
                details=f'Login bem-sucedido para usuário: {username}',
                category=self.CATEGORY_LOGIN,
                severity=self.SEVERITY_INFO
            )
        else:
            self.log_security_event(
                action='LOGIN_FAILED',
                details=f'Login falhado para usuário: {username}. Motivo: {reason or "Credenciais inválidas"}',
                category=self.CATEGORY_LOGIN,
                severity=self.SEVERITY_WARNING,
                metadata={'failed_username': username, 'failure_reason': reason}
            )
    
    def log_admin_action(self, action: str, target_user: str = None, details: str = None) -> None:
        """Registra ação administrativa"""
        self.log_security_event(
            action=f'ADMIN_{action.upper()}',
            details=details or f'Ação administrativa: {action}' + (f' em usuário: {target_user}' if target_user else ''),
            category=self.CATEGORY_ADMIN,
            severity=self.SEVERITY_INFO,
            metadata={'target_user': target_user, 'admin_action': action}
        )
    
    def log_2fa_event(self, action: str, success: bool = True, details: str = None) -> None:
        """Registra evento de 2FA"""
        severity = self.SEVERITY_INFO if success else self.SEVERITY_WARNING
        self.log_security_event(
            action=f'2FA_{action.upper()}',
            details=details or f'Evento 2FA: {action}',
            category=self.CATEGORY_2FA,
            severity=severity
        )
    
    def log_rate_limit_exceeded(self, endpoint: str, limit: str) -> None:
        """Registra excesso de rate limit"""
        self.log_security_event(
            action='RATE_LIMIT_EXCEEDED',
            details=f'Rate limit excedido para endpoint: {endpoint} (limite: {limit})',
            category=self.CATEGORY_RATE_LIMIT,
            severity=self.SEVERITY_WARNING,
            metadata={'endpoint': endpoint, 'limit': limit}
        )
    
    def log_security_violation(self, violation_type: str, details: str = None) -> None:
        """Registra violação de segurança"""
        self.log_security_event(
            action=f'SECURITY_VIOLATION_{violation_type.upper()}',
            details=details or f'Violação de segurança: {violation_type}',
            category=self.CATEGORY_SECURITY,
            severity=self.SEVERITY_ERROR,
            metadata={'violation_type': violation_type}
        )
    
    def log_suspicious_activity(self, activity_type: str, details: str = None, risk_score: int = 70) -> None:
        """Registra atividade suspeita"""
        self.log_security_event(
            action=f'SUSPICIOUS_{activity_type.upper()}',
            details=details or f'Atividade suspeita: {activity_type}',
            category=self.CATEGORY_SECURITY,
            severity=self.SEVERITY_WARNING,
            risk_score=risk_score,
            metadata={'activity_type': activity_type}
        )
    
    def get_security_summary(self, hours: int = 24) -> Dict[str, Any]:
        """
        Obtém resumo de segurança das últimas horas
        
        Args:
            hours: Número de horas para análise
        
        Returns:
            Dicionário com estatísticas de segurança
        """
        from datetime import timedelta
        
        cutoff_time = datetime.utcnow() - timedelta(hours=hours)
        
        # Consultar logs recentes
        recent_logs = Log.query.filter(
            Log.timestamp >= cutoff_time,
            Log.category.in_([
                self.CATEGORY_LOGIN,
                self.CATEGORY_SECURITY,
                self.CATEGORY_2FA,
                self.CATEGORY_RATE_LIMIT
            ])
        ).all()
        
        # Calcular estatísticas
        total_events = len(recent_logs)
        critical_events = len([log for log in recent_logs if log.severity == self.SEVERITY_CRITICAL])
        error_events = len([log for log in recent_logs if log.severity == self.SEVERITY_ERROR])
        warning_events = len([log for log in recent_logs if log.severity == self.SEVERITY_WARNING])
        
        # Eventos por categoria
        events_by_category = {}
        for log in recent_logs:
            events_by_category[log.category] = events_by_category.get(log.category, 0) + 1
        
        # IPs mais ativos
        ip_activity = {}
        for log in recent_logs:
            if log.ip_address:
                ip_activity[log.ip_address] = ip_activity.get(log.ip_address, 0) + 1
        
        top_ips = sorted(ip_activity.items(), key=lambda x: x[1], reverse=True)[:10]
        
        # Score de risco médio
        risk_scores = [log.risk_score for log in recent_logs if log.risk_score > 0]
        avg_risk_score = sum(risk_scores) / len(risk_scores) if risk_scores else 0
        
        return {
            'period_hours': hours,
            'total_events': total_events,
            'critical_events': critical_events,
            'error_events': error_events,
            'warning_events': warning_events,
            'events_by_category': events_by_category,
            'top_active_ips': top_ips,
            'average_risk_score': round(avg_risk_score, 2),
            'high_risk_events': len([log for log in recent_logs if log.risk_score >= 70])
        }
    
    def _get_client_ip(self) -> str:
        """Obtém IP do cliente considerando proxies"""
        if not request:
            return None
        
        # Verificar headers de proxy
        if request.headers.get('X-Forwarded-For'):
            return request.headers.get('X-Forwarded-For').split(',')[0].strip()
        elif request.headers.get('X-Real-IP'):
            return request.headers.get('X-Real-IP')
        else:
            return request.remote_addr
    
    def _get_session_id(self) -> str:
        """Gera ID de sessão único para correlação de eventos"""
        if not request:
            return None
        
        # Usar combinação de IP + User-Agent para gerar ID de sessão
        ip = self._get_client_ip()
        user_agent = request.headers.get('User-Agent', '')
        
        if ip and user_agent:
            session_data = f"{ip}:{user_agent}"
            return hashlib.md5(session_data.encode()).hexdigest()[:16]
        
        return None
    
    def _check_automatic_actions(self, action: str, risk_score: int, ip_address: str, user_id: int) -> None:
        """Verifica se ações automáticas devem ser tomadas baseadas no evento"""
        # Ações automáticas para eventos de alto risco
        if risk_score >= 90:
            # Bloquear IP automaticamente para eventos críticos
            if ip_address:
                from src.security.rate_limiter import security_rate_limiter
                security_rate_limiter.block_ip(ip_address, duration=3600)  # 1 hora
        
        elif risk_score >= 70:
            # Alertas para administradores
            self._send_security_alert(action, risk_score, ip_address, user_id)
    
    def _send_security_alert(self, action: str, risk_score: int, ip_address: str, user_id: int) -> None:
        """Envia alerta de segurança para administradores"""
        try:
            # Implementar notificação para administradores
            # Pode ser via Telegram, email, etc.
            current_app.logger.warning(
                f"SECURITY ALERT: {action} (Risk: {risk_score}) from IP: {ip_address} User: {user_id}"
            )
        except Exception as e:
            current_app.logger.error(f"Erro ao enviar alerta de segurança: {e}")


# Instância global do logger de segurança
security_logger = SecurityLogger()

