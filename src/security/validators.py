"""
Sistema de validação de entrada para prevenir ataques de injeção e garantir integridade dos dados
"""

from marshmallow import Schema, fields, validate, ValidationError, pre_load
import re
from markupsafe import escape
from typing import Dict, Any


class SecurityValidationError(Exception):
    """Exceção personalizada para erros de validação de segurança"""
    pass


def sanitize_string(value: str) -> str:
    """Sanitiza string para prevenir XSS"""
    if not isinstance(value, str):
        return value
    
    # Remove scripts e tags HTML perigosas primeiro
    dangerous_patterns = [
        r'<script[^>]*>.*?</script>',
        r'javascript:',
        r'vbscript:',
        r'onload=',
        r'onerror=',
        r'onclick=',
        r'onmouseover=',
        r'<iframe[^>]*>.*?</iframe>',
        r'<object[^>]*>.*?</object>',
        r'<embed[^>]*>.*?</embed>',
        r'<link[^>]*>',
        r'<meta[^>]*>',
    ]
    
    for pattern in dangerous_patterns:
        value = re.sub(pattern, '', value, flags=re.IGNORECASE | re.DOTALL)
    
    # Remove todas as tags HTML restantes
    value = re.sub(r'<[^>]+>', '', value)
    
    # Escape caracteres especiais
    value = escape(value)
    
    return value.strip()


def validate_password_strength(password: str) -> bool:
    """Valida força da senha"""
    if len(password) < 8:
        return False
    
    # Deve conter pelo menos uma letra minúscula
    if not re.search(r'[a-z]', password):
        return False
    
    # Deve conter pelo menos uma letra maiúscula
    if not re.search(r'[A-Z]', password):
        return False
    
    # Deve conter pelo menos um número
    if not re.search(r'\d', password):
        return False
    
    # Deve conter pelo menos um caractere especial
    if not re.search(r'[!@#$%^&*(),.?":{}|<>]', password):
        return False
    
    return True


def validate_username(username: str) -> bool:
    """Valida formato do username"""
    # Username deve ter entre 3 e 30 caracteres
    if not 3 <= len(username) <= 30:
        return False
    
    # Deve conter apenas letras, números, underscore e hífen
    if not re.match(r'^[a-zA-Z0-9_-]+$', username):
        return False
    
    # Não pode começar ou terminar com underscore ou hífen
    if username.startswith(('_', '-')) or username.endswith(('_', '-')):
        return False
    
    return True


def validate_email_format(email: str) -> bool:
    """Valida formato do email"""
    pattern = r'^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$'
    return bool(re.match(pattern, email))


def validate_domain_name(domain: str) -> bool:
    """Valida formato do nome de domínio"""
    pattern = r'^[a-zA-Z0-9]([a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?(\.[a-zA-Z0-9]([a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?)*$'
    return bool(re.match(pattern, domain)) and len(domain) <= 253


class BaseSecureSchema(Schema):
    """Schema base com sanitização automática"""
    
    @pre_load
    def sanitize_input(self, data, **kwargs):
        """Sanitiza todos os campos de string"""
        if isinstance(data, dict):
            sanitized = {}
            for key, value in data.items():
                if isinstance(value, str):
                    sanitized[key] = sanitize_string(value)
                else:
                    sanitized[key] = value
            return sanitized
        return data


class UserRegistrationSchema(BaseSecureSchema):
    """Schema para validação de registro de usuário"""
    
    username = fields.Str(
        required=True,
        validate=[
            validate.Length(min=3, max=30),
            lambda x: validate_username(x) or ValidationError("Username deve conter apenas letras, números, _ e -")
        ]
    )
    
    email = fields.Email(
        required=True,
        validate=[
            validate.Length(max=255),
            lambda x: validate_email_format(x) or ValidationError("Formato de email inválido")
        ]
    )
    
    password = fields.Str(
        required=True,
        validate=[
            validate.Length(min=8, max=128),
            lambda x: validate_password_strength(x) or ValidationError(
                "Senha deve ter pelo menos 8 caracteres, incluindo maiúscula, minúscula, número e caractere especial"
            )
        ]
    )


class UserLoginSchema(BaseSecureSchema):
    """Schema para validação de login"""
    
    username = fields.Str(
        required=True,
        validate=validate.Length(min=1, max=30)
    )
    
    password = fields.Str(
        required=True,
        validate=validate.Length(min=1, max=128)
    )
    
    otp_code = fields.Str(
        required=False,
        validate=validate.Regexp(r'^\d{6}$', error="Código OTP deve ter 6 dígitos")
    )


class PasswordChangeSchema(BaseSecureSchema):
    """Schema para validação de alteração de senha"""
    
    current_password = fields.Str(
        required=True,
        validate=validate.Length(min=1, max=128)
    )
    
    new_password = fields.Str(
        required=True,
        validate=[
            validate.Length(min=8, max=128),
            lambda x: validate_password_strength(x) or ValidationError(
                "Nova senha deve ter pelo menos 8 caracteres, incluindo maiúscula, minúscula, número e caractere especial"
            )
        ]
    )


class DomainSchema(BaseSecureSchema):
    """Schema para validação de domínio"""
    
    domain_name = fields.Str(
        required=True,
        validate=[
            validate.Length(min=1, max=253),
            lambda x: validate_domain_name(x) or ValidationError("Nome de domínio inválido")
        ]
    )
    
    max_users = fields.Int(
        required=False,
        validate=validate.Range(min=1, max=10000)
    )
    
    cost_per_use = fields.Int(
        required=False,
        validate=validate.Range(min=0, max=1000)
    )


class URLGenerationSchema(BaseSecureSchema):
    """Schema para validação de geração de URL"""
    
    domain_id = fields.Int(
        required=True,
        validate=validate.Range(min=1)
    )
    
    script_id = fields.Int(
        required=True,
        validate=validate.Range(min=1)
    )
    
    custom_suffix = fields.Str(
        required=False,
        validate=[
            validate.Length(min=1, max=50),
            validate.Regexp(r'^[a-zA-Z0-9_-]+$', error="Sufixo deve conter apenas letras, números, _ e -")
        ]
    )


class AdminUserManagementSchema(BaseSecureSchema):
    """Schema para validação de gerenciamento de usuários por admin"""
    
    username = fields.Str(
        required=False,
        validate=[
            validate.Length(min=3, max=30),
            lambda x: validate_username(x) or ValidationError("Username deve conter apenas letras, números, _ e -")
        ]
    )
    
    email = fields.Email(
        required=False,
        validate=validate.Length(max=255)
    )
    
    is_admin = fields.Bool(required=False)
    is_active = fields.Bool(required=False)
    is_banned = fields.Bool(required=False)
    credits = fields.Int(
        required=False,
        validate=validate.Range(min=0, max=999999)
    )


class TelegramConfigSchema(BaseSecureSchema):
    """Schema para validação de configuração do Telegram"""
    
    telegram_username = fields.Str(
        required=False,
        validate=[
            validate.Length(min=1, max=32),
            validate.Regexp(r'^@?[a-zA-Z0-9_]+$', error="Username do Telegram inválido")
        ]
    )
    
    telegram_chat_id = fields.Str(
        required=False,
        validate=[
            validate.Length(min=1, max=20),
            validate.Regexp(r'^-?\d+$', error="Chat ID deve ser numérico")
        ]
    )


def validate_request_data(schema_class: Schema, data: Dict[str, Any]) -> Dict[str, Any]:
    """
    Valida dados de requisição usando o schema especificado
    
    Args:
        schema_class: Classe do schema para validação
        data: Dados a serem validados
    
    Returns:
        Dados validados e sanitizados
    
    Raises:
        SecurityValidationError: Se a validação falhar
    """
    try:
        schema = schema_class()
        validated_data = schema.load(data)
        return validated_data
    except ValidationError as e:
        raise SecurityValidationError(f"Erro de validação: {e.messages}")


# Instâncias dos schemas para uso direto
user_registration_schema = UserRegistrationSchema()
user_login_schema = UserLoginSchema()
password_change_schema = PasswordChangeSchema()
domain_schema = DomainSchema()
url_generation_schema = URLGenerationSchema()
admin_user_management_schema = AdminUserManagementSchema()
telegram_config_schema = TelegramConfigSchema()

