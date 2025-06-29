"""
Sistema de autenticação de dois fatores (2FA) usando TOTP
"""

import pyotp
import qrcode
import io
import base64
from typing import Tuple, Optional
from flask import current_app
from src.models.user import db, User, Log
from src.services.cache_service import cache_service
import secrets
import string


class TwoFactorAuth:
    """Sistema de autenticação de dois fatores"""
    
    def __init__(self):
        self.issuer_name = "Phishing Manager"
    
    def generate_secret(self) -> str:
        """Gera uma chave secreta para TOTP"""
        return pyotp.random_base32()
    
    def generate_backup_codes(self, count: int = 10) -> list:
        """Gera códigos de backup para recuperação"""
        codes = []
        for _ in range(count):
            # Gerar código de 8 caracteres alfanuméricos
            code = ''.join(secrets.choice(string.ascii_uppercase + string.digits) for _ in range(8))
            codes.append(code)
        return codes
    
    def get_provisioning_uri(self, user: User, secret: str) -> str:
        """Gera URI de provisionamento para apps de autenticação"""
        totp = pyotp.TOTP(secret)
        return totp.provisioning_uri(
            name=user.email,
            issuer_name=self.issuer_name
        )
    
    def generate_qr_code(self, provisioning_uri: str) -> str:
        """Gera QR code em base64 para configuração do 2FA"""
        qr = qrcode.QRCode(
            version=1,
            error_correction=qrcode.constants.ERROR_CORRECT_L,
            box_size=10,
            border=4,
        )
        qr.add_data(provisioning_uri)
        qr.make(fit=True)
        
        # Criar imagem
        img = qr.make_image(fill_color="black", back_color="white")
        
        # Converter para base64
        buffer = io.BytesIO()
        img.save(buffer, format='PNG')
        buffer.seek(0)
        
        img_base64 = base64.b64encode(buffer.getvalue()).decode()
        return f"data:image/png;base64,{img_base64}"
    
    def verify_totp_code(self, secret: str, code: str, window: int = 1) -> bool:
        """
        Verifica código TOTP
        
        Args:
            secret: Chave secreta do usuário
            code: Código fornecido pelo usuário
            window: Janela de tolerância (padrão: 1 = ±30 segundos)
        
        Returns:
            True se o código for válido
        """
        if not secret or not code:
            return False
        
        try:
            totp = pyotp.TOTP(secret)
            return totp.verify(code, valid_window=window)
        except Exception:
            return False
    
    def verify_backup_code(self, user: User, code: str) -> bool:
        """
        Verifica código de backup
        
        Args:
            user: Usuário
            code: Código de backup fornecido
        
        Returns:
            True se o código for válido e ainda não usado
        """
        if not user.backup_codes or not code:
            return False
        
        # Verificar se o código existe e não foi usado
        backup_codes = user.backup_codes.split(',') if user.backup_codes else []
        code_upper = code.upper().strip()
        
        if code_upper in backup_codes:
            # Remover código usado
            backup_codes.remove(code_upper)
            user.backup_codes = ','.join(backup_codes)
            db.session.commit()
            
            # Log do uso do código de backup
            self._log_2fa_event(user.id, "BACKUP_CODE_USED", f"Código de backup usado: {code_upper[:4]}****")
            
            return True
        
        return False
    
    def enable_2fa_for_user(self, user: User) -> Tuple[str, str, list]:
        """
        Habilita 2FA para um usuário
        
        Returns:
            Tuple com (secret, qr_code_base64, backup_codes)
        """
        # Gerar nova chave secreta
        secret = self.generate_secret()
        
        # Gerar códigos de backup
        backup_codes = self.generate_backup_codes()
        
        # Salvar no usuário (ainda não ativado)
        user.totp_secret_temp = secret  # Temporário até confirmação
        user.backup_codes = ','.join(backup_codes)
        db.session.commit()
        
        # Gerar QR code
        provisioning_uri = self.get_provisioning_uri(user, secret)
        qr_code = self.generate_qr_code(provisioning_uri)
        
        self._log_2fa_event(user.id, "2FA_SETUP_INITIATED", "Configuração de 2FA iniciada")
        
        return secret, qr_code, backup_codes
    
    def confirm_2fa_setup(self, user: User, code: str) -> bool:
        """
        Confirma configuração do 2FA verificando o primeiro código
        
        Args:
            user: Usuário
            code: Código TOTP fornecido
        
        Returns:
            True se a configuração foi confirmada
        """
        if not user.totp_secret_temp:
            return False
        
        # Verificar código
        if self.verify_totp_code(user.totp_secret_temp, code):
            # Ativar 2FA
            user.totp_secret = user.totp_secret_temp
            user.totp_secret_temp = None
            user.two_factor_enabled = True
            db.session.commit()
            
            self._log_2fa_event(user.id, "2FA_ENABLED", "2FA ativado com sucesso")
            return True
        
        return False
    
    def disable_2fa_for_user(self, user: User, code: str = None, backup_code: str = None) -> bool:
        """
        Desabilita 2FA para um usuário
        
        Args:
            user: Usuário
            code: Código TOTP (opcional)
            backup_code: Código de backup (opcional)
        
        Returns:
            True se o 2FA foi desabilitado
        """
        # Verificar se pelo menos um código foi fornecido
        if not code and not backup_code:
            return False
        
        # Verificar código TOTP ou backup
        valid_code = False
        if code and user.totp_secret:
            valid_code = self.verify_totp_code(user.totp_secret, code)
        elif backup_code:
            valid_code = self.verify_backup_code(user, backup_code)
        
        if valid_code:
            # Desabilitar 2FA
            user.two_factor_enabled = False
            user.totp_secret = None
            user.totp_secret_temp = None
            user.backup_codes = None
            db.session.commit()
            
            self._log_2fa_event(user.id, "2FA_DISABLED", "2FA desabilitado")
            return True
        
        return False
    
    def regenerate_backup_codes(self, user: User, code: str = None, backup_code: str = None) -> Optional[list]:
        """
        Regenera códigos de backup
        
        Args:
            user: Usuário
            code: Código TOTP (opcional)
            backup_code: Código de backup (opcional)
        
        Returns:
            Lista de novos códigos de backup ou None se falhar
        """
        # Verificar se pelo menos um código foi fornecido
        if not code and not backup_code:
            return None
        
        # Verificar código TOTP ou backup
        valid_code = False
        if code and user.totp_secret:
            valid_code = self.verify_totp_code(user.totp_secret, code)
        elif backup_code:
            valid_code = self.verify_backup_code(user, backup_code)
        
        if valid_code:
            # Gerar novos códigos
            new_backup_codes = self.generate_backup_codes()
            user.backup_codes = ','.join(new_backup_codes)
            db.session.commit()
            
            self._log_2fa_event(user.id, "BACKUP_CODES_REGENERATED", "Códigos de backup regenerados")
            return new_backup_codes
        
        return None
    
    def is_2fa_required_for_user(self, user: User) -> bool:
        """Verifica se 2FA é obrigatório para o usuário"""
        # 2FA obrigatório para administradores
        if user.is_admin:
            return True
        
        # Verificar configuração global (se implementada)
        # return current_app.config.get('REQUIRE_2FA_FOR_ALL', False)
        
        return False
    
    def check_2fa_rate_limit(self, user_id: int) -> bool:
        """
        Verifica rate limiting para tentativas de 2FA
        
        Returns:
            True se deve bloquear (muitas tentativas)
        """
        cache_key = f"2fa_attempts:{user_id}"
        attempts = cache_service.get(cache_key) or 0
        
        if attempts >= 5:  # Máximo 5 tentativas por hora
            return True
        
        return False
    
    def record_2fa_attempt(self, user_id: int, success: bool) -> None:
        """Registra tentativa de 2FA"""
        cache_key = f"2fa_attempts:{user_id}"
        
        if success:
            # Limpar tentativas em caso de sucesso
            cache_service.delete(cache_key)
        else:
            # Incrementar tentativas falhadas
            attempts = cache_service.get(cache_key) or 0
            cache_service.set(cache_key, attempts + 1, ex=3600)  # 1 hora
    
    def _log_2fa_event(self, user_id: int, action: str, details: str) -> None:
        """Registra evento de 2FA no log"""
        try:
            log = Log(
                user_id=user_id,
                action=action,
                details=details
            )
            db.session.add(log)
            db.session.commit()
        except Exception as e:
            current_app.logger.error(f"Erro ao registrar log de 2FA: {e}")


# Instância global do sistema 2FA
two_factor_auth = TwoFactorAuth()

