import requests
import os
from src.models.user import Log, db
from datetime import datetime

class TelegramService:
    def __init__(self):
        self.bot_token = os.environ.get('TELEGRAM_BOT_TOKEN')
        self.base_url = f"https://api.telegram.org/bot{self.bot_token}"
    
    def is_configured(self):
        """Verifica se o bot do Telegram está configurado"""
        return self.bot_token is not None
    
    def send_message(self, chat_id, message):
        """Envia uma mensagem para um chat específico no Telegram"""
        if not self.is_configured():
            return False, "Bot do Telegram não configurado"
        
        url = f"{self.base_url}/sendMessage"
        data = {
            'chat_id': chat_id,
            'text': message,
            'parse_mode': 'HTML'
        }
        
        try:
            response = requests.post(url, data=data, timeout=10)
            response.raise_for_status()
            return True, "Mensagem enviada com sucesso"
        except requests.exceptions.RequestException as e:
            return False, f"Erro ao enviar mensagem: {str(e)}"
    
    def send_otp(self, user, otp_code):
        """Envia código OTP para o usuário via Telegram"""
        if not user.telegram_chat_id:
            return False, "Chat ID do Telegram não configurado para este usuário"
        
        message = f"""
🔐 <b>Código de Verificação - Phishing Manager</b>

Seu código OTP é: <code>{otp_code}</code>

⏰ Este código expira em 5 minutos.
🚫 Não compartilhe este código com ninguém.

Se você não solicitou este código, ignore esta mensagem.
        """
        
        success, error_msg = self.send_message(user.telegram_chat_id, message)
        
        # Registrar no log
        if success:
            log = Log(
                user_id=user.id,
                action='OTP_SENT_TELEGRAM',
                details=f'Código OTP enviado via Telegram para {user.username}'
            )
        else:
            log = Log(
                user_id=user.id,
                action='OTP_SEND_FAILED',
                details=f'Falha ao enviar OTP via Telegram para {user.username}: {error_msg}'
            )
        
        db.session.add(log)
        db.session.commit()
        
        return success, error_msg
    
    def verify_chat_id(self, chat_id):
        """Verifica se um chat_id é válido enviando uma mensagem de teste"""
        if not self.is_configured():
            return False, "Bot do Telegram não configurado"
        
        test_message = """
🤖 <b>Configuração do Telegram - Phishing Manager</b>

Seu Telegram foi configurado com sucesso!

Agora você receberá códigos OTP de verificação neste chat quando o sistema de autenticação de dois fatores estiver ativado.
        """
        
        return self.send_message(chat_id, test_message)
    
    def get_bot_info(self):
        """Obtém informações sobre o bot"""
        if not self.is_configured():
            return None, "Bot do Telegram não configurado"
        
        url = f"{self.base_url}/getMe"
        
        try:
            response = requests.get(url, timeout=10)
            response.raise_for_status()
            data = response.json()
            
            if data.get('ok'):
                return data.get('result'), None
            else:
                return None, data.get('description', 'Erro desconhecido')
        except requests.exceptions.RequestException as e:
            return None, f"Erro ao obter informações do bot: {str(e)}"
    
    def get_chat_info(self, chat_id):
        """Obtém informações sobre um chat específico"""
        if not self.is_configured():
            return None, "Bot do Telegram não configurado"
        
        url = f"{self.base_url}/getChat"
        data = {'chat_id': chat_id}
        
        try:
            response = requests.post(url, data=data, timeout=10)
            response.raise_for_status()
            data = response.json()
            
            if data.get('ok'):
                return data.get('result'), None
            else:
                return None, data.get('description', 'Chat não encontrado ou bot não tem acesso')
        except requests.exceptions.RequestException as e:
            return None, f"Erro ao obter informações do chat: {str(e)}"

# Instância global do serviço do Telegram
telegram_service = TelegramService()

