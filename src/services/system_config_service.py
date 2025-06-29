import os
import json
from src.models.user import db, User
from src.services.environment_service import env_config
from werkzeug.security import generate_password_hash

class SystemConfigService:
    def __init__(self):
        self.config_file = os.path.join(os.path.dirname(__file__), '..', 'config.json')
        self._load_config()

    def _load_config(self):
        if os.path.exists(self.config_file):
            with open(self.config_file, 'r') as f:
                self.system_config = json.load(f)
        else:
            self.system_config = {
                'TELEGRAM_BOT_TOKEN': None,
                'TELEGRAM_ADMIN_CHAT_ID': None,
                'SECRET_KEY': None
            }
            self._save_config()

    def _save_config(self):
        with open(self.config_file, 'w') as f:
            json.dump(self.system_config, f, indent=4)

    def get_config(self):
        return self.system_config

    def update_config(self, new_config):
        self.system_config.update(new_config)
        self._save_config()
        # Atualizar env_config em tempo de execução se necessário
        if 'SECRET_KEY' in new_config:
            env_config.config['SECRET_KEY'] = new_config['SECRET_KEY']
        if 'TELEGRAM_BOT_TOKEN' in new_config:
            env_config.config['TELEGRAM_BOT_TOKEN'] = new_config['TELEGRAM_BOT_TOKEN']
        if 'TELEGRAM_ADMIN_CHAT_ID' in new_config:
            env_config.config['TELEGRAM_ADMIN_CHAT_ID'] = new_config['TELEGRAM_ADMIN_CHAT_ID']

    def generate_secret_key(self):
        import secrets
        new_key = secrets.token_urlsafe(32)
        self.update_config({'SECRET_KEY': new_key})
        return new_key

    def setup_initial_admin(self, username, password):
        with db.app.app_context():
            user = User.query.filter_by(username=username).first()
            if not user:
                hashed_password = generate_password_hash(password)
                new_user = User(
                    username=username,
                    email=f'{username}@system.local',
                    password_hash=hashed_password,
                    is_admin=True,
                    is_active=True,
                    credits=999999,
                    is_root=True,
                    require_password_change=False # Já está configurando a senha
                )
                db.session.add(new_user)
                db.session.commit()
                print(f"Usuário administrador inicial '{username}' criado com sucesso.")
                return True
            return False

system_config_service = SystemConfigService()


