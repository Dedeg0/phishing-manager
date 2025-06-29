"""
Módulos de instalação para diferentes modos do Phishing Manager
"""

import os
import sys
import json
import time
import shutil
import requests
import subprocess
from pathlib import Path
from typing import Dict, List, Optional, Any
from abc import ABC, abstractmethod

from .core import InstallerError, CommandRunner, ProgressBar


class BaseInstaller(ABC):
    """Classe base para instaladores"""
    
    def __init__(self, config: Dict[str, Any], runner: CommandRunner, ui):
        self.config = config
        self.runner = runner
        self.ui = ui
        self.logger = runner.logger
        self.errors = []
    
    @abstractmethod
    def install(self) -> bool:
        """Executa instalação"""
        pass
    
    @abstractmethod
    def uninstall(self) -> bool:
        """Remove instalação"""
        pass
    
    def validate_config(self) -> bool:
        """Valida configuração"""
        required_fields = [
            'admin_username', 'admin_password', 'admin_email'
        ]
        
        for field in required_fields:
            if not self.config.get(field):
                self.errors.append(f"Campo obrigatório não configurado: {field}")
        
        return len(self.errors) == 0
    
    def create_env_file(self, path: str) -> None:
        """Cria arquivo .env com configurações"""
        env_content = f"""# Configurações do Phishing Manager
SECRET_KEY={self._generate_secret_key()}
DATABASE_URL={self.config.get('database_url', 'sqlite:///instance/phishing_manager.db')}
TELEGRAM_BOT_TOKEN={self.config.get('telegram_bot_token', '')}
TELEGRAM_ADMIN_CHAT_ID={self.config.get('telegram_admin_chat_id', '')}
FLASK_ENV={self.config.get('environment', 'development')}

# Configurações de segurança
SECURITY_PASSWORD_SALT={self._generate_secret_key()}
WTF_CSRF_SECRET_KEY={self._generate_secret_key()}

# Configurações de cache
CACHE_TYPE=simple
CACHE_DEFAULT_TIMEOUT=300

# Configurações de upload
MAX_CONTENT_LENGTH=16777216
UPLOAD_FOLDER=uploads

# Configurações de log
LOG_LEVEL=INFO
LOG_FILE=logs/phishing_manager.log
"""
        
        with open(path, 'w', encoding='utf-8') as f:
            f.write(env_content)
    
    def _generate_secret_key(self) -> str:
        """Gera chave secreta aleatória"""
        import secrets
        return secrets.token_urlsafe(32)
    
    def wait_for_service(self, url: str, timeout: int = 60) -> bool:
        """Aguarda serviço ficar disponível"""
        start_time = time.time()
        while time.time() - start_time < timeout:
            try:
                response = requests.get(url, timeout=5)
                if response.status_code == 200:
                    return True
            except requests.exceptions.RequestException:
                pass
            time.sleep(2)
        return False
    
    def setup_initial_admin(self, backend_url: str) -> bool:
        """Configura usuário administrador inicial"""
        setup_url = f"{backend_url}/api/setup"
        setup_data = {
            "admin_username": self.config['admin_username'],
            "admin_password": self.config['admin_password'],
            "admin_email": self.config['admin_email'],
            "telegram_bot_token": self.config.get('telegram_bot_token', ''),
            "telegram_admin_chat_id": self.config.get('telegram_admin_chat_id', '')
        }
        
        try:
            self.logger.info(f"Configurando administrador inicial em {setup_url}")
            response = requests.post(setup_url, json=setup_data, timeout=30)
            if response.status_code == 200:
                self.logger.info("Administrador inicial configurado com sucesso")
                return True
            else:
                self.logger.error(f"Erro na configuração inicial: {response.status_code} - {response.text}")
                return False
        except requests.exceptions.RequestException as e:
            self.logger.error(f"Erro ao conectar ao backend: {e}")
            return False


class ManualInstaller(BaseInstaller):
    """Instalador manual tradicional"""
    
    def install(self) -> bool:
        """Executa instalação manual"""
        try:
            self.ui.print_step(1, 6, "Validando configuração")
            if not self.validate_config():
                return False
            
            self.ui.print_step(2, 6, "Instalando backend (Flask)")
            if not self._install_backend():
                return False
            
            self.ui.print_step(3, 6, "Instalando frontend (React)")
            if not self._install_frontend():
                return False
            
            self.ui.print_step(4, 6, "Configurando ambiente")
            if not self._setup_environment():
                return False
            
            self.ui.print_step(5, 6, "Inicializando banco de dados")
            if not self._init_database():
                return False
            
            self.ui.print_step(6, 6, "Configurando administrador inicial")
            if not self._setup_admin():
                return False
            
            self.ui.print_success("Instalação manual concluída com sucesso!")
            return True
            
        except Exception as e:
            self.logger.error(f"Erro durante instalação manual: {e}")
            self.errors.append(str(e))
            return False
    
    def _install_backend(self) -> bool:
        """Instala backend Flask"""
        backend_dir = Path("phishing-manager")
        if not backend_dir.exists():
            self.errors.append(f"Diretório {backend_dir} não encontrado")
            return False
        
        try:
            # Criar ambiente virtual
            self.logger.info("Criando ambiente virtual")
            self.runner.run("python3 -m venv venv", cwd=str(backend_dir))
            
            # Instalar dependências
            self.logger.info("Instalando dependências do backend")
            activate_cmd = "source venv/bin/activate"
            install_cmd = f"{activate_cmd} && pip install --upgrade pip && pip install -r requirements.txt"
            self.runner.run(install_cmd, cwd=str(backend_dir))
            
            return True
        except InstallerError as e:
            self.errors.append(f"Erro ao instalar backend: {e}")
            return False
    
    def _install_frontend(self) -> bool:
        """Instala frontend React"""
        frontend_dir = Path("phishing-manager-frontend")
        if not frontend_dir.exists():
            self.errors.append(f"Diretório {frontend_dir} não encontrado")
            return False
        
        try:
            # Instalar dependências
            self.logger.info("Instalando dependências do frontend")
            self.runner.run("npm install --legacy-peer-deps", cwd=str(frontend_dir))
            
            return True
        except InstallerError as e:
            self.errors.append(f"Erro ao instalar frontend: {e}")
            return False
    
    def _setup_environment(self) -> bool:
        """Configura ambiente"""
        try:
            # Criar arquivo .env
            env_path = Path("phishing-manager") / ".env"
            self.create_env_file(str(env_path))
            
            # Criar diretórios necessários
            dirs_to_create = [
                "phishing-manager/instance",
                "phishing-manager/logs",
                "phishing-manager/uploads"
            ]
            
            for dir_path in dirs_to_create:
                Path(dir_path).mkdir(parents=True, exist_ok=True)
            
            return True
        except Exception as e:
            self.errors.append(f"Erro ao configurar ambiente: {e}")
            return False
    
    def _init_database(self) -> bool:
        """Inicializa banco de dados"""
        try:
            backend_dir = Path("phishing-manager")
            activate_cmd = "source venv/bin/activate"
            
            # Inicializar banco
            init_cmd = f"{activate_cmd} && cd src && python -c \"from main import app, db; app.app_context().push(); db.create_all()\""
            self.runner.run(init_cmd, cwd=str(backend_dir))
            
            return True
        except InstallerError as e:
            self.errors.append(f"Erro ao inicializar banco: {e}")
            return False
    
    def _setup_admin(self) -> bool:
        """Configura administrador inicial"""
        try:
            backend_dir = Path("phishing-manager")
            backend_cwd = backend_dir / "src"
            venv_python = backend_dir / "venv" / "bin" / "python"
            
            # Iniciar backend temporariamente
            self.logger.info("Iniciando backend temporariamente")
            backend_process = subprocess.Popen(
                [str(venv_python), "-m", "flask", "run", "--host=127.0.0.1", "--port=5000"],
                cwd=str(backend_cwd),
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                env={**os.environ, "FLASK_APP": "main.py"}
            )
            
            try:
                # Aguardar backend iniciar
                if not self.wait_for_service("http://127.0.0.1:5000/health", timeout=60):
                    self.errors.append("Backend não respondeu a tempo")
                    return False
                
                # Configurar administrador
                success = self.setup_initial_admin("http://127.0.0.1:5000")
                return success
                
            finally:
                # Parar backend
                backend_process.terminate()
                backend_process.wait()
            
        except Exception as e:
            self.errors.append(f"Erro ao configurar administrador: {e}")
            return False
    
    def uninstall(self) -> bool:
        """Remove instalação manual"""
        try:
            # Remover ambiente virtual
            venv_path = Path("phishing-manager/venv")
            if venv_path.exists():
                shutil.rmtree(venv_path)
            
            # Remover node_modules
            node_modules = Path("phishing-manager-frontend/node_modules")
            if node_modules.exists():
                shutil.rmtree(node_modules)
            
            # Remover arquivos de configuração
            config_files = [
                "phishing-manager/.env",
                "phishing-manager/instance/phishing_manager.db"
            ]
            
            for file_path in config_files:
                path = Path(file_path)
                if path.exists():
                    path.unlink()
            
            self.ui.print_success("Instalação manual removida com sucesso!")
            return True
            
        except Exception as e:
            self.logger.error(f"Erro ao remover instalação: {e}")
            return False


class DockerInstaller(BaseInstaller):
    """Instalador usando Docker"""
    
    def install(self) -> bool:
        """Executa instalação com Docker"""
        try:
            self.ui.print_step(1, 5, "Validando configuração")
            if not self.validate_config():
                return False
            
            self.ui.print_step(2, 5, "Criando arquivos Docker")
            if not self._create_docker_files():
                return False
            
            self.ui.print_step(3, 5, "Construindo imagens Docker")
            if not self._build_images():
                return False
            
            self.ui.print_step(4, 5, "Iniciando serviços")
            if not self._start_services():
                return False
            
            self.ui.print_step(5, 5, "Configurando administrador inicial")
            if not self._setup_admin_docker():
                return False
            
            self.ui.print_success("Instalação Docker concluída com sucesso!")
            return True
            
        except Exception as e:
            self.logger.error(f"Erro durante instalação Docker: {e}")
            self.errors.append(str(e))
            return False
    
    def _create_docker_files(self) -> bool:
        """Cria arquivos Docker necessários"""
        try:
            # Dockerfile para backend
            backend_dockerfile = """FROM python:3.11-slim

WORKDIR /app

# Instalar dependências do sistema
RUN apt-get update && apt-get install -y \\
    gcc \\
    && rm -rf /var/lib/apt/lists/*

# Copiar requirements e instalar dependências Python
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Copiar código da aplicação
COPY . .

# Criar diretórios necessários
RUN mkdir -p instance logs uploads

# Expor porta
EXPOSE 5000

# Comando para iniciar aplicação
CMD ["python", "src/main.py"]
"""
            
            with open("phishing-manager/Dockerfile", 'w') as f:
                f.write(backend_dockerfile)
            
            # Dockerfile para frontend
            frontend_dockerfile = """FROM node:18-alpine

WORKDIR /app

# Copiar package.json e instalar dependências
COPY package*.json ./
RUN npm install --legacy-peer-deps

# Copiar código da aplicação
COPY . .

# Construir aplicação
RUN npm run build

# Instalar servidor estático
RUN npm install -g serve

# Expor porta
EXPOSE 3000

# Comando para servir aplicação
CMD ["serve", "-s", "build", "-l", "3000"]
"""
            
            frontend_dir = Path("phishing-manager-frontend")
            if frontend_dir.exists():
                with open(frontend_dir / "Dockerfile", 'w') as f:
                    f.write(frontend_dockerfile)
            
            # docker-compose.yml
            compose_content = f"""version: '3.8'

services:
  backend:
    build: ./phishing-manager
    ports:
      - "{self.config.get('backend_port', 5000)}:5000"
    environment:
      - SECRET_KEY={self._generate_secret_key()}
      - DATABASE_URL={self.config.get('database_url', 'sqlite:///instance/phishing_manager.db')}
      - TELEGRAM_BOT_TOKEN={self.config.get('telegram_bot_token', '')}
      - TELEGRAM_ADMIN_CHAT_ID={self.config.get('telegram_admin_chat_id', '')}
      - FLASK_ENV={self.config.get('environment', 'development')}
    volumes:
      - ./data:/app/instance
      - ./logs:/app/logs
    networks:
      - phishing-manager

  frontend:
    build: ./phishing-manager-frontend
    ports:
      - "{self.config.get('frontend_port', 3000)}:3000"
    depends_on:
      - backend
    networks:
      - phishing-manager

networks:
  phishing-manager:
    driver: bridge

volumes:
  data:
  logs:
"""
            
            with open("docker-compose.yml", 'w') as f:
                f.write(compose_content)
            
            # Criar diretórios para volumes
            Path("data").mkdir(exist_ok=True)
            Path("logs").mkdir(exist_ok=True)
            
            return True
            
        except Exception as e:
            self.errors.append(f"Erro ao criar arquivos Docker: {e}")
            return False
    
    def _build_images(self) -> bool:
        """Constrói imagens Docker"""
        try:
            self.logger.info("Construindo imagens Docker")
            self.runner.run("docker-compose build", timeout=600)
            return True
        except InstallerError as e:
            self.errors.append(f"Erro ao construir imagens: {e}")
            return False
    
    def _start_services(self) -> bool:
        """Inicia serviços Docker"""
        try:
            self.logger.info("Iniciando serviços Docker")
            self.runner.run("docker-compose up -d")
            
            # Aguardar serviços iniciarem
            backend_url = f"http://localhost:{self.config.get('backend_port', 5000)}/health"
            if not self.wait_for_service(backend_url, timeout=120):
                self.errors.append("Backend não respondeu a tempo")
                return False
            
            return True
        except InstallerError as e:
            self.errors.append(f"Erro ao iniciar serviços: {e}")
            return False
    
    def _setup_admin_docker(self) -> bool:
        """Configura administrador no ambiente Docker"""
        try:
            backend_url = f"http://localhost:{self.config.get('backend_port', 5000)}"
            return self.setup_initial_admin(backend_url)
        except Exception as e:
            self.errors.append(f"Erro ao configurar administrador: {e}")
            return False
    
    def uninstall(self) -> bool:
        """Remove instalação Docker"""
        try:
            # Parar e remover containers
            self.runner.run("docker-compose down -v", check=False)
            
            # Remover imagens
            self.runner.run("docker-compose down --rmi all", check=False)
            
            # Remover arquivos Docker
            docker_files = [
                "docker-compose.yml",
                "phishing-manager/Dockerfile",
                "phishing-manager-frontend/Dockerfile"
            ]
            
            for file_path in docker_files:
                path = Path(file_path)
                if path.exists():
                    path.unlink()
            
            self.ui.print_success("Instalação Docker removida com sucesso!")
            return True
            
        except Exception as e:
            self.logger.error(f"Erro ao remover instalação Docker: {e}")
            return False


class SystemdInstaller(BaseInstaller):
    """Instalador como serviço SystemD"""
    
    def install(self) -> bool:
        """Executa instalação como serviço SystemD"""
        try:
            self.ui.print_step(1, 7, "Validando configuração")
            if not self.validate_config():
                return False
            
            self.ui.print_step(2, 7, "Criando usuário do serviço")
            if not self._create_service_user():
                return False
            
            self.ui.print_step(3, 7, "Instalando aplicação")
            if not self._install_application():
                return False
            
            self.ui.print_step(4, 7, "Configurando ambiente")
            if not self._setup_environment_systemd():
                return False
            
            self.ui.print_step(5, 7, "Criando serviços SystemD")
            if not self._create_systemd_services():
                return False
            
            self.ui.print_step(6, 7, "Iniciando serviços")
            if not self._start_systemd_services():
                return False
            
            self.ui.print_step(7, 7, "Configurando administrador inicial")
            if not self._setup_admin_systemd():
                return False
            
            self.ui.print_success("Instalação SystemD concluída com sucesso!")
            return True
            
        except Exception as e:
            self.logger.error(f"Erro durante instalação SystemD: {e}")
            self.errors.append(str(e))
            return False
    
    def _create_service_user(self) -> bool:
        """Cria usuário para o serviço"""
        try:
            user = self.config.get('service_user', 'phishing-manager')
            group = self.config.get('service_group', 'phishing-manager')
            
            # Criar grupo
            self.runner.run(f"sudo groupadd -f {group}", check=False)
            
            # Criar usuário
            self.runner.run(
                f"sudo useradd -r -g {group} -d /opt/phishing-manager -s /bin/false {user}",
                check=False
            )
            
            return True
        except Exception as e:
            self.errors.append(f"Erro ao criar usuário do serviço: {e}")
            return False
    
    def _install_application(self) -> bool:
        """Instala aplicação no diretório do sistema"""
        try:
            install_path = Path(self.config.get('install_path', '/opt/phishing-manager'))
            user = self.config.get('service_user', 'phishing-manager')
            group = self.config.get('service_group', 'phishing-manager')
            
            # Criar diretório de instalação
            self.runner.run(f"sudo mkdir -p {install_path}")
            
            # Copiar arquivos
            self.runner.run(f"sudo cp -r phishing-manager/* {install_path}/")
            
            # Instalar dependências
            self.runner.run(f"sudo python3 -m venv {install_path}/venv")
            self.runner.run(f"sudo {install_path}/venv/bin/pip install -r {install_path}/requirements.txt")
            
            # Definir permissões
            self.runner.run(f"sudo chown -R {user}:{group} {install_path}")
            self.runner.run(f"sudo chmod -R 755 {install_path}")
            
            return True
        except InstallerError as e:
            self.errors.append(f"Erro ao instalar aplicação: {e}")
            return False
    
    def _setup_environment_systemd(self) -> bool:
        """Configura ambiente para SystemD"""
        try:
            install_path = Path(self.config.get('install_path', '/opt/phishing-manager'))
            
            # Criar arquivo .env
            env_path = install_path / ".env"
            self.create_env_file(str(env_path))
            
            # Definir permissões
            user = self.config.get('service_user', 'phishing-manager')
            group = self.config.get('service_group', 'phishing-manager')
            self.runner.run(f"sudo chown {user}:{group} {env_path}")
            self.runner.run(f"sudo chmod 600 {env_path}")
            
            return True
        except Exception as e:
            self.errors.append(f"Erro ao configurar ambiente: {e}")
            return False
    
    def _create_systemd_services(self) -> bool:
        """Cria arquivos de serviço SystemD"""
        try:
            install_path = self.config.get('install_path', '/opt/phishing-manager')
            user = self.config.get('service_user', 'phishing-manager')
            group = self.config.get('service_group', 'phishing-manager')
            
            # Serviço backend
            backend_service = f"""[Unit]
Description=Phishing Manager Backend
After=network.target

[Service]
Type=simple
User={user}
Group={group}
WorkingDirectory={install_path}/src
Environment=PATH={install_path}/venv/bin
ExecStart={install_path}/venv/bin/python main.py
Restart=always
RestartSec=10

[Install]
WantedBy=multi-user.target
"""
            
            with open("/tmp/phishing-manager-backend.service", 'w') as f:
                f.write(backend_service)
            
            self.runner.run("sudo mv /tmp/phishing-manager-backend.service /etc/systemd/system/")
            
            # Recarregar SystemD
            self.runner.run("sudo systemctl daemon-reload")
            self.runner.run("sudo systemctl enable phishing-manager-backend")
            
            return True
        except Exception as e:
            self.errors.append(f"Erro ao criar serviços SystemD: {e}")
            return False
    
    def _start_systemd_services(self) -> bool:
        """Inicia serviços SystemD"""
        try:
            self.runner.run("sudo systemctl start phishing-manager-backend")
            
            # Aguardar serviço iniciar
            if not self.wait_for_service("http://localhost:5000/health", timeout=60):
                self.errors.append("Serviço backend não respondeu a tempo")
                return False
            
            return True
        except InstallerError as e:
            self.errors.append(f"Erro ao iniciar serviços: {e}")
            return False
    
    def _setup_admin_systemd(self) -> bool:
        """Configura administrador no ambiente SystemD"""
        try:
            return self.setup_initial_admin("http://localhost:5000")
        except Exception as e:
            self.errors.append(f"Erro ao configurar administrador: {e}")
            return False
    
    def uninstall(self) -> bool:
        """Remove instalação SystemD"""
        try:
            # Parar e desabilitar serviços
            self.runner.run("sudo systemctl stop phishing-manager-backend", check=False)
            self.runner.run("sudo systemctl disable phishing-manager-backend", check=False)
            
            # Remover arquivos de serviço
            service_files = [
                "/etc/systemd/system/phishing-manager-backend.service"
            ]
            
            for service_file in service_files:
                self.runner.run(f"sudo rm -f {service_file}", check=False)
            
            # Recarregar SystemD
            self.runner.run("sudo systemctl daemon-reload", check=False)
            
            # Remover diretório de instalação
            install_path = self.config.get('install_path', '/opt/phishing-manager')
            self.runner.run(f"sudo rm -rf {install_path}", check=False)
            
            # Remover usuário do serviço
            user = self.config.get('service_user', 'phishing-manager')
            self.runner.run(f"sudo userdel {user}", check=False)
            
            self.ui.print_success("Instalação SystemD removida com sucesso!")
            return True
            
        except Exception as e:
            self.logger.error(f"Erro ao remover instalação SystemD: {e}")
            return False


def get_installer(install_mode: str, config: Dict[str, Any], runner: CommandRunner, ui) -> BaseInstaller:
    """Factory para criar instalador apropriado"""
    installers = {
        'manual': ManualInstaller,
        'docker': DockerInstaller,
        'systemd': SystemdInstaller
    }
    
    installer_class = installers.get(install_mode)
    if not installer_class:
        raise ValueError(f"Modo de instalação não suportado: {install_mode}")
    
    return installer_class(config, runner, ui)

