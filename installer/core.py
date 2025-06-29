"""
Módulo core do instalador aprimorado do Phishing Manager
"""

import os
import sys
import subprocess
import platform
import shutil
import json
import time
import logging
from typing import Dict, List, Optional, Tuple
from pathlib import Path


class InstallerError(Exception):
    """Exceção personalizada para erros do instalador"""
    pass


class SystemInfo:
    """Classe para obter informações do sistema"""
    
    @staticmethod
    def get_os_info() -> Dict[str, str]:
        """Obtém informações do sistema operacional"""
        return {
            'system': platform.system(),
            'release': platform.release(),
            'version': platform.version(),
            'machine': platform.machine(),
            'processor': platform.processor(),
            'architecture': platform.architecture()[0]
        }
    
    @staticmethod
    def get_python_info() -> Dict[str, str]:
        """Obtém informações do Python"""
        return {
            'version': platform.python_version(),
            'implementation': platform.python_implementation(),
            'executable': sys.executable
        }
    
    @staticmethod
    def check_memory() -> Dict[str, int]:
        """Verifica memória disponível (Linux)"""
        try:
            with open('/proc/meminfo', 'r') as f:
                meminfo = f.read()
            
            mem_total = 0
            mem_available = 0
            
            for line in meminfo.split('\n'):
                if line.startswith('MemTotal:'):
                    mem_total = int(line.split()[1]) * 1024  # Convert KB to bytes
                elif line.startswith('MemAvailable:'):
                    mem_available = int(line.split()[1]) * 1024
            
            return {
                'total': mem_total,
                'available': mem_available,
                'total_gb': round(mem_total / (1024**3), 2),
                'available_gb': round(mem_available / (1024**3), 2)
            }
        except:
            return {'total': 0, 'available': 0, 'total_gb': 0, 'available_gb': 0}
    
    @staticmethod
    def check_disk_space(path: str = '.') -> Dict[str, int]:
        """Verifica espaço em disco"""
        try:
            stat = shutil.disk_usage(path)
            return {
                'total': stat.total,
                'used': stat.used,
                'free': stat.free,
                'total_gb': round(stat.total / (1024**3), 2),
                'used_gb': round(stat.used / (1024**3), 2),
                'free_gb': round(stat.free / (1024**3), 2)
            }
        except:
            return {'total': 0, 'used': 0, 'free': 0, 'total_gb': 0, 'used_gb': 0, 'free_gb': 0}


class CommandRunner:
    """Classe para executar comandos do sistema com logging"""
    
    def __init__(self, logger: logging.Logger):
        self.logger = logger
    
    def run(self, command: str, cwd: Optional[str] = None, shell: bool = True, 
            check: bool = True, timeout: Optional[int] = None) -> subprocess.CompletedProcess:
        """
        Executa comando do sistema
        
        Args:
            command: Comando a ser executado
            cwd: Diretório de trabalho
            shell: Usar shell
            check: Verificar código de retorno
            timeout: Timeout em segundos
        
        Returns:
            CompletedProcess object
        
        Raises:
            InstallerError: Se comando falhar
        """
        self.logger.info(f"Executando comando: {command}")
        
        try:
            if platform.system() == "Linux" and shell:
                result = subprocess.run(
                    ["bash", "-c", command],
                    cwd=cwd,
                    capture_output=True,
                    text=True,
                    timeout=timeout,
                    check=check
                )
            else:
                result = subprocess.run(
                    command,
                    shell=shell,
                    cwd=cwd,
                    capture_output=True,
                    text=True,
                    timeout=timeout,
                    check=check
                )
            
            if result.stdout:
                self.logger.debug(f"STDOUT: {result.stdout}")
            if result.stderr:
                self.logger.debug(f"STDERR: {result.stderr}")
            
            return result
            
        except subprocess.CalledProcessError as e:
            error_msg = f"Comando falhou: {command}\nCódigo: {e.returncode}\nSTDOUT: {e.stdout}\nSTDERR: {e.stderr}"
            self.logger.error(error_msg)
            raise InstallerError(error_msg)
        
        except subprocess.TimeoutExpired as e:
            error_msg = f"Comando expirou: {command}\nTimeout: {timeout}s"
            self.logger.error(error_msg)
            raise InstallerError(error_msg)
        
        except Exception as e:
            error_msg = f"Erro inesperado ao executar comando: {command}\nErro: {str(e)}"
            self.logger.error(error_msg)
            raise InstallerError(error_msg)
    
    def run_silent(self, command: str, **kwargs) -> bool:
        """Executa comando silenciosamente, retorna True se sucesso"""
        try:
            self.run(command, check=True, **kwargs)
            return True
        except InstallerError:
            return False


class DependencyChecker:
    """Classe para verificar dependências do sistema"""
    
    def __init__(self, logger: logging.Logger, runner: CommandRunner):
        self.logger = logger
        self.runner = runner
        self.requirements = {
            'python': {'min_version': '3.9', 'commands': ['python3', 'python']},
            'node': {'min_version': '14.0', 'commands': ['node']},
            'npm': {'min_version': '6.0', 'commands': ['npm']},
            'git': {'min_version': '2.0', 'commands': ['git']},
            'curl': {'min_version': '7.0', 'commands': ['curl']},
            'wget': {'min_version': '1.0', 'commands': ['wget']}
        }
    
    def check_command_exists(self, command: str) -> bool:
        """Verifica se comando existe no sistema"""
        return self.runner.run_silent(f"command -v {command}")
    
    def get_version(self, command: str, version_flag: str = '--version') -> Optional[str]:
        """Obtém versão de um comando"""
        try:
            result = self.runner.run(f"{command} {version_flag}", check=True)
            return result.stdout.strip()
        except InstallerError:
            return None
    
    def parse_version(self, version_string: str) -> Tuple[int, int, int]:
        """Parse version string para tupla (major, minor, patch)"""
        try:
            # Extrair números da versão
            import re
            version_match = re.search(r'(\d+)\.(\d+)\.?(\d+)?', version_string)
            if version_match:
                major = int(version_match.group(1))
                minor = int(version_match.group(2))
                patch = int(version_match.group(3) or 0)
                return (major, minor, patch)
        except:
            pass
        return (0, 0, 0)
    
    def compare_versions(self, version1: str, version2: str) -> int:
        """Compara duas versões. Retorna 1 se v1 > v2, -1 se v1 < v2, 0 se iguais"""
        v1 = self.parse_version(version1)
        v2 = self.parse_version(version2)
        
        if v1 > v2:
            return 1
        elif v1 < v2:
            return -1
        else:
            return 0
    
    def check_dependency(self, name: str) -> Dict[str, any]:
        """
        Verifica uma dependência específica
        
        Returns:
            Dict com informações da dependência
        """
        if name not in self.requirements:
            return {'name': name, 'found': False, 'error': 'Dependência desconhecida'}
        
        req = self.requirements[name]
        result = {
            'name': name,
            'found': False,
            'command': None,
            'version': None,
            'version_ok': False,
            'min_version': req['min_version'],
            'error': None
        }
        
        # Tentar encontrar comando
        for cmd in req['commands']:
            if self.check_command_exists(cmd):
                result['command'] = cmd
                result['found'] = True
                break
        
        if not result['found']:
            result['error'] = f"Comando não encontrado: {', '.join(req['commands'])}"
            return result
        
        # Verificar versão
        version_str = self.get_version(result['command'])
        if version_str:
            result['version'] = version_str
            if self.compare_versions(version_str, req['min_version']) >= 0:
                result['version_ok'] = True
            else:
                result['error'] = f"Versão muito antiga. Mínima: {req['min_version']}"
        else:
            result['error'] = "Não foi possível obter versão"
        
        return result
    
    def check_all_dependencies(self) -> Dict[str, Dict[str, any]]:
        """Verifica todas as dependências"""
        results = {}
        for name in self.requirements:
            results[name] = self.check_dependency(name)
        return results
    
    def check_system_requirements(self) -> Dict[str, any]:
        """Verifica requisitos mínimos do sistema"""
        memory = SystemInfo.check_memory()
        disk = SystemInfo.check_disk_space()
        
        requirements_met = {
            'memory': memory['available_gb'] >= 1.0,  # Mínimo 1GB RAM disponível
            'disk': disk['free_gb'] >= 2.0,  # Mínimo 2GB espaço livre
            'os': platform.system() == 'Linux'
        }
        
        return {
            'memory': memory,
            'disk': disk,
            'requirements_met': requirements_met,
            'all_ok': all(requirements_met.values())
        }


class ConfigManager:
    """Gerenciador de configurações do instalador"""
    
    def __init__(self, config_file: str = "installer_config.json"):
        self.config_file = Path(config_file)
        self.config = {}
    
    def load_config(self) -> Dict:
        """Carrega configuração do arquivo"""
        if self.config_file.exists():
            try:
                with open(self.config_file, 'r', encoding='utf-8') as f:
                    self.config = json.load(f)
                return self.config
            except Exception as e:
                print(f"Erro ao carregar configuração: {e}")
        return {}
    
    def save_config(self, config: Dict) -> None:
        """Salva configuração no arquivo"""
        try:
            self.config = config
            with open(self.config_file, 'w', encoding='utf-8') as f:
                json.dump(config, f, indent=4, ensure_ascii=False)
        except Exception as e:
            print(f"Erro ao salvar configuração: {e}")
    
    def get(self, key: str, default=None):
        """Obtém valor da configuração"""
        return self.config.get(key, default)
    
    def set(self, key: str, value):
        """Define valor na configuração"""
        self.config[key] = value
    
    def update(self, updates: Dict):
        """Atualiza múltiplos valores"""
        self.config.update(updates)


class Logger:
    """Configurador de logging para o instalador"""
    
    @staticmethod
    def setup_logger(name: str = "installer", level: int = logging.INFO, 
                    log_file: Optional[str] = None) -> logging.Logger:
        """Configura logger para o instalador"""
        logger = logging.getLogger(name)
        logger.setLevel(level)
        
        # Remover handlers existentes
        for handler in logger.handlers[:]:
            logger.removeHandler(handler)
        
        # Formatter
        formatter = logging.Formatter(
            '%(asctime)s - %(name)s - %(levelname)s - %(message)s'
        )
        
        # Console handler
        console_handler = logging.StreamHandler()
        console_handler.setLevel(level)
        console_handler.setFormatter(formatter)
        logger.addHandler(console_handler)
        
        # File handler se especificado
        if log_file:
            file_handler = logging.FileHandler(log_file, encoding='utf-8')
            file_handler.setLevel(logging.DEBUG)
            file_handler.setFormatter(formatter)
            logger.addHandler(file_handler)
        
        return logger


class ProgressBar:
    """Barra de progresso simples para o terminal"""
    
    def __init__(self, total: int, width: int = 50, prefix: str = "Progresso"):
        self.total = total
        self.width = width
        self.prefix = prefix
        self.current = 0
    
    def update(self, step: int = 1):
        """Atualiza progresso"""
        self.current += step
        self.display()
    
    def display(self):
        """Exibe barra de progresso"""
        percent = (self.current / self.total) * 100
        filled = int(self.width * self.current // self.total)
        bar = '█' * filled + '-' * (self.width - filled)
        
        print(f'\r{self.prefix}: |{bar}| {percent:.1f}% ({self.current}/{self.total})', end='')
        
        if self.current >= self.total:
            print()  # Nova linha quando completo
    
    def finish(self):
        """Finaliza barra de progresso"""
        self.current = self.total
        self.display()


def validate_email(email: str) -> bool:
    """Valida formato de email"""
    import re
    pattern = r'^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$'
    return bool(re.match(pattern, email))


def validate_username(username: str) -> bool:
    """Valida formato de username"""
    import re
    # Username deve ter 3-30 caracteres, apenas letras, números, _ e -
    pattern = r'^[a-zA-Z0-9_-]{3,30}$'
    return bool(re.match(pattern, username))


def validate_password(password: str) -> Tuple[bool, List[str]]:
    """
    Valida força da senha
    
    Returns:
        Tuple (is_valid, list_of_issues)
    """
    issues = []
    
    if len(password) < 8:
        issues.append("Deve ter pelo menos 8 caracteres")
    
    if not any(c.islower() for c in password):
        issues.append("Deve conter pelo menos uma letra minúscula")
    
    if not any(c.isupper() for c in password):
        issues.append("Deve conter pelo menos uma letra maiúscula")
    
    if not any(c.isdigit() for c in password):
        issues.append("Deve conter pelo menos um número")
    
    if not any(c in "!@#$%^&*(),.?\":{}|<>" for c in password):
        issues.append("Deve conter pelo menos um caractere especial")
    
    return len(issues) == 0, issues

