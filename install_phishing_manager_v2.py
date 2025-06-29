#!/usr/bin/env python3
"""
Instalador Aprimorado do Phishing Manager v2.0

Este instalador oferece uma experiência melhorada com:
- Interface interativa e intuitiva
- Detecção automática de dependências
- Múltiplos modos de instalação (Manual, Docker, SystemD)
- Tratamento robusto de erros
- Logs detalhados
- Validação de configurações
- Backup e restauração
"""

import os
import sys
import platform
import argparse
from pathlib import Path

# Adicionar diretório do instalador ao path
sys.path.insert(0, str(Path(__file__).parent))

from installer import (
    SystemInfo, CommandRunner, DependencyChecker, ConfigManager,
    Logger, UI, ConfigurationWizard, get_installer, InstallerError
)


class PhishingManagerInstaller:
    """Instalador principal do Phishing Manager"""
    
    def __init__(self, args):
        self.args = args
        self.setup_logging()
        self.setup_ui()
        self.setup_components()
        self.errors = []
    
    def setup_logging(self):
        """Configura sistema de logging"""
        log_level = getattr(self.args, 'log_level', 'INFO')
        log_file = getattr(self.args, 'log_file', 'installer.log')
        
        self.logger = Logger.setup_logger(
            name="phishing_manager_installer",
            level=getattr(__import__('logging'), log_level.upper()),
            log_file=log_file if not getattr(self.args, 'no_log_file', False) else None
        )
    
    def setup_ui(self):
        """Configura interface de usuário"""
        use_colors = not getattr(self.args, 'no_colors', False)
        self.ui = UI(use_colors=use_colors)
    
    def setup_components(self):
        """Configura componentes do instalador"""
        self.runner = CommandRunner(self.logger)
        self.dependency_checker = DependencyChecker(self.logger, self.runner)
        self.config_manager = ConfigManager()
        self.wizard = ConfigurationWizard(self.ui)
    
    def check_prerequisites(self) -> bool:
        """Verifica pré-requisitos do sistema"""
        self.ui.print_section("Verificação de Pré-requisitos")
        
        # Verificar sistema operacional
        if platform.system() != "Linux":
            self.ui.print_error("Este instalador é destinado apenas para sistemas Linux.")
            return False
        
        # Verificar permissões
        if getattr(self.args, 'install_mode', 'manual') == 'systemd' and os.geteuid() != 0:
            self.ui.print_error("Instalação SystemD requer privilégios de root (sudo).")
            return False
        
        # Obter informações do sistema
        system_info = {
            'os': SystemInfo.get_os_info(),
            'python': SystemInfo.get_python_info(),
            'memory': SystemInfo.check_memory(),
            'disk': SystemInfo.check_disk_space()
        }
        
        # Exibir informações do sistema
        if not getattr(self.args, 'quiet', False):
            self.ui.show_system_info(system_info)
        
        # Verificar requisitos mínimos
        requirements = self.dependency_checker.check_system_requirements()
        if not requirements['all_ok']:
            self.ui.print_error("Sistema não atende aos requisitos mínimos:")
            if not requirements['requirements_met']['memory']:
                self.ui.print_error("- Memória insuficiente (mínimo 1GB disponível)")
            if not requirements['requirements_met']['disk']:
                self.ui.print_error("- Espaço em disco insuficiente (mínimo 2GB livres)")
            if not requirements['requirements_met']['os']:
                self.ui.print_error("- Sistema operacional não suportado")
            return False
        
        return True
    
    def check_dependencies(self) -> bool:
        """Verifica dependências necessárias"""
        self.ui.print_section("Verificação de Dependências")
        
        dependencies = self.dependency_checker.check_all_dependencies()
        
        if not getattr(self.args, 'quiet', False):
            self.ui.show_dependency_status(dependencies)
        
        # Verificar dependências críticas
        critical_deps = ['python', 'git']
        install_mode = getattr(self.args, 'install_mode', 'manual')
        
        if install_mode == 'docker':
            critical_deps.extend(['docker', 'docker-compose'])
        elif install_mode == 'manual':
            critical_deps.extend(['node', 'npm'])
        
        missing_critical = []
        for dep in critical_deps:
            if dep in dependencies:
                dep_info = dependencies[dep]
                if not dep_info['found'] or not dep_info['version_ok']:
                    missing_critical.append(dep)
        
        if missing_critical:
            self.ui.print_error(f"Dependências críticas não atendidas: {', '.join(missing_critical)}")
            
            if not getattr(self.args, 'force', False):
                install_deps = self.ui.input_yes_no(
                    "Tentar instalar dependências automaticamente?",
                    default=True
                )
                
                if install_deps:
                    return self.install_missing_dependencies(missing_critical)
                else:
                    self.ui.print_info("Instale as dependências manualmente e execute o instalador novamente.")
                    return False
        
        return True
    
    def install_missing_dependencies(self, missing_deps: list) -> bool:
        """Instala dependências faltantes automaticamente"""
        self.ui.print_section("Instalação Automática de Dependências")
        
        try:
            # Detectar gerenciador de pacotes
            package_managers = {
                'apt': 'apt-get',
                'yum': 'yum',
                'dnf': 'dnf',
                'pacman': 'pacman',
                'zypper': 'zypper'
            }
            
            pm = None
            for name, cmd in package_managers.items():
                if self.runner.run_silent(f"command -v {cmd}"):
                    pm = name
                    break
            
            if not pm:
                self.ui.print_error("Gerenciador de pacotes não detectado.")
                return False
            
            self.ui.print_info(f"Usando gerenciador de pacotes: {pm}")
            
            # Mapear dependências para pacotes
            package_map = {
                'apt': {
                    'python': 'python3 python3-pip python3-venv',
                    'node': 'nodejs npm',
                    'git': 'git',
                    'curl': 'curl',
                    'wget': 'wget',
                    'docker': 'docker.io',
                    'docker-compose': 'docker-compose'
                },
                'yum': {
                    'python': 'python3 python3-pip',
                    'node': 'nodejs npm',
                    'git': 'git',
                    'curl': 'curl',
                    'wget': 'wget',
                    'docker': 'docker',
                    'docker-compose': 'docker-compose'
                }
            }
            
            packages_to_install = []
            for dep in missing_deps:
                if dep in package_map.get(pm, {}):
                    packages_to_install.extend(package_map[pm][dep].split())
            
            if packages_to_install:
                # Atualizar cache de pacotes
                if pm == 'apt':
                    self.runner.run("sudo apt-get update")
                    install_cmd = f"sudo apt-get install -y {' '.join(packages_to_install)}"
                elif pm == 'yum':
                    install_cmd = f"sudo yum install -y {' '.join(packages_to_install)}"
                elif pm == 'dnf':
                    install_cmd = f"sudo dnf install -y {' '.join(packages_to_install)}"
                else:
                    self.ui.print_error(f"Instalação automática não suportada para {pm}")
                    return False
                
                self.ui.print_info(f"Instalando pacotes: {' '.join(packages_to_install)}")
                self.runner.run(install_cmd, timeout=600)
                
                self.ui.print_success("Dependências instaladas com sucesso!")
                return True
            
        except InstallerError as e:
            self.ui.print_error(f"Erro ao instalar dependências: {e}")
            return False
        
        return True
    
    def configure_installation(self) -> dict:
        """Configura parâmetros da instalação"""
        # Carregar configuração existente
        existing_config = self.config_manager.load_config()
        
        # Usar argumentos da linha de comando se fornecidos
        if hasattr(self.args, 'config_file') and self.args.config_file:
            try:
                import json
                with open(self.args.config_file, 'r') as f:
                    cli_config = json.load(f)
                existing_config.update(cli_config)
            except Exception as e:
                self.ui.print_warning(f"Erro ao carregar arquivo de configuração: {e}")
        
        # Usar modo não-interativo se especificado
        if getattr(self.args, 'non_interactive', False):
            if not existing_config:
                self.ui.print_error("Modo não-interativo requer configuração existente.")
                return None
            return existing_config
        
        # Executar assistente de configuração
        config = self.wizard.run(existing_config)
        
        # Salvar configuração
        self.config_manager.save_config(config)
        
        return config
    
    def perform_installation(self, config: dict) -> bool:
        """Executa a instalação"""
        self.ui.print_section("Executando Instalação")
        
        # Confirmar instalação
        if not getattr(self.args, 'yes', False):
            if not self.ui.confirm_installation(config):
                self.ui.print_info("Instalação cancelada pelo usuário.")
                return False
        
        # Obter instalador apropriado
        install_mode = config.get('install_mode', 'manual')
        try:
            installer = get_installer(install_mode, config, self.runner, self.ui)
        except ValueError as e:
            self.ui.print_error(str(e))
            return False
        
        # Executar instalação
        success = installer.install()
        
        if success:
            self.ui.show_completion_message(config)
        else:
            self.ui.show_error_summary(installer.errors)
        
        return success
    
    def run_uninstall(self) -> bool:
        """Executa desinstalação"""
        self.ui.print_header("DESINSTALAÇÃO DO PHISHING MANAGER")
        
        # Carregar configuração
        config = self.config_manager.load_config()
        if not config:
            self.ui.print_error("Configuração não encontrada. Não é possível determinar o modo de instalação.")
            return False
        
        install_mode = config.get('install_mode', 'manual')
        
        # Confirmar desinstalação
        if not getattr(self.args, 'yes', False):
            confirm = self.ui.input_yes_no(
                f"Confirma a desinstalação do Phishing Manager (modo: {install_mode})?",
                default=False
            )
            if not confirm:
                self.ui.print_info("Desinstalação cancelada.")
                return False
        
        # Obter instalador e executar desinstalação
        try:
            installer = get_installer(install_mode, config, self.runner, self.ui)
            success = installer.uninstall()
            
            if success:
                # Remover configuração
                config_file = Path("installer_config.json")
                if config_file.exists():
                    config_file.unlink()
                
                self.ui.print_success("Desinstalação concluída com sucesso!")
            
            return success
            
        except Exception as e:
            self.ui.print_error(f"Erro durante desinstalação: {e}")
            return False
    
    def run(self) -> int:
        """Executa o instalador"""
        try:
            # Exibir cabeçalho
            if not getattr(self.args, 'quiet', False):
                self.ui.print_header("INSTALADOR DO PHISHING MANAGER v2.0")
            
            # Verificar se é desinstalação
            if getattr(self.args, 'uninstall', False):
                success = self.run_uninstall()
                return 0 if success else 1
            
            # Verificar pré-requisitos
            if not self.check_prerequisites():
                return 1
            
            # Verificar dependências
            if not self.check_dependencies():
                return 1
            
            # Configurar instalação
            config = self.configure_installation()
            if not config:
                return 1
            
            # Executar instalação
            success = self.perform_installation(config)
            return 0 if success else 1
            
        except KeyboardInterrupt:
            self.ui.print_error("\nInstalação interrompida pelo usuário.")
            return 130
        except Exception as e:
            self.logger.exception("Erro inesperado durante instalação")
            self.ui.print_error(f"Erro inesperado: {e}")
            return 1


def create_argument_parser():
    """Cria parser de argumentos da linha de comando"""
    parser = argparse.ArgumentParser(
        description="Instalador Aprimorado do Phishing Manager v2.0",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Exemplos de uso:
  %(prog)s                          # Instalação interativa
  %(prog)s --install-mode docker    # Instalação Docker
  %(prog)s --non-interactive        # Usar configuração salva
  %(prog)s --uninstall              # Desinstalar
  %(prog)s --check-deps             # Apenas verificar dependências
        """
    )
    
    # Argumentos principais
    parser.add_argument(
        '--install-mode',
        choices=['manual', 'docker', 'systemd'],
        help='Modo de instalação'
    )
    
    parser.add_argument(
        '--config-file',
        help='Arquivo de configuração JSON'
    )
    
    parser.add_argument(
        '--non-interactive',
        action='store_true',
        help='Modo não-interativo (usar configuração salva)'
    )
    
    parser.add_argument(
        '--uninstall',
        action='store_true',
        help='Desinstalar Phishing Manager'
    )
    
    parser.add_argument(
        '--check-deps',
        action='store_true',
        help='Apenas verificar dependências'
    )
    
    # Argumentos de controle
    parser.add_argument(
        '--yes', '-y',
        action='store_true',
        help='Responder sim para todas as perguntas'
    )
    
    parser.add_argument(
        '--force',
        action='store_true',
        help='Forçar instalação mesmo com dependências faltantes'
    )
    
    parser.add_argument(
        '--quiet', '-q',
        action='store_true',
        help='Modo silencioso (menos output)'
    )
    
    parser.add_argument(
        '--no-colors',
        action='store_true',
        help='Desabilitar cores no terminal'
    )
    
    # Argumentos de logging
    parser.add_argument(
        '--log-level',
        choices=['DEBUG', 'INFO', 'WARNING', 'ERROR'],
        default='INFO',
        help='Nível de log'
    )
    
    parser.add_argument(
        '--log-file',
        default='installer.log',
        help='Arquivo de log'
    )
    
    parser.add_argument(
        '--no-log-file',
        action='store_true',
        help='Não criar arquivo de log'
    )
    
    return parser


def main():
    """Função principal"""
    parser = create_argument_parser()
    args = parser.parse_args()
    
    # Verificar se é apenas verificação de dependências
    if args.check_deps:
        ui = UI(use_colors=not args.no_colors)
        logger = Logger.setup_logger(level=getattr(__import__('logging'), args.log_level))
        runner = CommandRunner(logger)
        checker = DependencyChecker(logger, runner)
        
        ui.print_header("VERIFICAÇÃO DE DEPENDÊNCIAS")
        dependencies = checker.check_all_dependencies()
        ui.show_dependency_status(dependencies)
        
        # Verificar requisitos do sistema
        requirements = checker.check_system_requirements()
        system_info = {
            'memory': requirements['memory'],
            'disk': requirements['disk']
        }
        ui.show_system_info({'memory': system_info['memory'], 'disk': system_info['disk']})
        
        return 0 if requirements['all_ok'] else 1
    
    # Executar instalador
    installer = PhishingManagerInstaller(args)
    return installer.run()


if __name__ == "__main__":
    sys.exit(main())

