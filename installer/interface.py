"""
Interface interativa para o instalador do Phishing Manager
"""

import os
import sys
import getpass
from typing import Dict, List, Optional, Any
from .core import validate_email, validate_username, validate_password


class Colors:
    """Códigos de cores ANSI para terminal"""
    RESET = '\033[0m'
    BOLD = '\033[1m'
    DIM = '\033[2m'
    
    # Cores de texto
    BLACK = '\033[30m'
    RED = '\033[31m'
    GREEN = '\033[32m'
    YELLOW = '\033[33m'
    BLUE = '\033[34m'
    MAGENTA = '\033[35m'
    CYAN = '\033[36m'
    WHITE = '\033[37m'
    
    # Cores de fundo
    BG_BLACK = '\033[40m'
    BG_RED = '\033[41m'
    BG_GREEN = '\033[42m'
    BG_YELLOW = '\033[43m'
    BG_BLUE = '\033[44m'
    BG_MAGENTA = '\033[45m'
    BG_CYAN = '\033[46m'
    BG_WHITE = '\033[47m'


class UI:
    """Classe para interface de usuário do instalador"""
    
    def __init__(self, use_colors: bool = True):
        self.use_colors = use_colors and self._supports_color()
    
    def _supports_color(self) -> bool:
        """Verifica se terminal suporta cores"""
        return (
            hasattr(sys.stdout, "isatty") and sys.stdout.isatty() and
            os.environ.get("TERM") != "dumb"
        )
    
    def _colorize(self, text: str, color: str) -> str:
        """Aplica cor ao texto se suportado"""
        if self.use_colors:
            return f"{color}{text}{Colors.RESET}"
        return text
    
    def print_header(self, title: str, width: int = 80):
        """Imprime cabeçalho estilizado"""
        border = "=" * width
        padding = (width - len(title) - 2) // 2
        header = f"{' ' * padding} {title} {' ' * padding}"
        if len(header) < width:
            header += " "
        
        print()
        print(self._colorize(border, Colors.CYAN + Colors.BOLD))
        print(self._colorize(header, Colors.CYAN + Colors.BOLD))
        print(self._colorize(border, Colors.CYAN + Colors.BOLD))
        print()
    
    def print_section(self, title: str):
        """Imprime título de seção"""
        print(self._colorize(f"\n--- {title} ---", Colors.YELLOW + Colors.BOLD))
    
    def print_success(self, message: str):
        """Imprime mensagem de sucesso"""
        print(self._colorize(f"✓ {message}", Colors.GREEN))
    
    def print_error(self, message: str):
        """Imprime mensagem de erro"""
        print(self._colorize(f"✗ {message}", Colors.RED))
    
    def print_warning(self, message: str):
        """Imprime mensagem de aviso"""
        print(self._colorize(f"⚠ {message}", Colors.YELLOW))
    
    def print_info(self, message: str):
        """Imprime mensagem informativa"""
        print(self._colorize(f"ℹ {message}", Colors.BLUE))
    
    def print_step(self, step: int, total: int, message: str):
        """Imprime passo atual"""
        print(self._colorize(f"[{step}/{total}] {message}", Colors.CYAN))
    
    def input_text(self, prompt: str, default: str = None, required: bool = True) -> str:
        """Solicita entrada de texto"""
        if default:
            full_prompt = f"{prompt} [{default}]: "
        else:
            full_prompt = f"{prompt}: "
        
        while True:
            try:
                value = input(full_prompt).strip()
                if not value and default:
                    return default
                if not value and required:
                    self.print_error("Este campo é obrigatório.")
                    continue
                return value
            except KeyboardInterrupt:
                print("\nOperação cancelada pelo usuário.")
                sys.exit(1)
    
    def input_password(self, prompt: str = "Senha", confirm: bool = True, 
                      validate: bool = True) -> str:
        """Solicita entrada de senha"""
        while True:
            try:
                password = getpass.getpass(f"{prompt}: ")
                
                if validate:
                    is_valid, issues = validate_password(password)
                    if not is_valid:
                        self.print_error("Senha não atende aos requisitos:")
                        for issue in issues:
                            print(f"  - {issue}")
                        continue
                
                if confirm:
                    confirm_password = getpass.getpass("Confirme a senha: ")
                    if password != confirm_password:
                        self.print_error("Senhas não coincidem.")
                        continue
                
                return password
            except KeyboardInterrupt:
                print("\nOperação cancelada pelo usuário.")
                sys.exit(1)
    
    def input_choice(self, prompt: str, choices: List[str], default: str = None) -> str:
        """Solicita escolha entre opções"""
        choices_str = "/".join(choices)
        if default:
            full_prompt = f"{prompt} ({choices_str}) [{default}]: "
        else:
            full_prompt = f"{prompt} ({choices_str}): "
        
        while True:
            try:
                choice = input(full_prompt).strip().lower()
                if not choice and default:
                    return default.lower()
                if choice in [c.lower() for c in choices]:
                    return choice
                self.print_error(f"Escolha inválida. Opções: {choices_str}")
            except KeyboardInterrupt:
                print("\nOperação cancelada pelo usuário.")
                sys.exit(1)
    
    def input_yes_no(self, prompt: str, default: bool = None) -> bool:
        """Solicita confirmação sim/não"""
        if default is True:
            choices = ["s", "n"]
            default_str = "s"
        elif default is False:
            choices = ["s", "n"]
            default_str = "n"
        else:
            choices = ["s", "n"]
            default_str = None
        
        choice = self.input_choice(prompt, choices, default_str)
        return choice == "s"
    
    def input_email(self, prompt: str = "Email", default: str = None) -> str:
        """Solicita entrada de email com validação"""
        while True:
            email = self.input_text(prompt, default)
            if validate_email(email):
                return email
            self.print_error("Formato de email inválido.")
    
    def input_username(self, prompt: str = "Username", default: str = None) -> str:
        """Solicita entrada de username com validação"""
        while True:
            username = self.input_text(prompt, default)
            if validate_username(username):
                return username
            self.print_error("Username deve ter 3-30 caracteres (letras, números, _ e -).")
    
    def show_menu(self, title: str, options: List[str], allow_back: bool = False) -> int:
        """Exibe menu de opções"""
        self.print_section(title)
        
        for i, option in enumerate(options, 1):
            print(f"{i}. {option}")
        
        if allow_back:
            print("0. Voltar")
        
        while True:
            try:
                choice = input("\nEscolha uma opção: ").strip()
                if not choice.isdigit():
                    self.print_error("Digite um número válido.")
                    continue
                
                choice_num = int(choice)
                if allow_back and choice_num == 0:
                    return 0
                if 1 <= choice_num <= len(options):
                    return choice_num
                
                self.print_error(f"Opção inválida. Digite um número entre 1 e {len(options)}.")
            except KeyboardInterrupt:
                print("\nOperação cancelada pelo usuário.")
                sys.exit(1)
    
    def show_system_info(self, system_info: Dict[str, Any]):
        """Exibe informações do sistema"""
        self.print_section("Informações do Sistema")
        
        os_info = system_info.get('os', {})
        python_info = system_info.get('python', {})
        memory_info = system_info.get('memory', {})
        disk_info = system_info.get('disk', {})
        
        print(f"Sistema Operacional: {os_info.get('system', 'N/A')} {os_info.get('release', '')}")
        print(f"Arquitetura: {os_info.get('architecture', 'N/A')}")
        print(f"Python: {python_info.get('version', 'N/A')} ({python_info.get('implementation', 'N/A')})")
        print(f"Memória: {memory_info.get('available_gb', 0):.1f}GB disponível de {memory_info.get('total_gb', 0):.1f}GB")
        print(f"Disco: {disk_info.get('free_gb', 0):.1f}GB livres de {disk_info.get('total_gb', 0):.1f}GB")
    
    def show_dependency_status(self, dependencies: Dict[str, Dict[str, Any]]):
        """Exibe status das dependências"""
        self.print_section("Status das Dependências")
        
        for name, info in dependencies.items():
            if info['found'] and info['version_ok']:
                status = self._colorize("✓ OK", Colors.GREEN)
                version_info = f"({info['version']})" if info['version'] else ""
            elif info['found'] and not info['version_ok']:
                status = self._colorize("⚠ VERSÃO ANTIGA", Colors.YELLOW)
                version_info = f"({info['version']}, mín: {info['min_version']})"
            else:
                status = self._colorize("✗ NÃO ENCONTRADO", Colors.RED)
                version_info = ""
            
            print(f"{name.capitalize()}: {status} {version_info}")
            if info.get('error'):
                print(f"  {self._colorize(info['error'], Colors.RED)}")
    
    def show_installation_summary(self, config: Dict[str, Any]):
        """Exibe resumo da instalação"""
        self.print_section("Resumo da Instalação")
        
        print(f"Modo de instalação: {config.get('install_mode', 'N/A')}")
        print(f"Usuário administrador: {config.get('admin_username', 'N/A')}")
        print(f"Email: {config.get('admin_email', 'N/A')}")
        print(f"Bot Telegram configurado: {'Sim' if config.get('telegram_bot_token') else 'Não'}")
        print(f"Ambiente: {config.get('environment', 'development')}")
        
        if config.get('install_mode') == 'docker':
            print(f"Porta backend: {config.get('backend_port', 5000)}")
            print(f"Porta frontend: {config.get('frontend_port', 3000)}")
    
    def confirm_installation(self, config: Dict[str, Any]) -> bool:
        """Confirma instalação com o usuário"""
        self.show_installation_summary(config)
        print()
        return self.input_yes_no("Confirma a instalação com essas configurações?")
    
    def show_progress_step(self, step: str, current: int, total: int):
        """Exibe progresso da instalação"""
        progress = int((current / total) * 100)
        bar_length = 30
        filled_length = int(bar_length * current // total)
        bar = '█' * filled_length + '-' * (bar_length - filled_length)
        
        print(f"\r[{bar}] {progress}% - {step}", end='', flush=True)
        if current >= total:
            print()  # Nova linha quando completo
    
    def show_completion_message(self, config: Dict[str, Any]):
        """Exibe mensagem de conclusão"""
        self.print_header("INSTALAÇÃO CONCLUÍDA COM SUCESSO!")
        
        install_mode = config.get('install_mode', 'manual')
        
        if install_mode == 'docker':
            self.print_info("Para iniciar o Phishing Manager:")
            print("1. Execute: docker-compose up -d")
            print(f"2. Acesse: http://localhost:{config.get('frontend_port', 3000)}")
        
        elif install_mode == 'systemd':
            self.print_info("Para gerenciar o Phishing Manager:")
            print("1. Iniciar: sudo systemctl start phishing-manager")
            print("2. Parar: sudo systemctl stop phishing-manager")
            print("3. Status: sudo systemctl status phishing-manager")
            print(f"4. Acesse: http://localhost:{config.get('frontend_port', 3000)}")
        
        else:
            self.print_info("Para iniciar o Phishing Manager:")
            print("1. Backend:")
            print("   cd phishing-manager")
            print("   source venv/bin/activate")
            print("   flask run")
            print("2. Frontend (novo terminal):")
            print("   cd phishing-manager-frontend")
            print("   npm start")
            print(f"3. Acesse: http://localhost:{config.get('frontend_port', 3000)}")
        
        print()
        self.print_success("Instalação concluída! Verifique os logs em caso de problemas.")
        
        # Informações de login
        print()
        self.print_section("Informações de Login")
        print(f"Username: {config.get('admin_username')}")
        print(f"Email: {config.get('admin_email')}")
        print("Senha: (a que você definiu durante a instalação)")
    
    def show_error_summary(self, errors: List[str]):
        """Exibe resumo de erros"""
        self.print_section("ERROS ENCONTRADOS")
        for i, error in enumerate(errors, 1):
            self.print_error(f"{i}. {error}")
        
        print()
        self.print_info("Verifique os logs para mais detalhes.")
    
    def pause(self, message: str = "Pressione Enter para continuar..."):
        """Pausa execução aguardando entrada do usuário"""
        try:
            input(message)
        except KeyboardInterrupt:
            print("\nOperação cancelada pelo usuário.")
            sys.exit(1)
    
    def clear_screen(self):
        """Limpa tela do terminal"""
        os.system('clear' if os.name == 'posix' else 'cls')


class ConfigurationWizard:
    """Assistente de configuração interativo"""
    
    def __init__(self, ui: UI):
        self.ui = ui
        self.config = {}
    
    def run(self, existing_config: Dict = None) -> Dict[str, Any]:
        """Executa assistente de configuração"""
        self.ui.print_header("ASSISTENTE DE CONFIGURAÇÃO")
        
        if existing_config:
            use_existing = self.ui.input_yes_no(
                "Configuração existente encontrada. Deseja usá-la?", 
                default=True
            )
            if use_existing:
                self.config = existing_config.copy()
                return self.config
        
        # Modo de instalação
        self._configure_install_mode()
        
        # Configurações básicas
        self._configure_admin_user()
        
        # Configurações do Telegram
        self._configure_telegram()
        
        # Configurações de ambiente
        self._configure_environment()
        
        # Configurações específicas do modo
        if self.config['install_mode'] == 'docker':
            self._configure_docker()
        elif self.config['install_mode'] == 'systemd':
            self._configure_systemd()
        
        return self.config
    
    def _configure_install_mode(self):
        """Configura modo de instalação"""
        self.ui.print_section("Modo de Instalação")
        
        modes = [
            "Manual (instalação tradicional)",
            "Docker (containerizado)",
            "SystemD (serviço do sistema)"
        ]
        
        choice = self.ui.show_menu("Escolha o modo de instalação", modes)
        
        mode_map = {1: 'manual', 2: 'docker', 3: 'systemd'}
        self.config['install_mode'] = mode_map[choice]
    
    def _configure_admin_user(self):
        """Configura usuário administrador"""
        self.ui.print_section("Usuário Administrador")
        
        self.config['admin_username'] = self.ui.input_username(
            "Nome de usuário do administrador",
            self.config.get('admin_username', 'admin')
        )
        
        self.config['admin_email'] = self.ui.input_email(
            "Email do administrador",
            self.config.get('admin_email')
        )
        
        if not self.config.get('admin_password'):
            self.ui.print_info("A senha deve ter pelo menos 8 caracteres com maiúscula, minúscula, número e símbolo.")
            self.config['admin_password'] = self.ui.input_password(
                "Senha do administrador"
            )
    
    def _configure_telegram(self):
        """Configura integração com Telegram"""
        self.ui.print_section("Configuração do Telegram")
        
        configure_telegram = self.ui.input_yes_no(
            "Deseja configurar integração com Telegram?",
            default=True
        )
        
        if configure_telegram:
            self.config['telegram_bot_token'] = self.ui.input_text(
                "Token do Bot Telegram",
                self.config.get('telegram_bot_token')
            )
            
            self.config['telegram_admin_chat_id'] = self.ui.input_text(
                "Chat ID do administrador",
                self.config.get('telegram_admin_chat_id')
            )
        else:
            self.config['telegram_bot_token'] = ""
            self.config['telegram_admin_chat_id'] = ""
    
    def _configure_environment(self):
        """Configura ambiente"""
        self.ui.print_section("Configuração do Ambiente")
        
        environments = ["development", "production", "testing"]
        env_choice = self.ui.input_choice(
            "Ambiente de execução",
            environments,
            self.config.get('environment', 'development')
        )
        
        self.config['environment'] = env_choice
        
        # Configurações específicas de produção
        if env_choice == 'production':
            self.config['use_https'] = self.ui.input_yes_no(
                "Usar HTTPS?", default=True
            )
            
            if self.config['use_https']:
                self.config['ssl_cert_path'] = self.ui.input_text(
                    "Caminho do certificado SSL",
                    self.config.get('ssl_cert_path', '/etc/ssl/certs/phishing-manager.crt')
                )
                
                self.config['ssl_key_path'] = self.ui.input_text(
                    "Caminho da chave SSL",
                    self.config.get('ssl_key_path', '/etc/ssl/private/phishing-manager.key')
                )
    
    def _configure_docker(self):
        """Configura opções específicas do Docker"""
        self.ui.print_section("Configuração Docker")
        
        self.config['backend_port'] = int(self.ui.input_text(
            "Porta do backend",
            str(self.config.get('backend_port', 5000))
        ))
        
        self.config['frontend_port'] = int(self.ui.input_text(
            "Porta do frontend",
            str(self.config.get('frontend_port', 3000))
        ))
        
        self.config['use_external_db'] = self.ui.input_yes_no(
            "Usar banco de dados externo?",
            default=False
        )
        
        if self.config['use_external_db']:
            self.config['database_url'] = self.ui.input_text(
                "URL do banco de dados",
                self.config.get('database_url', 'postgresql://user:pass@localhost/phishing_manager')
            )
    
    def _configure_systemd(self):
        """Configura opções específicas do SystemD"""
        self.ui.print_section("Configuração SystemD")
        
        self.config['service_user'] = self.ui.input_text(
            "Usuário do serviço",
            self.config.get('service_user', 'phishing-manager')
        )
        
        self.config['service_group'] = self.ui.input_text(
            "Grupo do serviço",
            self.config.get('service_group', 'phishing-manager')
        )
        
        self.config['install_path'] = self.ui.input_text(
            "Caminho de instalação",
            self.config.get('install_path', '/opt/phishing-manager')
        )

