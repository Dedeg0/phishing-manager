"""
Instalador aprimorado do Phishing Manager

Este módulo fornece um sistema de instalação robusto e interativo
para o Phishing Manager com suporte a múltiplos modos de instalação.
"""

from .core import (
    InstallerError,
    SystemInfo,
    CommandRunner,
    DependencyChecker,
    ConfigManager,
    Logger,
    ProgressBar,
    validate_email,
    validate_username,
    validate_password
)

from .interface import (
    Colors,
    UI,
    ConfigurationWizard
)

from .installers import (
    BaseInstaller,
    ManualInstaller,
    DockerInstaller,
    SystemdInstaller,
    get_installer
)

__version__ = "2.0.0"
__author__ = "Phishing Manager Team"
__description__ = "Instalador aprimorado do Phishing Manager"

__all__ = [
    # Core
    'InstallerError',
    'SystemInfo',
    'CommandRunner',
    'DependencyChecker',
    'ConfigManager',
    'Logger',
    'ProgressBar',
    'validate_email',
    'validate_username',
    'validate_password',
    
    # Interface
    'Colors',
    'UI',
    'ConfigurationWizard',
    
    # Installers
    'BaseInstaller',
    'ManualInstaller',
    'DockerInstaller',
    'SystemdInstaller',
    'get_installer'
]

