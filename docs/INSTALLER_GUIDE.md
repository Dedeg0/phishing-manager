# Guia do Instalador Aprimorado do Phishing Manager v2.0

## Visão Geral

O instalador aprimorado do Phishing Manager v2.0 oferece uma experiência de instalação robusta e interativa com múltiplas opções de implantação.

## Características Principais

### 🔧 Detecção Automática de Dependências
- Verificação automática de Python, Node.js, Git, Docker e outras dependências
- Instalação automática de dependências faltantes (quando possível)
- Validação de versões mínimas necessárias

### 🎯 Múltiplos Modos de Instalação
- **Manual**: Instalação tradicional com ambiente virtual
- **Docker**: Instalação containerizada com Docker Compose
- **SystemD**: Instalação como serviço do sistema

### 🛡️ Validação e Segurança
- Validação de configurações antes da instalação
- Verificação de requisitos mínimos do sistema
- Senhas fortes obrigatórias
- Logs detalhados de instalação

### 🎨 Interface Interativa
- Interface colorida e intuitiva
- Assistente de configuração passo-a-passo
- Barras de progresso em tempo real
- Mensagens de erro detalhadas

## Instalação Rápida

### Método 1: Script Automatizado
```bash
curl -sSL https://raw.githubusercontent.com/Dedeg0/phishing-manager/main/scripts/install.sh | bash
```

### Método 2: Manual
```bash
git clone https://github.com/Dedeg0/phishing-manager.git
cd phishing-manager/phishing-manager
python3 install_phishing_manager_v2.py
```

## Modos de Instalação

### 1. Instalação Manual
Instalação tradicional com ambiente virtual Python e servidor de desenvolvimento.

**Requisitos:**
- Python 3.9+
- Node.js 14+
- npm 6+
- Git

**Comando:**
```bash
python3 install_phishing_manager_v2.py --install-mode manual
```

**Estrutura após instalação:**
```
phishing-manager/
├── venv/                 # Ambiente virtual Python
├── src/                  # Código fonte do backend
├── .env                  # Configurações
├── instance/             # Banco de dados
└── logs/                 # Logs da aplicação

phishing-manager-frontend/
├── node_modules/         # Dependências Node.js
├── build/                # Build de produção
└── src/                  # Código fonte do frontend
```

### 2. Instalação Docker
Instalação containerizada usando Docker e Docker Compose.

**Requisitos:**
- Docker 20+
- Docker Compose 1.29+

**Comando:**
```bash
python3 install_phishing_manager_v2.py --install-mode docker
```

**Arquivos criados:**
- `docker-compose.yml`: Configuração dos serviços
- `phishing-manager/Dockerfile`: Imagem do backend
- `phishing-manager-frontend/Dockerfile`: Imagem do frontend

**Gerenciamento:**
```bash
# Iniciar serviços
docker-compose up -d

# Parar serviços
docker-compose down

# Ver logs
docker-compose logs -f

# Reiniciar
docker-compose restart
```

### 3. Instalação SystemD
Instalação como serviço do sistema Linux.

**Requisitos:**
- Linux com SystemD
- Privilégios de root (sudo)
- Python 3.9+

**Comando:**
```bash
sudo python3 install_phishing_manager_v2.py --install-mode systemd
```

**Gerenciamento:**
```bash
# Iniciar serviço
sudo systemctl start phishing-manager-backend

# Parar serviço
sudo systemctl stop phishing-manager-backend

# Status do serviço
sudo systemctl status phishing-manager-backend

# Habilitar inicialização automática
sudo systemctl enable phishing-manager-backend

# Ver logs
sudo journalctl -u phishing-manager-backend -f
```

## Opções da Linha de Comando

### Opções Principais
```bash
--install-mode MODE       # Modo de instalação (manual, docker, systemd)
--config-file FILE        # Arquivo de configuração JSON
--non-interactive         # Modo não-interativo
--uninstall              # Desinstalar
--check-deps             # Apenas verificar dependências
```

### Opções de Controle
```bash
--yes, -y                # Responder sim para todas as perguntas
--force                  # Forçar instalação mesmo com dependências faltantes
--quiet, -q              # Modo silencioso
--no-colors              # Desabilitar cores
```

### Opções de Logging
```bash
--log-level LEVEL        # Nível de log (DEBUG, INFO, WARNING, ERROR)
--log-file FILE          # Arquivo de log
--no-log-file            # Não criar arquivo de log
```

## Exemplos de Uso

### Instalação Interativa Padrão
```bash
python3 install_phishing_manager_v2.py
```

### Instalação Docker Silenciosa
```bash
python3 install_phishing_manager_v2.py --install-mode docker --non-interactive --quiet
```

### Verificar Dependências
```bash
python3 install_phishing_manager_v2.py --check-deps
```

### Desinstalar
```bash
python3 install_phishing_manager_v2.py --uninstall
```

### Instalação com Configuração Personalizada
```bash
python3 install_phishing_manager_v2.py --config-file config.json --yes
```

## Arquivo de Configuração

Exemplo de arquivo de configuração JSON:

```json
{
    "install_mode": "docker",
    "admin_username": "admin",
    "admin_email": "admin@example.com",
    "admin_password": "StrongPass123!",
    "telegram_bot_token": "123456789:ABCdefGHIjklMNOpqrsTUVwxyz",
    "telegram_admin_chat_id": "123456789",
    "environment": "production",
    "backend_port": 5000,
    "frontend_port": 3000,
    "use_https": true,
    "ssl_cert_path": "/etc/ssl/certs/phishing-manager.crt",
    "ssl_key_path": "/etc/ssl/private/phishing-manager.key"
}
```

## Solução de Problemas

### Dependências Faltantes
```bash
# Verificar dependências
python3 install_phishing_manager_v2.py --check-deps

# Instalar dependências automaticamente
python3 install_phishing_manager_v2.py --force
```

### Problemas de Permissão
```bash
# Para instalação SystemD
sudo python3 install_phishing_manager_v2.py --install-mode systemd

# Para Docker (adicionar usuário ao grupo docker)
sudo usermod -aG docker $USER
newgrp docker
```

### Logs de Instalação
```bash
# Ver logs detalhados
python3 install_phishing_manager_v2.py --log-level DEBUG

# Logs em arquivo específico
python3 install_phishing_manager_v2.py --log-file /tmp/install.log
```

### Reinstalação
```bash
# Desinstalar primeiro
python3 install_phishing_manager_v2.py --uninstall --yes

# Reinstalar
python3 install_phishing_manager_v2.py
```

## Estrutura do Instalador

### Módulos Principais
- `installer/core.py`: Funcionalidades principais
- `installer/interface.py`: Interface de usuário
- `installer/installers.py`: Implementações dos instaladores
- `tests/test_installer.py`: Testes automatizados

### Arquivos de Configuração
- `installer_config.json`: Configuração salva
- `installer.log`: Logs de instalação
- `.env`: Variáveis de ambiente (após instalação)

## Requisitos do Sistema

### Mínimos
- **OS**: Linux (Ubuntu 18+, CentOS 7+, Debian 9+)
- **RAM**: 1GB disponível
- **Disco**: 2GB livres
- **Python**: 3.9+

### Recomendados
- **RAM**: 2GB+ disponível
- **Disco**: 5GB+ livres
- **CPU**: 2+ cores
- **Python**: 3.11+

## Segurança

### Validações Implementadas
- Senhas fortes obrigatórias (8+ caracteres, maiúscula, minúscula, número, símbolo)
- Validação de emails e usernames
- Verificação de permissões antes de operações privilegiadas
- Logs de segurança detalhados

### Boas Práticas
- Execute como usuário não-root (exceto para instalação SystemD)
- Use HTTPS em produção
- Configure firewall adequadamente
- Mantenha dependências atualizadas

## Suporte

### Logs
- Logs de instalação: `installer.log`
- Logs da aplicação: `logs/phishing_manager.log`
- Logs do sistema: `journalctl -u phishing-manager-backend`

### Comandos Úteis
```bash
# Status dos serviços
systemctl status phishing-manager-backend

# Verificar portas
netstat -tlnp | grep :5000

# Verificar processos
ps aux | grep phishing

# Verificar Docker
docker-compose ps
docker-compose logs
```

### Contato
- GitHub Issues: https://github.com/Dedeg0/phishing-manager/issues
- Documentação: https://github.com/Dedeg0/phishing-manager/wiki

