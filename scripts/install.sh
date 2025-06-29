#!/bin/bash

# Script de instalação simplificado do Phishing Manager
# Este script baixa e executa o instalador aprimorado

set -e

# Cores para output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Funções auxiliares
print_info() {
    echo -e "${BLUE}[INFO]${NC} $1"
}

print_success() {
    echo -e "${GREEN}[SUCCESS]${NC} $1"
}

print_warning() {
    echo -e "${YELLOW}[WARNING]${NC} $1"
}

print_error() {
    echo -e "${RED}[ERROR]${NC} $1"
}

# Verificar se está rodando como root (para instalação systemd)
check_root() {
    if [[ $EUID -eq 0 ]] && [[ "$INSTALL_MODE" != "systemd" ]]; then
        print_warning "Não é recomendado executar como root, exceto para instalação systemd"
        read -p "Continuar mesmo assim? (y/N): " -n 1 -r
        echo
        if [[ ! $REPLY =~ ^[Yy]$ ]]; then
            exit 1
        fi
    fi
}

# Verificar dependências básicas
check_basic_deps() {
    print_info "Verificando dependências básicas..."
    
    # Python 3
    if ! command -v python3 &> /dev/null; then
        print_error "Python 3 não encontrado. Instale Python 3.9+ antes de continuar."
        exit 1
    fi
    
    # Git
    if ! command -v git &> /dev/null; then
        print_error "Git não encontrado. Instale git antes de continuar."
        exit 1
    fi
    
    print_success "Dependências básicas verificadas"
}

# Baixar ou atualizar repositório
setup_repository() {
    print_info "Configurando repositório..."
    
    if [[ -d "phishing-manager" ]]; then
        print_info "Diretório phishing-manager já existe. Atualizando..."
        cd phishing-manager
        git pull origin main || {
            print_warning "Erro ao atualizar repositório. Continuando com versão local..."
        }
        cd ..
    else
        print_info "Clonando repositório..."
        git clone https://github.com/Dedeg0/phishing-manager.git || {
            print_error "Erro ao clonar repositório"
            exit 1
        }
    fi
    
    print_success "Repositório configurado"
}

# Executar instalador
run_installer() {
    print_info "Executando instalador aprimorado..."
    
    cd phishing-manager/phishing-manager
    
    # Tornar instalador executável
    chmod +x install_phishing_manager_v2.py
    
    # Executar com argumentos passados
    python3 install_phishing_manager_v2.py "$@"
}

# Mostrar ajuda
show_help() {
    cat << EOF
Script de Instalação do Phishing Manager

Uso: $0 [OPÇÕES]

OPÇÕES:
    --mode MODE         Modo de instalação (manual, docker, systemd)
    --non-interactive   Modo não-interativo
    --uninstall         Desinstalar
    --check-deps        Apenas verificar dependências
    --help              Mostrar esta ajuda

EXEMPLOS:
    $0                          # Instalação interativa
    $0 --mode docker            # Instalação Docker
    $0 --non-interactive        # Usar configuração salva
    $0 --uninstall              # Desinstalar
    $0 --check-deps             # Verificar dependências

Para mais opções, execute:
    python3 phishing-manager/phishing-manager/install_phishing_manager_v2.py --help

EOF
}

# Função principal
main() {
    echo "=================================================="
    echo "    Instalador do Phishing Manager v2.0"
    echo "=================================================="
    echo
    
    # Verificar argumentos
    if [[ "$1" == "--help" ]] || [[ "$1" == "-h" ]]; then
        show_help
        exit 0
    fi
    
    # Extrair modo de instalação dos argumentos
    INSTALL_MODE=""
    for arg in "$@"; do
        if [[ "$arg" == "--mode" ]]; then
            shift
            INSTALL_MODE="$1"
            break
        elif [[ "$arg" == "--install-mode" ]]; then
            shift
            INSTALL_MODE="$1"
            break
        fi
    done
    
    # Verificar root se necessário
    check_root
    
    # Verificar dependências básicas
    check_basic_deps
    
    # Configurar repositório
    setup_repository
    
    # Executar instalador
    run_installer "$@"
    
    print_success "Script de instalação concluído!"
}

# Executar função principal com todos os argumentos
main "$@"

