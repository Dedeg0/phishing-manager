# Phishing Manager

Este é um sistema completo de gerenciamento de campanhas de phishing para fins educacionais e de pesquisa de segurança. Ele oferece funcionalidades avançadas para criação de links de phishing, gerenciamento de usuários, domínios, e coleta de informações em tempo real.

## Funcionalidades Principais

- **Gerenciamento de Usuários:** Criação, edição, exclusão, gerenciamento de créditos e permissões.
- **Autenticação Segura:** Login com OTP (One-Time Password) via Telegram.
- **Gerenciamento de Domínios:** Adição, ativação/desativação de domínios, com gerenciamento automático de DNS.
- **Geração de URLs de Phishing:** Criação de URLs únicas com sufixos aleatórios, personalizáveis e com controle de expiração.
- **Scripts de Phishing:** Suporte a scripts de exemplo (Apple, Google) com captura automática de credenciais e tracking avançado.
- **Sistema Anti-Redpage e Anti-Bot:** Detecção e limpeza de URLs, proteção contra bots com múltiplos níveis e fingerprinting avançado.
- **Notificações em Tempo Real:** Envio de informações (IPLogger, User-Agent, etc.) via Telegram para o dono do link e para logs de auditoria.
- **Interface Frontend:** Painel administrativo e de usuário intuitivo e responsivo, com dashboard, gerenciamento de links, histórico e configurações.
- **Métricas e Relatórios:** Coleta de métricas de ambiente (local/online), relatórios detalhados de performance e segurança.
- **Gerenciamento de Credenciais:** Painel seguro para visualizar e exportar credenciais capturadas.
- **Cache:** Otimização de performance com cache em memória.

## Estrutura do Projeto

O projeto é dividido em duas partes principais:

- **`phishing-manager/` (Backend Flask):** Contém a lógica de negócio, APIs, modelos de dados, serviços e rotas.
- **`phishing-manager-frontend/` (Frontend React):** Contém a interface de usuário, componentes e assets.

## Requisitos

- Python 3.9+
- Node.js 14+
- npm ou yarn
- Docker e Docker Compose (recomendado para ambiente de produção)

## Instalação e Configuração

### 1. Backend (Flask)

```bash
cd phishing-manager
pip install -r requirements.txt
# Configurar variáveis de ambiente (veja .env.example)
flask db upgrade
flask run
```

### 2. Frontend (React)

```bash
cd phishing-manager-frontend
npm install
npm start
```

## Variáveis de Ambiente

Crie um arquivo `.env` na raiz do diretório `phishing-manager` com as seguintes variáveis:

```
SECRET_KEY=sua_chave_secreta_aqui
DATABASE_URL=sqlite:///instance/phishing_manager.db
TELEGRAM_BOT_TOKEN=seu_token_do_bot_telegram
TELEGRAM_ADMIN_CHAT_ID=seu_chat_id_de_admin_telegram
FLASK_ENV=development # ou production
```

## Docker Compose (Recomendado para Produção)

Para facilitar a implantação, você pode usar o Docker Compose. Crie um arquivo `docker-compose.yml` na raiz do projeto:

```yaml
version: '3.8'

services:
  backend:
    build: ./phishing-manager
    ports:
      - "5000:5000"
    volumes:
      - ./phishing-manager:/app
    environment:
      - SECRET_KEY=${SECRET_KEY}
      - DATABASE_URL=${DATABASE_URL}
      - TELEGRAM_BOT_TOKEN=${TELEGRAM_BOT_TOKEN}
      - TELEGRAM_ADMIN_CHAT_ID=${TELEGRAM_ADMIN_CHAT_ID}
      - FLASK_ENV=${FLASK_ENV}

  frontend:
    build: ./phishing-manager-frontend
    ports:
      - "3000:3000"
    volumes:
      - ./phishing-manager-frontend:/app
    depends_on:
      - backend
```

Para construir e iniciar os serviços:

```bash
docker-compose build
docker-compose up
```

## Contribuição

Sinta-se à vontade para contribuir com melhorias e novas funcionalidades. Abra um pull request ou uma issue no repositório.

## Licença

Este projeto está licenciado sob a licença MIT. Veja o arquivo `LICENSE` para mais detalhes.


