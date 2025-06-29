# Configuração do Sistema OTP com Telegram

## Visão Geral

O sistema de OTP (One-Time Password) integrado com Telegram adiciona uma camada extra de segurança ao Phishing Manager. Quando habilitado, os usuários receberão códigos de verificação de 6 dígitos em seus chats do Telegram durante o processo de login.

## Configuração do Bot do Telegram

### 1. Criar um Bot no Telegram

1. Abra o Telegram e procure por `@BotFather`
2. Inicie uma conversa com o BotFather
3. Digite `/newbot` para criar um novo bot
4. Siga as instruções para escolher um nome e username para o bot
5. O BotFather fornecerá um token de acesso (ex: `123456789:ABCdefGHIjklMNOpqrsTUVwxyz`)

### 2. Configurar o Token no Sistema

Defina a variável de ambiente `TELEGRAM_BOT_TOKEN` com o token fornecido pelo BotFather:

```bash
export TELEGRAM_BOT_TOKEN="123456789:ABCdefGHIjklMNOpqrsTUVwxyz"
```

Ou adicione ao arquivo `.env` na raiz do projeto:

```
TELEGRAM_BOT_TOKEN=123456789:ABCdefGHIjklMNOpqrsTUVwxyz
```

## Como os Usuários Configuram o Telegram

### 1. Obter o Chat ID

Para configurar o Telegram, os usuários precisam do seu Chat ID. Existem várias formas de obtê-lo:

**Método 1: Usando @userinfobot**
1. Procure por `@userinfobot` no Telegram
2. Inicie uma conversa e envie `/start`
3. O bot retornará informações incluindo o Chat ID

**Método 2: Usando @get_id_bot**
1. Procure por `@get_id_bot` no Telegram
2. Inicie uma conversa e o bot enviará automaticamente o Chat ID

**Método 3: Através da API do Telegram**
1. Envie uma mensagem para o bot criado
2. Acesse: `https://api.telegram.org/bot<TOKEN>/getUpdates`
3. Procure pelo campo `"chat":{"id":CHAT_ID}`

### 2. Configurar no Sistema

1. Faça login no sistema
2. Acesse as configurações de segurança
3. Insira o Chat ID obtido
4. Opcionalmente, insira seu username do Telegram
5. Clique em "Configurar Telegram"
6. O sistema enviará uma mensagem de confirmação

### 3. Habilitar OTP

1. Após configurar o Telegram, habilite o OTP nas configurações
2. Teste o envio de OTP usando a função de teste
3. A partir de agora, todos os logins exigirão código OTP

## Endpoints da API

### Configuração do Telegram

```http
POST /api/telegram/configure
Content-Type: application/json
Authorization: Bearer <token>

{
    "chat_id": "123456789",
    "telegram_username": "@meuusername"
}
```

### Habilitar OTP

```http
POST /api/otp/enable
Authorization: Bearer <token>
```

### Desabilitar OTP

```http
POST /api/otp/disable
Authorization: Bearer <token>
```

### Testar Envio de OTP

```http
POST /api/otp/test
Authorization: Bearer <token>
```

### Login com OTP

```http
POST /api/login
Content-Type: application/json

{
    "username": "usuario",
    "password": "senha",
    "otp_code": "123456"
}
```

Se o OTP estiver habilitado e não for fornecido, o sistema retornará:

```json
{
    "otp_required": true,
    "message": "Código OTP enviado para seu Telegram. Insira o código para continuar."
}
```

## Funcionalidades Administrativas

### Desabilitar OTP de um Usuário

```http
POST /api/admin/users/<user_id>/disable-otp
Authorization: Bearer <admin_token>
```

### Visualizar Logs de OTP

Os logs do sistema registram todas as atividades relacionadas ao OTP:

- `OTP_ENABLED`: OTP habilitado pelo usuário
- `OTP_DISABLED`: OTP desabilitado pelo usuário
- `OTP_SENT_TELEGRAM`: Código OTP enviado via Telegram
- `OTP_SEND_FAILED`: Falha ao enviar OTP
- `OTP_VERIFICATION_FAILED`: Código OTP inválido
- `TELEGRAM_CONFIGURED`: Telegram configurado
- `TELEGRAM_REMOVED`: Configuração do Telegram removida

## Segurança

### Características do Sistema OTP

- **Códigos de 6 dígitos**: Gerados aleatoriamente
- **Expiração**: Códigos expiram em 5 minutos
- **Tentativas limitadas**: Máximo de 3 tentativas por código
- **Uso único**: Cada código só pode ser usado uma vez
- **Logs completos**: Todas as atividades são registradas

### Medidas de Segurança

1. **Validação de Chat ID**: O sistema verifica se o Chat ID é válido antes de salvar
2. **Mensagens criptografadas**: Comunicação via HTTPS com a API do Telegram
3. **Limpeza automática**: Códigos expirados são automaticamente removidos
4. **Bloqueio por tentativas**: Após 3 tentativas incorretas, o código é invalidado

## Troubleshooting

### Problemas Comuns

**1. "Bot do Telegram não configurado"**
- Verifique se a variável `TELEGRAM_BOT_TOKEN` está definida
- Confirme se o token está correto

**2. "Chat não encontrado ou bot não tem acesso"**
- Certifique-se de que o usuário iniciou uma conversa com o bot
- Verifique se o Chat ID está correto

**3. "Falha ao enviar mensagem"**
- Verifique a conexão com a internet
- Confirme se o bot não foi bloqueado pelo usuário
- Verifique se o token do bot ainda é válido

**4. "Código OTP inválido ou expirado"**
- Códigos expiram em 5 minutos
- Cada código só pode ser usado uma vez
- Máximo de 3 tentativas por código

### Logs para Depuração

Consulte os logs do sistema para identificar problemas:

```http
GET /api/admin/logs?page=1&per_page=50
Authorization: Bearer <admin_token>
```

Procure por ações relacionadas ao OTP e Telegram para identificar a causa dos problemas.

