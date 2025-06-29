# Sistema Anti-Redpage e Anti-Bot Avançado

## Visão Geral

O sistema anti-redpage e anti-bot é uma solução avançada de proteção que previne a detecção de URLs de phishing por sistemas de segurança e bloqueia o acesso de bots automatizados. O sistema utiliza múltiplas camadas de proteção e técnicas de ofuscação para manter as URLs funcionais e seguras.

## Funcionalidades Principais

### 1. Sistema Anti-Redpage

#### Detecção de Indicadores de Redpage
O sistema identifica automaticamente indicadores comuns que podem levar uma URL a ser marcada como suspeita:

**Indicadores de Domínio:**
- Palavras-chave suspeitas: security, warning, alert, blocked, suspended
- Termos relacionados à segurança: violation, abuse, malware, phishing, fraud
- Domínios de verificação conhecidos: safebrowsing.google.com, phishtank.com

**Indicadores de Parâmetros:**
- Parâmetros de tracking: utm_source, utm_medium, fbclid, gclid
- Parâmetros de monitoramento: track, analytics, monitor, detect

#### Limpeza Automática de URLs
O sistema oferece três tipos de limpeza:

1. **redpage_removal**: Remove apenas indicadores de redpage
2. **bot_protection**: Adiciona proteções contra bots
3. **full_clean**: Limpeza completa com todas as proteções

**Ações de Limpeza:**
- Remoção de parâmetros suspeitos
- Adição de parâmetros de ofuscação legítimos
- Normalização de estrutura da URL
- Verificação de domínios seguros

### 2. Sistema Anti-Bot

#### Detecção Avançada de Bots
O sistema utiliza múltiplas técnicas para identificar comportamento automatizado:

**Análise de User-Agent:**
- Detecção de padrões conhecidos de bots
- Verificação de User-Agents genéricos/falsos
- Análise da estrutura e validade do User-Agent

**Análise de Headers HTTP:**
- Verificação de headers suspeitos (X-Forwarded-For, X-Real-IP)
- Detecção de headers ausentes ou em ordem incorreta
- Análise de padrões de requisição

**Análise de Comportamento:**
- Monitoramento de intervalos entre requests
- Detecção de padrões regulares suspeitos
- Análise de frequência de acesso

**Fingerprinting Avançado:**
- Canvas fingerprinting
- WebGL fingerprinting
- Audio fingerprinting
- Análise de resolução e configurações do sistema

#### Sistema de Pontuação
Cada visitante recebe uma pontuação de 0.0 (humano) a 1.0 (bot) baseada em:
- Indicadores detectados
- Confiança da análise
- Histórico de comportamento

#### Níveis de Proteção
- **Low (0.9)**: Bloqueia apenas bots óbvios
- **Medium (0.7)**: Proteção balanceada (padrão)
- **High (0.5)**: Proteção máxima, pode gerar falsos positivos

### 3. Sistema de Desafios

Quando um visitante é detectado como possivelmente suspeito, o sistema pode apresentar desafios:

**Tipos de Desafio:**
- **JavaScript**: Resolução de operações matemáticas simples
- **CAPTCHA**: Verificação de texto
- **Timing**: Aguardar tempo mínimo antes de continuar

### 4. Blacklist e Whitelist

**Blacklist de IPs:**
- Bloqueio automático ou manual de IPs
- Expiração configurável
- Logs detalhados de atividades

**Atividades Suspeitas:**
- Registro automático de comportamentos anômalos
- Classificação por severidade (low, medium, high, critical)
- Sistema de resolução para administradores

## Endpoints da API

### Limpeza de URLs

```http
# Adicionar URL para limpeza
POST /api/protection/clean-url
Content-Type: application/json
Authorization: Bearer <token>

{
    "url": "https://exemplo.com/page?utm_source=suspicious&track=123",
    "cleaning_type": "full_clean"
}

# Resposta
{
    "message": "URL limpa com sucesso",
    "cleaning_id": 1,
    "original_url": "https://exemplo.com/page?utm_source=suspicious&track=123",
    "cleaned_url": "https://exemplo.com/page?v=1640995200&ref=organic&lang=pt-BR",
    "issues_found": [
        "Parâmetros suspeitos removidos: ['utm_source', 'track']"
    ],
    "actions_taken": [
        "Remoção de parâmetros de tracking",
        "Adição de parâmetros de ofuscação"
    ],
    "is_clean": true,
    "remaining_credits": 49
}
```

### Listar Limpezas

```http
# Listar minhas limpezas
GET /api/protection/my-cleanings?page=1&per_page=20
Authorization: Bearer <token>

# Resposta
{
    "cleanings": [
        {
            "id": 1,
            "original_url": "https://exemplo.com/page?utm_source=suspicious",
            "cleaned_url": "https://exemplo.com/page?v=1640995200",
            "status": "completed",
            "cleaning_type": "full_clean",
            "issues_found": ["Parâmetros suspeitos removidos"],
            "actions_taken": ["Remoção de parâmetros de tracking"],
            "created_at": "2025-06-21T10:00:00",
            "completed_at": "2025-06-21T10:00:05"
        }
    ],
    "total": 1,
    "pages": 1,
    "current_page": 1
}
```

### Análise de Visitantes

```http
# Analisar visitante para detecção de bot
POST /api/protection/analyze-visitor
Content-Type: application/json

{
    "user_agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36",
    "headers": {
        "Accept": "text/html,application/xhtml+xml",
        "Accept-Language": "pt-BR,pt;q=0.9"
    },
    "ip_address": "192.168.1.100",
    "fingerprint": {
        "screen_resolution": "1920x1080",
        "timezone": "America/Sao_Paulo",
        "canvas_fingerprint": "abc123def456"
    }
}

# Resposta
{
    "is_bot": false,
    "bot_score": 0.2,
    "confidence": 0.85,
    "indicators": [
        "User-Agent genérico detectado"
    ],
    "risk_level": "low"
}
```

### Gerenciamento de Blacklist

```http
# Adicionar IP à blacklist (apenas admins)
POST /api/protection/blacklist-ip
Content-Type: application/json
Authorization: Bearer <admin_token>

{
    "ip_address": "192.168.1.100",
    "reason": "Bot detectado com alta confiança",
    "expires_hours": 24
}

# Listar blacklist
GET /api/protection/blacklist?page=1&active_only=true
Authorization: Bearer <admin_token>

# Remover da blacklist
DELETE /api/protection/blacklist/1
Authorization: Bearer <admin_token>
```

### Atividades Suspeitas

```http
# Listar atividades suspeitas (apenas admins)
GET /api/protection/suspicious-activities?severity=high&resolved=false
Authorization: Bearer <admin_token>

# Marcar como resolvida
POST /api/protection/suspicious-activities/1/resolve
Authorization: Bearer <admin_token>
```

### Configuração de Proteção por URL

```http
# Atualizar proteção de uma URL específica
POST /api/protection/url-protection/abc123def456
Content-Type: application/json
Authorization: Bearer <token>

{
    "is_protected": true,
    "protection_level": "high"
}
```

### Estatísticas de Proteção

```http
# Obter estatísticas gerais (apenas admins)
GET /api/protection/protection-stats
Authorization: Bearer <admin_token>

# Resposta
{
    "general_stats": {
        "total_cleanings": 150,
        "successful_cleanings": 145,
        "failed_cleanings": 5,
        "success_rate": 96.67,
        "total_blacklisted_ips": 25,
        "total_suspicious_activities": 89,
        "unresolved_suspicious": 12
    },
    "recent_stats": {
        "cleanings_last_week": 23,
        "suspicious_activities_last_week": 15
    },
    "cleaning_types": [
        {"type": "full_clean", "count": 80},
        {"type": "redpage_removal", "count": 45},
        {"type": "bot_protection", "count": 25}
    ],
    "severity_distribution": [
        {"severity": "low", "count": 45},
        {"severity": "medium", "count": 30},
        {"severity": "high", "count": 12},
        {"severity": "critical", "count": 2}
    ]
}
```

## Integração com Sistema de Tracking

### Proteção Automática
Quando uma URL protegida é acessada, o sistema:

1. **Verifica Blacklist**: Bloqueia IPs conhecidos
2. **Analisa Comportamento**: Detecta padrões de bot
3. **Aplica Proteções**: Baseado no nível configurado
4. **Registra Atividade**: Logs detalhados para auditoria
5. **Notifica Usuários**: Via Telegram se configurado

### Fingerprinting Avançado
O sistema coleta automaticamente:
- Canvas fingerprint para identificação única
- WebGL fingerprint para detecção de ambientes virtuais
- Audio fingerprint para verificação de hardware real
- Comportamento de mouse e teclado

### Desafios Dinâmicos
Visitantes suspeitos podem receber:
- Desafios matemáticos simples
- Verificações de JavaScript
- Testes de timing humano

## Configuração e Personalização

### Variáveis de Ambiente

```bash
# Configurações de proteção
ANTI_BOT_ENABLED=true
DEFAULT_PROTECTION_LEVEL=medium
AUTO_BLACKLIST_BOTS=false

# Thresholds de detecção
BOT_SCORE_THRESHOLD_LOW=0.9
BOT_SCORE_THRESHOLD_MEDIUM=0.7
BOT_SCORE_THRESHOLD_HIGH=0.5

# Configurações de desafio
CHALLENGE_ENABLED=true
CHALLENGE_TYPE=javascript
```

### Configurações do Sistema

As configurações podem ser ajustadas via API ou interface administrativa:

```http
# Atualizar configuração
POST /api/admin/system-config
Content-Type: application/json
Authorization: Bearer <admin_token>

{
    "key": "default_protection_level",
    "value": "high",
    "description": "Nível de proteção padrão para novas URLs"
}
```

## Monitoramento e Logs

### Tipos de Logs Registrados

- `URL_CLEANED`: Limpeza de URL realizada
- `BOT_DETECTED`: Bot detectado pelo sistema
- `IP_BLACKLISTED`: IP adicionado à blacklist
- `SUSPICIOUS_ACTIVITY`: Atividade suspeita registrada
- `CHALLENGE_FAILED`: Falha em desafio anti-bot
- `PROTECTION_BYPASSED`: Tentativa de bypass detectada

### Métricas de Monitoramento

- Taxa de detecção de bots
- Eficácia da limpeza de URLs
- Falsos positivos/negativos
- Performance do sistema de proteção

## Exemplo de Uso Completo

### 1. Configurar Proteções

```bash
# Configurar variáveis de ambiente
export ANTI_BOT_ENABLED=true
export DEFAULT_PROTECTION_LEVEL=medium
```

### 2. Limpar URL Suspeita

```bash
curl -X POST http://localhost:5000/api/protection/clean-url \
  -H "Content-Type: application/json" \
  -H "Authorization: Bearer <token>" \
  -d '{
    "url": "https://exemplo.com/login?utm_source=phishing&track=123",
    "cleaning_type": "full_clean"
  }'
```

### 3. Gerar URL Protegida

```bash
curl -X POST http://localhost:5000/api/urls/generate \
  -H "Content-Type: application/json" \
  -H "Authorization: Bearer <token>" \
  -d '{
    "script_id": 1,
    "domain_id": 1
  }'
```

### 4. Configurar Proteção da URL

```bash
curl -X POST http://localhost:5000/api/protection/url-protection/abc123def456 \
  -H "Content-Type: application/json" \
  -H "Authorization: Bearer <token>" \
  -d '{
    "is_protected": true,
    "protection_level": "high"
  }'
```

### 5. Monitorar Atividades

```bash
# Verificar atividades suspeitas
curl -X GET http://localhost:5000/api/protection/suspicious-activities \
  -H "Authorization: Bearer <admin_token>"

# Verificar estatísticas
curl -X GET http://localhost:5000/api/protection/protection-stats \
  -H "Authorization: Bearer <admin_token>"
```

## Boas Práticas

### Para Usuários

1. **Use Limpeza Preventiva**: Limpe URLs antes de usar
2. **Configure Proteção Adequada**: Escolha nível baseado no risco
3. **Monitore Estatísticas**: Acompanhe detecções de bot
4. **Mantenha Créditos**: Limpeza consome créditos

### Para Administradores

1. **Monitore Blacklist**: Revise IPs bloqueados regularmente
2. **Analise Atividades Suspeitas**: Investigue padrões anômalos
3. **Ajuste Thresholds**: Baseado em falsos positivos/negativos
4. **Mantenha Logs**: Para auditoria e melhorias

### Segurança e Ética

⚠️ **IMPORTANTE**: Este sistema é destinado exclusivamente para:
- Fins educacionais e de pesquisa
- Testes de segurança autorizados
- Treinamento de conscientização sobre phishing
- Demonstrações acadêmicas

**NÃO deve ser usado para**:
- Atividades maliciosas reais
- Phishing não autorizado
- Bypass de sistemas de segurança legítimos
- Qualquer atividade ilegal

## Troubleshooting

### Problemas Comuns

**1. Muitos falsos positivos**
- Reduza o nível de proteção
- Ajuste thresholds de detecção
- Verifique configurações de fingerprinting

**2. Bots não detectados**
- Aumente o nível de proteção
- Ative mais indicadores de detecção
- Verifique logs de atividades suspeitas

**3. Limpeza não efetiva**
- Verifique indicadores personalizados
- Analise URLs que ainda são detectadas
- Ajuste parâmetros de ofuscação

**4. Performance degradada**
- Otimize consultas de blacklist
- Reduza frequência de análise
- Configure cache para fingerprints

### Logs de Debug

Para debug detalhado:

```bash
# Ativar logs verbosos
export FLASK_DEBUG=true
export LOG_LEVEL=DEBUG

# Monitorar logs em tempo real
tail -f logs/protection.log
```

O sistema anti-redpage e anti-bot oferece proteção robusta e configurável para manter URLs funcionais enquanto bloqueia acesso automatizado indesejado!

