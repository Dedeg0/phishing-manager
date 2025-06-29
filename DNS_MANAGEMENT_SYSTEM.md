# Sistema de Gerenciamento de DNS Automático

Este sistema oferece gerenciamento completo de DNS para domínios, incluindo configuração automática, verificação de propagação e geração de configurações prontas para copiar e colar.

## 🌐 Funcionalidades Principais

### 1. Gerenciamento Automático de DNS
- **Configuração automática** de registros DNS via API
- **Sincronização** com provedores DNS populares
- **Verificação de propagação** em tempo real
- **Monitoramento** de status dos domínios

### 2. Provedores Suportados
- **Cloudflare** - API completa com CDN integrado
- **AWS Route53** - Alta disponibilidade e geolocalização
- **GoDaddy** - Interface amigável com API
- **Namecheap** - DNS gratuito (configuração manual)
- **Manual** - Para qualquer provedor via copy & paste

### 3. Configurações Copy & Paste
- **Registros prontos** para copiar e colar
- **Scripts de configuração** para linha de comando
- **Templates específicos** para cada provedor
- **Instruções detalhadas** passo a passo

## 📋 Tipos de Registros DNS

### Registros Padrão Criados Automaticamente:
```
Tipo: A
Nome: @
Valor: [IP_DO_SERVIDOR]
TTL: 300
Descrição: Registro principal do domínio

Tipo: A
Nome: www
Valor: [IP_DO_SERVIDOR]
TTL: 300
Descrição: Subdomínio www

Tipo: A
Nome: *
Valor: [IP_DO_SERVIDOR]
TTL: 300
Descrição: Wildcard para todos os subdomínios

Tipo: TXT
Nome: @
Valor: v=phishing-manager; domain=[DOMINIO]; server=[IP]
TTL: 300
Descrição: Verificação do sistema
```

## 🔧 Configuração por Provedor

### Cloudflare
```bash
# Via API
curl -X POST "https://api.cloudflare.com/client/v4/zones/ZONE_ID/dns_records" \
     -H "Authorization: Bearer YOUR_API_TOKEN" \
     -H "Content-Type: application/json" \
     --data '{"type":"A","name":"@","content":"127.0.0.1","ttl":300}'

# Via Interface Web:
# 1. Acesse dash.cloudflare.com
# 2. Selecione seu domínio
# 3. Vá para DNS > Records
# 4. Adicione os registros manualmente
```

### AWS Route53
```bash
# Via AWS CLI
cat > exemplo.com-records.json << 'EOF'
{
  "Changes": [
    {
      "Action": "CREATE",
      "ResourceRecordSet": {
        "Name": "exemplo.com",
        "Type": "A",
        "TTL": 300,
        "ResourceRecords": [
          {
            "Value": "127.0.0.1"
          }
        ]
      }
    }
  ]
}
EOF

aws route53 change-resource-record-sets --hosted-zone-id YOUR_ZONE_ID --change-batch file://exemplo.com-records.json
```

### GoDaddy
```bash
# Via API
curl -X PUT "https://api.godaddy.com/v1/domains/exemplo.com/records/A/@" \
     -H "Authorization: sso-key YOUR_API_KEY:YOUR_API_SECRET" \
     -H "Content-Type: application/json" \
     --data '[{"data":"127.0.0.1","ttl":300}]'
```

### Configuração Manual
```
# Para qualquer provedor DNS:

Tipo: A
Nome/Host: @
Valor/Destino: 127.0.0.1
TTL: 300 segundos

Tipo: A
Nome/Host: www
Valor/Destino: 127.0.0.1
TTL: 300 segundos

Tipo: A
Nome/Host: *
Valor/Destino: 127.0.0.1
TTL: 300 segundos

Tipo: TXT
Nome/Host: @
Valor/Destino: v=phishing-manager; domain=exemplo.com; server=127.0.0.1
TTL: 300 segundos
```

## 🚀 API Endpoints

### Gerar Configuração DNS
```http
POST /api/dns/generate-config/{domain_id}
Content-Type: application/json

{
  "provider": "cloudflare",
  "server_type": "primary"
}
```

### Verificar Propagação DNS
```http
POST /api/dns/verify-propagation/{domain_id}
Content-Type: application/json

{
  "expected_ip": "127.0.0.1"
}
```

### Listar Registros DNS
```http
GET /api/dns/records/{domain_id}
```

### Criar Registro DNS
```http
POST /api/dns/records/{domain_id}
Content-Type: application/json

{
  "record_type": "A",
  "name": "api",
  "value": "127.0.0.1",
  "ttl": 300
}
```

### Configurar Provedor DNS
```http
POST /api/dns/configure-provider/{domain_id}
Content-Type: application/json

{
  "provider": "cloudflare",
  "auto_management": true,
  "api_key": "your_api_token",
  "zone_id": "your_zone_id"
}
```

### Sincronizar DNS
```http
POST /api/dns/sync/{domain_id}
```

### Criar Registros Padrão
```http
POST /api/dns/setup-defaults/{domain_id}
Content-Type: application/json

{
  "server_type": "primary"
}
```

## 🔍 Verificação e Monitoramento

### Comandos de Verificação
```bash
# Verificar registro A principal
nslookup exemplo.com

# Verificar subdomínio www
nslookup www.exemplo.com

# Verificar registro TXT
dig exemplo.com TXT

# Verificar wildcard
nslookup test.exemplo.com

# Verificar propagação global
# Use ferramentas online como whatsmydns.net
```

### Status de Propagação
O sistema verifica automaticamente:
- ✅ **Registro A principal** - Domínio raiz aponta para o servidor
- ✅ **Subdomínio www** - www.dominio.com funciona
- ✅ **Registro TXT** - Verificação do sistema presente
- ✅ **Conectividade HTTP** - Servidor responde via HTTP
- ✅ **Wildcard** - Subdomínios aleatórios funcionam

## ⚙️ Configurações do Sistema

### Variáveis de Ambiente
```bash
# IPs dos servidores
PRIMARY_SERVER_IP=127.0.0.1
SECONDARY_SERVER_IP=127.0.0.1
CDN_SERVER_IP=127.0.0.1

# Configurações de DNS
AUTO_DNS_SYNC=false
DNS_PROPAGATION_CHECK=true
```

### Configurações por Domínio
- **Provedor DNS** - cloudflare, route53, godaddy, namecheap, manual
- **Gerenciamento Automático** - Habilita/desabilita sincronização via API
- **Chaves de API** - Credenciais para acesso ao provedor
- **Zone ID** - Identificador da zona DNS
- **Status** - pending, configured, error

## 📊 Métricas e Estatísticas

### Dashboard DNS
- **Total de domínios** configurados
- **Domínios online/offline**
- **Registros sincronizados**
- **Erros de sincronização**
- **Última verificação** de propagação

### Logs de Atividade
- Configurações DNS geradas
- Verificações de propagação
- Sincronizações executadas
- Erros e falhas
- Alterações em registros

## 🛠️ Operações em Lote

### Sincronização em Massa
```http
POST /api/dns/bulk-operations/{domain_id}
Content-Type: application/json

{
  "operation": "sync_all"
}
```

### Reset de Sincronização
```http
POST /api/dns/bulk-operations/{domain_id}
Content-Type: application/json

{
  "operation": "reset_sync"
}
```

### Remoção em Lote
```http
POST /api/dns/bulk-operations/{domain_id}
Content-Type: application/json

{
  "operation": "delete_selected",
  "record_ids": [1, 2, 3]
}
```

## 🔐 Segurança

### Proteção de APIs
- **Autenticação obrigatória** para todas as operações
- **Permissões por domínio** - usuários só acessam seus domínios
- **Logs de auditoria** para todas as alterações
- **Validação de dados** em todas as entradas

### Chaves de API
- **Armazenamento seguro** das credenciais
- **Criptografia** das chaves sensíveis
- **Rotação** recomendada das chaves
- **Acesso restrito** apenas para administradores

## 📚 Exemplos de Uso

### Configuração Completa de um Domínio
```python
# 1. Configurar provedor
POST /api/dns/configure-provider/1
{
  "provider": "cloudflare",
  "auto_management": true,
  "api_key": "your_token",
  "zone_id": "your_zone"
}

# 2. Criar registros padrão
POST /api/dns/setup-defaults/1
{
  "server_type": "primary"
}

# 3. Sincronizar com provedor
POST /api/dns/sync/1

# 4. Verificar propagação
POST /api/dns/verify-propagation/1
{
  "expected_ip": "127.0.0.1"
}
```

### Configuração Manual (Copy & Paste)
```python
# 1. Gerar configuração
POST /api/dns/generate-config/1
{
  "provider": "manual",
  "server_type": "primary"
}

# 2. Copiar configuração gerada
# 3. Colar no provedor DNS
# 4. Verificar propagação
POST /api/dns/verify-propagation/1
```

## 🎯 Melhores Práticas

### Configuração Inicial
1. **Escolha o provedor** adequado às suas necessidades
2. **Configure as credenciais** de API se disponível
3. **Crie registros padrão** usando o sistema
4. **Verifique a propagação** antes de usar
5. **Monitore o status** regularmente

### Manutenção
1. **Sincronize regularmente** se usando API
2. **Verifique propagação** após mudanças
3. **Monitore logs** para detectar problemas
4. **Mantenha credenciais** atualizadas
5. **Faça backup** das configurações

### Solução de Problemas
1. **Verifique credenciais** de API
2. **Confirme Zone ID** correto
3. **Aguarde propagação** (até 48h)
4. **Use ferramentas** de verificação online
5. **Consulte logs** do sistema

## 📞 Suporte

### Ferramentas de Diagnóstico
- **Verificação de propagação** integrada
- **Logs detalhados** de todas as operações
- **Status em tempo real** dos domínios
- **Métricas de performance** DNS

### Recursos Externos
- **whatsmydns.net** - Verificação global de propagação
- **dig** e **nslookup** - Comandos de linha
- **DNS Checker** - Ferramentas online
- **Documentação** dos provedores DNS

Este sistema oferece uma solução completa para gerenciamento de DNS, desde configuração manual até automação completa via API, garantindo que seus domínios estejam sempre configurados corretamente e funcionando perfeitamente.

