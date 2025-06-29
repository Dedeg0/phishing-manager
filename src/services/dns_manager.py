import requests
import json
import socket
import dns.resolver
import dns.exception
from datetime import datetime, timedelta
from src.models.user import db, Domain, DNSRecord, Log
import os

class DNSManager:
    def __init__(self):
        self.providers = {
            'cloudflare': CloudflareProvider(),
            'route53': Route53Provider(),
            'godaddy': GoDaddyProvider(),
            'namecheap': NamecheapProvider(),
            'manual': ManualProvider()
        }
        
        # IPs dos servidores para apontar
        self.server_ips = {
            'primary': os.environ.get('PRIMARY_SERVER_IP', '127.0.0.1'),
            'secondary': os.environ.get('SECONDARY_SERVER_IP', '127.0.0.1'),
            'cdn': os.environ.get('CDN_SERVER_IP', '127.0.0.1')
        }
    
    def get_provider(self, provider_name):
        """Retorna o provedor DNS especificado"""
        return self.providers.get(provider_name.lower())
    
    def generate_dns_config(self, domain, provider='manual', server_type='primary'):
        """Gera configuração DNS para um domínio"""
        domain_name = domain.domain_name
        server_ip = self.server_ips.get(server_type, self.server_ips['primary'])
        
        # Registros DNS básicos necessários
        records = [
            {
                'type': 'A',
                'name': '@',
                'value': server_ip,
                'ttl': 300,
                'description': 'Registro principal do domínio'
            },
            {
                'type': 'A',
                'name': 'www',
                'value': server_ip,
                'ttl': 300,
                'description': 'Subdomínio www'
            },
            {
                'type': 'A',
                'name': '*',
                'value': server_ip,
                'ttl': 300,
                'description': 'Wildcard para todos os subdomínios'
            },
            {
                'type': 'TXT',
                'name': '@',
                'value': f'v=phishing-manager; domain={domain_name}; server={server_ip}',
                'ttl': 300,
                'description': 'Verificação do sistema'
            }
        ]
        
        # Gerar configurações específicas do provedor
        provider_obj = self.get_provider(provider)
        if provider_obj:
            config = provider_obj.generate_config(domain_name, records)
        else:
            config = self.generate_manual_config(domain_name, records)
        
        return {
            'domain': domain_name,
            'provider': provider,
            'server_ip': server_ip,
            'records': records,
            'config': config,
            'instructions': self.get_setup_instructions(provider),
            'verification': self.get_verification_steps(domain_name)
        }
    
    def generate_manual_config(self, domain_name, records):
        """Gera configuração manual para copiar e colar"""
        config_text = f"""
# Configuração DNS para {domain_name}
# Copie e cole os registros abaixo no seu provedor DNS

"""
        
        for record in records:
            config_text += f"""
# {record['description']}
Tipo: {record['type']}
Nome: {record['name']}
Valor: {record['value']}
TTL: {record['ttl']}
---
"""
        
        return {
            'format': 'manual',
            'content': config_text,
            'copy_paste_ready': True
        }
    
    def get_setup_instructions(self, provider):
        """Retorna instruções de configuração para cada provedor"""
        instructions = {
            'cloudflare': [
                "1. Acesse o painel do Cloudflare",
                "2. Selecione seu domínio",
                "3. Vá para a aba 'DNS'",
                "4. Adicione os registros conforme especificado",
                "5. Certifique-se de que o proxy está desabilitado (nuvem cinza)"
            ],
            'route53': [
                "1. Acesse o console da AWS Route53",
                "2. Selecione sua zona hospedada",
                "3. Clique em 'Create Record'",
                "4. Adicione cada registro individualmente",
                "5. Aguarde a propagação (pode levar até 48h)"
            ],
            'godaddy': [
                "1. Acesse o painel do GoDaddy",
                "2. Vá para 'Meus Produtos' > 'DNS'",
                "3. Clique em 'Gerenciar' ao lado do seu domínio",
                "4. Adicione os registros DNS",
                "5. Salve as alterações"
            ],
            'namecheap': [
                "1. Acesse o painel do Namecheap",
                "2. Vá para 'Domain List'",
                "3. Clique em 'Manage' ao lado do seu domínio",
                "4. Vá para a aba 'Advanced DNS'",
                "5. Adicione os registros conforme especificado"
            ],
            'manual': [
                "1. Acesse o painel do seu provedor DNS",
                "2. Localize a seção de gerenciamento de DNS",
                "3. Adicione os registros conforme especificado",
                "4. Salve as alterações",
                "5. Aguarde a propagação DNS (15 minutos a 48 horas)"
            ]
        }
        
        return instructions.get(provider, instructions['manual'])
    
    def get_verification_steps(self, domain_name):
        """Retorna passos para verificar a configuração DNS"""
        return [
            f"1. Execute: nslookup {domain_name}",
            f"2. Execute: nslookup www.{domain_name}",
            f"3. Execute: dig {domain_name} TXT",
            f"4. Teste o acesso: http://{domain_name}",
            f"5. Teste wildcard: http://test.{domain_name}",
            "6. Use ferramentas online como whatsmydns.net para verificar propagação global"
        ]
    
    def verify_dns_propagation(self, domain_name, expected_ip=None):
        """Verifica se o DNS foi propagado corretamente"""
        if not expected_ip:
            expected_ip = self.server_ips['primary']
        
        results = {
            'domain': domain_name,
            'expected_ip': expected_ip,
            'checks': {},
            'is_propagated': False,
            'errors': []
        }
        
        # Verificar registro A principal
        try:
            answers = dns.resolver.resolve(domain_name, 'A')
            ips = [str(answer) for answer in answers]
            results['checks']['root_domain'] = {
                'status': 'success',
                'ips': ips,
                'matches_expected': expected_ip in ips
            }
        except dns.exception.DNSException as e:
            results['checks']['root_domain'] = {
                'status': 'error',
                'error': str(e)
            }
            results['errors'].append(f"Erro ao resolver {domain_name}: {e}")
        
        # Verificar www
        try:
            answers = dns.resolver.resolve(f'www.{domain_name}', 'A')
            ips = [str(answer) for answer in answers]
            results['checks']['www_subdomain'] = {
                'status': 'success',
                'ips': ips,
                'matches_expected': expected_ip in ips
            }
        except dns.exception.DNSException as e:
            results['checks']['www_subdomain'] = {
                'status': 'error',
                'error': str(e)
            }
            results['errors'].append(f"Erro ao resolver www.{domain_name}: {e}")
        
        # Verificar registro TXT
        try:
            answers = dns.resolver.resolve(domain_name, 'TXT')
            txt_records = [str(answer) for answer in answers]
            results['checks']['txt_verification'] = {
                'status': 'success',
                'records': txt_records,
                'has_verification': any('phishing-manager' in record for record in txt_records)
            }
        except dns.exception.DNSException as e:
            results['checks']['txt_verification'] = {
                'status': 'error',
                'error': str(e)
            }
        
        # Verificar conectividade HTTP
        try:
            response = requests.get(f'http://{domain_name}', timeout=10, allow_redirects=False)
            results['checks']['http_connectivity'] = {
                'status': 'success',
                'status_code': response.status_code,
                'reachable': True
            }
        except requests.RequestException as e:
            results['checks']['http_connectivity'] = {
                'status': 'error',
                'error': str(e),
                'reachable': False
            }
        
        # Determinar se está propagado
        root_ok = results['checks'].get('root_domain', {}).get('matches_expected', False)
        www_ok = results['checks'].get('www_subdomain', {}).get('matches_expected', False)
        results['is_propagated'] = root_ok and www_ok
        
        return results
    
    def sync_domain_records(self, domain):
        """Sincroniza registros DNS de um domínio com o provedor"""
        if not domain.auto_dns_management or not domain.dns_provider:
            return {'error': 'Gerenciamento automático não habilitado'}
        
        provider = self.get_provider(domain.dns_provider)
        if not provider:
            return {'error': f'Provedor {domain.dns_provider} não suportado'}
        
        try:
            # Obter registros locais
            local_records = DNSRecord.query.filter_by(domain_id=domain.id, is_active=True).all()
            
            # Sincronizar com provedor
            sync_results = []
            for record in local_records:
                if not record.is_synced:
                    result = provider.create_record(domain, record)
                    if result.get('success'):
                        record.is_synced = True
                        record.external_id = result.get('record_id')
                        record.last_sync = datetime.utcnow()
                        record.sync_error = None
                    else:
                        record.sync_error = result.get('error')
                    
                    sync_results.append({
                        'record_id': record.id,
                        'success': result.get('success', False),
                        'error': result.get('error')
                    })
            
            # Atualizar status do domínio
            domain.dns_last_sync = datetime.utcnow()
            domain.dns_status = 'configured' if all(r.is_synced for r in local_records) else 'error'
            
            db.session.commit()
            
            return {
                'success': True,
                'synced_records': len([r for r in sync_results if r['success']]),
                'failed_records': len([r for r in sync_results if not r['success']]),
                'results': sync_results
            }
            
        except Exception as e:
            domain.dns_status = 'error'
            db.session.commit()
            return {'error': str(e)}
    
    def create_default_records(self, domain, server_type='primary'):
        """Cria registros DNS padrão para um domínio"""
        server_ip = self.server_ips.get(server_type, self.server_ips['primary'])
        
        default_records = [
            {
                'record_type': 'A',
                'name': '@',
                'value': server_ip,
                'ttl': 300
            },
            {
                'record_type': 'A',
                'name': 'www',
                'value': server_ip,
                'ttl': 300
            },
            {
                'record_type': 'A',
                'name': '*',
                'value': server_ip,
                'ttl': 300
            },
            {
                'record_type': 'TXT',
                'name': '@',
                'value': f'v=phishing-manager; domain={domain.domain_name}; server={server_ip}',
                'ttl': 300
            }
        ]
        
        created_records = []
        for record_data in default_records:
            # Verificar se o registro já existe
            existing = DNSRecord.query.filter_by(
                domain_id=domain.id,
                record_type=record_data['record_type'],
                name=record_data['name']
            ).first()
            
            if not existing:
                record = DNSRecord(
                    domain_id=domain.id,
                    **record_data
                )
                db.session.add(record)
                created_records.append(record)
        
        db.session.commit()
        return created_records

class CloudflareProvider:
    def __init__(self):
        self.api_base = 'https://api.cloudflare.com/client/v4'
        self.headers = {
            'Content-Type': 'application/json'
        }
    
    def generate_config(self, domain_name, records):
        """Gera configuração específica do Cloudflare"""
        config_text = f"""
# Configuração Cloudflare para {domain_name}
# Use a API ou interface web do Cloudflare

# Via API (substitua YOUR_API_TOKEN e ZONE_ID):
"""
        
        for record in records:
            config_text += f"""
curl -X POST "https://api.cloudflare.com/client/v4/zones/ZONE_ID/dns_records" \\
     -H "Authorization: Bearer YOUR_API_TOKEN" \\
     -H "Content-Type: application/json" \\
     --data '{{"type":"{record['type']}","name":"{record['name']}","content":"{record['value']}","ttl":{record['ttl']}}}'

"""
        
        config_text += f"""
# Via Interface Web:
# 1. Acesse dash.cloudflare.com
# 2. Selecione {domain_name}
# 3. Vá para DNS > Records
# 4. Adicione os registros manualmente
"""
        
        return {
            'format': 'cloudflare',
            'content': config_text,
            'api_ready': True,
            'web_interface': True
        }
    
    def create_record(self, domain, record):
        """Cria um registro DNS no Cloudflare"""
        if not domain.dns_api_key or not domain.dns_zone_id:
            return {'success': False, 'error': 'API key ou Zone ID não configurados'}
        
        headers = self.headers.copy()
        headers['Authorization'] = f'Bearer {domain.dns_api_key}'
        
        data = {
            'type': record.record_type,
            'name': record.name,
            'content': record.value,
            'ttl': record.ttl
        }
        
        if record.priority:
            data['priority'] = record.priority
        
        try:
            response = requests.post(
                f'{self.api_base}/zones/{domain.dns_zone_id}/dns_records',
                headers=headers,
                json=data,
                timeout=30
            )
            
            if response.status_code == 200:
                result = response.json()
                if result.get('success'):
                    return {
                        'success': True,
                        'record_id': result['result']['id']
                    }
                else:
                    return {
                        'success': False,
                        'error': result.get('errors', ['Erro desconhecido'])[0]
                    }
            else:
                return {
                    'success': False,
                    'error': f'HTTP {response.status_code}: {response.text}'
                }
                
        except requests.RequestException as e:
            return {'success': False, 'error': str(e)}

class Route53Provider:
    def __init__(self):
        self.service_name = 'route53'
    
    def generate_config(self, domain_name, records):
        """Gera configuração específica do Route53"""
        config_text = f"""
# Configuração AWS Route53 para {domain_name}
# Use AWS CLI ou console web

# Via AWS CLI:
# Primeiro, crie um arquivo JSON com os registros:

cat > {domain_name}-records.json << 'EOF'
{{
  "Changes": [
"""
        
        for i, record in enumerate(records):
            comma = "," if i < len(records) - 1 else ""
            config_text += f"""
    {{
      "Action": "CREATE",
      "ResourceRecordSet": {{
        "Name": "{record['name']}.{domain_name}" if record['name'] != '@' else "{domain_name}",
        "Type": "{record['type']}",
        "TTL": {record['ttl']},
        "ResourceRecords": [
          {{
            "Value": "{record['value']}"
          }}
        ]
      }}
    }}{comma}"""
        
        config_text += f"""
  ]
}}
EOF

# Execute o comando:
aws route53 change-resource-record-sets --hosted-zone-id YOUR_ZONE_ID --change-batch file://{domain_name}-records.json

# Via Console Web:
# 1. Acesse console.aws.amazon.com/route53
# 2. Selecione sua zona hospedada
# 3. Clique em "Create Record"
# 4. Adicione cada registro individualmente
"""
        
        return {
            'format': 'route53',
            'content': config_text,
            'cli_ready': True,
            'web_interface': True
        }
    
    def create_record(self, domain, record):
        """Cria um registro DNS no Route53 (requer boto3)"""
        return {'success': False, 'error': 'Implementação Route53 requer configuração AWS'}

class GoDaddyProvider:
    def __init__(self):
        self.api_base = 'https://api.godaddy.com/v1'
    
    def generate_config(self, domain_name, records):
        """Gera configuração específica do GoDaddy"""
        config_text = f"""
# Configuração GoDaddy para {domain_name}
# Use a API ou interface web do GoDaddy

# Via API (substitua YOUR_API_KEY e YOUR_API_SECRET):
"""
        
        for record in records:
            config_text += f"""
curl -X PUT "https://api.godaddy.com/v1/domains/{domain_name}/records/{record['type']}/{record['name']}" \\
     -H "Authorization: sso-key YOUR_API_KEY:YOUR_API_SECRET" \\
     -H "Content-Type: application/json" \\
     --data '[{{"data":"{record['value']}","ttl":{record['ttl']}}}]'

"""
        
        config_text += f"""
# Via Interface Web:
# 1. Acesse dcc.godaddy.com
# 2. Selecione {domain_name}
# 3. Vá para DNS > Manage Zones
# 4. Adicione os registros manualmente
"""
        
        return {
            'format': 'godaddy',
            'content': config_text,
            'api_ready': True,
            'web_interface': True
        }
    
    def create_record(self, domain, record):
        """Cria um registro DNS no GoDaddy"""
        return {'success': False, 'error': 'Implementação GoDaddy em desenvolvimento'}

class NamecheapProvider:
    def __init__(self):
        self.api_base = 'https://api.namecheap.com/xml.response'
    
    def generate_config(self, domain_name, records):
        """Gera configuração específica do Namecheap"""
        config_text = f"""
# Configuração Namecheap para {domain_name}
# Use a interface web do Namecheap (API limitada)

# Via Interface Web:
# 1. Acesse ap.www.namecheap.com
# 2. Vá para Domain List
# 3. Clique em "Manage" ao lado de {domain_name}
# 4. Vá para "Advanced DNS"
# 5. Adicione os registros:

"""
        
        for record in records:
            config_text += f"""
Tipo: {record['type']}
Host: {record['name']}
Valor: {record['value']}
TTL: {record['ttl']}
---
"""
        
        return {
            'format': 'namecheap',
            'content': config_text,
            'web_interface': True
        }
    
    def create_record(self, domain, record):
        """Namecheap tem API limitada para DNS"""
        return {'success': False, 'error': 'Namecheap requer configuração manual via interface web'}

class ManualProvider:
    def generate_config(self, domain_name, records):
        """Gera configuração manual genérica"""
        config_text = f"""
# Configuração DNS Manual para {domain_name}
# Copie e cole no seu provedor DNS

"""
        
        for record in records:
            config_text += f"""
Tipo: {record['type']}
Nome/Host: {record['name']}
Valor/Destino: {record['value']}
TTL: {record['ttl']} segundos
Descrição: {record['description']}
---
"""
        
        config_text += f"""

# Instruções Gerais:
# 1. Acesse o painel do seu provedor DNS
# 2. Localize a seção de gerenciamento de registros DNS
# 3. Adicione cada registro conforme especificado acima
# 4. Salve as alterações
# 5. Aguarde a propagação (15 minutos a 48 horas)

# Verificação:
# Execute os comandos abaixo para verificar:
# nslookup {domain_name}
# nslookup www.{domain_name}
# dig {domain_name} TXT
"""
        
        return {
            'format': 'manual',
            'content': config_text,
            'copy_paste_ready': True
        }
    
    def create_record(self, domain, record):
        """Provedor manual não suporta criação automática"""
        return {'success': False, 'error': 'Provedor manual requer configuração manual'}

# Instância global do gerenciador DNS
dns_manager = DNSManager()

