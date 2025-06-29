from flask import Blueprint, request, jsonify
from flask_login import login_required, current_user
from src.models.user import db, Domain, DNSRecord, Log
from src.services.dns_manager import dns_manager
from src.routes.user import log_action
from datetime import datetime
import json

dns_bp = Blueprint('dns', __name__)

@dns_bp.route('/generate-config/<int:domain_id>', methods=['POST'])
@login_required
def generate_dns_config(domain_id):
    """Gera configuração DNS para um domínio"""
    domain = Domain.query.get_or_404(domain_id)
    
    # Verificar permissão (admin ou usuário com acesso ao domínio)
    if not current_user.is_admin:
        user_domain = next((ud for ud in current_user.user_domains if ud.domain_id == domain_id), None)
        if not user_domain:
            return jsonify({'error': 'Acesso negado ao domínio'}), 403
    
    data = request.get_json() or {}
    provider = data.get('provider', 'manual')
    server_type = data.get('server_type', 'primary')
    
    # Gerar configuração DNS
    config = dns_manager.generate_dns_config(domain, provider, server_type)
    
    # Registrar no log
    log_action('DNS_CONFIG_GENERATED', f'Configuração DNS gerada para {domain.domain_name} (provedor: {provider})', current_user.id)
    
    return jsonify({
        'message': 'Configuração DNS gerada com sucesso',
        'config': config
    }), 200

@dns_bp.route('/verify-propagation/<int:domain_id>', methods=['POST'])
@login_required
def verify_dns_propagation(domain_id):
    """Verifica a propagação DNS de um domínio"""
    domain = Domain.query.get_or_404(domain_id)
    
    # Verificar permissão
    if not current_user.is_admin:
        user_domain = next((ud for ud in current_user.user_domains if ud.domain_id == domain_id), None)
        if not user_domain:
            return jsonify({'error': 'Acesso negado ao domínio'}), 403
    
    data = request.get_json() or {}
    expected_ip = data.get('expected_ip')
    
    # Verificar propagação
    verification_result = dns_manager.verify_dns_propagation(domain.domain_name, expected_ip)
    
    # Atualizar status do domínio baseado na verificação
    if verification_result['is_propagated']:
        domain.dns_status = 'configured'
        domain.is_online = True
    else:
        domain.dns_status = 'error'
        domain.is_online = False
    
    domain.last_status_check = datetime.utcnow()
    db.session.commit()
    
    # Registrar no log
    status = 'propagado' if verification_result['is_propagated'] else 'não propagado'
    log_action('DNS_VERIFICATION', f'DNS do domínio {domain.domain_name} verificado: {status}', current_user.id)
    
    return jsonify({
        'message': 'Verificação DNS concluída',
        'verification': verification_result
    }), 200

@dns_bp.route('/records/<int:domain_id>', methods=['GET'])
@login_required
def get_dns_records(domain_id):
    """Lista registros DNS de um domínio"""
    domain = Domain.query.get_or_404(domain_id)
    
    # Verificar permissão
    if not current_user.is_admin:
        user_domain = next((ud for ud in current_user.user_domains if ud.domain_id == domain_id), None)
        if not user_domain:
            return jsonify({'error': 'Acesso negado ao domínio'}), 403
    
    records = DNSRecord.query.filter_by(domain_id=domain_id, is_active=True).all()
    
    return jsonify({
        'domain': domain.to_dict(),
        'records': [record.to_dict() for record in records],
        'total_records': len(records)
    }), 200

@dns_bp.route('/records/<int:domain_id>', methods=['POST'])
@login_required
def create_dns_record(domain_id):
    """Cria um novo registro DNS"""
    if not current_user.is_admin:
        return jsonify({'error': 'Apenas administradores podem criar registros DNS'}), 403
    
    domain = Domain.query.get_or_404(domain_id)
    data = request.get_json()
    
    if not data:
        return jsonify({'error': 'Dados do registro são obrigatórios'}), 400
    
    # Validar campos obrigatórios
    required_fields = ['record_type', 'name', 'value']
    for field in required_fields:
        if not data.get(field):
            return jsonify({'error': f'Campo {field} é obrigatório'}), 400
    
    # Validar tipo de registro
    valid_types = ['A', 'AAAA', 'CNAME', 'MX', 'TXT', 'NS', 'SRV']
    if data['record_type'].upper() not in valid_types:
        return jsonify({'error': f'Tipo de registro inválido. Use: {valid_types}'}), 400
    
    # Verificar se o registro já existe
    existing_record = DNSRecord.query.filter_by(
        domain_id=domain_id,
        record_type=data['record_type'].upper(),
        name=data['name'],
        is_active=True
    ).first()
    
    if existing_record:
        return jsonify({'error': 'Registro DNS já existe'}), 400
    
    # Criar registro
    record = DNSRecord(
        domain_id=domain_id,
        record_type=data['record_type'].upper(),
        name=data['name'],
        value=data['value'],
        ttl=data.get('ttl', 300),
        priority=data.get('priority')
    )
    
    db.session.add(record)
    db.session.commit()
    
    # Tentar sincronizar automaticamente se configurado
    if domain.auto_dns_management:
        sync_result = dns_manager.sync_domain_records(domain)
        if not sync_result.get('success'):
            record.sync_error = sync_result.get('error')
            db.session.commit()
    
    # Registrar no log
    log_action('DNS_RECORD_CREATED', f'Registro DNS criado: {record.name}.{domain.domain_name} {record.record_type}', current_user.id)
    
    return jsonify({
        'message': 'Registro DNS criado com sucesso',
        'record': record.to_dict()
    }), 201

@dns_bp.route('/records/<int:record_id>', methods=['PUT'])
@login_required
def update_dns_record(record_id):
    """Atualiza um registro DNS"""
    if not current_user.is_admin:
        return jsonify({'error': 'Apenas administradores podem atualizar registros DNS'}), 403
    
    record = DNSRecord.query.get_or_404(record_id)
    data = request.get_json()
    
    if not data:
        return jsonify({'error': 'Dados para atualização são obrigatórios'}), 400
    
    # Atualizar campos permitidos
    updatable_fields = ['value', 'ttl', 'priority']
    for field in updatable_fields:
        if field in data:
            setattr(record, field, data[field])
    
    # Marcar como não sincronizado para re-sincronização
    record.is_synced = False
    record.sync_error = None
    
    db.session.commit()
    
    # Tentar sincronizar automaticamente se configurado
    if record.domain.auto_dns_management:
        sync_result = dns_manager.sync_domain_records(record.domain)
        if not sync_result.get('success'):
            record.sync_error = sync_result.get('error')
            db.session.commit()
    
    # Registrar no log
    log_action('DNS_RECORD_UPDATED', f'Registro DNS atualizado: {record.name}.{record.domain.domain_name} {record.record_type}', current_user.id)
    
    return jsonify({
        'message': 'Registro DNS atualizado com sucesso',
        'record': record.to_dict()
    }), 200

@dns_bp.route('/records/<int:record_id>', methods=['DELETE'])
@login_required
def delete_dns_record(record_id):
    """Remove um registro DNS"""
    if not current_user.is_admin:
        return jsonify({'error': 'Apenas administradores podem remover registros DNS'}), 403
    
    record = DNSRecord.query.get_or_404(record_id)
    domain_name = record.domain.domain_name
    record_info = f'{record.name}.{domain_name} {record.record_type}'
    
    # Marcar como inativo ao invés de deletar
    record.is_active = False
    db.session.commit()
    
    # Registrar no log
    log_action('DNS_RECORD_DELETED', f'Registro DNS removido: {record_info}', current_user.id)
    
    return jsonify({'message': f'Registro DNS {record_info} removido com sucesso'}), 200

@dns_bp.route('/setup-defaults/<int:domain_id>', methods=['POST'])
@login_required
def setup_default_records(domain_id):
    """Cria registros DNS padrão para um domínio"""
    if not current_user.is_admin:
        return jsonify({'error': 'Apenas administradores podem configurar registros padrão'}), 403
    
    domain = Domain.query.get_or_404(domain_id)
    data = request.get_json() or {}
    server_type = data.get('server_type', 'primary')
    
    # Criar registros padrão
    created_records = dns_manager.create_default_records(domain, server_type)
    
    # Tentar sincronizar automaticamente se configurado
    sync_result = None
    if domain.auto_dns_management:
        sync_result = dns_manager.sync_domain_records(domain)
    
    # Registrar no log
    log_action('DNS_DEFAULTS_CREATED', f'Registros DNS padrão criados para {domain.domain_name} ({len(created_records)} registros)', current_user.id)
    
    return jsonify({
        'message': f'{len(created_records)} registros DNS padrão criados',
        'records': [record.to_dict() for record in created_records],
        'sync_result': sync_result
    }), 201

@dns_bp.route('/sync/<int:domain_id>', methods=['POST'])
@login_required
def sync_domain_dns(domain_id):
    """Sincroniza registros DNS com o provedor"""
    if not current_user.is_admin:
        return jsonify({'error': 'Apenas administradores podem sincronizar DNS'}), 403
    
    domain = Domain.query.get_or_404(domain_id)
    
    if not domain.auto_dns_management:
        return jsonify({'error': 'Gerenciamento automático de DNS não está habilitado'}), 400
    
    # Executar sincronização
    sync_result = dns_manager.sync_domain_records(domain)
    
    # Registrar no log
    if sync_result.get('success'):
        log_action('DNS_SYNC_SUCCESS', f'DNS sincronizado para {domain.domain_name}: {sync_result.get("synced_records")} registros', current_user.id)
    else:
        log_action('DNS_SYNC_FAILED', f'Falha na sincronização DNS para {domain.domain_name}: {sync_result.get("error")}', current_user.id)
    
    return jsonify({
        'message': 'Sincronização DNS concluída',
        'result': sync_result
    }), 200

@dns_bp.route('/configure-provider/<int:domain_id>', methods=['POST'])
@login_required
def configure_dns_provider(domain_id):
    """Configura provedor DNS para um domínio"""
    if not current_user.is_admin:
        return jsonify({'error': 'Apenas administradores podem configurar provedores DNS'}), 403
    
    domain = Domain.query.get_or_404(domain_id)
    data = request.get_json()
    
    if not data:
        return jsonify({'error': 'Dados de configuração são obrigatórios'}), 400
    
    # Validar provedor
    valid_providers = ['cloudflare', 'route53', 'godaddy', 'namecheap', 'manual']
    provider = data.get('provider')
    if provider not in valid_providers:
        return jsonify({'error': f'Provedor inválido. Use: {valid_providers}'}), 400
    
    # Atualizar configurações do domínio
    domain.dns_provider = provider
    domain.auto_dns_management = data.get('auto_management', False)
    
    # Configurações específicas do provedor
    if provider in ['cloudflare', 'route53', 'godaddy']:
        domain.dns_api_key = data.get('api_key')
        domain.dns_api_secret = data.get('api_secret')
        domain.dns_zone_id = data.get('zone_id')
    
    domain.dns_status = 'pending'
    db.session.commit()
    
    # Registrar no log
    log_action('DNS_PROVIDER_CONFIGURED', f'Provedor DNS configurado para {domain.domain_name}: {provider}', current_user.id)
    
    return jsonify({
        'message': f'Provedor DNS {provider} configurado com sucesso',
        'domain': domain.to_dict()
    }), 200

@dns_bp.route('/providers', methods=['GET'])
@login_required
def get_dns_providers():
    """Lista provedores DNS disponíveis"""
    providers = [
        {
            'id': 'cloudflare',
            'name': 'Cloudflare',
            'description': 'Provedor DNS global com CDN integrado',
            'features': ['API completa', 'Gerenciamento automático', 'CDN gratuito'],
            'requires_api': True,
            'config_fields': ['api_key', 'zone_id']
        },
        {
            'id': 'route53',
            'name': 'AWS Route53',
            'description': 'Serviço DNS da Amazon Web Services',
            'features': ['Alta disponibilidade', 'Integração AWS', 'Geolocalização'],
            'requires_api': True,
            'config_fields': ['api_key', 'api_secret', 'zone_id']
        },
        {
            'id': 'godaddy',
            'name': 'GoDaddy',
            'description': 'Provedor DNS popular com interface simples',
            'features': ['Interface amigável', 'API disponível', 'Suporte 24/7'],
            'requires_api': True,
            'config_fields': ['api_key', 'api_secret']
        },
        {
            'id': 'namecheap',
            'name': 'Namecheap',
            'description': 'Registrador de domínios com DNS gratuito',
            'features': ['DNS gratuito', 'Interface web', 'Preços competitivos'],
            'requires_api': False,
            'config_fields': []
        },
        {
            'id': 'manual',
            'name': 'Configuração Manual',
            'description': 'Para qualquer provedor DNS via configuração manual',
            'features': ['Universal', 'Copy & paste', 'Sem API necessária'],
            'requires_api': False,
            'config_fields': []
        }
    ]
    
    return jsonify({
        'providers': providers,
        'total': len(providers)
    }), 200

@dns_bp.route('/templates/<provider>', methods=['GET'])
@login_required
def get_dns_template(provider):
    """Retorna template de configuração para um provedor específico"""
    domain_name = request.args.get('domain', 'exemplo.com')
    server_type = request.args.get('server_type', 'primary')
    
    # Criar um domínio temporário para gerar o template
    temp_domain = type('Domain', (), {'domain_name': domain_name})()
    
    # Gerar configuração
    config = dns_manager.generate_dns_config(temp_domain, provider, server_type)
    
    return jsonify({
        'provider': provider,
        'template': config,
        'instructions': dns_manager.get_setup_instructions(provider),
        'verification_steps': dns_manager.get_verification_steps(domain_name)
    }), 200

@dns_bp.route('/check-status/<int:domain_id>', methods=['GET'])
@login_required
def check_dns_status(domain_id):
    """Verifica status atual do DNS de um domínio"""
    domain = Domain.query.get_or_404(domain_id)
    
    # Verificar permissão
    if not current_user.is_admin:
        user_domain = next((ud for ud in current_user.user_domains if ud.domain_id == domain_id), None)
        if not user_domain:
            return jsonify({'error': 'Acesso negado ao domínio'}), 403
    
    # Obter registros DNS
    records = DNSRecord.query.filter_by(domain_id=domain_id, is_active=True).all()
    
    # Verificar propagação se solicitado
    check_propagation = request.args.get('check_propagation', 'false').lower() == 'true'
    propagation_result = None
    
    if check_propagation:
        propagation_result = dns_manager.verify_dns_propagation(domain.domain_name)
        
        # Atualizar status baseado na verificação
        if propagation_result['is_propagated']:
            domain.dns_status = 'configured'
            domain.is_online = True
        else:
            domain.dns_status = 'error'
            domain.is_online = False
        
        domain.last_status_check = datetime.utcnow()
        db.session.commit()
    
    return jsonify({
        'domain': domain.to_dict(),
        'records': [record.to_dict() for record in records],
        'propagation': propagation_result,
        'summary': {
            'total_records': len(records),
            'synced_records': len([r for r in records if r.is_synced]),
            'pending_sync': len([r for r in records if not r.is_synced]),
            'has_errors': any(r.sync_error for r in records)
        }
    }), 200

@dns_bp.route('/bulk-operations/<int:domain_id>', methods=['POST'])
@login_required
def bulk_dns_operations(domain_id):
    """Executa operações em lote nos registros DNS"""
    if not current_user.is_admin:
        return jsonify({'error': 'Apenas administradores podem executar operações em lote'}), 403
    
    domain = Domain.query.get_or_404(domain_id)
    data = request.get_json()
    
    if not data or not data.get('operation'):
        return jsonify({'error': 'Operação é obrigatória'}), 400
    
    operation = data['operation']
    record_ids = data.get('record_ids', [])
    
    if operation == 'sync_all':
        # Sincronizar todos os registros
        sync_result = dns_manager.sync_domain_records(domain)
        log_action('DNS_BULK_SYNC', f'Sincronização em lote executada para {domain.domain_name}', current_user.id)
        return jsonify({'message': 'Sincronização em lote concluída', 'result': sync_result}), 200
    
    elif operation == 'delete_selected':
        # Deletar registros selecionados
        if not record_ids:
            return jsonify({'error': 'IDs dos registros são obrigatórios'}), 400
        
        deleted_count = 0
        for record_id in record_ids:
            record = DNSRecord.query.filter_by(id=record_id, domain_id=domain_id).first()
            if record:
                record.is_active = False
                deleted_count += 1
        
        db.session.commit()
        log_action('DNS_BULK_DELETE', f'{deleted_count} registros DNS removidos em lote para {domain.domain_name}', current_user.id)
        return jsonify({'message': f'{deleted_count} registros removidos com sucesso'}), 200
    
    elif operation == 'reset_sync':
        # Resetar status de sincronização
        records = DNSRecord.query.filter_by(domain_id=domain_id, is_active=True).all()
        for record in records:
            record.is_synced = False
            record.sync_error = None
            record.external_id = None
        
        db.session.commit()
        log_action('DNS_BULK_RESET', f'Status de sincronização resetado para {len(records)} registros de {domain.domain_name}', current_user.id)
        return jsonify({'message': f'Status de sincronização resetado para {len(records)} registros'}), 200
    
    else:
        return jsonify({'error': 'Operação inválida'}), 400

