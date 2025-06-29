from flask import Blueprint, request, jsonify, send_file
from flask_login import login_required, current_user
from src.models.user import db
from src.services.credential_service import CredentialService
from src.routes.user import log_action
from datetime import datetime
import tempfile
import os

credentials_bp = Blueprint('credentials', __name__)

@credentials_bp.route('/my-credentials', methods=['GET'])
@login_required
def get_my_credentials():
    """Lista credenciais capturadas do usuário"""
    try:
        anonymize = request.args.get('anonymize', 'true').lower() == 'true'
        limit = int(request.args.get('limit', 50))
        offset = int(request.args.get('offset', 0))
        
        result = CredentialService.get_user_credentials(
            user_id=current_user.id,
            anonymize=anonymize,
            limit=limit,
            offset=offset
        )
        
        log_action(current_user.id, 'view_credentials', f'Visualizou {len(result["credentials"])} credenciais')
        
        return jsonify({
            'success': True,
            'data': result
        })
        
    except Exception as e:
        return jsonify({
            'success': False,
            'message': f'Erro ao buscar credenciais: {str(e)}'
        }), 500

@credentials_bp.route('/credential/<int:credential_id>', methods=['GET'])
@login_required
def get_credential_details():
    """Obtém detalhes de uma credencial específica"""
    try:
        credential_id = request.view_args['credential_id']
        anonymize = request.args.get('anonymize', 'false').lower() == 'true'
        
        credential = CredentialService.get_credential_by_id(
            credential_id=credential_id,
            user_id=current_user.id,
            anonymize=anonymize
        )
        
        if not credential:
            return jsonify({
                'success': False,
                'message': 'Credencial não encontrada'
            }), 404
        
        log_action(current_user.id, 'view_credential_details', f'Visualizou detalhes da credencial {credential_id}')
        
        return jsonify({
            'success': True,
            'data': credential
        })
        
    except Exception as e:
        return jsonify({
            'success': False,
            'message': f'Erro ao buscar credencial: {str(e)}'
        }), 500

@credentials_bp.route('/credential/<int:credential_id>/verify', methods=['POST'])
@login_required
def verify_credential():
    """Marca uma credencial como verificada"""
    try:
        credential_id = request.view_args['credential_id']
        
        success = CredentialService.verify_credential(
            credential_id=credential_id,
            user_id=current_user.id
        )
        
        if success:
            log_action(current_user.id, 'verify_credential', f'Verificou credencial {credential_id}')
            return jsonify({
                'success': True,
                'message': 'Credencial verificada com sucesso'
            })
        else:
            return jsonify({
                'success': False,
                'message': 'Credencial não encontrada ou erro na verificação'
            }), 404
            
    except Exception as e:
        return jsonify({
            'success': False,
            'message': f'Erro ao verificar credencial: {str(e)}'
        }), 500

@credentials_bp.route('/credential/<int:credential_id>/anonymize', methods=['POST'])
@login_required
def anonymize_credential():
    """Anonimiza uma credencial"""
    try:
        credential_id = request.view_args['credential_id']
        
        success = CredentialService.anonymize_credential(
            credential_id=credential_id,
            user_id=current_user.id
        )
        
        if success:
            log_action(current_user.id, 'anonymize_credential', f'Anonimizou credencial {credential_id}')
            return jsonify({
                'success': True,
                'message': 'Credencial anonimizada com sucesso'
            })
        else:
            return jsonify({
                'success': False,
                'message': 'Credencial não encontrada ou erro na anonimização'
            }), 404
            
    except Exception as e:
        return jsonify({
            'success': False,
            'message': f'Erro ao anonimizar credencial: {str(e)}'
        }), 500

@credentials_bp.route('/credential/<int:credential_id>', methods=['DELETE'])
@login_required
def delete_credential():
    """Remove uma credencial"""
    try:
        credential_id = request.view_args['credential_id']
        
        success = CredentialService.delete_credential(
            credential_id=credential_id,
            user_id=current_user.id
        )
        
        if success:
            log_action(current_user.id, 'delete_credential', f'Removeu credencial {credential_id}')
            return jsonify({
                'success': True,
                'message': 'Credencial removida com sucesso'
            })
        else:
            return jsonify({
                'success': False,
                'message': 'Credencial não encontrada'
            }), 404
            
    except Exception as e:
        return jsonify({
            'success': False,
            'message': f'Erro ao remover credencial: {str(e)}'
        }), 500

@credentials_bp.route('/export', methods=['POST'])
@login_required
def export_credentials():
    """Exporta credenciais em diferentes formatos"""
    try:
        data = request.get_json() or {}
        
        format_type = data.get('format', 'json').lower()
        anonymize = data.get('anonymize', True)
        filters = data.get('filters', {})
        
        # Validar formato
        if format_type not in ['json', 'csv']:
            return jsonify({
                'success': False,
                'message': 'Formato não suportado. Use json ou csv.'
            }), 400
        
        # Exportar dados
        exported_data = CredentialService.export_credentials(
            user_id=current_user.id,
            format=format_type,
            anonymize=anonymize,
            filters=filters
        )
        
        if exported_data is None:
            return jsonify({
                'success': False,
                'message': 'Erro ao exportar dados'
            }), 500
        
        # Criar arquivo temporário
        with tempfile.NamedTemporaryFile(mode='w', delete=False, suffix=f'.{format_type}') as temp_file:
            temp_file.write(exported_data)
            temp_file_path = temp_file.name
        
        # Definir nome do arquivo
        timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
        filename = f'credentials_export_{timestamp}.{format_type}'
        
        log_action(current_user.id, 'export_credentials', f'Exportou credenciais em formato {format_type}')
        
        # Enviar arquivo e limpar depois
        def remove_file(response):
            try:
                os.unlink(temp_file_path)
            except:
                pass
            return response
        
        return send_file(
            temp_file_path,
            as_attachment=True,
            download_name=filename,
            mimetype='application/json' if format_type == 'json' else 'text/csv'
        )
        
    except Exception as e:
        return jsonify({
            'success': False,
            'message': f'Erro ao exportar: {str(e)}'
        }), 500

@credentials_bp.route('/statistics', methods=['GET'])
@login_required
def get_credentials_statistics():
    """Obtém estatísticas das credenciais capturadas"""
    try:
        stats = CredentialService.get_statistics(current_user.id)
        
        log_action(current_user.id, 'view_credential_stats', 'Visualizou estatísticas de credenciais')
        
        return jsonify({
            'success': True,
            'data': stats
        })
        
    except Exception as e:
        return jsonify({
            'success': False,
            'message': f'Erro ao obter estatísticas: {str(e)}'
        }), 500

@credentials_bp.route('/search', methods=['GET'])
@login_required
def search_credentials():
    """Busca credenciais por termo"""
    try:
        search_term = request.args.get('q', '').strip()
        anonymize = request.args.get('anonymize', 'true').lower() == 'true'
        
        if not search_term:
            return jsonify({
                'success': False,
                'message': 'Termo de busca é obrigatório'
            }), 400
        
        results = CredentialService.search_credentials(
            user_id=current_user.id,
            search_term=search_term,
            anonymize=anonymize
        )
        
        log_action(current_user.id, 'search_credentials', f'Buscou credenciais: "{search_term}"')
        
        return jsonify({
            'success': True,
            'data': {
                'credentials': results,
                'total': len(results),
                'search_term': search_term
            }
        })
        
    except Exception as e:
        return jsonify({
            'success': False,
            'message': f'Erro na busca: {str(e)}'
        }), 500

@credentials_bp.route('/bulk-operations', methods=['POST'])
@login_required
def bulk_operations():
    """Operações em lote nas credenciais"""
    try:
        data = request.get_json()
        operation = data.get('operation')
        credential_ids = data.get('credential_ids', [])
        
        if not operation or not credential_ids:
            return jsonify({
                'success': False,
                'message': 'Operação e IDs são obrigatórios'
            }), 400
        
        success_count = 0
        error_count = 0
        
        for credential_id in credential_ids:
            try:
                if operation == 'verify':
                    success = CredentialService.verify_credential(credential_id, current_user.id)
                elif operation == 'anonymize':
                    success = CredentialService.anonymize_credential(credential_id, current_user.id)
                elif operation == 'delete':
                    success = CredentialService.delete_credential(credential_id, current_user.id)
                else:
                    continue
                
                if success:
                    success_count += 1
                else:
                    error_count += 1
                    
            except:
                error_count += 1
        
        log_action(current_user.id, 'bulk_credential_operation', 
                  f'Operação {operation}: {success_count} sucessos, {error_count} erros')
        
        return jsonify({
            'success': True,
            'message': f'Operação concluída: {success_count} sucessos, {error_count} erros',
            'data': {
                'success_count': success_count,
                'error_count': error_count,
                'total_processed': len(credential_ids)
            }
        })
        
    except Exception as e:
        return jsonify({
            'success': False,
            'message': f'Erro na operação em lote: {str(e)}'
        }), 500

