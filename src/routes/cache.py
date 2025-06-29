from flask import Blueprint, request, jsonify
from flask_login import login_required, current_user
from src.services.cache_service import cache_service
from src.routes.user import log_action, admin_required

cache_bp = Blueprint('cache', __name__)

@cache_bp.route('/info', methods=['GET'])
@login_required
@admin_required
def get_cache_info():
    """Obtém informações sobre o cache"""
    try:
        cache_info = cache_service.get_cache_info()
        
        log_action(current_user.id, 'view_cache_info', 'Visualizou informações do cache')
        
        return jsonify({
            'success': True,
            'data': cache_info
        })
        
    except Exception as e:
        return jsonify({
            'success': False,
            'message': f'Erro ao obter informações do cache: {str(e)}'
        }), 500

@cache_bp.route('/clear', methods=['POST'])
@login_required
@admin_required
def clear_cache():
    """Limpa todo o cache"""
    try:
        success = cache_service.clear_all_cache()
        
        if success:
            log_action(current_user.id, 'clear_cache', 'Limpou todo o cache')
            return jsonify({
                'success': True,
                'message': 'Cache limpo com sucesso'
            })
        else:
            return jsonify({
                'success': False,
                'message': 'Erro ao limpar cache'
            }), 500
            
    except Exception as e:
        return jsonify({
            'success': False,
            'message': f'Erro ao limpar cache: {str(e)}'
        }), 500

@cache_bp.route('/invalidate/user/<int:user_id>', methods=['POST'])
@login_required
@admin_required
def invalidate_user_cache(user_id):
    """Invalida cache de um usuário específico"""
    try:
        cache_service.invalidate_user_cache(user_id)
        
        log_action(current_user.id, 'invalidate_user_cache', f'Invalidou cache do usuário {user_id}')
        
        return jsonify({
            'success': True,
            'message': f'Cache do usuário {user_id} invalidado'
        })
        
    except Exception as e:
        return jsonify({
            'success': False,
            'message': f'Erro ao invalidar cache do usuário: {str(e)}'
        }), 500

@cache_bp.route('/invalidate/url/<int:url_id>', methods=['POST'])
@login_required
def invalidate_url_cache(url_id):
    """Invalida cache de uma URL específica"""
    try:
        # Verificar se o usuário tem acesso à URL
        from src.models.user import GeneratedURL
        url = GeneratedURL.query.filter_by(id=url_id, user_id=current_user.id).first()
        
        if not url and not current_user.is_admin:
            return jsonify({
                'success': False,
                'message': 'URL não encontrada ou sem permissão'
            }), 404
        
        cache_service.invalidate_url_cache(url_id)
        
        log_action(current_user.id, 'invalidate_url_cache', f'Invalidou cache da URL {url_id}')
        
        return jsonify({
            'success': True,
            'message': f'Cache da URL {url_id} invalidado'
        })
        
    except Exception as e:
        return jsonify({
            'success': False,
            'message': f'Erro ao invalidar cache da URL: {str(e)}'
        }), 500

@cache_bp.route('/invalidate/admin', methods=['POST'])
@login_required
@admin_required
def invalidate_admin_cache():
    """Invalida cache administrativo"""
    try:
        cache_service.invalidate_admin_cache()
        
        log_action(current_user.id, 'invalidate_admin_cache', 'Invalidou cache administrativo')
        
        return jsonify({
            'success': True,
            'message': 'Cache administrativo invalidado'
        })
        
    except Exception as e:
        return jsonify({
            'success': False,
            'message': f'Erro ao invalidar cache administrativo: {str(e)}'
        }), 500

@cache_bp.route('/invalidate/global', methods=['POST'])
@login_required
@admin_required
def invalidate_global_cache():
    """Invalida caches globais"""
    try:
        cache_service.invalidate_global_cache()
        
        log_action(current_user.id, 'invalidate_global_cache', 'Invalidou caches globais')
        
        return jsonify({
            'success': True,
            'message': 'Caches globais invalidados'
        })
        
    except Exception as e:
        return jsonify({
            'success': False,
            'message': f'Erro ao invalidar caches globais: {str(e)}'
        }), 500

@cache_bp.route('/warm-up', methods=['POST'])
@login_required
def warm_up_cache():
    """Pré-carrega cache do usuário"""
    try:
        success = cache_service.warm_up_cache(current_user.id)
        
        if success:
            log_action(current_user.id, 'warm_up_cache', 'Aqueceu cache pessoal')
            return jsonify({
                'success': True,
                'message': 'Cache aquecido com sucesso'
            })
        else:
            return jsonify({
                'success': False,
                'message': 'Erro ao aquecer cache'
            }), 500
            
    except Exception as e:
        return jsonify({
            'success': False,
            'message': f'Erro ao aquecer cache: {str(e)}'
        }), 500

@cache_bp.route('/warm-up/admin', methods=['POST'])
@login_required
@admin_required
def warm_up_admin_cache():
    """Pré-carrega caches administrativos"""
    try:
        # Aquecer cache administrativo
        cache_service.cache_admin_stats()
        cache_service.cache_script_list()
        cache_service.cache_domain_list()
        
        log_action(current_user.id, 'warm_up_admin_cache', 'Aqueceu cache administrativo')
        
        return jsonify({
            'success': True,
            'message': 'Cache administrativo aquecido com sucesso'
        })
        
    except Exception as e:
        return jsonify({
            'success': False,
            'message': f'Erro ao aquecer cache administrativo: {str(e)}'
        }), 500

