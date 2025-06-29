from flask import Blueprint, request, jsonify, current_app
from flask_login import login_required, current_user
from src.services.environment_service import env_config
from src.routes.user import log_action, admin_required
import time
from datetime import datetime

metrics_bp = Blueprint('metrics', __name__)

@metrics_bp.before_app_request
def before_request():
    """Registra início da requisição para métricas"""
    request.start_time = time.time()

@metrics_bp.after_app_request
def after_request(response):
    """Registra métricas da requisição"""
    if hasattr(request, 'start_time'):
        duration = time.time() - request.start_time
        env_config.log_request_metrics(request, response, duration)
    return response

@metrics_bp.route('/health', methods=['GET'])
def health_check():
    """Endpoint de health check"""
    try:
        health = env_config.get_health_status(current_app)
        
        status_code = 200
        if health['status'] == 'degraded':
            status_code = 200  # Ainda funcional
        elif health['status'] == 'unhealthy':
            status_code = 503  # Service Unavailable
        
        return jsonify(health), status_code
        
    except Exception as e:
        return jsonify({
            'timestamp': datetime.utcnow().isoformat(),
            'status': 'error',
            'message': str(e)
        }), 500

@metrics_bp.route('/system', methods=['GET'])
@login_required
@admin_required
def get_system_metrics():
    """Obtém métricas do sistema"""
    try:
        metrics = env_config.get_system_metrics()
        
        log_action(current_user.id, 'view_system_metrics', 'Visualizou métricas do sistema')
        
        return jsonify({
            'success': True,
            'data': metrics
        })
        
    except Exception as e:
        return jsonify({
            'success': False,
            'message': f'Erro ao obter métricas do sistema: {str(e)}'
        }), 500

@metrics_bp.route('/application', methods=['GET'])
@login_required
@admin_required
def get_application_metrics():
    """Obtém métricas da aplicação"""
    try:
        metrics = env_config.get_application_metrics(current_app)
        
        log_action(current_user.id, 'view_app_metrics', 'Visualizou métricas da aplicação')
        
        return jsonify({
            'success': True,
            'data': metrics
        })
        
    except Exception as e:
        return jsonify({
            'success': False,
            'message': f'Erro ao obter métricas da aplicação: {str(e)}'
        }), 500

@metrics_bp.route('/requests', methods=['GET'])
@login_required
@admin_required
def get_request_metrics():
    """Obtém métricas de requisições"""
    try:
        metrics = env_config.get_request_metrics_summary()
        
        log_action(current_user.id, 'view_request_metrics', 'Visualizou métricas de requisições')
        
        return jsonify({
            'success': True,
            'data': metrics
        })
        
    except Exception as e:
        return jsonify({
            'success': False,
            'message': f'Erro ao obter métricas de requisições: {str(e)}'
        }), 500

@metrics_bp.route('/environment', methods=['GET'])
@login_required
@admin_required
def get_environment_info():
    """Obtém informações do ambiente"""
    try:
        config = env_config.export_config()
        
        log_action(current_user.id, 'view_environment_info', 'Visualizou informações do ambiente')
        
        return jsonify({
            'success': True,
            'data': config
        })
        
    except Exception as e:
        return jsonify({
            'success': False,
            'message': f'Erro ao obter informações do ambiente: {str(e)}'
        }), 500

@metrics_bp.route('/dashboard', methods=['GET'])
@login_required
@admin_required
def get_metrics_dashboard():
    """Obtém dados completos para dashboard de métricas"""
    try:
        dashboard_data = {
            'timestamp': datetime.utcnow().isoformat(),
            'environment': env_config.environment,
            'health': env_config.get_health_status(current_app),
            'system': env_config.get_system_metrics(),
            'application': env_config.get_application_metrics(current_app),
            'requests': env_config.get_request_metrics_summary()
        }
        
        log_action(current_user.id, 'view_metrics_dashboard', 'Visualizou dashboard de métricas')
        
        return jsonify({
            'success': True,
            'data': dashboard_data
        })
        
    except Exception as e:
        return jsonify({
            'success': False,
            'message': f'Erro ao obter dados do dashboard: {str(e)}'
        }), 500

@metrics_bp.route('/performance', methods=['GET'])
@login_required
@admin_required
def get_performance_metrics():
    """Obtém métricas de performance específicas"""
    try:
        from src.services.cache_service import cache_service
        
        performance_data = {
            'timestamp': datetime.utcnow().isoformat(),
            'environment': env_config.environment,
            'cache': cache_service.get_cache_info(),
            'database': {
                'connection_pool': 'SQLite (single connection)',
                'query_optimization': 'Basic indexing'
            },
            'system_resources': {
                'cpu': env_config.get_system_metrics()['system']['cpu_percent'],
                'memory': env_config.get_system_metrics()['system']['memory']['percent'],
                'disk': env_config.get_system_metrics()['system']['disk']['percent']
            }
        }
        
        log_action(current_user.id, 'view_performance_metrics', 'Visualizou métricas de performance')
        
        return jsonify({
            'success': True,
            'data': performance_data
        })
        
    except Exception as e:
        return jsonify({
            'success': False,
            'message': f'Erro ao obter métricas de performance: {str(e)}'
        }), 500

@metrics_bp.route('/export', methods=['GET'])
@login_required
@admin_required
def export_metrics():
    """Exporta todas as métricas em formato JSON"""
    try:
        export_data = {
            'export_timestamp': datetime.utcnow().isoformat(),
            'environment': env_config.environment,
            'system_info': env_config.export_config(),
            'health_status': env_config.get_health_status(current_app),
            'system_metrics': env_config.get_system_metrics(),
            'application_metrics': env_config.get_application_metrics(current_app),
            'request_metrics': env_config.get_request_metrics_summary(),
            'cache_info': None
        }
        
        try:
            from src.services.cache_service import cache_service
            export_data['cache_info'] = cache_service.get_cache_info()
        except:
            pass
        
        log_action(current_user.id, 'export_metrics', 'Exportou métricas do sistema')
        
        return jsonify({
            'success': True,
            'data': export_data
        })
        
    except Exception as e:
        return jsonify({
            'success': False,
            'message': f'Erro ao exportar métricas: {str(e)}'
        }), 500

@metrics_bp.route('/config/update', methods=['POST'])
@login_required
@admin_required
def update_environment_config():
    """Atualiza configurações do ambiente (apenas algumas permitidas)"""
    try:
        data = request.get_json()
        
        # Configurações que podem ser atualizadas em runtime
        allowed_configs = [
            'CACHE_DEFAULT_TIMEOUT',
            'RATE_LIMIT',
            'LOG_LEVEL',
            'ENABLE_METRICS',
            'ENABLE_PROFILING'
        ]
        
        updated = {}
        for key, value in data.items():
            if key in allowed_configs:
                env_config.config[key] = value
                updated[key] = value
        
        if updated:
            log_action(current_user.id, 'update_environment_config', f'Atualizou configurações: {list(updated.keys())}')
            
            return jsonify({
                'success': True,
                'message': 'Configurações atualizadas com sucesso',
                'updated': updated
            })
        else:
            return jsonify({
                'success': False,
                'message': 'Nenhuma configuração válida fornecida'
            }), 400
        
    except Exception as e:
        return jsonify({
            'success': False,
            'message': f'Erro ao atualizar configurações: {str(e)}'
        }), 500

