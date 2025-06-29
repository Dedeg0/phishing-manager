from flask import Blueprint, request, jsonify, send_file
from flask_login import login_required, current_user
from src.services.report_service import ReportService
from src.routes.user import log_action
from datetime import datetime
import tempfile
import os

reports_bp = Blueprint('reports', __name__)

@reports_bp.route('/performance', methods=['GET'])
@login_required
def get_performance_report():
    """Gera relatório de performance do usuário"""
    try:
        days = int(request.args.get('days', 30))
        
        if days > 365:
            return jsonify({
                'success': False,
                'message': 'Período máximo é de 365 dias'
            }), 400
        
        report_data = ReportService.generate_user_performance_report(
            user_id=current_user.id,
            days=days
        )
        
        if not report_data:
            return jsonify({
                'success': False,
                'message': 'Erro ao gerar relatório'
            }), 500
        
        # Gerar gráficos
        charts = ReportService.generate_charts(report_data)
        
        log_action(current_user.id, 'generate_performance_report', f'Gerou relatório de {days} dias')
        
        return jsonify({
            'success': True,
            'data': {
                'report': report_data,
                'charts': charts
            }
        })
        
    except Exception as e:
        return jsonify({
            'success': False,
            'message': f'Erro ao gerar relatório: {str(e)}'
        }), 500

@reports_bp.route('/security', methods=['GET'])
@login_required
def get_security_report():
    """Gera relatório de segurança"""
    try:
        days = int(request.args.get('days', 30))
        
        if days > 365:
            return jsonify({
                'success': False,
                'message': 'Período máximo é de 365 dias'
            }), 400
        
        report_data = ReportService.generate_security_report(
            user_id=current_user.id,
            days=days
        )
        
        if not report_data:
            return jsonify({
                'success': False,
                'message': 'Erro ao gerar relatório de segurança'
            }), 500
        
        log_action(current_user.id, 'generate_security_report', f'Gerou relatório de segurança de {days} dias')
        
        return jsonify({
            'success': True,
            'data': report_data
        })
        
    except Exception as e:
        return jsonify({
            'success': False,
            'message': f'Erro ao gerar relatório de segurança: {str(e)}'
        }), 500

@reports_bp.route('/export/pdf', methods=['POST'])
@login_required
def export_report_pdf():
    """Exporta relatório em PDF"""
    try:
        data = request.get_json() or {}
        report_type = data.get('type', 'performance')
        days = int(data.get('days', 30))
        
        if days > 365:
            return jsonify({
                'success': False,
                'message': 'Período máximo é de 365 dias'
            }), 400
        
        # Gerar dados do relatório
        if report_type == 'performance':
            report_data = ReportService.generate_user_performance_report(
                user_id=current_user.id,
                days=days
            )
        elif report_type == 'security':
            report_data = ReportService.generate_security_report(
                user_id=current_user.id,
                days=days
            )
        else:
            return jsonify({
                'success': False,
                'message': 'Tipo de relatório inválido'
            }), 400
        
        if not report_data:
            return jsonify({
                'success': False,
                'message': 'Erro ao gerar dados do relatório'
            }), 500
        
        # Gerar gráficos se for relatório de performance
        charts_data = None
        if report_type == 'performance':
            charts_data = ReportService.generate_charts(report_data)
        
        # Exportar para PDF
        pdf_path = ReportService.export_report_to_pdf(report_data, charts_data)
        
        if not pdf_path or not os.path.exists(pdf_path):
            return jsonify({
                'success': False,
                'message': 'Erro ao gerar PDF'
            }), 500
        
        # Definir nome do arquivo
        timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
        filename = f'relatorio_{report_type}_{timestamp}.pdf'
        
        log_action(current_user.id, 'export_report_pdf', f'Exportou relatório {report_type} em PDF')
        
        # Enviar arquivo
        def remove_file(response):
            try:
                os.unlink(pdf_path)
            except:
                pass
            return response
        
        return send_file(
            pdf_path,
            as_attachment=True,
            download_name=filename,
            mimetype='application/pdf'
        )
        
    except Exception as e:
        return jsonify({
            'success': False,
            'message': f'Erro ao exportar PDF: {str(e)}'
        }), 500

@reports_bp.route('/dashboard-data', methods=['GET'])
@login_required
def get_dashboard_data():
    """Obtém dados resumidos para o dashboard"""
    try:
        days = int(request.args.get('days', 7))  # Últimos 7 dias por padrão
        
        # Gerar relatório resumido
        report_data = ReportService.generate_user_performance_report(
            user_id=current_user.id,
            days=days
        )
        
        if not report_data:
            return jsonify({
                'success': False,
                'message': 'Erro ao obter dados do dashboard'
            }), 500
        
        # Extrair apenas dados essenciais para o dashboard
        dashboard_data = {
            'summary': report_data.get('summary', {}),
            'daily_data': report_data.get('daily_data', [])[-7:],  # Últimos 7 dias
            'top_scripts': report_data.get('script_performance', [])[:5],  # Top 5 scripts
            'top_countries': report_data.get('country_stats', [])[:5]  # Top 5 países
        }
        
        return jsonify({
            'success': True,
            'data': dashboard_data
        })
        
    except Exception as e:
        return jsonify({
            'success': False,
            'message': f'Erro ao obter dados do dashboard: {str(e)}'
        }), 500

@reports_bp.route('/comparison', methods=['POST'])
@login_required
def get_comparison_report():
    """Gera relatório comparativo entre períodos"""
    try:
        data = request.get_json() or {}
        
        # Período atual
        current_days = int(data.get('current_days', 30))
        # Período anterior (mesmo número de dias)
        previous_days = current_days * 2  # Para pegar o período anterior
        
        # Relatório atual
        current_report = ReportService.generate_user_performance_report(
            user_id=current_user.id,
            days=current_days
        )
        
        # Relatório anterior (simulado - seria necessário implementar lógica mais complexa)
        previous_report = ReportService.generate_user_performance_report(
            user_id=current_user.id,
            days=previous_days
        )
        
        if not current_report or not previous_report:
            return jsonify({
                'success': False,
                'message': 'Erro ao gerar relatórios comparativos'
            }), 500
        
        # Calcular variações
        current_summary = current_report.get('summary', {})
        previous_summary = previous_report.get('summary', {})
        
        comparison = {}
        for key in current_summary:
            current_value = current_summary.get(key, 0)
            previous_value = previous_summary.get(key, 0)
            
            if previous_value > 0:
                change_percent = ((current_value - previous_value) / previous_value) * 100
            else:
                change_percent = 100 if current_value > 0 else 0
            
            comparison[key] = {
                'current': current_value,
                'previous': previous_value,
                'change': current_value - previous_value,
                'change_percent': round(change_percent, 2)
            }
        
        log_action(current_user.id, 'generate_comparison_report', f'Gerou relatório comparativo de {current_days} dias')
        
        return jsonify({
            'success': True,
            'data': {
                'current_period': current_report,
                'previous_period': previous_report,
                'comparison': comparison
            }
        })
        
    except Exception as e:
        return jsonify({
            'success': False,
            'message': f'Erro ao gerar relatório comparativo: {str(e)}'
        }), 500

@reports_bp.route('/custom', methods=['POST'])
@login_required
def generate_custom_report():
    """Gera relatório customizado com filtros específicos"""
    try:
        data = request.get_json() or {}
        
        # Parâmetros do relatório customizado
        start_date = data.get('start_date')
        end_date = data.get('end_date')
        include_charts = data.get('include_charts', True)
        filters = data.get('filters', {})
        
        if not start_date or not end_date:
            return jsonify({
                'success': False,
                'message': 'Datas de início e fim são obrigatórias'
            }), 400
        
        # Calcular dias entre as datas
        from datetime import datetime
        start = datetime.fromisoformat(start_date.replace('Z', '+00:00'))
        end = datetime.fromisoformat(end_date.replace('Z', '+00:00'))
        days = (end - start).days
        
        if days > 365:
            return jsonify({
                'success': False,
                'message': 'Período máximo é de 365 dias'
            }), 400
        
        # Gerar relatório base
        report_data = ReportService.generate_user_performance_report(
            user_id=current_user.id,
            days=days
        )
        
        if not report_data:
            return jsonify({
                'success': False,
                'message': 'Erro ao gerar relatório customizado'
            }), 500
        
        # Aplicar filtros adicionais se necessário
        # (implementar lógica de filtros específicos aqui)
        
        # Gerar gráficos se solicitado
        charts = {}
        if include_charts:
            charts = ReportService.generate_charts(report_data)
        
        log_action(current_user.id, 'generate_custom_report', f'Gerou relatório customizado de {days} dias')
        
        return jsonify({
            'success': True,
            'data': {
                'report': report_data,
                'charts': charts,
                'filters_applied': filters
            }
        })
        
    except Exception as e:
        return jsonify({
            'success': False,
            'message': f'Erro ao gerar relatório customizado: {str(e)}'
        }), 500

