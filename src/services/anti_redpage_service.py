import re
import hashlib
import json
import requests
import time
from datetime import datetime, timedelta
from urllib.parse import urlparse, parse_qs, urlencode, urlunparse
from src.models.user import db, BlacklistedIP, SuspiciousActivity, URLCleaning, Log
import user_agents

class AntiRedpageService:
    def __init__(self):
        self.redpage_indicators = [
            # Indicadores comuns de redpage
            'security', 'warning', 'alert', 'blocked', 'suspended',
            'violation', 'abuse', 'malware', 'phishing', 'fraud',
            'restricted', 'banned', 'flagged', 'reported', 'unsafe',
            'dangerous', 'threat', 'risk', 'compromised', 'infected'
        ]
        
        self.suspicious_params = [
            # Parâmetros suspeitos que podem indicar tracking/detecção
            'utm_source', 'utm_medium', 'utm_campaign', 'fbclid',
            'gclid', 'ref', 'source', 'campaign', 'track', 'analytics',
            'monitor', 'detect', 'scan', 'check', 'verify', 'validate'
        ]
        
        self.bot_user_agents = [
            # User agents conhecidos de bots/crawlers
            'bot', 'crawler', 'spider', 'scraper', 'scanner',
            'googlebot', 'bingbot', 'slurp', 'duckduckbot',
            'facebookexternalhit', 'twitterbot', 'linkedinbot',
            'whatsapp', 'telegram', 'discord', 'slack'
        ]
    
    def clean_url(self, url, cleaning_type='full_clean'):
        """Limpa uma URL removendo parâmetros suspeitos e indicadores de redpage"""
        try:
            parsed = urlparse(url)
            issues_found = []
            actions_taken = []
            
            # Verificar domínio por indicadores de redpage
            domain_issues = self._check_domain_indicators(parsed.netloc)
            if domain_issues:
                issues_found.extend(domain_issues)
            
            # Limpar parâmetros suspeitos
            if parsed.query:
                clean_params = self._clean_url_parameters(parsed.query)
                if clean_params['removed']:
                    issues_found.append(f"Parâmetros suspeitos removidos: {clean_params['removed']}")
                    actions_taken.append("Remoção de parâmetros de tracking")
                
                # Reconstruir URL com parâmetros limpos
                clean_query = urlencode(clean_params['clean_params'])
                parsed = parsed._replace(query=clean_query)
            
            # Verificar path por indicadores suspeitos
            path_issues = self._check_path_indicators(parsed.path)
            if path_issues:
                issues_found.extend(path_issues)
            
            # Adicionar parâmetros de ofuscação se necessário
            if cleaning_type in ['redpage_removal', 'full_clean']:
                obfuscated = self._add_obfuscation_params(parsed)
                if obfuscated != parsed:
                    actions_taken.append("Adição de parâmetros de ofuscação")
                    parsed = obfuscated
            
            cleaned_url = urlunparse(parsed)
            
            return {
                'cleaned_url': cleaned_url,
                'issues_found': issues_found,
                'actions_taken': actions_taken,
                'is_clean': len(issues_found) == 0
            }
            
        except Exception as e:
            return {
                'cleaned_url': url,
                'issues_found': [f"Erro na limpeza: {str(e)}"],
                'actions_taken': [],
                'is_clean': False
            }
    
    def _check_domain_indicators(self, domain):
        """Verifica indicadores de redpage no domínio"""
        issues = []
        domain_lower = domain.lower()
        
        for indicator in self.redpage_indicators:
            if indicator in domain_lower:
                issues.append(f"Indicador de redpage no domínio: '{indicator}'")
        
        # Verificar se é um domínio de segurança conhecido
        security_domains = [
            'safebrowsing.google.com', 'phishtank.com', 'virustotal.com',
            'urlvoid.com', 'sucuri.net', 'sitecheck.sucuri.net'
        ]
        
        for sec_domain in security_domains:
            if sec_domain in domain_lower:
                issues.append(f"Domínio de verificação de segurança detectado: {sec_domain}")
        
        return issues
    
    def _check_path_indicators(self, path):
        """Verifica indicadores de redpage no caminho da URL"""
        issues = []
        path_lower = path.lower()
        
        for indicator in self.redpage_indicators:
            if indicator in path_lower:
                issues.append(f"Indicador de redpage no caminho: '{indicator}'")
        
        return issues
    
    def _clean_url_parameters(self, query_string):
        """Remove parâmetros suspeitos da query string"""
        params = parse_qs(query_string, keep_blank_values=True)
        clean_params = {}
        removed_params = []
        
        for key, values in params.items():
            key_lower = key.lower()
            is_suspicious = False
            
            # Verificar se o parâmetro é suspeito
            for suspicious in self.suspicious_params:
                if suspicious in key_lower:
                    is_suspicious = True
                    removed_params.append(key)
                    break
            
            # Verificar valores suspeitos
            if not is_suspicious:
                for value in values:
                    value_lower = str(value).lower()
                    for indicator in self.redpage_indicators:
                        if indicator in value_lower:
                            is_suspicious = True
                            removed_params.append(f"{key}={value}")
                            break
                    if is_suspicious:
                        break
            
            if not is_suspicious:
                clean_params[key] = values
        
        return {
            'clean_params': clean_params,
            'removed': removed_params
        }
    
    def _add_obfuscation_params(self, parsed_url):
        """Adiciona parâmetros de ofuscação para evitar detecção"""
        current_params = parse_qs(parsed_url.query, keep_blank_values=True)
        
        # Adicionar parâmetros comuns que parecem legítimos
        obfuscation_params = {
            'v': [str(int(time.time()))],  # Versão/timestamp
            'ref': ['organic'],  # Referência orgânica
            'lang': ['pt-BR'],  # Idioma
            'tz': ['America/Sao_Paulo']  # Timezone
        }
        
        # Mesclar parâmetros existentes com ofuscação
        for key, values in obfuscation_params.items():
            if key not in current_params:
                current_params[key] = values
        
        new_query = urlencode(current_params, doseq=True)
        return parsed_url._replace(query=new_query)

class AntiBotService:
    def __init__(self):
        self.bot_indicators = {
            'user_agent_patterns': [
                r'bot', r'crawler', r'spider', r'scraper', r'scanner',
                r'curl', r'wget', r'python', r'requests', r'urllib',
                r'headless', r'phantom', r'selenium', r'webdriver'
            ],
            'suspicious_headers': [
                'x-forwarded-for', 'x-real-ip', 'x-cluster-client-ip',
                'cf-connecting-ip', 'x-original-forwarded-for'
            ],
            'timing_thresholds': {
                'min_time_between_requests': 1.0,  # segundos
                'max_requests_per_minute': 30,
                'max_requests_per_hour': 500
            }
        }
        
        self.request_history = {}  # Cache em memória para tracking de requests
    
    def analyze_visitor(self, request_data, visitor_data=None):
        """Analisa um visitante para detectar comportamento de bot"""
        bot_score = 0.0
        indicators = []
        
        # Análise do User-Agent
        ua_analysis = self._analyze_user_agent(request_data.get('user_agent', ''))
        bot_score += ua_analysis['score']
        indicators.extend(ua_analysis['indicators'])
        
        # Análise de headers
        headers_analysis = self._analyze_headers(request_data.get('headers', {}))
        bot_score += headers_analysis['score']
        indicators.extend(headers_analysis['indicators'])
        
        # Análise de timing (se temos dados históricos)
        if visitor_data:
            timing_analysis = self._analyze_timing_patterns(visitor_data)
            bot_score += timing_analysis['score']
            indicators.extend(timing_analysis['indicators'])
        
        # Análise de fingerprinting
        fingerprint_analysis = self._analyze_fingerprint(request_data)
        bot_score += fingerprint_analysis['score']
        indicators.extend(fingerprint_analysis['indicators'])
        
        # Normalizar score (0.0 a 1.0)
        bot_score = min(bot_score, 1.0)
        
        return {
            'is_bot': bot_score > 0.7,
            'bot_score': bot_score,
            'confidence': self._calculate_confidence(bot_score, len(indicators)),
            'indicators': indicators,
            'risk_level': self._get_risk_level(bot_score)
        }
    
    def _analyze_user_agent(self, user_agent_string):
        """Analisa o User-Agent para detectar bots"""
        score = 0.0
        indicators = []
        
        if not user_agent_string:
            return {'score': 0.8, 'indicators': ['User-Agent ausente']}
        
        ua_lower = user_agent_string.lower()
        
        # Verificar padrões conhecidos de bot
        for pattern in self.bot_indicators['user_agent_patterns']:
            if re.search(pattern, ua_lower):
                score += 0.3
                indicators.append(f"Padrão de bot detectado: {pattern}")
        
        # Verificar se é um User-Agent muito comum (suspeito)
        common_fake_uas = [
            'mozilla/5.0 (windows nt 10.0; win64; x64) applewebkit/537.36',
            'mozilla/5.0 (macintosh; intel mac os x 10_15_7) applewebkit/537.36'
        ]
        
        for fake_ua in common_fake_uas:
            if fake_ua in ua_lower:
                score += 0.2
                indicators.append("User-Agent genérico/falso detectado")
                break
        
        # Analisar estrutura do User-Agent
        try:
            parsed_ua = user_agents.parse(user_agent_string)
            if not parsed_ua.browser.family or not parsed_ua.os.family:
                score += 0.4
                indicators.append("User-Agent malformado")
        except:
            score += 0.5
            indicators.append("Erro ao analisar User-Agent")
        
        return {'score': score, 'indicators': indicators}
    
    def _analyze_headers(self, headers):
        """Analisa headers HTTP para detectar bots"""
        score = 0.0
        indicators = []
        
        # Verificar headers suspeitos
        for header in self.bot_indicators['suspicious_headers']:
            if header.lower() in [h.lower() for h in headers.keys()]:
                score += 0.2
                indicators.append(f"Header suspeito: {header}")
        
        # Verificar ausência de headers comuns
        common_headers = ['accept', 'accept-language', 'accept-encoding']
        missing_headers = [h for h in common_headers if h not in [hk.lower() for hk in headers.keys()]]
        
        if missing_headers:
            score += len(missing_headers) * 0.1
            indicators.append(f"Headers comuns ausentes: {missing_headers}")
        
        # Verificar ordem dos headers (bots frequentemente têm ordem diferente)
        header_order = list(headers.keys())
        if len(header_order) > 3:
            # Headers normalmente começam com Host, User-Agent, Accept...
            expected_start = ['host', 'user-agent', 'accept']
            actual_start = [h.lower() for h in header_order[:3]]
            
            if actual_start != expected_start:
                score += 0.15
                indicators.append("Ordem de headers suspeita")
        
        return {'score': score, 'indicators': indicators}
    
    def _analyze_timing_patterns(self, visitor_data):
        """Analisa padrões de timing para detectar bots"""
        score = 0.0
        indicators = []
        
        # Verificar se temos dados de visitas anteriores
        if visitor_data.get('visit_count', 1) > 1:
            # Calcular intervalo entre visitas
            first_visit = visitor_data.get('first_visit')
            last_visit = visitor_data.get('last_visit')
            
            if first_visit and last_visit:
                time_diff = (last_visit - first_visit).total_seconds()
                visit_count = visitor_data.get('visit_count', 1)
                
                if visit_count > 1:
                    avg_interval = time_diff / (visit_count - 1)
                    
                    # Intervalos muito regulares são suspeitos
                    if avg_interval < self.bot_indicators['timing_thresholds']['min_time_between_requests']:
                        score += 0.4
                        indicators.append("Intervalos entre requests muito curtos")
                    
                    # Muitas visitas em pouco tempo
                    if visit_count > 10 and time_diff < 300:  # 10 visitas em 5 minutos
                        score += 0.3
                        indicators.append("Muitas visitas em pouco tempo")
        
        return {'score': score, 'indicators': indicators}
    
    def _analyze_fingerprint(self, request_data):
        """Analisa fingerprinting para detectar bots"""
        score = 0.0
        indicators = []
        
        # Verificar se temos dados de fingerprinting
        fingerprint_data = request_data.get('fingerprint', {})
        
        # Verificar resolução de tela suspeita
        screen_resolution = fingerprint_data.get('screen_resolution')
        if screen_resolution:
            # Resoluções muito comuns ou estranhas podem indicar bot
            suspicious_resolutions = ['1920x1080', '1366x768', '1024x768', '800x600']
            if screen_resolution in suspicious_resolutions:
                score += 0.1
                indicators.append(f"Resolução suspeita: {screen_resolution}")
        
        # Verificar timezone
        timezone = fingerprint_data.get('timezone')
        if timezone and timezone == 'UTC':
            score += 0.2
            indicators.append("Timezone UTC (comum em bots)")
        
        # Verificar se JavaScript está desabilitado
        if not fingerprint_data.get('javascript_enabled', True):
            score += 0.3
            indicators.append("JavaScript desabilitado")
        
        # Verificar plugins ausentes
        plugins = fingerprint_data.get('plugins', [])
        if len(plugins) == 0:
            score += 0.2
            indicators.append("Nenhum plugin detectado")
        
        return {'score': score, 'indicators': indicators}
    
    def _calculate_confidence(self, bot_score, indicator_count):
        """Calcula a confiança da detecção"""
        base_confidence = min(bot_score, 0.9)
        indicator_bonus = min(indicator_count * 0.05, 0.1)
        return min(base_confidence + indicator_bonus, 1.0)
    
    def _get_risk_level(self, bot_score):
        """Determina o nível de risco baseado no score"""
        if bot_score >= 0.8:
            return 'critical'
        elif bot_score >= 0.6:
            return 'high'
        elif bot_score >= 0.4:
            return 'medium'
        else:
            return 'low'
    
    def should_block_request(self, analysis_result, protection_level='medium'):
        """Determina se um request deve ser bloqueado baseado na análise"""
        thresholds = {
            'low': 0.9,
            'medium': 0.7,
            'high': 0.5
        }
        
        threshold = thresholds.get(protection_level, 0.7)
        return analysis_result['bot_score'] >= threshold
    
    def generate_challenge(self, challenge_type='javascript'):
        """Gera um desafio para verificar se é humano"""
        challenges = {
            'javascript': self._generate_js_challenge(),
            'captcha': self._generate_simple_captcha(),
            'timing': self._generate_timing_challenge()
        }
        
        return challenges.get(challenge_type, challenges['javascript'])
    
    def _generate_js_challenge(self):
        """Gera um desafio JavaScript simples"""
        import random
        
        num1 = random.randint(1, 10)
        num2 = random.randint(1, 10)
        result = num1 + num2
        
        challenge_code = f"""
        <script>
            function verifyHuman() {{
                var answer = {num1} + {num2};
                var userAnswer = prompt("Para continuar, resolva: {num1} + {num2} = ?");
                if (parseInt(userAnswer) === answer) {{
                    document.getElementById('challenge-form').style.display = 'none';
                    document.getElementById('content').style.display = 'block';
                    return true;
                }} else {{
                    alert("Resposta incorreta. Tente novamente.");
                    return false;
                }}
            }}
            
            // Verificar se JavaScript está habilitado
            document.addEventListener('DOMContentLoaded', function() {{
                document.getElementById('js-disabled').style.display = 'none';
                document.getElementById('challenge-form').style.display = 'block';
            }});
        </script>
        """
        
        return {
            'type': 'javascript',
            'code': challenge_code,
            'expected_result': result,
            'description': f"Resolva: {num1} + {num2} = ?"
        }
    
    def _generate_simple_captcha(self):
        """Gera um CAPTCHA simples baseado em texto"""
        import random
        import string
        
        captcha_text = ''.join(random.choices(string.ascii_uppercase + string.digits, k=5))
        
        return {
            'type': 'captcha',
            'text': captcha_text,
            'description': f"Digite o código: {captcha_text}"
        }
    
    def _generate_timing_challenge(self):
        """Gera um desafio baseado em timing"""
        return {
            'type': 'timing',
            'min_wait_time': 3,  # segundos
            'description': "Aguarde 3 segundos antes de continuar"
        }

# Instâncias globais dos serviços
anti_redpage_service = AntiRedpageService()
anti_bot_service = AntiBotService()

