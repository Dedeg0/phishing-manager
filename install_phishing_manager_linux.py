import os
import subprocess
import sys
import platform
import requests
import json
import time

CONFIG_FILE = "installer_config.json"

def run_command(command, cwd=None, shell=True):
    print(f"Executando: {command}")
    if platform.system() == "Linux":
        process = subprocess.run(["bash", "-c", command], cwd=cwd, capture_output=True, text=True)
    else:
        process = subprocess.run(command, shell=shell, cwd=cwd, capture_output=True, text=True)

    if process.returncode != 0:
        print(f"Erro ao executar comando: {command}")
        print(f"STDOUT: {process.stdout}")
        print(f"STDERR: {process.stderr}")
        sys.exit(1)
    return process.stdout

def check_python():
    print("Verificando instalação do Python...")
    try:
        version = run_command("python3 --version")
        print(f"Python encontrado: {version.strip()}")
        return True
    except:
        print("Python 3.9+ não encontrado. Por favor, instale-o via gerenciador de pacotes.")
        return False

def check_node():
    print("Verificando instalação do Node.js...")
    try:
        version = run_command("node --version")
        print(f"Node.js encontrado: {version.strip()}")
        return True
    except:
        print("Node.js não encontrado. Por favor, instale-o.")
        return False

def check_npm_installed():
    print("Verificando se o npm está instalado...")
    try:
        run_command("npm --version")
        print("npm encontrado.")
        return True
    except:
        print("npm não encontrado.")
        return False

def install_backend():
    print("\n--- Instalando Backend (Flask) ---")
    backend_dir = "phishing-manager"
    if not os.path.exists(backend_dir):
        print(f"Diretório {backend_dir} não encontrado.")
        sys.exit(1)

    print("Criando ambiente virtual...")
    run_command("python3 -m venv venv", cwd=backend_dir)

    activate_cmd = os.path.join("venv", "bin", "activate")
    print("Ativando ambiente virtual e instalando dependências...")
    run_command(f"source {activate_cmd} && pip install -r requirements.txt", cwd=backend_dir)
    print("Backend instalado com sucesso.")

def install_frontend():
    print("\n--- Instalando Frontend (React) ---")
    frontend_dir = "phishing-manager-frontend"
    if not os.path.exists(frontend_dir):
        print(f"Diretório {frontend_dir} não encontrado.")
        sys.exit(1)

    if check_npm_installed():
        print("npm já está instalado.")
    else:
        print("npm não encontrado.")
        sys.exit(1)

    print("Instalando dependências do Node.js...")
    run_command("npm install --legacy-peer-deps", cwd=frontend_dir)
    print("Frontend instalado com sucesso.")

def wait_for_backend(url, timeout=60):
    start_time = time.time()
    while time.time() - start_time < timeout:
        try:
            response = requests.get(url, timeout=5)
            if response.status_code == 200:
                return True
        except requests.exceptions.RequestException:
            pass
        print("Aguardando backend iniciar...")
        time.sleep(2)
    return False

def run_initial_setup(admin_username, admin_password, telegram_bot_token, telegram_admin_chat_id):
    print("\n--- Executando Configuração Inicial ---")
    backend_dir = "phishing-manager"
    backend_cwd = os.path.join(os.getcwd(), backend_dir, "src")
    venv_python = os.path.join(os.getcwd(), backend_dir, "venv", "bin", "python")

    print(f"CWD para backend_process: {backend_cwd}")
    print(f"Python do venv: {venv_python}")

    backend_process = subprocess.Popen(
        [venv_python, "-m", "flask", "run", "--host=127.0.0.1", "--port=5000"],
        cwd=backend_cwd,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        env={**os.environ, "FLASK_APP": "main.py", "FLASK_ENV": "development"}
    )

    print("Aguardando o backend iniciar...")
    if not wait_for_backend("http://127.0.0.1:5000/health", timeout=60):
        print("Backend não respondeu a tempo.")
        backend_process.terminate()
        backend_process.wait()
        sys.exit(1)

    setup_url = "http://127.0.0.1:5000/api/setup"
    setup_data = {
        "admin_username": admin_username,
        "admin_password": admin_password,
        "telegram_bot_token": telegram_bot_token,
        "telegram_admin_chat_id": telegram_admin_chat_id
    }

    try:
        print(f"Enviando dados de configuração para {setup_url}...")
        response = requests.post(setup_url, json=setup_data, timeout=30)
        if response.status_code == 200:
            print("Configuração inicial concluída com sucesso!")
        else:
            print(f"Erro na configuração inicial: {response.status_code} - {response.text}")
            sys.exit(1)
    except requests.exceptions.RequestException as e:
        print(f"Erro ao conectar ao backend para configuração: {e}")
        sys.exit(1)
    finally:
        print("Parando o backend...")
        backend_process.terminate()
        backend_process.wait()

def save_config(config):
    with open(CONFIG_FILE, "w") as f:
        json.dump(config, f, indent=4)

def load_config():
    if os.path.exists(CONFIG_FILE):
        with open(CONFIG_FILE, "r") as f:
            return json.load(f)
    return None

def main():
    if platform.system() != "Linux":
        print("Este instalador é destinado apenas para sistemas Linux.")
        sys.exit(1)

    print("\n--- Instalador do Phishing Manager para Linux ---")

    if not check_python() or not check_node():
        print("Por favor, instale os requisitos e execute o instalador novamente.")
        sys.exit(1)

    saved_config = load_config()
    if saved_config:
        print("Configurações salvas encontradas. Deseja usá-las ou editar? (u/e)")
        choice = input("[u/e]: ").lower()
        if choice == "u":
            admin_username = saved_config["admin_username"]
            admin_password = saved_config["admin_password"]
            telegram_bot_token = saved_config["telegram_bot_token"]
            telegram_admin_chat_id = saved_config["telegram_admin_chat_id"]
            print("Usando configurações salvas.")
        else:
            admin_username = input(f"Digite o nome de usuário para o administrador inicial (ex: dedeg0) [{saved_config['admin_username']}]: ") or saved_config["admin_username"]
            admin_password = input("Digite a senha para o administrador inicial (deixe em branco para manter a anterior): ") or saved_config["admin_password"]
            telegram_bot_token = input(f"Digite o Token do seu Bot do Telegram [{saved_config['telegram_bot_token']}]: ") or saved_config["telegram_bot_token"]
            telegram_admin_chat_id = input(f"Digite o Chat ID do administrador do Telegram [{saved_config['telegram_admin_chat_id']}]: ") or saved_config["telegram_admin_chat_id"]
            save_config({
                "admin_username": admin_username,
                "admin_password": admin_password,
                "telegram_bot_token": telegram_bot_token,
                "telegram_admin_chat_id": telegram_admin_chat_id
            })
    else:
        admin_username = input("Digite o nome de usuário para o administrador inicial (ex: dedeg0): ")
        admin_password = input("Digite a senha para o administrador inicial: ")
        telegram_bot_token = input("Digite o Token do seu Bot do Telegram: ")
        telegram_admin_chat_id = input("Digite o Chat ID do administrador do Telegram: ")
        save_config({
            "admin_username": admin_username,
            "admin_password": admin_password,
            "telegram_bot_token": telegram_bot_token,
            "telegram_admin_chat_id": telegram_admin_chat_id
        })

    install_backend()
    install_frontend()
    run_initial_setup(admin_username, admin_password, telegram_bot_token, telegram_admin_chat_id)

    print("\n--- Instalação Concluída! ---")
    print("Para iniciar o Phishing Manager:")
    print("1. Abra um terminal.")
    print("2. Navegue até o diretório 'phishing-manager':")
    print("   cd phishing-manager")
    print("3. Ative o ambiente virtual e inicie o backend:")
    print("   source venv/bin/activate && flask run")
    print("4. Abra outro terminal.")
    print("5. Navegue até o diretório 'phishing-manager-frontend':")
    print("   cd phishing-manager-frontend")
    print("6. Inicie o frontend:")
    print("   npm start")
    print("7. Acesse: http://localhost:3000")

if __name__ == "__main__":
    main()
