import requests
import json

url = "https://5000-if2qyyg00g4evekcif9s6-904eb191.manusvm.computer/api/login"
headers = {"Content-Type": "application/json"}
data = {"username": "test_admin", "password": "admin_password"}

try:
    response = requests.post(url, headers=headers, data=json.dumps(data))
    print(f"Status Code: {response.status_code}")
    print(f"Response Headers: {response.headers}")
    try:
        print(f"Response JSON: {response.json()}")
    except json.JSONDecodeError:
        print(f"Response Text: {response.text}")
except requests.exceptions.RequestException as e:
    print(f"Request failed: {e}")


