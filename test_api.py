import os
import requests
from dotenv import load_dotenv

load_dotenv()
API_KEY = os.getenv("VT_API_KEY")

url = "https://www.virustotal.com/api/v3/urls"
headers = {"x-apikey": API_KEY}

# On teste avec une URL connue
data = {"url": "https://www.google.com"}
response = requests.post(url, headers=headers, data=data)

print(response.status_code)
print(response.json())

import time

analysis_id = response.json()["data"]["id"]

# On attend un peu que l'analyse se termine
time.sleep(15)

result_url = f"https://www.virustotal.com/api/v3/analyses/{analysis_id}"
result_response = requests.get(result_url, headers=headers)

print(result_response.status_code)
print(result_response.json())