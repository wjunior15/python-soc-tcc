import os
import requests
import json

app_host = str(os.getenv("APP_HOST"))
app_port = str(os.getenv("APP_PORT"))
max_iter = int(os.getenv("MAX_ITER"))

url = "http://"+app_host+":"+app_port+"/sum"
print("URL definida:",url)

payload = json.dumps({
  "a": "5",
  "b":"4"
})
headers = {
  'Content-Type': 'application/json'
}

for i in range(max_iter):
    response = requests.request("POST", url, headers=headers, data=payload)
    print(response.text)

print("Seção Encerrada")