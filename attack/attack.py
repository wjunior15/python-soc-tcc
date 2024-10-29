import os
import requests
import json

app_host = str(os.getenv("APP_HOST"))
app_port = str(os.getenv("APP_PORT"))

url = "http://"+app_host+":"+app_port+"/sum"
print("URL definida:",url)

payload = json.dumps({
  "a": "5",
  "b":"4"
})
headers = {
  'Content-Type': 'application/json'
}

while 1:
  try:
    response = requests.request("POST", url, headers=headers, data=payload)
    print(response.text)
  except Exception as e:
    print(e)