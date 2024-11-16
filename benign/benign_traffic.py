import os
import requests
import json
import time
import random

app_host = str(os.getenv("APP_HOST"))
app_port = str(os.getenv("APP_PORT"))

url = "http://"+app_host+":"+app_port+"/sum"
print("URL definida:",url)

value_a = str(random.randint(0,10))
payload = json.dumps({
  "a": value_a
})
headers = {
  'Content-Type': 'application/json'
}

while 1:
  try:
    value_a = str(random.randint(0,10))
    payload = json.dumps({
      "a": value_a
    })
    headers = {
      'Content-Type': 'application/json'
    }
        
    response = requests.request("POST", url, headers=headers, data=payload)
    print(response.text)
  except Exception as e:
    print(e)
    
  loop_interval = random.randint(2,10)  
  time.sleep(loop_interval)