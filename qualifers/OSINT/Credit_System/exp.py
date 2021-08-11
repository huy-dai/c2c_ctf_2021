import requests
import os

os.chdir("./OSINT/Credit_System")

keys = []
with open("./keys.txt","r") as f:
    for line in f:
        keys.append(line.strip())

for key in keys:
    url = "https://pastebin.com/"+key
    print(url)
    r = requests.get(url)
    if "This page is no longer available" not in r.text:
        print(r.text)
