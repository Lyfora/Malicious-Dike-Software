import requests
import os

API_URL = "https://api.github.com/repos/bormaa/Benign-NET/contents/sourceforgeexe"
DOWNLOAD_LIMIT = 25

response = requests.get(API_URL)
data = response.json()

os.makedirs("softonicnet", exist_ok=True)

for i, item in enumerate(data[:DOWNLOAD_LIMIT]):
    file_url = item['download_url']
    filename = item['name']
    r = requests.get(file_url)
    with open(f"netexe_100/{filename}", "wb") as f:
        f.write(r.content)

print(f"Downloaded {min(len(data), DOWNLOAD_LIMIT)} files to netexe_100/")
