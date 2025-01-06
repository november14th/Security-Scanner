import requests
import json
api_key = "4d6b3feadc43f4fee57105b967eec3eef71a2ee666ca62db779f2d545d767ce8"
urlscan_api_key = "25bb2a6d-afe4-4cb4-9c0c-19b452559701"

def small_size_files(files): 
    url = "https://www.virustotal.com/api/v3/files"

    headers = {
        "accept": "application/json",
        "content-type": "multipart/form-data",
        "x-apikey": api_key
    }

    response = requests.post(url, headers=headers, files=files)

    return(response)

def large_size_files():


    url = "https://www.virustotal.com/api/v3/files/upload_url"
    headers = {"accept": "application/json"}

    response = requests.get(url, headers=headers)
    

    return(response)

def scan_url_virustotal(url, api_key):

    url = "https://www.virustotal.com/api/v3/urls"

    payload = { "url": url }
    headers = {
        "accept": "application/json",
        "x-apikey": api_key,
        "content-type": "application/x-www-form-urlencoded"
    }

    response = requests.post(url, data=payload, headers=headers)

    return(response)

def get_url_report(id, api_key):
    print(f"hello,{id}")
    url = f"https://www.virustotal.com/api/v3/urls/{id}"

    headers = {
        "accept": "application/json",
        "x-apikey": api_key,
        "content-type": "application/x-www-form-urlencoded"
    }
    response = requests.get(url=url, headers = headers)
    
    return(response)

def urlscanio(urlscan_api_key, domain):
    
    headers = {'API-Key':urlscan_api_key,'Content-Type':'application/json'}
    
    url = "https://urlscan.io/api/v1/scan/"
    
    data = {"url": domain, "visibility": "public"}
    response = requests.post(url=url,headers=headers, data=json.dumps(data))
    
    return(response.json())

    



