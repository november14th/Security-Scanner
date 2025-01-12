import requests
import json
import os
import time
import aiohttp
import asyncio
from openai import OpenAI
import google.generativeai as genai
from dotenv import load_dotenv
load_dotenv()

virustotal_api_key = os.getenv("VIRUSTOTAL_API_KEY")

urlscan_api_key = os.getenv("URLSCAN_API_KEY")

client = OpenAI(
  api_key=os.getenv("OPENAI_API_KEY"))

genai.configure(api_key=os.getenv(""))

def generate_description_openai(json_data):
    prompt = f"Explain the following JSON data in a way that is easy to understand for both technical and non-technical users:\n\n{json.dumps(json_data, indent=2)}\n\nExplanation:"
    completion = client.chat.completions.create(
        model=genai.GenerativeModel("gemini-1.5-flash"), 
        messages=[
            {"role": "system", "content": "You are a helpful assistant that explains JSON data in simple terms."},
            {"role": "user", "content": prompt}
        ],
        max_tokens=300,  
        temperature=0.7,  
    )
    return completion.choices[0].message.content

def generate_description_gemini(json_data):
    model = genai.GenerativeModel("gemini-1.5-flash")
    

    response = model.generate_content(f"""You are a cybersecurity analyst with expertise in analyzing scan results and generating detailed reports. Your task is to analyze the following JSON data from a URL or file scan and provide a comprehensive report. Give h2 to title and h3 to below mentioned headings. The report should include the following sections:

    1. **Overview**:
    - Summarize the scan results in 2-3 sentences.
    - Highlight the most critical findings (e.g., security risks, performance issues).

    2. **Threat Indicators**:
    - List any identified threats (e.g., malware, phishing, vulnerabilities).
    - Include severity levels (e.g., high, medium, low) and descriptions.

    3. **Behavioral Analysis**:
    - Describe any observed behaviors (e.g., network activity, file modifications).
    - Highlight suspicious or malicious activities.

    4. **Technical Details**:
    - Provide technical insights into the findings (e.g., specific vulnerabilities, attack vectors).
    - Include relevant metadata (e.g., IP addresses, domains, file hashes).

    5. **Recommendations**:
    - Suggest actionable steps to mitigate identified risks.
    - Provide best practices for improving security.

    6. **Conclusion**:
    - Summarize the overall risk level (e.g., low, moderate, high).
    - Provide a final assessment of the scan results.

    Here is the JSON data to analyze:{json.dumps(json_data, indent=2)}

    Generate the report in Markdown format with clear headings and bullet points for readability.""")
    return(response.text)


def small_size_files(files): 

    url = "https://www.virustotal.com/api/v3/files"
    headers = {
        "accept": "application/json",
        "content-type": "multipart/form-data",
        "x-apikey": virustotal_api_key
    }
    response = requests.post(url, headers=headers, files=files)
    return(response)

def large_size_files():

    url = "https://www.virustotal.com/api/v3/files/upload_url"
    headers = {"accept": "application/json"}
    response = requests.get(url, headers=headers)
    return(response)

def get_file_info(filehash):


    url = f"https://www.virustotal.com/api/v3/files/{filehash}"
    headers = {
        "accept": "application/json",
        "x-apikey": virustotal_api_key,
        "content-type": "application/x-www-form-urlencoded"
    }

    response = requests.get(url, headers=headers)

    return(response)

def scan_url_virustotal(url, virustotal_api_key):

    url = "https://www.virustotal.com/api/v3/urls"

    payload = { "url": url }
    headers = {
        "accept": "application/json",
        "x-apikey": virustotal_api_key,
        "content-type": "application/x-www-form-urlencoded"
    }

    response = requests.post(url, data=payload, headers=headers)

    return(response)

def get_url_report(id, virustotal_api_key):
    
    
    url = f"https://www.virustotal.com/api/v3/urls/{id}"

    headers = {
        "accept": "application/json",
        "x-apikey": virustotal_api_key,
        "content-type": "application/x-www-form-urlencoded"
    }
    response = requests.get(url=url, headers = headers)
    
    return(response)

def urlscanio(urlscan_api_key, domain):
    
    headers = {'API-Key':urlscan_api_key,'Content-Type':'application/json'}
    
    url = "https://urlscan.io/api/v1/scan/"
    
    data = {"url": domain, "visibility": "public"}
    headers = {'API-Key': urlscan_api_key, 'Content-Type': 'application/json'}
    response = requests.post(url=url,headers=headers, data=json.dumps(data))
    return(response.json())



async def urlscanresult(urlscan_api_key, result_id):
    headers = {'API-Key':urlscan_api_key,'Content-Type':'application/json'}
    # print("uuid", result_id)
    url = f"https://urlscan.io/api/v1/result/{result_id}"
    # response = requests.get(url=url,headers=headers)
    # print("response", response)
    # return(response.json())

    async with aiohttp.ClientSession() as session:
        async with session.get(url,headers=headers) as response:
            return await response.json()



# def virustotal_api_usage(id, virustotal_api_key):
#     url = f"https://www.virustotal.com/api/v3/users/{virustotal_api_key}"
#     headers = {
#         "accept": "application/json",
#         "x-apikey": virustotal_api_key
#     }

#     response = requests.get(url, headers=headers)

#     print(response.text)

# async def urlscanio(urlscan_api_key, domain):
#     headers = {'API-Key':urlscan_api_key,'Content-Type':'application/json'}
    
#     url = "https://urlscan.io/api/v1/scan/"
    
#     data = {"url": domain, "visibility": "public"}
#     headers = {'API-Key': urlscan_api_key, 'Content-Type': 'application/json'}
#     # response = requests.post(url=url,headers=headers, data=json.dumps(data))
#     # return(response.json())

#     async with aiohttp.ClientSession() as session:
#         async with session.post(url,headers=headers, json=data) as response:
#             return await response.json()

async def urlscan_logic(urlscan_api_key, url):
    response = await urlscanio(urlscan_api_key, url)
    print("response", response)
    if response['message'] == 'Submission successful' and response.get("uuid"):
        link = response["result"]
        uuid = response["uuid"]
        
        # time.sleep(10)
        result = urlscanresult(urlscan_api_key, uuid)
        return result
    else:
        return {"error": "Scan failed", "details": response}