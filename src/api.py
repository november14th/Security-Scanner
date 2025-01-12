import requests
import json
import os
from openai import OpenAI
import google.generativeai as genai
from dotenv import load_dotenv
load_dotenv()

api_key = os.getenv("VIRUSTOTAL_API_KEY")
urlscan_api_key = os.getenv("URLSCAN_API_KEY")

client = OpenAI(
  api_key=os.getenv("OPENAI_API_KEY"))

genai.configure(api_key=os.getenv("GEMINI_API_KEY"))





def generate_description_openai(json_data):
    prompt = f"Explain the following JSON data in a way that is easy to understand for both technical and non-technical users:\n\n{json.dumps(json_data, indent=2)}\n\nExplanation:"
    completion = client.chat.completions.create(
        model=genai.GenerativeModel("gemini-1.5-flash"), 
        messages=[
            {"role": "system", "content": "You are a helpful assistant that explains JSON data in simple terms."},
            {"role": "user", "content": prompt}
        ],
        max_tokens=300,  # Adjust based on the desired length of the explanation
        temperature=0.7,  # Adjust for creativity vs. accuracy
    )
    return completion.choices[0].message.content

def generate_description_gemini(json_data):
    model = genai.GenerativeModel("gemini-1.5-flash")
    
    response = model.generate_content(f"""You are a cybersecurity expert skilled at interpreting and explaining scan results for both technical and non-technical audiences. Analyze the following scan results and provide:

    A technical summary with key findings, including detected vulnerabilities, risk levels, affected systems, and potential impacts. Use precise language suitable for IT professionals or security analysts.
    A non-technical explanation that simplifies the findings into clear, jargon-free language for stakeholders without a technical background. Highlight the risks, their potential consequences, and actionable next steps.
    Recommendations for remediation or further investigation tailored to both audiences, ensuring they are actionable and understandable. 
    Here is the input: \n\n{json.dumps(json_data, indent=2)}\n\n
    Please do not provide recommendations. Just explain the result.""")

    return (response.text)


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

def get_file_info(filehash):


    url = f"https://www.virustotal.com/api/v3/files/{filehash}"
    headers = {
        "accept": "application/json",
        "x-apikey": api_key,
        "content-type": "application/x-www-form-urlencoded"
    }

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

def urlscanresult(urlscan_api_key, result_id):
    headers = {'API-Key':urlscan_api_key,'Content-Type':'application/json'}
    
    url = f"https://urlscan.io/api/v1/result/{result_id}"
    
    
    response = requests.get(url=url,headers=headers)
    
    return(response.json())



