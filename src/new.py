import streamlit as st
from PIL import Image
import os
import mimetypes
from api import *
import hashlib
import base64
import time

# Service Selection
scan_option = st.selectbox("Select a service to scan URLs", ["VirusTotal", "urlscan.io"])

# Tabs for options

if scan_option == "VirusTotal":
    # Header Logo and Title
    st.image("assets/virustotal-svgrepo-com.svg", width=30)
    
    st.markdown("""Analyse suspicious files, domains, IPs and URLs to detect malware and other breaches, automatically share them with the security community.""")
    tab1, tab2 = st.tabs(["FILE", "URL"])
    with tab1:
        st.subheader("File Analysis")
        uploaded_file = st.file_uploader("Upload a file to analyze", type=["jpeg", "png", "exe", "dll", "pdf", "docx", "xlsx", "zip", "rar"])
        
        # print(uploaded_file_hash)
        api_key = st.text_input("Enter your VirusTotal API key", type="password")
        if not api_key:
            api_key = "4d6b3feadc43f4fee57105b967eec3eef71a2ee666ca62db779f2d545d767ce8"
        if uploaded_file and api_key:
            if st.button("Scan File"):
                # Save the uploaded file temporarily
                file_path = os.path.join("temp", uploaded_file.name)
                uploaded_file_hash = hashlib.md5(uploaded_file.read()).hexdigest()
                
                # Create the temp directory if it doesn't exist
                # os.makedirs("temp", exist_ok=True)
                
                # # Write the uploaded file's content to the temp file
                # with open(file_path, "wb") as f:
                #     f.write(uploaded_file.getvalue())
                
                # # Determine the MIME type
                # mime_type, _ = mimetypes.guess_type(file_path)
                # if mime_type is None:
                #     mime_type = "application/octet-stream"

                # # Prepare the files dictionary
                # files = {"file": (uploaded_file.name, open(file_path, "rb"), mime_type)}
                response = get_file_info(uploaded_file_hash)
                 
                if response.status_code == 200:
                    st.success("File uploaded and scanned successfully!")
                    st.json(response.json())
                else:
                    st.error(f"Error: {response.status_code}")
                    st.write(response.text)
                
                

    
    with tab2:
        st.subheader("URL Analysis")
        url = st.text_input("Enter a URL to scan")
        

        url_id = base64.urlsafe_b64encode(url.encode()).decode().strip("=")
        api_key = st.text_input("Enter your VirusTotal API key", type="password", key= "url_api_key")
        if not api_key:
            api_key = "4d6b3feadc43f4fee57105b967eec3eef71a2ee666ca62db779f2d545d767ce8"
        if st.button("Scan URL"):
            if url and api_key:
                st.success(f"Scanning URL: {url} using {scan_option}")
                response = scan_url_virustotal(url, api_key)
                print(response.json())
                if response.status_code == 200:
                    st.success("File uploaded and scanned successfully!")
                    id = response.json()["data"]["id"]
                    print(id)
                    
                    report_response = get_url_report(url_id, api_key)
                    
                    st.json(report_response.json())
                    

                else:
                    st.error(f"Error: {response.status_code}")
                    st.write(response.text)
            else:
                st.error("Please enter a valid URL.")
    

else:
    
    # Header Logo and Title
    st.image("assets/urlscan-logo-png_seeklogo-428511.png", width=30)
    st.markdown("""A sandbox for the web""")
    st.subheader("URL Analysis")
    url = st.text_input("Enter a URL to scan")
    api_key = st.text_input("Enter your URLScan API key", type="password", key= "url_api_key")
    if not api_key:
            urlscan_api_key = "e8b04ba3-1253-48f4-8599-2c9f2a6b1183"
    if st.button("Scan URL"):
        if url and urlscan_api_key:
            st.success(f"Scanning URL: {url} using {scan_option}")
           
            response = urlscanio(urlscan_api_key, url)
            # print(response)
            if response["result"]:
                
                link = response["result"] 
                uuid = response["uuid"]
                time.sleep(10)
                result = urlscanresult(urlscan_api_key, uuid)
                
                st.json(result)
                # st.components.v1.iframe(link, width=800, height=600)
                # 
                # st.spinner("Polling for scan results...")

                st.markdown(f"🔗 Click [here]({link}) to view the complete result.", unsafe_allow_html=True)
                

            
            # st.json(response)

            # else:
            #     st.error(f"Error: {response.status_code}")
            #     st.write(response.text)

        else:
            st.error("Please enter a valid URL.")


# Footer Icon
st.markdown("""---""")
st.markdown("Made with Streamlit")
