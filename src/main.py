import streamlit as st
import os
from api import *
import hashlib
import base64
import time




# Service Selection
scan_option = st.selectbox("Select a service to scan URLs", ["VirusTotal", "urlscan.io"])

# Tabs for options

if scan_option == "VirusTotal":
    
    st.image("assets/virustotal-svgrepo-com.svg", width=30)
    
    st.markdown("""Analyse suspicious files, domains, IPs and URLs to detect malware and other breaches, automatically share them with the security community.""")
    tab1, tab2 = st.tabs(["FILE", "URL"])
    with tab1:
        st.subheader("File Analysis")
        uploaded_file = st.file_uploader("Upload a file to analyze", type=["jpeg", "png", "exe", "dll", "pdf", "docx", "xlsx", "zip", "rar"])
        
        
        api_key = st.text_input("Enter your VirusTotal API key", type="password")
        if not api_key:
            api_key = "4d6b3feadc43f4fee57105b967eec3eef71a2ee666ca62db779f2d545d767ce8"
        st.sidebar.subheader("Check API Quotas")
        if st.sidebar.button("Fetch Quotas"):
            if api_key:
                url = "https://urlscan.io/user/quotas/"
                headers = {"Content-Type": "application/json", "API-Key": api_key}
                
                try:
                    response = requests.get(url, headers=headers)
                    if response.status_code == 200:
                        quotas = response.json()
                        st.sidebar.subheader("Quota Information")
                        for category, data in quotas.items():
                            if isinstance(data, dict):  # Handle nested dictionaries
                                st.sidebar.markdown(f"### {category.capitalize()}")
                                for subcategory, details in data.items():
                                    if isinstance(details, dict):
                                        st.sidebar.markdown(f"#### {subcategory.capitalize()}")
                                        for key, value in details.items():
                                            st.sidebar.write(f"{key.capitalize()}: {value}")
                                    else:
                                        st.sidebar.write(f"{subcategory.capitalize()}: {details}")
                            else:
                                st.sidebar.write(f"{category.capitalize()}: {data}")
                    else:
                        st.sidebar.error(f"Failed to fetch quotas. Status code: {response.status_code}")
                        st.sidebar.text(response.text)
                except Exception as e:
                    st.sidebar.error("An error occurred while fetching quotas.")
                    st.sidebar.exception(e)
            else:
                st.sidebar.warning("Please enter your API key.")
        if uploaded_file and api_key:
            if st.button("Scan File"):
                # Save the uploaded file temporarily
                file_path = os.path.join("temp", uploaded_file.name)
                uploaded_file_hash = hashlib.md5(uploaded_file.read()).hexdigest()
                
               
                response = get_file_info(uploaded_file_hash)
                 
                if response.status_code == 200:
                    st.success("File uploaded and scanned successfully!")
                    st.subheader("Original Scan Results")
                    ##st.json(response.json())
                    with st.container(height=400): 
                        st.json(response.json())

                    
                    with st.spinner("Generating explanation..."):
                        description = generate_description_gemini(response.json())
                        st.subheader("Human-Readable Explanation")
                        st.write(description)
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
                    
                    st.subheader("Original Scan Results")
                    with st.container(height=400): 
                        st.json(report_response.json())
                    
                    if st.button("Generate Human-Readable Explanation"):

                        with st.spinner("Generating explanation..."):
                            description = generate_description_gemini(report_response.json())
                            st.subheader("Human-Readable Explanation")
                            st.write(description)
                

                else:
                    st.error(f"Error: {response.status_code}")
                    st.write(response.text)

            
            else:
                st.error("Please enter a valid URL.")
    

else:
    
    # Header Logo and Title (URLSCAN)
    st.image("assets/urlscan-logo-png_seeklogo-428511.png", width=30)
    st.markdown("""A sandbox for the web""")
    st.subheader("URL Analysis")
    url = st.text_input("Enter a URL to scan")
    api_key = st.text_input("Enter your URLScan API key", type="password", key= "url_api_key")
    if not api_key:
            urlscan_api_key = "e8b04ba3-1253-48f4-8599-2c9f2a6b1183"
    # st.sidebar.subheader("Check API Quotas")
    # if st.sidebar.button("Fetch Quotas"):
    #     if api_key:
    #         url = "https://urlscan.io/user/quotas/"
    #         headers = {"Content-Type": "application/json", "API-Key": api_key}
            
    #         try:
    #             response = requests.get(url, headers=headers)
    #             if response.status_code == 200:
    #                 quotas = response.json()
    #                 st.sidebar.subheader("Quota Information")
    #                 for category, data in quotas.items():
    #                     if isinstance(data, dict):  # Handle nested dictionaries
    #                         st.sidebar.markdown(f"### {category.capitalize()}")
    #                         for subcategory, details in data.items():
    #                             if isinstance(details, dict):
    #                                 st.sidebar.markdown(f"#### {subcategory.capitalize()}")
    #                                 for key, value in details.items():
    #                                     st.sidebar.write(f"{key.capitalize()}: {value}")
    #                             else:
    #                                 st.sidebar.write(f"{subcategory.capitalize()}: {details}")
    #                     else:
    #                         st.sidebar.write(f"{category.capitalize()}: {data}")
    #             else:
    #                 st.sidebar.error(f"Failed to fetch quotas. Status code: {response.status_code}")
    #                 st.sidebar.text(response.text)
    #         except Exception as e:
    #             st.sidebar.error("An error occurred while fetching quotas.")
    #             st.sidebar.exception(e)
    #     else:
    #         st.sidebar.warning("Please enter your API key.")
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
                st.subheader("Original Scan Results")
                with st.container(height=400): 
                    st.json(result)
                if st.button("Generate Human-Readable Explanation"):

                    with st.spinner("Generating explanation..."):
                            description = generate_description_gemini(result)
                            print(description)
                            st.subheader("Human-Readable Explanation")
                            st.write(description)
                # st.components.v1.iframe(link, width=800, height=600)
                # 
                # st.spinner("Polling for scan results...")
                
                
                # st.markdown(f"🔗 Click [here]({link}) to view the complete result.", unsafe_allow_html=True)
                
                # if st.button("Generate Human-Readable Explanation"):
                #     print("hello")
                #     description = generate_description_gemini(result)
                #     print("here")
                #     st.subheader("Human-Readable Explanation")
                #     st.write(description)
        
            # st.json(response)

            else:
                st.error(f"Error: {response.status_code}")
                st.write(response.text)

        else:
            st.error("Please enter a valid URL.")


# Footer Icon
st.markdown("""---""")
st.markdown("Made with Streamlit")
