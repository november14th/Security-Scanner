import streamlit as st
import os
import mimetypes


from PIL import Image
from api import *
# Page Configuration
## st.set_page_config(page_title="VirusTotal Clone", page_icon=":shield:", layout="centered")

# Header Logo and Title
###st.image("https://upload.wikimedia.org/wikipedia/commons/thumb/6/6e/VirusTotal_logo.svg/1200px-VirusTotal_logo.svg.png", width=200)
st.title("UXCam Security Scanner")

# Subtitle
st.markdown("""
Analyse suspicious files, domains, IPs and URLs to detect malware and other breaches, automatically share them with the security community.
""")

# Tabs for options
tab1, tab2 = st.tabs(["FILE", "URL", ])

with tab1:
    st.subheader("File Analysis")
    uploaded_file = st.file_uploader("Upload a file to analyze", type=["jpeg", "png", "exe", "dll", "pdf", "docx", "xlsx", "zip", "rar", "jpg", "png"])
    api_key = "4d6b3feadc43f4fee57105b967eec3eef71a2ee666ca62db779f2d545d767ce8"


    if uploaded_file and api_key:
        if st.button("Scan File"):
            # Save the uploaded file temporarily
            file_path = os.path.join("temp", uploaded_file.name)
            
            # Create the temp directory if it doesn't exist
            os.makedirs("temp", exist_ok=True)
            
            # Write the uploaded file's content to the temp file
            with open(file_path, "wb") as f:
                f.write(uploaded_file.getvalue())
            
            # Determine the MIME type
            mime_type, _ = mimetypes.guess_type(file_path)
            if mime_type is None:
                mime_type = "application/octet-stream"

            # Prepare the files dictionary
            files = {"file": (uploaded_file.name, open(file_path, "rb"), mime_type)}
            
            # API headers
            headers = {
                "accept": "application/json",
                "x-apikey": api_key
            }
            
            # Send the POST request
            url = "https://www.virustotal.com/api/v3/files"
            response = requests.post(url, files=files, headers=headers)
            
            # Display the response
            if response.status_code == 200:
                st.success("File uploaded and scanned successfully!")
                st.json(response.json())
            else:
                st.error(f"Error: {response.status_code}")
                st.write(response.text)
            
            # Clean up: Remove the temporary file after scanning
            os.remove(file_path)
   

with tab2:
    st.subheader("URL Analysis")
    url = st.text_input("Enter a URL to scan")
    if st.button("Scan URL"):
        if url:
            st.success(f"Scanning URL: {url}")
        else:
            st.error("Please enter a valid URL.")



# Footer Icon
st.markdown("""---""")
st.markdown("Made with Streamlit")
