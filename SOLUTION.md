## **Design Decisions**

1. UI Design: A simple, intuitive interface for uploading files and entering URLs for scans. Designed for accessibility by both technical and non-technical users.

2. API Integrations:
- VirusTotal: Used for file and hash-based scans.
- urlscan.io: Used for URL scans.

3. File Security:
- Hash calculation performed locally before uploading files.
- Files are uploaded only with user consent.
- Temporary files are deleted immediately after upload.


4. Result Presentation: Results are shown in JSON format and enhanced for clarity using AI.

## **Setting up the Project**

- **Python**: Ensure Python 3.8 or later is installed on your system.
- **Pip**: Ensure pip is installed for managing Python packages.
- **Docker**: Install Docker if you plan to run the project inside a container.
- **Environment File**: A .env file should exist in the root directory containing any required environment variables (e.g., API keys).

## Setup Instructions
### 1. Clone the repository
```bash
git clone <repository-url>
cd <repository-folder>
```

### 2. Set Up a Virtual Environment
```bash
python3 -m venv venv
source venv/bin/activate  # On macOS/Linux
venv\Scripts\activate     # On Windows
```

### 3. Install Dependencies
```bash
pip install -r requirements.txt
```

## Running the Application
### 1. Run the Streamlit App
```bash
streamlit run src/main.py
```

### 2. Access the App
After running the command, Streamlit will provide a local URL (e.g., http://localhost:8501). Open this URL in your web browser to interact with the app.

#### Using Docker
##### 1. Build the Docker Image
docker build -t security-scanner .

##### 2. Run the Docker Container
docker run -p 8501:8501 streamlit-app

##### 3. Access the App
Open http://localhost:8501 in your web browser to use the app.

## Environment Variables
The project uses a .env file to store sensitive data such as API keys. Add the following variables to the .env file:


URLSCAN_API_KEY=<your_api_key_here>
VIRUSTOTAL_API_KEY=<your_api_key_here>
OPENAI_API_KEY=<your_api_key_here>
GEMINI_API_KEY=<your_api_key_here>



