# PhishGuard AI 🛡️🤖

An AI-powered Cyber Threat Intelligence and URL analysis tool. Built as a practical portfolio project for a SOC L1 Analyst role, integrating **VirusTotal Threat Intelligence** with **Google Gemini AI**.

## 🚀 Features
- **Real-time Scanning**: Analyzes suspicious URLs against 70+ antivirus engines using the VirusTotal API v3.
- **AI Security Analyst**: Gemini AI interprets raw threat data and provides professional, actionable security recommendations.
- **Scan History**: Automatically tracks and stores your recent scan results locally (`scans.json`).
- **Dark Mode UI**: A clean, professional dashboard designed for cybersecurity experts.

## 🛠️ Tech Stack
- **Backend:** Python, Flask, Requests
- **Frontend:** HTML5, CSS3, Jinja2
- **APIs:** VirusTotal API v3, Google Generative AI (Gemini)
- **Environment Management:** python-dotenv

## ⚙️ Setup & Installation
1. **Clone this repository:**
   ```bash
   git clone [https://github.com/22314713/Phish-Guard.git](https://github.com/22314713/Phish-Guard.git)
   cd Phish-Guard
   ```
2. **Install the required dependencies:**
   ```bash
   pip install -r requirements.txt
   ```

3. **Create a .env file in the root directory and add your API keys:**
   ```bash
   VT_API_KEY=your_virustotal_api_key_here
   GEMINI_API_KEY=your_gemini_api_key_here
   ```

4. **Run the application:** 
    ```bash
   python app.py
    ```

5. **Open your browser and go to**
    ```bash
    http://127.0.0.1:5001
    ``` 

**⚠️ Disclaimer**
This tool is created for educational and research purposes only. Do not use the API for scanning highly sensitive or confidential internal URLs, as third-party services (VirusTotal/Google) process the data.
