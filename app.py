import os
import json
import base64
import re
import requests
import google.generativeai as genai
from flask import Flask, render_template, request
from dotenv import load_dotenv

# Load environment variables from .env file
load_dotenv()

app = Flask(__name__)
VT_API_KEY = os.getenv('VT_API_KEY')
GEMINI_KEY = os.getenv('GEMINI_API_KEY')
SCANS_FILE = 'scans.json'

# Configure Gemini AI settings
genai.configure(api_key=GEMINI_KEY)

# Automatic model selector to prevent 404 API errors
def get_working_model():
    try:
        for m in genai.list_models():
            if 'generateContent' in m.supported_generation_methods:
                return m.name # Automatically pick the first working model
    except Exception as e:
        print(f"Model listing error: {e}")
    return 'gemini-1.5-flash' # Fallback model

# Initialize the generative model dynamically
ai_model = genai.GenerativeModel(get_working_model())

def get_ai_analysis(url, stats):
    """
    Analyzes cybersecurity data using Gemini AI to provide a professional report.
    """
    prompt = f"""
    Act as a Senior Cybersecurity Analyst. Analyze the following data and provide a brief English report:
    URL: {url}
    Analysis: {stats['malicious']} malicious, {stats['suspicious']} suspicious, {stats['harmless']} clean detections.
    
    Format:
    - Risk Score: [Low/Medium/High/Critical]
    - Summary: (1-2 sentences technical observation)
    - Recommendation: (Clear advice for the user)
    Keep it professional, concise, and in English.
    """
    try:
        response = ai_model.generate_content(prompt)
        text = response.text
        
        # Convert Markdown formatting to styled HTML tags
        text = re.sub(r'\*\*(.*?)\*\*', r'<strong style="color: var(--accent);">\1</strong>', text)
        text = re.sub(r'`(.*?)`', r'<code style="background: rgba(0,0,0,0.3); padding: 2px 6px; border-radius: 4px; color: #ff7b72;">\1</code>', text)
        text = text.replace('\n', '<br>')
        
        return text
    except Exception as e:
        return f"AI Analysis currently unavailable: {str(e)}"

def load_recent_scans():
    """Loads recent scan history from the local JSON file."""
    if os.path.exists(SCANS_FILE):
        try:
            with open(SCANS_FILE, 'r') as f: return json.load(f)
        except: return []
    return []

def save_scan(url, malicious_count):
    """Saves new scan results to history and limits the list to the last 5 entries."""
    scans = load_recent_scans()
    scans = [s for s in scans if s['url'] != url]
    scans.insert(0, {"url": url, "count": malicious_count})
    with open(SCANS_FILE, 'w') as f: json.dump(scans[:5], f)

def scan_url_with_vt(url):
    """Performs URL analysis via the VirusTotal v3 API using Base64 encoding."""
    url_id = base64.urlsafe_b64encode(url.encode()).decode().strip("=")
    api_url = f"https://www.virustotal.com/api/v3/urls/{url_id}"
    headers = {"accept": "application/json", "x-apikey": VT_API_KEY}
    
    try:
        res = requests.get(api_url, headers=headers)
        if res.status_code == 200: return {"status": "success", "data": res.json()}
        return {"status": "error", "message": f"VT API Error: {res.status_code}"}
    except Exception as e: return {"status": "error", "message": str(e)}

@app.route('/')
def index():
    return render_template('index.html', recent_scans=load_recent_scans())

@app.route('/analyze', methods=['POST'])
def analyze():
    target_url = request.form.get('url', '')
    recent = load_recent_scans()
    
    # Ensure the URL has a valid protocol prefix
    if not target_url.startswith(('http://', 'https://')): 
        target_url = 'https://' + target_url

    res = scan_url_with_vt(target_url)
    
    if res['status'] == 'success':
        stats = res['data']['data']['attributes']['last_analysis_stats']
        risk_score = stats['malicious'] + stats['suspicious']
        
        # Fetch the AI-generated security insight
        ai_comment = get_ai_analysis(target_url, stats)
        
        save_scan(target_url, stats['malicious'])
        return render_template('index.html', target_url=target_url, stats=stats, 
                               risk_score=risk_score, ai_comment=ai_comment, 
                               total_engines=sum(stats.values()), recent_scans=load_recent_scans())
    
    return render_template('index.html', error=res['message'], recent_scans=recent)

if __name__ == '__main__':
    app.run(debug=True, port=5001)