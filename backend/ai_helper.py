import os
import json
from dotenv import load_dotenv

# Try importing Gemini
try:
    from google import genai
    from google.genai import types
    GENAI_AVAILABLE = True
except ImportError:
    GENAI_AVAILABLE = False

load_dotenv()

# 🔑 CONFIGURATION
GEMINI_API_KEY = os.getenv("GEMINI_API_KEY")

def get_offline_report(target, scan_results):
    """Fallback if AI is down."""
    criticals = [r for r in scan_results if "CRITICAL" in str(r.get('risk_level')).upper()]
    highs = [r for r in scan_results if "HIGH" in str(r.get('risk_level', '')).upper() or "High" in str(r.get('risk_level', ''))]
    
    report = f"""### 🛡️ Security Summary for {target} (Offline Mode)
Detected **{len(criticals)}** critical issues and **{len(highs)}** high-risk vulnerabilities.

**Top Recommendations:**
1. Immediately patch or disable services flagged as CRITICAL.
2. Review exposed ports ({', '.join([str(r['port']) for r in scan_results[:3]])}).
3. Ensure all service versions are up to date.
"""
    return {"security_score": max(0, 100 - (len(criticals) * 20) - (len(highs) * 10)), "ai_report": report}

def get_ai_analysis(target, scan_results):
    """Generates the main security report."""
    if not GENAI_AVAILABLE or not GEMINI_API_KEY:
        return get_offline_report(target, scan_results)

    try:
        client = genai.Client(api_key=GEMINI_API_KEY)
        # Sort and limit to send most relevant data
        filtered_results = sorted(scan_results, key=lambda x: str(x.get('risk_level')), reverse=True)[:15]
        
        prompt = f"""As a Senior Security Analyst, analyze these VAPT results for target '{target}'.
        Findings: {json.dumps(filtered_results)}
        
        Provide a concise report in Markdown format with:
        1. Executive Summary
        2. Top Threats & Potential Impact
        3. Strategic Remediation Roadmap
        
        Keep it professional and technical."""

        response = client.models.generate_content(model="gemini-2.0-flash", contents=prompt)
        
        # Estimate a score based on results
        criticals = len([r for r in scan_results if "CRITICAL" in str(r.get('risk_level')).upper()])
        score = max(0, 100 - (criticals * 25))

        return {
            "security_score": score,
            "ai_report": response.text
        }
    except Exception as e:
        print(f"⚠️ AI Analysis Failed: {e}")
        return get_offline_report(target, scan_results)

def get_chat_response(message, scan_context):
    """Simple conversational assistant."""
    if not GENAI_AVAILABLE or not GEMINI_API_KEY:
        return "🤖 AI Assistant (Offline): I am unable to connect to Gemini. Please check your API key."

    try:
        client = genai.Client(api_key=GEMINI_API_KEY)
        target = scan_context.get('target', 'unknown')
        results = scan_context.get('results', [])
        
        results_summary = [f"Port {r.get('port')}: {r.get('service')} ({r.get('risk_level')})" for r in results[:10]]
        
        prompt = f"""You are VaptAI, a helpful security assistant. 
        Context: The user is scanning {target}. 
        Found vulnerabilities: {results_summary}.
        
        User Question: {message}
        
        Answer professionally and suggest remediation if they ask about vulnerabilities."""

        response = client.models.generate_content(model="gemini-2.0-flash", contents=prompt)
        return response.text
    except Exception as e:
        if "429" in str(e):
            return "🤖 AI Assistant: My quota is exceeded. Please try again in a minute."
        return f"⚠️ Chat Error: {e}"

def get_ai_patch(vuln):
    """Simple AI patch generator."""
    if not GENAI_AVAILABLE or not GEMINI_API_KEY:
        return "Offline: Suggesting manual update of service to latest stable version."
    try:
        client = genai.Client(api_key=GEMINI_API_KEY)
        prompt = f"Provide a technical code-level remediation patch or configuration fix for this vulnerability: {json.dumps(vuln)}. Include 'Fix' and 'Rationale'."
        response = client.models.generate_content(model="gemini-2.0-flash", contents=prompt)
        return response.text
    except:
        return "Error generating AI patch. Refer to official vendor security bulletins."
