import os
import json

# Try importing the new library, handle error if missing
try:
    from google import genai
    from google.genai import types
    GENAI_AVAILABLE = True
except ImportError:
    GENAI_AVAILABLE = False

# 🔑 CONFIGURATION
# Replace with your actual key if not using env variables, but env var is safer
GEMINI_API_KEY = os.getenv("GEMINI_API_KEY", "AIzaSyDdaJxnp3eKd6o93DK1sb51VqfjXIvvl2s")

def get_offline_report(target, scan_results):
    """
    Fallback logic to generate a report if AI is unavailable.
    Ensures the user always gets a professional result.
    """
    criticals = [r for r in scan_results if "CRITICAL" in str(r.get('risk_level')).upper()]
    highs = [r for r in scan_results if "HIGH" in str(r.get('risk_level')).upper()]
    
    score = max(0, 100 - (len(criticals) * 20) - (len(highs) * 10))
    
    report = f"""### 🛡️ Executive Summary (Offline Mode)
The security posture for **{target}** has been analyzed using local expert logic. 
Detected {len(criticals)} critical and {len(highs)} high-risk vulnerabilities.

### 🚨 Top Critical Risks
1. {criticals[0]['service'] if criticals else 'Insecure Services'}: High risk of exploitation.
2. {highs[0]['service'] if highs else 'Open Ports'}: Potential entry point for attackers.

### ✨ AI Remediation Roadmap
- **Immediate**: Close all unused ports and update service versions.
- **Network**: Implement a strict Firewall/WAF policy.
- **Web**: Apply missing security headers (CSP, HSTS).

### 🔮 Attack Surface Insights
The attack surface is {'vulnerable' if criticals else 'moderately exposed'}. Immediate patching is recommended.
"""
    return {"security_score": score, "ai_report": report}

def get_ai_analysis(target, scan_results):
    """
    Sends scan data to Gemini. Falls back to Offline Mode if quota is hit.
    """
    if not GEMINI_API_KEY:
        return get_offline_report(target, scan_results)

    try:
        client = genai.Client(api_key=GEMINI_API_KEY)
        
        # Token limit optimization
        filtered_results = [r for r in scan_results if "CRITICAL" in str(r.get('risk_level')).upper() or "HIGH" in str(r.get('risk_level')).upper()][:15]
        if not filtered_results: filtered_results = scan_results[:10]

        prompt = f"Analyze these VAPT results for {target} and return JSON with 'security_score' and 'ai_report' (Markdown): {json.dumps(filtered_results)}"

        response = client.models.generate_content(
            model="gemini-2.0-flash",
            contents=prompt,
            config=types.GenerateContentConfig(temperature=0.7, response_mime_type="application/json")
        )
        
        result_data = json.loads(response.text)
        return {
            "security_score": result_data.get("security_score", 50),
            "ai_report": result_data.get("ai_report", "No report generated.")
        }

    except Exception as e:
        print(f"⚠️ AI API Failed (Quota/Network). Switching to Offline Mode. Error: {e}")
        # Automatically fallback to offline mode so the UI doesn't break
        return get_offline_report(target, scan_results)

def get_ai_patch(vulnerability_details):
    """
    Generates a code-level remediation patch for a specific vulnerability.
    """
    if not GEMINI_API_KEY:
        return "⚠️ AI API Key missing. Please provide an API key to generate a patch."

    try:
        client = genai.Client(api_key=GEMINI_API_KEY)
        prompt = f"""Generate a specific code-level remediation patch for this vulnerability:
        {json.dumps(vulnerability_details)}
        
        Return the response in a clean Markdown format including:
        1. 🛠️ **The Fix**: A clear code snippet or configuration change.
        2. 📝 **Explanation**: Why this fix works.
        3. 🚀 **Next Steps**: How to apply and test it.
        
        Focus on providing practical, copy-pasteable code for the relevant environment (e.g., Nginx, Apache, Python, etc.)."""

        response = client.models.generate_content(
            model="gemini-2.0-flash",
            contents=prompt
        )
        return response.text

    except Exception as e:
        print(f"⚠️ AI Patch Generation Failed: {e}")
        return "⚠️ Failed to generate patch. Please try again or check logs."

def get_chat_response(message, scan_context):
    """
    Conversational assistant. Provides a helpful static response if API fails.
    """
    try:
        client = genai.Client(api_key=GEMINI_API_KEY)
        # (Rest of previous optimized chat logic...)
        results_summary = [f"Port {r.get('port')}: {r.get('service')}" for r in scan_context.get("results", [])[:10]]
        prompt = f"Target: {scan_context.get('target')}. Findings: {results_summary}. User: {message}"

        response = client.models.generate_content(model="gemini-2.0-flash", contents=prompt)
        return response.text

    except Exception as e:
        if "429" in str(e):
            return "🤖 **VaptAI (Local Mode)**: I've hit the Google Free Tier limit. To fix this permanently, please add your own API Key. For now, I recommend patching the Critical vulnerabilities found in your report."
        return "⚠️ Assistant currently in maintenance. Please check the main report."