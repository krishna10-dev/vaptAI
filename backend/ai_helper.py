import json
import logging
import os
from pathlib import Path

try:
    from dotenv import load_dotenv
except ImportError:
    def load_dotenv(*args, **kwargs):
        return False

try:
    from google import genai
    GENAI_AVAILABLE = True
except ImportError:
    GENAI_AVAILABLE = False

LOGGER = logging.getLogger(__name__)

load_dotenv(dotenv_path=Path(__file__).with_name(".env"), override=False)

GEMINI_API_KEY = os.getenv("GEMINI_API_KEY", "").strip()
DEFAULT_MODEL = os.getenv("GEMINI_MODEL", "gemini-2.5-flash").strip() or "gemini-2.5-flash"
# Prefer currently supported Gemini/Gemma models for generate_content.
# Some keys can be rate-limited on specific Gemini tiers while Gemma remains available.
MODEL_FALLBACKS = [
    DEFAULT_MODEL,
    "gemini-2.5-flash",
    "gemini-2.5-pro",
    "gemini-2.0-flash",
    "gemma-3-12b-it",
    "gemma-3-4b-it",
]
INVALID_KEY_MARKERS = {"", "your_gemini_api_key_here", "replace_me", "changeme"}

_CLIENT = None
_LAST_AI_ERROR = ""


def _risk_rank(item):
    level = str((item or {}).get("risk_level", "")).upper()
    if "CRITICAL" in level:
        return 4
    if "HIGH" in level:
        return 3
    if "MEDIUM" in level:
        return 2
    if "LOW" in level:
        return 1
    return 0


def _security_score(scan_results):
    score = 100
    for item in scan_results:
        rank = _risk_rank(item)
        if rank == 4:
            score -= 25
        elif rank == 3:
            score -= 12
        elif rank == 2:
            score -= 6
        elif rank == 1:
            score -= 2
    return max(0, min(100, score))


def _extract_text(response):
    try:
        text = getattr(response, "text", None)
        if text:
            return text.strip()
    except Exception:
        pass
    candidates = getattr(response, "candidates", None) or []
    for candidate in candidates:
        content = getattr(candidate, "content", None)
        parts = getattr(content, "parts", None) or []
        for part in parts:
            part_text = getattr(part, "text", None)
            if part_text:
                return str(part_text).strip()
    return ""


def _get_client():
    global _CLIENT
    if not GENAI_AVAILABLE or GEMINI_API_KEY.lower() in INVALID_KEY_MARKERS:
        return None
    if _CLIENT is None:
        _CLIENT = genai.Client(api_key=GEMINI_API_KEY)
    return _CLIENT


def _generate_content(prompt):
    global _LAST_AI_ERROR
    client = _get_client()
    if client is None:
        _LAST_AI_ERROR = "AI disabled: missing or placeholder GEMINI_API_KEY."
        return ""
    last_error = None
    seen = set()
    for model in MODEL_FALLBACKS:
        if not model or model in seen:
            continue
        seen.add(model)
        try:
            response = client.models.generate_content(model=model, contents=prompt)
            text = _extract_text(response)
            if text:
                _LAST_AI_ERROR = ""
                return text
        except Exception as exc:
            last_error = exc
            continue
    if last_error:
        LOGGER.warning("Gemini generation failed: %s", last_error)
        err = str(last_error)
        _LAST_AI_ERROR = err
    return ""


def get_offline_report(target, scan_results):
    """Fallback if AI is unavailable or fails."""
    scan_results = scan_results or []
    criticals = [r for r in scan_results if _risk_rank(r) == 4]
    highs = [r for r in scan_results if _risk_rank(r) == 3]
    exposed_ports = [str(r.get("port", "N/A")) for r in scan_results[:3]]

    report = f"""### Security Summary for {target or "unknown target"} (Offline Mode)
Detected **{len(criticals)}** critical issues and **{len(highs)}** high-risk vulnerabilities.

**Top Recommendations:**
1. Immediately patch or isolate services flagged as critical.
2. Review externally exposed ports ({", ".join(exposed_ports) if exposed_ports else "none detected"}).
3. Validate service versions and apply current vendor security updates.
"""
    return {"security_score": _security_score(scan_results), "ai_report": report}


def get_ai_analysis(target, scan_results):
    """Generate the main security report."""
    scan_results = scan_results or []
    if _get_client() is None:
        return get_offline_report(target, scan_results)

    filtered_results = sorted(scan_results, key=_risk_rank, reverse=True)[:15]
    prompt = f"""As a Senior Security Analyst, analyze these VAPT findings for target '{target or "unknown"}'.
Findings: {json.dumps(filtered_results)}

Provide concise Markdown with:
1. Executive Summary
2. Top Threats and Potential Impact
3. Strategic Remediation Roadmap
4. Prioritized Next 72-Hour Action Plan
"""
    report = _generate_content(prompt)
    if not report:
        return get_offline_report(target, scan_results)
    return {"security_score": _security_score(scan_results), "ai_report": report}


def get_attack_suggestion(vuln):
    """Generate a short actionable mitigation suggestion."""
    if _get_client() is None:
        return "Check service version and apply latest security patches."
    prompt = (
        "As a security expert, provide one actionable sentence to mitigate this vulnerability. "
        f"Vulnerability data: {json.dumps(vuln or {})}"
    )
    text = _generate_content(prompt)
    return text or "Patch the service and restrict unnecessary port access."


def get_chat_response(message, scan_context):
    """Conversational security assistant response."""
    if _get_client() is None:
        return "AI assistant is offline. Set a valid GEMINI_API_KEY to enable chat."

    scan_context = scan_context or {}
    target = scan_context.get("target") or "unknown"
    results = scan_context.get("results") or []
    results_summary = [
        f"Port {r.get('port')}: {r.get('service')} ({r.get('risk_level')})"
        for r in results[:10]
        if isinstance(r, dict)
    ]

    prompt = f"""You are VaptAI, a practical cybersecurity assistant.
Target: {target}
Known findings: {results_summary}
User question: {message or ""}

Respond clearly, include remediation when relevant, and avoid speculation.
"""
    text = _generate_content(prompt)
    if "API_KEY_INVALID" in _LAST_AI_ERROR or "API key not valid" in _LAST_AI_ERROR:
        return "AI assistant is offline: invalid GEMINI_API_KEY. Update backend/.env and restart backend."
    return text or "I could not generate a response right now. Please retry in a moment."


def get_ai_patch(vuln):
    """Generate a technical remediation patch suggestion."""
    if _get_client() is None:
        return "Offline: Update affected software to a patched stable release and reduce exposure."
    prompt = (
        "Provide a technical remediation patch or configuration fix for this vulnerability. "
        "Return sections titled 'Fix' and 'Rationale'. "
        f"Vulnerability data: {json.dumps(vuln or {})}"
    )
    text = _generate_content(prompt)
    return text or "Unable to generate AI patch. Refer to official vendor security bulletins."
