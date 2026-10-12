import argparse, base64, csv, json, os, re
from datetime import datetime, timezone
from email import policy
from email.parser import BytesParser
from email.utils import parseaddr
from pathlib import Path
from urllib.parse import urlparse

URL_RE = re.compile(r"""(?i)\bhttps?://[^\s<>"'()\]]+""")
URGENCY = ("urgent", "immediately", "within 24 hours", "suspended", "verify your account",
           "confirm your password", "unusual activity", "action required")
URL_WORDS = ("verify", "login", "password", "account", "secure", "update")
SHORTENERS = {"bit.ly", "tinyurl.com", "t.co", "is.gd", "ow.ly", "buff.ly"}
BRANDS = ["microsoft", "google", "apple", "paypal", "amazon"]

def extract_urls(text):
    return sorted(set(x.rstrip(".,;:!?") for x in URL_RE.findall(text)))

def parse_email(path):
    with path.open("rb") as f: msg = BytesParser(policy=policy.default).parse(f)
    parts = []
    candidates = msg.walk() if msg.is_multipart() else [msg]
    for part in candidates:
        if part.get_content_maintype() == "multipart" or part.get_content_disposition() == "attachment": continue
        try:
            value = part.get_content()
            if isinstance(value, str): parts.append(value)
        except (LookupError, UnicodeError, AttributeError): pass
    name, sender = parseaddr(str(msg.get("From", "")))
    _, reply = parseaddr(str(msg.get("Reply-To", "")))
    auth = " ".join(str(x) for x in msg.get_all("Authentication-Results", []))
    body = "\n".join(parts)
    return {"file":path.name,"from_name":name,"from_address":sender,"reply_to":reply,
            "subject":str(msg.get("Subject","")),"date":str(msg.get("Date","")),
            "authentication_results":auth,"body":body,"urls":extract_urls(body)}

def domain_of(address):
    return address.rsplit("@",1)[1].lower().strip(" >") if "@" in address else ""

def url_flags(url):
    flags=[]; parsed=urlparse(url); host=(parsed.hostname or "").lower()
    if not host: return ["url_missing_host"]
    if host in SHORTENERS: flags.append("url_shortener")
    try:
        import ipaddress
        ipaddress.ip_address(host); flags.append("ip_literal_url_host")
    except ValueError: pass
    if any(x in url.lower() for x in URL_WORDS): flags.append("suspicious_url_wording")
    if parsed.scheme.lower() != "https": flags.append("non_https_url")
    return flags

def analyze(parsed):
    findings=[]; score=0
    sender=parsed.get("from_address",""); reply=parsed.get("reply_to","")
    sd, rd = domain_of(sender), domain_of(reply)
    display=parsed.get("from_name","").lower()
    text=(parsed.get("subject","")+"\n"+parsed.get("body","")).lower()
    auth=parsed.get("authentication_results","").lower()
    if rd and sd and rd != sd: findings.append("reply_to_domain_mismatch"); score += 2
    if any(x in auth for x in ("spf=fail","dkim=fail","dmarc=fail","spf=softfail")):
        findings.append("authentication_failure_in_header"); score += 2
    if any(x in text for x in URGENCY): findings.append("urgency_or_credential_request_language"); score += 1
    if any(b in display for b in BRANDS) and sd and not any(b.replace(" ","") in sd.replace(".","") for b in BRANDS):
        findings.append("brand_like_display_name_domain_mismatch"); score += 1
    url_findings=[]
    for url in parsed.get("urls",[]):
        flags=url_flags(url)
        if flags:
            url_findings.append({"url":url,"flags":flags})
            if any(x in flags for x in ("url_shortener","ip_literal_url_host")): score += 2
            if "suspicious_url_wording" in flags: score += 1
    score=min(score,8)
    return {"file":parsed.get("file",""),"from_name":parsed.get("from_name",""),
            "from_address":sender,"reply_to":reply,"subject":parsed.get("subject",""),
            "date":parsed.get("date",""),"authentication_results":parsed.get("authentication_results",""),
            "urls":parsed.get("urls",[]),"url_findings":url_findings,"findings":sorted(set(findings)),
            "risk_score":score,"risk":"high" if score>=5 else "medium" if score>=3 else "low",
            "recommended_action":"analyst_review" if score>=3 else "routine_review",
            "analyzed_at_utc":datetime.now(timezone.utc).isoformat(),
            "note":"Heuristic triage only; no URL was visited and authentication was not independently verified."}

def vt_lookup(url, api_key):
    try: import requests
    except ImportError as e: raise RuntimeError("Install optional dependency: pip install -r requirements-optional.txt") from e
    encoded=base64.urlsafe_b64encode(url.encode()).decode().rstrip("=")
    response=requests.get("https://www.virustotal.com/api/v3/urls/"+encoded,
                          headers={"x-apikey":api_key},timeout=10)
    if response.status_code==404: return {"url":url,"status":"not_found","message":"No existing report; URL not submitted."}
    response.raise_for_status()
    stats=response.json().get("data",{}).get("attributes",{}).get("last_analysis_stats",{})
    return {"url":url,"status":"found","last_analysis_stats":stats}

def main():
    p=argparse.ArgumentParser(description="Analyze a local .eml file without opening its URLs.")
    p.add_argument("--input",required=True,type=Path); p.add_argument("--out",required=True,type=Path)
    p.add_argument("--virustotal",action="store_true",help="Lookup existing VirusTotal URL reports (opt-in)")
    a=p.parse_args()
    if a.input.suffix.lower()!=".eml": p.error("Input must be a local .eml file")
    try:
        parsed=parse_email(a.input); result=analyze(parsed)
        if a.virustotal:
            key=os.environ.get("VT_API_KEY","")
            if not key: p.error("--virustotal requires VT_API_KEY environment variable")
            result["virustotal_lookups"]=[vt_lookup(u,key) for u in parsed["urls"]]
        a.out.mkdir(parents=True,exist_ok=True)
        (a.out/"report.json").write_text(json.dumps(result,indent=2),encoding="utf-8")
        fields=["file","from_name","from_address","reply_to","subject","risk_score","risk","recommended_action"]
        with (a.out/"report.csv").open("w",newline="",encoding="utf-8") as f:
            w=csv.DictWriter(f,fieldnames=fields); w.writeheader(); w.writerow({k:result.get(k,"") for k in fields})
    except (OSError,ValueError,RuntimeError) as e: p.error(str(e))
    print(f"Analyzed {a.input.name}: risk={result['risk']} score={result['risk_score']}; report: {a.out}")

if __name__=="__main__": main()
