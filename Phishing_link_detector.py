import re
from urllib.parse import urlparse


# A list of known suspicious domains for basic detection
suspicious_domains = [
    "bit.ly", "tinyurl.com", "adf.ly", "goo.gl", "ow.ly", 
    "shadywebsite.com", "example-phish.com"
]

def is_shortened_url(url):
    """Check if the URL uses a known URL shortener service."""
    domain = urlparse(url).netloc
    return domain in suspicious_domains

def has_suspicious_keywords(url):
    """Check for common phishing keywords in the URL."""
    phishing_keywords = ["login", "verify", "secure", "bank", "update", "account", "signin", "password"]
    for keyword in phishing_keywords:
        if keyword in url.lower():
            return True
    return False

def has_unusual_characters(url):
    """Check for unusual characters in the domain or URL path."""
    # Look for excessive hyphens, dots, or non-ASCII characters
    domain = urlparse(url).netloc
    path = urlparse(url).path
    if re.search(r"[^\w\.\-\/]", domain + path):  # Non-standard characters
        return True
    return len(re.findall(r"-", domain)) > 2 or len(re.findall(r"\.", domain)) > 3

def is_blacklisted(url):
    """Check if the URL is blacklisted (using a third-party service like VirusTotal)."""
    # Replace 'your-api-key' with an actual API key for VirusTotal or another service
    api_key = "your-api-key"
    vt_url = f"https://www.virustotal.com/vtapi/v2/url/report"
    params = {"apikey": api_key, "resource": url}
    try:
        response = requests.get(vt_url, params=params)
        if response.status_code == 200:
            result = response.json()
            return result.get("positives", 0) > 0
    except Exception as e:
        print(f"Error checking blacklist: {e}")
    return False

def analyze_url(url):
    """Analyze the given URL for phishing characteristics."""
    print(f"Analyzing URL: {url}")
    flagged = False

    if is_shortened_url(url):
        print("⚠️ Detected shortened URL.")
        flagged = True
    if has_suspicious_keywords(url):
        print("⚠️ Detected suspicious keywords in the URL.")
        flagged = True
    if has_unusual_characters(url):
        print("⚠️ Detected unusual characters in the URL.")
        flagged = True
    if is_blacklisted(url):
        print("⚠️ URL is blacklisted.")
        flagged = True

    if flagged:
        print("🚨 This URL is potentially phishing!")
    else:
        print("✅ This URL appears safe.")

# Main function to get user input
def main():
    print("Welcome to the Phishing Link Detector!")
    url = input("Please enter the URL you want to scan: ")
    analyze_url(url)

if __name__ == "__main__":
    main()
