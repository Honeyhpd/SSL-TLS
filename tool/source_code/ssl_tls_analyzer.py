import tkinter as tk
from tkinter import ttk, messagebox, filedialog
import ttkbootstrap as tb
import ssl
import socket
from OpenSSL import crypto
import datetime
import csv
import requests
import dns.resolver
from urllib.parse import urlparse
from bs4 import BeautifulSoup

CERT_EXPIRY_THRESHOLD = 30
MIXED_CONTENT_THRESHOLD = 5
results = {}

def fetch_certificate(domain):
    try:
        ctx = ssl.create_default_context()
        with ctx.wrap_socket(socket.socket(), server_hostname=domain) as s:
            s.connect((domain, 443))
            cert = s.getpeercert(True)
            x509 = crypto.load_certificate(crypto.FILETYPE_ASN1, cert)
        return {
            "issuer": dict(x509.get_issuer().get_components()),
            "subject": dict(x509.get_subject().get_components()),
            "serial_number": x509.get_serial_number(),
            "version": x509.get_version() + 1,
            "signature_algorithm": x509.get_signature_algorithm().decode(),
            "not_before": datetime.datetime.strptime(x509.get_notBefore().decode(), '%Y%m%d%H%M%SZ'),
            "not_after": datetime.datetime.strptime(x509.get_notAfter().decode(), '%Y%m%d%H%M%SZ'),
        }
    except Exception as e:
        return str(e)

def analyze_vulnerabilities(cert_details):
    alerts = []
    now = datetime.datetime.now()
    expiry_date = cert_details["not_after"]
    alerts.append(f"Certificate Expiry Date: {expiry_date.strftime('%Y-%m-%d %H:%M:%S')}")
    if expiry_date < now:
        alerts.append("Critical: Certificate has expired.")
    elif (expiry_date - now).days <= CERT_EXPIRY_THRESHOLD:
        alerts.append(f"Warning: Certificate expires in {(expiry_date - now).days} days")
    if "sha1" in cert_details["signature_algorithm"].lower():
        alerts.append("Critical: Certificate uses a weak signature algorithm (e.g., SHA-1).")
    return alerts

def check_cipher_suites(domain):
    try:
        ctx = ssl.create_default_context()
        with ctx.wrap_socket(socket.socket(), server_hostname=domain) as s:
            s.connect((domain, 443))
            ciphers = s.shared_ciphers()
        weak_ciphers = ["RC4", "DES", "3DES"]
        found = [c for c in ciphers if any(w in c[0] for w in weak_ciphers)]
        return f"Weak ciphers detected: {', '.join(c[0] for c in found)}" if found else "No weak ciphers detected."
    except Exception as e:
        return f"Error checking ciphers: {e}"

def check_protocols(domain):
    deprecated_protocols = ["TLSv1", "TLSv1.1"]
    results = []
    for protocol in deprecated_protocols:
        try:
            ctx = ssl.SSLContext(getattr(ssl, f"PROTOCOL_{protocol.replace('.', '_')}", None))
            if not ctx:
                results.append(f"{protocol} not supported by Python")
                continue
            with ctx.wrap_socket(socket.socket(), server_hostname=domain) as s:
                s.connect((domain, 443))
            results.append(f"Deprecated protocol supported: {protocol}")
        except ssl.SSLError:
            results.append(f"{protocol} not supported")
        except Exception as e:
            results.append(f"Error checking {protocol}: {e}")
    return results

def check_clickjacking(domain):
    try:
        response = requests.get(f"http://{domain}", timeout=10)
        xfo = response.headers.get("X-Frame-Options", "").lower()
        if not xfo:
            return "Critical: Missing X-Frame-Options header"
        elif xfo not in ["deny", "sameorigin"]:
            return "Warning: Improper X-Frame-Options configuration"
        return "X-Frame-Options properly configured"
    except Exception as e:
        return f"Error: {str(e)}"

def check_hsts(domain):
    try:
        response = requests.get(f"https://{domain}", timeout=10)
        hsts = response.headers.get("Strict-Transport-Security", "")
        if not hsts:
            return "Critical: HSTS not enabled"
        elif "max-age" not in hsts:
            return "Warning: Missing max-age in HSTS policy"
        return f"HSTS enabled: {hsts}"
    except Exception as e:
        return f"Error: {str(e)}"

def check_csp(domain):
    try:
        response = requests.get(f"https://{domain}", timeout=10)
        return "CSP implemented" if "Content-Security-Policy" in response.headers else "Critical: CSP missing"
    except Exception as e:
        return f"Error: {str(e)}"

def check_cookies(domain):
    try:
        response = requests.get(f"https://{domain}", timeout=10)
        issues = []
        for cookie in response.cookies:
            if not cookie.secure:
                issues.append(f"Cookie {cookie.name} lacks Secure flag")
            if not cookie.has_nonstandard_attr("HttpOnly"):
                issues.append(f"Cookie {cookie.name} lacks HttpOnly flag")
            if not cookie.has_nonstandard_attr("SameSite"):
                issues.append(f"Cookie {cookie.name} lacks SameSite flag")
        return issues if issues else "All cookies secure"
    except Exception as e:
        return [f"Error: {str(e)}"]

def check_directory_listing(domain):
    try:
        response = requests.get(f"http://{domain}", timeout=10)
        return "Critical: Directory listing enabled" if "Index of" in response.text else "Directory listing safe"
    except Exception as e:
        return f"Error: {str(e)}"

def check_dns_records(domain):
    try:
        results = {"SPF": "Not found", "DMARC": "Not found"}
        for rdata in dns.resolver.resolve(domain, "TXT"):
            record = rdata.to_text()
            if "spf" in record.lower():
                results["SPF"] = "Found"
            if "dmarc" in record.lower():
                results["DMARC"] = "Found"
        return results
    except Exception as e:
        return {"Error": str(e)}

def check_mixed_content(domain):
    try:
        response = requests.get(f"https://{domain}", timeout=10)
        soup = BeautifulSoup(response.text, 'html.parser')
        mixed = [tag.get('src') or tag.get('href') for tag in soup.find_all(['img', 'script', 'link'])
                 if (tag.get('src') or tag.get('href') or '').startswith('http://')]
        count = len(mixed)
        if count >= MIXED_CONTENT_THRESHOLD:
            return f"Critical: {count} mixed content resources"
        elif count > 0:
            return f"Warning: {count} mixed content resources"
        return "No mixed content detected"
    except Exception as e:
        return f"Error: {str(e)}"

def check_cors(domain):
    try:
        response = requests.get(f"https://{domain}", timeout=10)
        headers = response.headers
        issues = []
        origin = headers.get('Access-Control-Allow-Origin')
        if not origin:
            issues.append("CORS: Missing origin control")
        elif origin == "*":
            issues.append("CORS: Wildcard origin allowed")
            if 'Access-Control-Allow-Credentials' in headers:
                issues.append("CORS: Credentials with wildcard")
        return "\n".join(issues) if issues else "CORS configuration secure"
    except Exception as e:
        return f"Error: {str(e)}"

def analyze_single_domain(domain):
    cert = fetch_certificate(domain)
    if isinstance(cert, str):
        return {"Error": cert}
    return {
        "SSL/TLS Analysis": analyze_vulnerabilities(cert),
        "Cipher Suites": check_cipher_suites(domain),
        "Protocol Support": check_protocols(domain),
        "Clickjacking Protection": check_clickjacking(domain),
        "HSTS Configuration": check_hsts(domain),
        "Content Security Policy": check_csp(domain),
        "Cookie Security": check_cookies(domain),
        "Directory Listing": check_directory_listing(domain),
        "DNS Records": check_dns_records(domain),
        "Mixed Content": check_mixed_content(domain),
        "CORS Configuration": check_cors(domain)
    }

# GUI Components
def analyze_single_website():
    domain = domain_entry.get().strip()
    if not domain:
        messagebox.showerror("Error", "Please enter a domain")
        return
    results.clear()
    results[domain] = analyze_single_domain(domain)
    display_results()

def analyze_multiple_websites():
    filepath = filedialog.askopenfilename(filetypes=[("Text Files", "*.txt")])
    if not filepath:
        return
    with open(filepath, "r") as f:
        domains = [line.strip() for line in f if line.strip()]
    results.clear()
    for domain in domains:
        results[domain] = analyze_single_domain(domain)
    display_results()

def display_results():
    tree.delete(*tree.get_children())
    for domain, data in results.items():
        for category, value in data.items():
            if isinstance(value, list):
                for item in value:
                    tree.insert("", "end", values=(domain, category, item))
            elif isinstance(value, dict):
                for k, v in value.items():
                    tree.insert("", "end", values=(domain, f"{category} - {k}", v))
            else:
                tree.insert("", "end", values=(domain, category, value))

def save_report():
    filepath = filedialog.asksaveasfilename(defaultextension=".csv", filetypes=[("CSV", "*.csv"), ("Text", "*.txt")])
    if not filepath:
        return
    try:
        with open(filepath, "w", newline="") as f:
            writer = csv.writer(f)
            writer.writerow(["Domain", "Category", "Finding"])
            for domain, data in results.items():
                for cat, val in data.items():
                    if isinstance(val, list):
                        for item in val:
                            writer.writerow([domain, cat, item])
                    elif isinstance(val, dict):
                        for k, v in val.items():
                            writer.writerow([domain, f"{cat} - {k}", v])
                    else:
                        writer.writerow([domain, cat, val])
        messagebox.showinfo("Success", f"Report saved to {filepath}")
    except Exception as e:
        messagebox.showerror("Error", f"Failed to save report: {e}")

# GUI Setup
root = tb.Window(themename="cyborg")
root.title("ProteX CERTIFICATE SECURITY ANALYZER")
root.geometry("1200x800")
root.state('zoomed')

main_frame = tb.Frame(root)
main_frame.pack(fill=tk.BOTH, expand=True, padx=20, pady=20)

header = tb.Label(main_frame, text="ProteX CERTIFICATE SECURITY ANALYZER", font=("Consolas", 24, "bold"), bootstyle="success")
header.pack(pady=10)

input_frame = tb.Frame(main_frame)
input_frame.pack(fill=tk.X, pady=10)

domain_entry = tb.Entry(input_frame, width=50, font=("Consolas", 12))
domain_entry.pack(side=tk.LEFT, padx=5)

tb.Button(input_frame, text="Analyze Single", command=analyze_single_website, bootstyle="success-outline").pack(side=tk.LEFT, padx=5)
tb.Button(input_frame, text="Bulk Analysis", command=analyze_multiple_websites, bootstyle="info-outline").pack(side=tk.LEFT, padx=5)

results_frame = tb.Frame(main_frame)
results_frame.pack(fill=tk.BOTH, expand=True)

tree = ttk.Treeview(results_frame, columns=("Domain", "Category", "Finding"), show="headings", height=20)
tree.heading("Domain", text="Domain")
tree.heading("Category", text="Security Category")
tree.heading("Finding", text="Security Findings")
tree.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)

scrollbar = tb.Scrollbar(results_frame, orient=tk.VERTICAL, command=tree.yview)
scrollbar.pack(side=tk.RIGHT, fill=tk.Y)
tree.configure(yscrollcommand=scrollbar.set)

tb.Button(main_frame, text="Export Report", command=save_report, bootstyle="primary-outline").pack(pady=10)
status = tb.Label(root, text="Ready", anchor=tk.W, bootstyle="light")
status.pack(side=tk.BOTTOM, fill=tk.X)

root.mainloop()