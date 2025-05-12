# SSL/TLS Certificate Analyzer Tool – ProteX

A desktop-based cybersecurity tool for in-depth analysis of SSL/TLS certificates and web security configurations across websites.

🛑 Problem Statement

Misconfigured SSL/TLS certificates and missing security headers expose web applications to serious threats like:
- Man-in-the-middle (MITM) attacks
- Data interception
- Session hijacking
- Clickjacking
- Cookie theft

Most online tools are either limited, require constant internet, or miss critical HTTP and DNS-related checks. There's a need for an **offline-capable**, **GUI-based**, and **comprehensive analyzer** that checks:
- SSL/TLS protocols & cipher suites
- Certificate validity & algorithms
- HTTP headers & cookies
- DNS records (SPF, DMARC)
- Clickjacking & mixed content

⚙️ Setup Instructions

1. Install Python (3.8 or higher)
   [Download Python](https://www.python.org/downloads/)

2. Install required libraries:
   pip install ttkbootstrap requests dnspython pyopenssl beautifulsoup4
   
    Run the app:
    python ssl_tls_analyzer.py

📸 Screenshots
1. GUI – Home Page

2. Security Findings View

3. Exported Report CSV

📜 Logs & Diagrams
Sample Output Log:

example.com
✔ Certificate expires in 20 days  
✔ HSTS enabled  
❌ CSP missing  
✔ TLSv1.2 supported  
❌ TLSv1.0 supported (deprecated)

Architecture Diagram:

+---------------------------+
|        User Input         |
+---------------------------+
           ↓
+---------------------------+
|   SSL/TLS Certificate     |
|   HTTP Header Analysis    |
|   DNS Records / Cookies   |
+---------------------------+
           ↓
+---------------------------+
|       GUI Display         |
|   Export .csv Reports     |
+---------------------------+

⚖️ License & Disclaimer

This project is developed for educational and academic purposes.
License: MIT
Disclaimer: The tool is not intended for scanning third-party domains without permission. Use responsibly and ethically.

▶️ YouTube Demo
Watch the working demo:
Click here to watch the video

👨‍💻 Author

    Mohan Gumgaonkar
    Honey Priya Dharshini V

