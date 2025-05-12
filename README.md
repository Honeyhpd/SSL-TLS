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
1. Comparitive Analysis
   
![image](https://github.com/user-attachments/assets/d03124b0-2e96-495d-99f4-0e4fb8067c4e)

![image](https://github.com/user-attachments/assets/648a870a-9621-409a-9c96-f9310507e514)


2. Gantt Chart
   
   ![image](https://github.com/user-attachments/assets/55753161-4df9-4d1f-bf46-4f4e23ce0cfb)


📜 Logs & Diagrams
Sample Output Log:

![image](https://github.com/user-attachments/assets/cf397e8d-25a1-423a-9251-eb1a4f82f573)



Architecture Diagram:

![image](https://github.com/user-attachments/assets/451891d7-d805-48e7-8fd4-e73793756917)


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

