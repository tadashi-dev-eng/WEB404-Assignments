# Assignment 1 

## 1. Executive Summary

This report presents the findings of a security assessment conducted against a locally hosted test instance of OWASP Juice Shop running on port 3000. The objective of this lab is to perform passive crawling and automated security scans, evaluate HTTP security headers, eliminate duplicate or false-positive findings, and formulate appropriate remediation strategies.   

The primary security weaknesses identified involve missing defense-in-depth HTTP security headers and sensitive technological information disclosure in application HTTP responses.   

---

## 2. Methodology & Tooling Setup

- Environment ArchitectureTarget Endpoint: http://localhost:3000 (Deployed via Docker)   
![alt text](assets/dockerun.png)

```NOTE
OWASP Juice Shop is a modern, open-source, and intentionally insecure web application that simulates a realistic online e-commerce store
```

![alt text](assets/weblocal.png)

- Proxied Listener: OWASP ZAP intercepting proxy running on 127.0.0.1:8080

  ![alt text](assets/zap.png)

- Nikto: Web server scanner.
  
![alt text](assets/Nickto.png)

## 3. Technical Execution Steps

### Executed Automated Scan with Nikto

![alt text](assets/nikto-scan.png)

### Findings:

VULN-01: Missing Content-Security-Policy (CSP) (Severity: High). There is no Content-Security-Policy header present

![alt text](assets/csp.png)

VULN-02: Wildcard CORS Access Control (Access-Control-Allow-Origin: *) (Severity: Medium). The cross-origin requests are unrestricted.

![alt text](assets/reasponse-header.png)

VULN-03: Sensitive Information Disclosure via Public /ftp/ Directory (Severity: Medium). It shows an active directory listing containing sensitive backup and operational files

![alt text](assets/ftp.png)


VULN-04: Information Disclosure via Inode-Based ETag Headers (Severity: Low).The ETag value W/"24b1-1a11ba1ef94" is generated using file metadata (specifically the file size 24b1 in hex and the system inode or exact modification timestamp 1a11ba1ef94 in hex)

![alt text](assets/v3.png)

### Passive Crawling with OWASP ZAP

