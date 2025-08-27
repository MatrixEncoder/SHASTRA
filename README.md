# SHASTRA

(Live demo deployed on Streamlit: https://shastra2.streamlit.app

## Overview
SHASTRA is a security scanner application designed to analyze source code and server logs for potential vulnerabilities. It utilizes regex patterns to detect various types of security threats, including SQL injection, XSS, and sensitive data exposure.

## Features

- Code Analysis: Detects common vulnerabilities like SQL Injection, XSS, and exposed secrets
- URL Analysis: Checks for security headers, SSL/TLS configuration, and other web security issues
- Log Analysis: Identifies potential attack patterns and suspicious activities in request logs
- Analyzes both source code and server logs.
- Detects vulnerabilities using regex patterns.
- Provides detailed reports with risk assessments.
- User-friendly interface built with Streamlit.

## Installation

1. Install the required dependencies:
```bash
pip install -r requirements.txt
```

To install SHASTRA, clone the repository and install the required dependencies:
```bash
git clone https://github.com/MatrixEncoder/SHASTRA.git
cd SHASTRA
pip install -r requirements.txt
```

## Usage

The scanner provides three main functions:

1. **Code Analysis**
   - Detects SQL Injection vulnerabilities
   - Identifies potential XSS risks
   - Finds exposed secrets and credentials
   - Checks for security misconfigurations

2. **URL Analysis**
   - Validates SSL/TLS configuration
   - Checks for security headers
   - Identifies insecure protocols

3. **Log Analysis**
   - Detects potential brute force attempts
   - Identifies suspicious patterns
   - Monitors for injection attempts

Run the application using Streamlit:
```bash
streamlit run security_scanner.py
```

## Example Usage

1. To analyze code:
   - Select option 1
   - Paste your code snippet
   - Review the security analysis results

2. To analyze a URL:
   - Select option 2
   - Enter the URL
   - Review the security headers and configuration analysis

3. To analyze logs:
   - Select option 3
   - Paste your log entries
   - Review potential security threats

## Output Format

For each detected vulnerability, the scanner provides:
- Risk Level (Critical, High, Medium, Low)
- Vulnerability Type
- Description of the issue
- Recommended fix with code examples
"# SHASTRA" 
