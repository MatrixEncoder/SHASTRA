import re
import requests
from bs4 import BeautifulSoup
import validators
from colorama import Fore, Style, init
import json
from typing import List, Dict, Union, Optional
import logging
import streamlit as st
import base64
import io
import csv
import datetime
import pytz
from github import Github

# Initialize colorama for colored output
init()

class SecurityScanner:
    def __init__(self):
        # Define risk level colors for HTML display
        self.risk_colors = {
            'Critical': '#800080',  # Purple
            'High': '#FF0000',      # Bright Red
            'Medium': '#FFFF00',    # Yellow
            'Low': '#00FF00'        # Green
        }
        
        # Common vulnerability patterns
        self.patterns = {
            'sql_injection': [
                r'SELECT.*FROM.*WHERE',
                r'INSERT\s+INTO',
                r'UPDATE.*SET',
                r'DELETE\s+FROM',
                r'UNION\s+SELECT',
            ],
            'xss': [
                r'<script.*?>',
                r'javascript:',
                r'onerror=',
                r'onload=',
                r'eval\(',
            ],
            'exposed_secrets': [
                r'(?i)(?:api[_-]?key|api[_-]?token|app[_-]?key|app[_-]?token|access[_-]?token|auth[_-]?token|client[_-]?secret|secret[_-]?key|token)["\']?\s*(?:=|:)\s*["\']([a-zA-Z0-9_\-\.]{20,})["\']',
                r'(?i)(?:password|passwd|pwd)["\']?\s*(?:=|:)\s*["\']([^\'\"]{8,})["\']',
                r'(?i)(?:BEGIN|END)\s+(?:RSA|DSA|EC|OPENSSH)\s+(?:PRIVATE)\s+KEY.*'  # Fix the unterminated string literals
            ],
            'insecure_configs': [
                r'debug\s*=\s*true',
                r'ALLOW_ALL_ORIGINS',
                r'JWT_SECRET',
            ]
        }

    def analyze_code(self, code_input: str, filename: Optional[str] = None, is_url_scan: bool = False) -> List[Dict]:
        """Analyze source code for potential security vulnerabilities."""
        vulnerabilities = []
        
        # Skip empty input
        if not code_input:
            return []
        
        # Define patterns for different vulnerabilities
        patterns = {
            'SQL Injection': [
                r'(?i)cursor\.execute\s*\(\s*["\'].*?(?:\+|\|\||&|AND|\%|\$|\{|\}|\?|@|#).*?["\']',
                r'(?i)(?:SELECT|INSERT|UPDATE|DELETE|DROP|ALTER|CREATE|TRUNCATE)\b.*?\+',
            ],
            'Command Injection': [
                r'(?i)os\.system\s*\(\s*(?:[^)]*\+[^)]*\))',
                r'(?i)subprocess\.(?:call|run|Popen)\s*\(\s*(?:[^)]*\+[^)]*\))',
                r'(?i)exec\s*\(\s*(?:[^)]*\+[^)]*\))',
            ],
            'XSS': [
                r'(?i)(?:innerHTML|outerHTML|document\.write|eval|setTimeout|setInterval)\s*\(\s*(?:["\'].*?["\']|\$.*?|\{.*?\}|\[.*?\])',
                r'(?i)(?:innerHTML|outerHTML|document\.write|eval|setTimeout|setInterval)\s*=\s*(?:["\'].*?["\']|\$.*?|\{.*?\}|\[.*?\])',
                r'(?i)(?:src|href)\s*=\s*(?:["\'](?:javascript|data):.*?["\'])',
                r'(?i)(?:<script>|<\/script>|<img[^>]*?onerror=|<iframe[^>]*?src=|<svg[^>]*?onload=)'
            ],
            'Hardcoded Secret': [
                r'(?i)(?:password|passwd|pwd)\s*=\s*["\'][^\'\"]+["\']',
                r'(?i)(?:api[_-]?key|api[_-]?token|app[_-]?key|app[_-]?token|access[_-]?token|auth[_-]?token|client[_-]?secret|secret[_-]?key|token)["\']?\s*(?:=|:)\s*["\']([a-zA-Z0-9_\-\.]{20,})["\']',
                r'(?i)(?:BEGIN|END)\s+(?:RSA|DSA|EC|OPENSSH)\s+(?:PRIVATE)\s+KEY.*'
            ]
        }
        
        # Split code into lines for line number tracking
        code_lines = code_input.split('\n')
        
        # Check for each vulnerability type
        for vuln_type, pattern_list in patterns.items():
            for pattern in pattern_list:
                for i, line in enumerate(code_lines, 1):
                    if re.search(pattern, line):
                        # Determine risk level
                        risk_level = 'High'
                        if vuln_type in ['SQL Injection', 'Command Injection', 'Hardcoded Secret']:
                            risk_level = 'Critical'
                        
                        # Determine fix recommendation
                        fix = {
                            'SQL Injection': 'Use parameterized queries or an ORM instead of string concatenation.',
                            'Command Injection': 'Use subprocess.run with a list of arguments, or use shlex.quote to escape shell metacharacters.',
                            'XSS': 'Use content security policy and sanitize user input before rendering.',
                            'Hardcoded Secret': 'Move secrets to environment variables or a secure configuration management system.'
                        }.get(vuln_type, 'Fix not specified')
                        
                        # Extract code snippet (the vulnerable line and 2 lines before and after for context)
                        start_idx = max(0, i - 3)
                        end_idx = min(len(code_lines), i + 2)
                        code_snippet = "\n".join(code_lines[start_idx:end_idx])
                        line_in_snippet = i - start_idx
                        
                        # Add vulnerability to the list with filename
                        vulnerabilities.append({
                            'type': vuln_type,
                            'risk_level': risk_level,
                            'description': f'Potential {vuln_type.lower()} detected',
                            'fix': fix,
                            'location': f'Line {i}',
                            'filename': filename if filename else 'Code Input',
                            'code_snippet': code_snippet,
                            'line_in_snippet': line_in_snippet
                        })
        
        return vulnerabilities

    def analyze_logs(self, logs_input: str, logs_file: Optional[str] = None) -> List[Dict]:
        """Analyze logs for potential security vulnerabilities."""
        if not logs_input or logs_input.strip() == "":
            return []

        vulnerabilities = []

        # Define patterns for different types of security issues
        patterns = {
            'SQL Injection': r'(?i)(select|update|delete|insert|union|drop)\s+.*(\s+from|\s+into|\s+where|\s+table)',
            'XSS Attack': r'(?i)(<script>|javascript:|onerror=|onload=|eval\()',
            'File Inclusion': r'(?i)(include|require)(_once)?\s*\([\'"]?\w+[\'"]?\)',
            'Command Injection': r'(?i)(system|exec|shell_exec|passthru|`.*`)',
            'Authentication Failure': r'(?i)(login\s+failed|auth.*fail|invalid\s+password|unauthorized)',
            'Directory Traversal': r'(?i)(\.\./|\.\./\./|~/)',
            'Suspicious IP': r'\b(?:\d{1,3}\.){3}\d{1,3}\b.*(?:attack|hack|exploit|scan)',
            'Port Scan': r'(?i)(port\s+scan|nmap|scanning)',
            'DoS Attack': r'(?i)(dos|ddos|denial\s+of\s+service|too\s+many\s+requests)',
            'Malware': r'(?i)(malware|virus|trojan|ransomware|backdoor)'
        }

        # Analyze each line in the logs
        for i, line in enumerate(logs_input.split('\n'), 1):
            for issue_type, pattern in patterns.items():
                if re.search(pattern, line):
                    vulnerabilities.append({
                        'type': issue_type,
                        'description': f'Potential {issue_type} detected',
                        'location': f'Line {i}',
                        'risk_level': self._determine_risk_level(issue_type),
                        'fix': self._get_fix_recommendation(issue_type),
                        'filename': logs_file if logs_file else 'Log Input'
                    })

        return vulnerabilities

    def analyze_url(self, url: str) -> List[Dict]:
        """Analyze a URL for potential security vulnerabilities."""
        vulnerabilities = []

        # Check if URL is valid
        if not validators.url(url):
            st.error("Invalid URL format. Please enter a valid URL.")
            return []
        
        try:
            # Fetch the URL content
            response = requests.get(url, timeout=10)
            content = response.text
            
            # Check for connection security
            if not url.startswith("https://"):
                vulnerabilities.append({
                    'type': 'Connection Security',
                    'risk_level': 'High',
                    'description': 'The URL does not use HTTPS, which can lead to man-in-the-middle attacks.',
                    'fix': 'Ensure the URL uses HTTPS for secure communication.',
                    'location': url
                })

            # Check for suspicious scripts
            suspicious_scripts = []  # Add logic to detect suspicious scripts
            if suspicious_scripts:
                vulnerabilities.append({
                    'type': 'Suspicious Scripts',
                    'risk_level': 'Medium',
                    'description': 'The following suspicious scripts were detected:',
                    'fix': 'Review and remove any suspicious scripts.',
                    'location': url,
                    'details': suspicious_scripts
                })

            # Check for tracking features
            tracking_features = []  # Add logic to detect tracking features
            if tracking_features:
                vulnerabilities.append({
                    'type': 'Tracking Features',
                    'risk_level': 'Medium',
                    'description': 'The following tracking features were detected:',
                    'fix': 'Consider disabling tracking features.',
                    'location': url,
                    'details': tracking_features
                })

            # Check for security headers
            headers = response.headers
            missing_headers = []
            critical_headers = ['Strict-Transport-Security', 'Content-Security-Policy', 'X-Content-Type-Options', 'X-Frame-Options']
            for header in critical_headers:
                if header not in headers:
                    missing_headers.append(header)
            if len(missing_headers) > 2:
                vulnerabilities.append({
                    'type': 'Missing Security Headers',
                    'risk_level': 'Medium',
                    'description': f'The following security headers are missing: {", ".join(missing_headers)}.',
                    'fix': 'Implement the missing security headers appropriate for your website.',
                    'location': url
                })

            # Check for suspicious cookies
            suspicious_cookies = []  # Add logic to detect suspicious cookies
            if suspicious_cookies:
                vulnerabilities.append({
                    'type': 'Suspicious Cookies',
                    'risk_level': 'Medium',
                    'description': 'The following suspicious cookies were detected:',
                    'fix': 'Review and secure cookie settings.',
                    'location': url,
                    'details': suspicious_cookies
                })

            # Check for forms and input vulnerabilities
            form_vulnerabilities = []  # Add logic to detect form vulnerabilities
            if form_vulnerabilities:
                vulnerabilities.append({
                    'type': 'Forms and Input',
                    'risk_level': 'High',
                    'description': 'The following vulnerabilities were found in forms:',
                    'fix': 'Ensure proper validation and sanitization of form inputs.',
                    'location': url,
                    'details': form_vulnerabilities
                })

            return vulnerabilities
            
        except requests.exceptions.RequestException as e:
            st.error(f"Error analyzing URL: {str(e)}")
            return []

    def analyze_url_content(self, url: str) -> List[Dict]:
        """Analyze the content of a URL for potential security vulnerabilities."""
        vulnerabilities = []
        
        # Check if URL is valid
        if not validators.url(url):
            st.error("Invalid URL format. Please enter a valid URL.")
            return []
        
        try:
            # Fetch the URL content
            response = requests.get(url, timeout=10)
            content = response.text
            
            # Extract domain for context
            domain = url.split('//')[-1].split('/')[0]
            
            # For URL content, we need to be extremely careful about false positives
            # Instead of analyzing the entire HTML content (which leads to many false positives),
            # we'll focus on specific security aspects that can be reliably detected
            
            # Check for security headers
            headers = response.headers
            missing_headers = []
            critical_headers = ['Strict-Transport-Security', 'Content-Security-Policy', 'X-Content-Type-Options', 'X-Frame-Options']
            for header in critical_headers:
                if header not in headers:
                    missing_headers.append(header)
            if len(missing_headers) > 2:
                vulnerabilities.append({
                    'type': 'Missing Security Headers',
                    'risk_level': 'Medium',
                    'description': f'The following security headers are missing: {", ".join(missing_headers)}.',
                    'fix': 'Implement the missing security headers appropriate for your website.',
                    'location': url,
                    'filename': url
                })
            
            # Check for mixed content (HTTP resources on HTTPS page)
            if url.startswith("https://") and ('http:' in content and 'https:' in content):
                # Look for http: in src or href attributes
                if re.search(r'(src|href)=["\']http:', content):
                    vulnerabilities.append({
                        'type': 'Mixed Content',
                        'risk_level': 'Medium',
                        'description': 'The page loads resources over HTTP on an HTTPS site, which can lead to man-in-the-middle attacks.',
                        'fix': 'Ensure all resources are loaded over HTTPS.',
                        'location': url,
                        'filename': url
                    })
            
            return vulnerabilities
            
        except requests.exceptions.RequestException as e:
            st.error(f"Error fetching URL: {str(e)}")
            return []

    def analyze_github_repo(self, owner: str, repo: str, token: Optional[str] = None, progress_placeholder=None) -> List[Dict]:
        """Analyze a GitHub repository for potential security vulnerabilities."""
        if not token:
            st.error("GitHub Personal Access Token is required to analyze repositories.")
            return []

        # Use the placeholder from the main function if provided
        progress_container = progress_placeholder if progress_placeholder else st.empty()
        
        try:
            # Initialize GitHub client
            progress_container.markdown(f"""
                <div style='
                    background: rgba(0,0,0,0.2);
                    padding: 20px;
                    border-radius: 10px;
                    border: 1px solid #00ffff;
                    margin-bottom: 20px;
                '>
                    <h3 style='color: #00ffff; margin: 0;'>Repository Analysis Progress</h3>
                    <div style='color: white; margin-top: 10px;'>
                        Authenticating with GitHub for repository: <span style='color: #00ffff;'>{owner}/{repo}</span>
                    </div>
                </div>
            """, unsafe_allow_html=True)
            
            g = Github(token)
            
            # Try to access the repository
            try:
                progress_container.markdown(f"""
                    <div style='
                        background: rgba(0,0,0,0.2);
                        padding: 20px;
                        border-radius: 10px;
                        border: 1px solid #00ffff;
                        margin-bottom: 20px;
                    '>
                        <h3 style='color: #00ffff; margin: 0;'>Repository Analysis Progress</h3>
                        <div style='color: white; margin-top: 10px;'>
                            Verifying access to repository: <span style='color: #00ffff;'>{owner}/{repo}</span>
                        </div>
                    </div>
                """, unsafe_allow_html=True)
                
                repository = g.get_repo(f"{owner}/{repo}")
                vulnerabilities = []

                # Get repository contents
                progress_container.markdown(f"""
                    <div style='
                        background: rgba(0,0,0,0.2);
                        padding: 20px;
                        border-radius: 10px;
                        border: 1px solid #00ffff;
                        margin-bottom: 20px;
                    '>
                        <h3 style='color: #00ffff; margin: 0;'>Repository Analysis Progress</h3>
                        <div style='color: white; margin-top: 10px;'>
                            🔍 Scanning repository structure for <span style='color: #00ffff;'>{owner}/{repo}</span>...
                        </div>
                    </div>
                """, unsafe_allow_html=True)
                
                contents = repository.get_contents("")
                code_files = []

                # Recursively get all code files
                while contents:
                    file_content = contents.pop(0)
                    if file_content.type == "dir":
                        contents.extend(repository.get_contents(file_content.path))
                    elif file_content.path.endswith(('.py', '.js', '.java', '.cpp', '.cs', '.php', '.rb')):
                        code_files.append(file_content)

                # Show initial analysis status
                total_files = len(code_files)
                if total_files == 0:
                    progress_container.markdown(f"""
                        <div style='
                            background: rgba(0,0,0,0.2);
                            padding: 20px;
                            border-radius: 10px;
                            border: 1px solid #ff0000;
                            margin-bottom: 20px;
                        '>
                            <h3 style='color: #ff0000; margin: 0;'>No Code Files Found</h3>
                            <div style='color: white; margin-top: 10px;'>
                                No supported code files were found in repository <span style='color: #ff0000;'>{owner}/{repo}</span>.
                                <br/>
                                Supported extensions: .py, .js, .java, .cpp, .cs, .php, .rb
                            </div>
                        </div>
                    """, unsafe_allow_html=True)
                    return []

                # Analyze each code file
                for index, file in enumerate(code_files, 1):
                    try:
                        # Update progress
                        progress_container.markdown(f"""
                            <div style='
                                background: rgba(0,0,0,0.2);
                                padding: 20px;
                                border-radius: 10px;
                                border: 1px solid #00ffff;
                                margin-bottom: 20px;
                            '>
                                <h3 style='color: #00ffff; margin: 0;'>Repository Analysis Progress</h3>
                                <div style='color: white; margin-top: 10px;'>
                                    📁 Analyzing file ({index}/{total_files}):
                                    <br/>
                                    <span style='color: #00ffff; font-family: monospace;'>{file.path}</span>
                                </div>
                            </div>
                        """, unsafe_allow_html=True)

                        content = file.decoded_content.decode('utf-8')
                        file_vulns = self.analyze_code(content, filename=file.path)
                        
                        # Add repository context to each vulnerability
                        for vuln in file_vulns:
                            vuln['location'] = f"{file.path}:{vuln['location']}"
                            vuln['filename'] = f"{owner}/{repo}/{file.path}"
                        
                        vulnerabilities.extend(file_vulns)
                    except Exception as e:
                        st.warning(f"Could not analyze {file.path}: {str(e)}")

                # Show completion status
                if vulnerabilities:
                    progress_container.markdown(f"""
                        <div style='
                            background: rgba(0,0,0,0.2);
                            padding: 20px;
                            border-radius: 10px;
                            border: 1px solid #ff0000;
                            margin-bottom: 20px;
                        '>
                            <h3 style='color: #ff0000; margin: 0;'>Analysis Complete - Vulnerabilities Found</h3>
                            <div style='color: white; margin-top: 10px;'>
                                Found {len(vulnerabilities)} potential vulnerabilities in {total_files} files of repository <span style='color: #ff0000;'>{owner}/{repo}</span>.
                            </div>
                        </div>
                    """, unsafe_allow_html=True)
                else:
                    progress_container.markdown(f"""
                        <div style='
                            background: rgba(0,0,0,0.2);
                            padding: 20px;
                            border-radius: 10px;
                            border: 1px solid #00ff00;
                            margin-bottom: 20px;
                        '>
                            <h3 style='color: #00ff00; margin: 0;'>Analysis Complete - No Vulnerabilities</h3>
                            <div style='color: white; margin-top: 10px;'>
                                Analyzed {total_files} files in repository <span style='color: #00ff00;'>{owner}/{repo}</span>. No vulnerabilities were found.
                            </div>
                        </div>
                    """, unsafe_allow_html=True)

                return vulnerabilities
                
            except Exception as e:
                st.error(f"Error accessing repository: {str(e)}")
                return []

        except Exception as e:
            st.error(f"Error analyzing repository: {str(e)}")
            return []

    def print_results(self, vulnerabilities: List[Dict]):
        """Print analysis results in a formatted way."""
        if not vulnerabilities:
            st.success("No vulnerabilities found!")
            return

        # Get filename from the first vulnerability or use a default
        filename = next((vuln.get('filename') for vuln in vulnerabilities if vuln.get('filename')), 'Code Input')

        # Define risk level information
        risk_info = {
            'Critical': {
                'icon': '',
                'color': '#ff00ff',  # Purple
                'bg_color': 'rgba(128, 0, 128, 0.2)',
                'border_color': '#ff00ff',
                'description': 'Severe vulnerabilities that require immediate attention'
            },
            'High': {
                'icon': '',
                'color': '#ff0000',  # Red
                'bg_color': 'rgba(255, 0, 0, 0.2)',
                'border_color': '#ff0000',
                'description': 'Significant vulnerabilities that should be addressed soon'
            },
            'Medium': {
                'icon': '',
                'color': '#ffff00',  # Yellow
                'bg_color': 'rgba(255, 255, 0, 0.2)',
                'border_color': '#ffff00',
                'description': 'Moderate vulnerabilities that should be planned for remediation'
            },
            'Low': {
                'icon': '',
                'color': '#00ff00',  # Green
                'bg_color': 'rgba(0, 255, 0, 0.2)',
                'border_color': '#00ff00',
                'description': 'Minor vulnerabilities that pose minimal risk'
            }
        }

        # Count vulnerabilities by risk level
        risk_counts = {'Critical': 0, 'High': 0, 'Medium': 0, 'Low': 0}
        for vuln in vulnerabilities:
            risk_level = vuln.get('risk_level', 'Low')  # Default to Low if not specified
            if risk_level in risk_counts:
                risk_counts[risk_level] += 1

        # Display summary section using st.columns for better layout
        st.markdown("<h2 style='color: #00ffff; margin-bottom: 20px;'>Summary</h2>", unsafe_allow_html=True)
        
        # Display analyzed file
        st.markdown(f"""
            <div style='
                background: rgba(0,0,0,0.2);
                padding: 15px;
                border-radius: 8px;
                margin-bottom: 20px;
                border: 1px solid #00ffff;
            '>
                <strong style='color: #00ffff;'>Analyzed File:</strong>
                <span style='color: white; margin-left: 10px;'>{filename}</span>
            </div>
        """, unsafe_allow_html=True)
        
        cols = st.columns(4)
        for idx, (risk_level, count) in enumerate(risk_counts.items()):
            info = risk_info[risk_level]
            with cols[idx]:
                st.markdown(f"""
                    <div style='
                        background: {info["bg_color"]};
                        border: 1px solid {info["border_color"]};
                        border-radius: 8px;
                        padding: 15px;
                        text-align: center;
                    '>
                        <div style='color: {info["color"]}; font-size: 1.2em; margin-bottom: 5px;'>
                            {info["icon"]} {risk_level}
                        </div>
                        <div style='color: {info["color"]}; font-size: 2em; font-weight: bold;'>
                            {count}
                        </div>
                    </div>
                """, unsafe_allow_html=True)

        # Display detailed findings
        st.markdown("<h2 style='color: #00ffff; margin: 30px 0 20px;'>Detailed Findings</h2>", unsafe_allow_html=True)

        # Group vulnerabilities by risk level
        grouped_vulns = {'Critical': [], 'High': [], 'Medium': [], 'Low': []}
        for vuln in vulnerabilities:
            risk_level = vuln.get('risk_level', 'Low')
            if risk_level in grouped_vulns:
                grouped_vulns[risk_level].append(vuln)

        # Display vulnerabilities grouped by risk level
        for risk_level in ['Critical', 'High', 'Medium', 'Low']:
            vulns = grouped_vulns[risk_level]
            if not vulns:
                continue

            info = risk_info[risk_level]
            
            for vuln in vulns:
                with st.container():
                    st.markdown(f"""
                        <div style='
                            background: {info["bg_color"]};
                            border: 1px solid {info["border_color"]};
                            border-radius: 10px;
                            padding: 20px;
                            margin: 10px 0;
                        '>
                            <div style='
                                display: flex;
                                justify-content: space-between;
                                align-items: center;
                                margin-bottom: 15px;
                            '>
                                <div style='color: {info["color"]}; font-size: 1.2em;'>
                                    {info["icon"]} {vuln.get('type', 'Unknown')}
                                </div>
                                <div style='
                                    background: rgba(0,0,0,0.2);
                                    color: {info["color"]};
                                    padding: 5px 10px;
                                    border-radius: 5px;
                                    font-weight: bold;
                                '>
                                    {risk_level}
                                </div>
                            </div>
                            <div style='background: rgba(0,0,0,0.2); padding: 15px; border-radius: 8px;'>
                                <div style='margin-bottom: 10px;'>
                                    <strong style='color: {info["color"]};'>Location:</strong>
                                    <span style='color: white; margin-left: 10px;'>{vuln.get('location', 'Unknown')}</span>
                                </div>
                                <div style='margin-bottom: 10px;'>
                                    <strong style='color: {info["color"]};'>Description:</strong>
                                    <div style='color: white; margin-top: 5px;'>{vuln.get('description', 'No description available')}</div>
                                </div>
                                <div style='margin-bottom: 10px;'>
                                    <strong style='color: {info["color"]};'>Fix:</strong>
                                    <div style='color: white; margin-top: 5px;'>{vuln.get('fix', 'No fix recommendation available')}</div>
                                </div>
                                <div style='margin-bottom: 10px;'>
                                    <strong style='color: {info["color"]};'>Impact:</strong>
                                    <div style='color: white; margin-top: 5px;'>{self._get_impact_description(vuln.get('type', 'Unknown'))}</div>
                                </div>
                                <div>
                                    <strong style='color: {info["color"]};'>References:</strong>
                                    <div style='color: white; margin-top: 5px;'>{self._get_references(vuln.get('type', 'Unknown'))}</div>
                                </div>
                                <div style='margin-top: 10px;'>
                                    <strong style='color: {info["color"]};'>Code Snippet:</strong>
                                    <pre style='background: rgba(0,0,0,0.2); padding: 10px; border-radius: 8px; color: white;'>
                                        <code style='color: white; font-family: monospace;'>
                                            {vuln.get('code_snippet', 'No code snippet available')}
                                        </code>
                                    </pre>
                                </div>
                            </div>
                        </div>
                    """, unsafe_allow_html=True)

        # Add export options at the bottom
        st.markdown("<h2 style='color: #00ffff; margin: 30px 0 20px;'>Export Results</h2>", unsafe_allow_html=True)
        
        # Create three columns for download buttons with proper styling
        col1, col2, col3 = st.columns(3)
        
        with col1:
            html_report = self.generate_html_report(vulnerabilities, filename)
            st.download_button(
                label="📄 Download HTML Report",
                data=html_report,
                file_name="vulnerability_report.html",
                mime="text/html",
                use_container_width=True,
            )
        
        with col2:
            csv_report = self.generate_csv_report(vulnerabilities, filename)
            st.download_button(
                label="📊 Download CSV Report",
                data=csv_report,
                file_name="vulnerability_report.csv",
                mime="text/csv",
                use_container_width=True,
            )
        
        with col3:
            md_report = self.generate_markdown_report(vulnerabilities, filename)
            st.download_button(
                label="📝 Download Markdown Report",
                data=md_report,
                file_name="vulnerability_report.md",
                mime="text/markdown",
                use_container_width=True,
            )

    def generate_html_report(self, vulnerabilities: List[Dict], filename: str = None) -> str:
        """Generate an HTML report of the vulnerabilities."""
        current_time = datetime.datetime.now(pytz.timezone('Asia/Kolkata')).strftime("%Y-%m-%d %H:%M:%S %Z")
        
        # Get the analyzed file name from the first vulnerability if not provided
        if not filename and vulnerabilities:
            filename = vulnerabilities[0].get('filename', 'Unknown File')
        elif not filename:
            filename = 'Unknown File'
        
        html = f"""
        <!DOCTYPE html>
        <html>
        <head>
            <title>SHASTRA - Security Vulnerability Report</title>
            <style>
                body {{
                    font-family: Arial, sans-serif;
                    line-height: 1.6;
                    margin: 0;
                    padding: 20px;
                    color: white;
                    background-color: #121212;
                }}
                .container {{
                    max-width: 1200px;
                    margin: 0 auto;
                    background: rgba(255, 255, 255, 0.1);
                    backdrop-filter: blur(10px);
                    border-radius: 15px;
                    padding: 30px;
                }}
                h1, h2 {{ color: #ffffff; }}
                h3 {{
                    margin-top: 25px;
                    padding: 10px;
                    background-color: #1E1E1E;
                    border-left: 4px solid #3498db;
                }}
                .risk-indicator {{
                    display: inline-block;
                    width: 12px;
                    height: 12px;
                    border-radius: 50%;
                    margin-right: 5px;
                }}
                .risk-critical {{
                    background-color: #9b59b6;
                }}
                .risk-high {{
                    background-color: #e74c3c;
                }}
                .risk-medium {{
                    background-color: #f39c12;
                }}
                .risk-low {{
                    background-color: #2ecc71;
                }}
                .footer {{
                    margin-top: 50px;
                    text-align: center;
                    font-size: 0.8em;
                    color: #7f8c8d;
                }}
            </style>
        </head>
        <body>
            <div class="container">
                <h1>SHASTRA - Security Vulnerability Report</h1>
                <p><strong>Generated on:</strong> {current_time}</p>
                <p><strong>Analyzed File:</strong> {filename}</p>
                
                <h2>Risk Scale</h2>
                <ul>
                    <li><span class="risk-indicator risk-critical"></span> <strong>Critical</strong>: Severe vulnerabilities that require immediate attention</li>
                    <li><span class="risk-indicator risk-high"></span> <strong>High</strong>: Significant vulnerabilities that should be addressed soon</li>
                    <li><span class="risk-indicator risk-medium"></span> <strong>Medium</strong>: Moderate vulnerabilities that should be planned for remediation</li>
                    <li><span class="risk-indicator risk-low"></span> <strong>Low</strong>: Minor vulnerabilities that pose minimal risk</li>
                </ul>
                
                <h2>Detected Vulnerabilities</h2>
        """
        
        if not vulnerabilities:
            html += "<p>No vulnerabilities detected.</p>"
        else:
            for vuln in vulnerabilities:
                risk_class = vuln['risk_level'].lower()
                html += f"""
                <h3 class="{risk_class}">
                    <span class="risk-indicator risk-{risk_class}"></span>
                    {vuln['type']} ({vuln['risk_level']})
                </h3>
                <div class="vulnerability-details">
                    <p><strong>Description:</strong> {vuln['description']}</p>
                """
                
                if 'fix' in vuln and vuln['fix']:
                    html += f"""
                    <p><strong>Recommended Fix:</strong></p>
                    <pre><code>{vuln['fix']}</code></pre>
                    """
                
                if 'location' in vuln and vuln['location']:
                    html += f"""
                    <p><strong>Location:</strong> {vuln['location']}</p>
                    """
                
                if 'code_snippet' in vuln and vuln['code_snippet']:
                    html += f"""
                    <p><strong>Code Snippet:</strong></p>
                    <pre><code>{vuln['code_snippet']}</code></pre>
                    """
                
                html += "</div>"
        
        html += """
                <div class=\"footer\">
                    <p>SHASTRA - Security Vulnerability Scanner</p>
                    <div style='margin-top:18px; padding:12px 0; color:#00ffff; font-size:0.97em; opacity:0.9;'>
                        <b>Privacy & Data Protection Notice</b><br>
                        <span style='font-size:0.96em; color:#b2f7ff;'>
                        SHASTRA does <b>not</b> store, log, or share any code, URLs, logs, or sensitive data submitted by users.<br>
                        All analysis is performed in-memory and is <b>not retained</b> after your session ends.<br>
                        <b>Your privacy and data security are of utmost importance.</b>
                        </span>
                    </div>
                </div>
            </div>
        </body>
        </html>
        """
        
        return html

    def generate_csv_report(self, vulnerabilities: List[Dict], filename: str = None) -> str:
        """Generate a CSV report of the vulnerabilities."""
        output = io.StringIO()
        writer = csv.writer(output)
        
        # Write header
        current_time = datetime.datetime.now(pytz.timezone('Asia/Kolkata')).strftime("%Y-%m-%d %H:%M:%S %Z")
        
        # Get the analyzed file name from the first vulnerability if not provided
        if not filename and vulnerabilities:
            filename = vulnerabilities[0].get('filename', 'Unknown File')
        elif not filename:
            filename = 'Unknown File'
        
        writer.writerow(['SHASTRA - Security Vulnerability Report'])
        writer.writerow(['Generated on:', current_time])
        writer.writerow(['Analyzed File:', filename])
        writer.writerow([])  # Empty row for spacing
        
        # Write column headers
        writer.writerow(['Type', 'Risk Level', 'Description', 'Recommended Fix', 'Location', 'Code Snippet'])
        
        # Write vulnerability data
        for vuln in vulnerabilities:
            writer.writerow([
                vuln['type'],
                vuln['risk_level'],
                vuln['description'],
                vuln.get('fix', ''),
                vuln.get('location', ''),
                vuln.get('code_snippet', '')
            ])
            
        return output.getvalue()

    def generate_markdown_report(self, vulnerabilities: List[Dict], filename: str = None) -> str:
        """Generate a markdown report of the vulnerabilities."""
        current_time = datetime.datetime.now(pytz.timezone('Asia/Kolkata')).strftime("%Y-%m-%d %H:%M:%S %Z")
        
        # Get the analyzed file name from the first vulnerability if not provided
        if not filename and vulnerabilities:
            filename = vulnerabilities[0].get('filename', 'Unknown File')
        elif not filename:
            filename = 'Unknown File'
        
        md = f"""# SHASTRA - Security Vulnerability Report
Generated on: {current_time}
Analyzed File: {filename}

## Risk Scale
-  **Critical**: Severe vulnerabilities that require immediate attention
-  **High**: Significant vulnerabilities that should be addressed soon
-  **Medium**: Moderate vulnerabilities that should be planned for remediation
-  **Low**: Minor vulnerabilities that pose minimal risk

## Detected Vulnerabilities

"""
        
        for vuln in vulnerabilities:
            risk_emoji = {
                'Critical': '',
                'High': '',
                'Medium': '',
                'Low': ''
            }.get(vuln['risk_level'], '')
            
            md += f"""### {risk_emoji} {vuln['type']} ({vuln['risk_level']})
**Description**: {vuln['description']}

"""
            if 'fix' in vuln and vuln['fix']:
                md += f"""**Recommended Fix**:
```
{vuln['fix']}
```

"""
            if 'location' in vuln and vuln['location']:
                md += f"""**Location**: {vuln['location']}

"""
            if 'code_snippet' in vuln and vuln['code_snippet']:
                md += f"""**Code Snippet**:
```
{vuln['code_snippet']}
```

"""
            
        md += """
---
**Privacy & Data Protection Notice**  
SHASTRA does **not** store, log, or share any code, URLs, logs, or sensitive data submitted by users.  
All analysis is performed in-memory and is **not retained** after your session ends.  
**Your privacy and data security are of utmost importance.**
"""
        return md

    def _determine_risk_level(self, issue_type: str) -> str:
        """Determine risk level based on the type of vulnerability."""
        if issue_type in ['SQL Injection', 'XSS Attack', 'Command Injection', 'Malware']:
            return 'Critical'
        elif issue_type in ['Authentication Failure', 'DoS Attack', 'Port Scan']:
            return 'High'
        elif issue_type in ['File Inclusion', 'Directory Traversal', 'Suspicious IP']:
            return 'Medium'
        return 'Low'

    def _get_fix_recommendation(self, issue_type: str) -> str:
        """Get a fix recommendation based on the type of vulnerability."""
        if issue_type == 'SQL Injection':
            return 'Use parameterized queries or an ORM instead of string concatenation.'
        elif issue_type == 'XSS Attack':
            return 'Use content security policy and sanitize user input before rendering.'
        elif issue_type == 'Command Injection':
            return 'Use prepared statements or parameterized queries instead of string concatenation.'
        elif issue_type == 'Authentication Failure':
            return 'Implement proper authentication and authorization mechanisms.'
        elif issue_type == 'DoS Attack':
            return 'Implement rate limiting and IP blocking to prevent abuse.'
        elif issue_type == 'Port Scan':
            return 'Close unnecessary ports and implement a firewall to restrict access.'
        elif issue_type == 'File Inclusion':
            return 'Use a whitelist approach for file inclusions and validate user input.'
        elif issue_type == 'Directory Traversal':
            return 'Use a whitelist approach for directory traversals and validate user input.'
        elif issue_type == 'Suspicious IP':
            return 'Block the suspicious IP address and monitor for further activity.'
        elif issue_type == 'Malware':
            return 'Remove the malware and update your antivirus software.'
        return 'No fix recommendation available.'

    def _get_impact_description(self, vuln_type: str) -> str:
        """Get detailed impact description for a vulnerability type."""
        impacts = {
            'SQL Injection': 'Can lead to unauthorized database access, data theft, data manipulation, and potential system compromise.',
            'Command Injection': 'Allows execution of arbitrary system commands, potentially leading to complete system takeover.',
            'XSS': 'Can enable attackers to steal user sessions, deface websites, or redirect users to malicious sites.',
            'Hardcoded Secret': 'Exposes sensitive credentials that could be used to gain unauthorized access to systems or services.',
            'Authentication Failure': 'Could allow unauthorized access to protected resources and sensitive data.',
            'File Inclusion': 'May enable attackers to access sensitive files or execute malicious code on the server.',
            'Directory Traversal': 'Allows access to files and directories outside the intended directory, potentially exposing sensitive data.',
            'Port Scan': 'Indicates potential reconnaissance activity, mapping system vulnerabilities for future attacks.',
            'DoS Attack': 'Can make services unavailable to legitimate users, disrupting business operations.',
            'Malware': 'May compromise system integrity, steal data, or use resources for malicious purposes.'
        }
        return impacts.get(vuln_type, 'Impact assessment not available for this vulnerability type.')

    def _get_references(self, vuln_type: str) -> str:
        """Get reference links for a vulnerability type."""
        references = {
            'SQL Injection': '• <a href="https://owasp.org/www-community/attacks/SQL_Injection" target="_blank">OWASP SQL Injection</a><br>• <a href="https://cwe.mitre.org/data/definitions/89.html" target="_blank">CWE-89</a>',
            'Command Injection': '• <a href="https://owasp.org/www-community/attacks/Command_Injection" target="_blank">OWASP Command Injection</a><br>• <a href="https://cwe.mitre.org/data/definitions/77.html" target="_blank">CWE-77</a>',
            'XSS': '• <a href="https://owasp.org/www-community/attacks/xss/" target="_blank">OWASP XSS</a><br>• <a href="https://cwe.mitre.org/data/definitions/79.html" target="_blank">CWE-79</a>',
            'Hardcoded Secret': '• <a href="https://owasp.org/www-community/vulnerabilities/Use_of_hard-coded_password" target="_blank">OWASP Hard-coded Password</a><br>• <a href="https://cwe.mitre.org/data/definitions/798.html" target="_blank">CWE-798</a>',
        }
        return references.get(vuln_type, 'No references available for this vulnerability type.')

def main():
    # Custom CSS for dark theme with neon-style animations
    st.set_page_config(page_title="SHASTRA", layout="wide")
    
    # Large, professional glowing shield logo at top left
    st.markdown('''
        <style>
        .shield-logo {
            position: absolute;
            top: 16px;
            left: 16px;
            z-index: 9999;
            width: 110px;
            height: 110px;
            display: flex;
            align-items: center;
            animation: shield-glow 2s infinite alternate;
        }
        @keyframes shield-glow {
            0% {
                filter: drop-shadow(0 0 8px #00e6ff) drop-shadow(0 0 16px #00cfff);
            }
            100% {
                filter: drop-shadow(0 0 32px #00e6ff) drop-shadow(0 0 64px #00cfff);
            }
        }
        .shield-svg {
            width: 110px;
            height: 110px;
        }
        </style>
        <div class="shield-logo">
            <svg class="shield-svg" viewBox="0 0 110 110" fill="none" xmlns="http://www.w3.org/2000/svg">
                <defs>
                  <radialGradient id="shield-glow" cx="50%" cy="50%" r="50%">
                    <stop offset="0%" stop-color="#00e6ff" stop-opacity="0.9"/>
                    <stop offset="100%" stop-color="#003366" stop-opacity="0.15"/>
                  </radialGradient>
                  <linearGradient id="shield-main" x1="0" y1="0" x2="0" y2="1">
                    <stop offset="0%" stop-color="#1a2a6c"/>
                    <stop offset="100%" stop-color="#00e6ff"/>
                  </linearGradient>
                </defs>
                <path d="M55 10 L100 28 V55 C100 85 55 100 55 100 C55 100 10 85 10 55 V28 Z" fill="url(#shield-glow)" stroke="#00e6ff" stroke-width="4"/>
                <path d="M55 22 L88 34 V55 C88 77 55 88 55 88 C55 88 22 77 22 55 V34 Z" fill="url(#shield-main)" stroke="#00e6ff" stroke-width="2.5"/>
                <path d="M55 38 L70 46 V55 C70 66 55 72 55 72 C55 72 40 66 40 55 V46 Z" fill="#fff" fill-opacity="0.10" stroke="#00e6ff" stroke-width="1.5"/>
            </svg>
        </div>
    ''', unsafe_allow_html=True)
    
    # Initialize the scanner
    scanner = SecurityScanner()
    
    # Custom header with neon effect
    st.markdown("""
        <div class='header'>
            <h1>SHASTRA</h1>
            <h3>Security Vulnerability Scanner</h3>
        </div>
    """, unsafe_allow_html=True)

    # Create tabs for different scanning options
    tabs = st.tabs(["Code Analysis", "URL Analysis", "Log Analysis", "GitHub Analysis"])

    with tabs[0]:
        st.markdown("""
            <div style='margin-bottom: 20px;'>
                <h2 style='color: #00ffff;'>Code Analysis</h2>
                <p>Enter your code below or upload a file to analyze for potential security vulnerabilities.</p>
            </div>
        """, unsafe_allow_html=True)
        
        # Code input area
        code_input = st.text_area("Enter your code here:", height=200)
        code_file = st.file_uploader("Or upload a file:", type=['py', 'js', 'java', 'cpp', 'cs', 'php', 'rb'])
        
        if st.button("🔍 SCAN CODE", key="analyze_code", use_container_width=True):
            # Create a progress placeholder
            progress_placeholder = st.empty()
            progress_placeholder.markdown("""
                <div style='
                    background: rgba(0,0,0,0.2);
                    padding: 20px;
                    border-radius: 10px;
                    border: 1px solid #00ffff;
                    margin-bottom: 20px;
                '>
                    <h3 style='color: #00ffff; margin: 0;'>Code Analysis Progress</h3>
                    <div style='color: white; margin-top: 10px;'>
                        Preparing to analyze code...
                    </div>
                </div>
            """, unsafe_allow_html=True)
            
            with st.spinner("Scanning code for vulnerabilities..."):
                filename = None
                if code_file is not None:
                    progress_placeholder.markdown(f"""
                        <div style='
                            background: rgba(0,0,0,0.2);
                            padding: 20px;
                            border-radius: 10px;
                            border: 1px solid #00ffff;
                            margin-bottom: 20px;
                        '>
                            <h3 style='color: #00ffff; margin: 0;'>Code Analysis Progress</h3>
                            <div style='color: white; margin-top: 10px;'>
                                Reading file: <span style='color: #00ffff;'>{code_file.name}</span>
                            </div>
                        </div>
                    """, unsafe_allow_html=True)
                    code_input = code_file.getvalue().decode()
                    filename = code_file.name
                elif code_input:
                    progress_placeholder.markdown("""
                        <div style='
                            background: rgba(0,0,0,0.2);
                            padding: 20px;
                            border-radius: 10px;
                            border: 1px solid #00ffff;
                            margin-bottom: 20px;
                        '>
                            <h3 style='color: #00ffff; margin: 0;'>Code Analysis Progress</h3>
                            <div style='color: white; margin-top: 10px;'>
                                Analyzing pasted code...
                            </div>
                        </div>
                    """, unsafe_allow_html=True)
                    filename = "Code Input"
                
                if code_input:
                    progress_placeholder.markdown("""
                        <div style='
                            background: rgba(0,0,0,0.2);
                            padding: 20px;
                            border-radius: 10px;
                            border: 1px solid #00ffff;
                            margin-bottom: 20px;
                        '>
                            <h3 style='color: #00ffff; margin: 0;'>Code Analysis Progress</h3>
                            <div style='color: white; margin-top: 10px;'>
                                Scanning for vulnerabilities...
                            </div>
                        </div>
                    """, unsafe_allow_html=True)
                    
                    vulnerabilities = scanner.analyze_code(code_input, filename=filename)
                    
                    if vulnerabilities:
                        progress_placeholder.markdown(f"""
                            <div style='
                                background: rgba(0,0,0,0.2);
                                padding: 20px;
                                border-radius: 10px;
                                border: 1px solid #ff0000;
                                margin-bottom: 20px;
                            '>
                                <h3 style='color: #ff0000; margin: 0;'>Analysis Complete - Vulnerabilities Found</h3>
                                <div style='color: white; margin-top: 10px;'>
                                    Found {len(vulnerabilities)} potential vulnerabilities.
                                </div>
                            </div>
                        """, unsafe_allow_html=True)
                        scanner.print_results(vulnerabilities)
                    else:
                        progress_placeholder.markdown("""
                            <div style='
                                background: rgba(0,0,0,0.2);
                                padding: 20px;
                                border-radius: 10px;
                                border: 1px solid #00ff00;
                                margin-bottom: 20px;
                            '>
                                <h3 style='color: #00ff00; margin: 0;'>Analysis Complete - No Vulnerabilities</h3>
                                <div style='color: white; margin-top: 10px;'>
                                    No vulnerabilities were found in the code.
                                </div>
                            </div>
                        """, unsafe_allow_html=True)
                else:
                    st.warning("Please enter code or upload a file to scan.")

    with tabs[1]:
        st.markdown("""
            <div style='margin-bottom: 20px;'>
                <h2 style='color: #00ffff;'>URL Analysis</h2>
                <p>Enter a URL below to analyze it for potential security vulnerabilities.</p>
            </div>
        """, unsafe_allow_html=True)
        
        # URL input
        url_input = st.text_input("Enter URL:")
        
        if st.button("🌐 SCAN URL", key="analyze_url", use_container_width=True):
            # Create a progress placeholder
            progress_placeholder = st.empty()
            progress_placeholder.markdown("""
                <div style='
                    background: rgba(0,0,0,0.2);
                    padding: 20px;
                    border-radius: 10px;
                    border: 1px solid #00ffff;
                    margin-bottom: 20px;
                '>
                    <h3 style='color: #00ffff; margin: 0;'>URL Analysis Progress</h3>
                    <div style='color: white; margin-top: 10px;'>
                        Preparing to analyze URL...
                    </div>
                </div>
            """, unsafe_allow_html=True)
            
            with st.spinner("Analyzing URL security..."):
                if url_input:
                    progress_placeholder.markdown(f"""
                        <div style='
                            background: rgba(0,0,0,0.2);
                            padding: 20px;
                            border-radius: 10px;
                            border: 1px solid #00ffff;
                            margin-bottom: 20px;
                        '>
                            <h3 style='color: #00ffff; margin: 0;'>URL Analysis Progress</h3>
                            <div style='color: white; margin-top: 10px;'>
                                Fetching URL: <span style='color: #00ffff;'>{url_input}</span>
                            </div>
                        </div>
                    """, unsafe_allow_html=True)
                    
                    vulnerabilities = scanner.analyze_url(url_input)
                    
                    if vulnerabilities:
                        progress_placeholder.markdown(f"""
                            <div style='
                                background: rgba(0,0,0,0.2);
                                padding: 20px;
                                border-radius: 10px;
                                border: 1px solid #ff0000;
                                margin-bottom: 20px;
                            '>
                                <h3 style='color: #ff0000; margin: 0;'>Analysis Complete - Vulnerabilities Found</h3>
                                <div style='color: white; margin-top: 10px;'>
                                    Found {len(vulnerabilities)} potential vulnerabilities in URL.
                                </div>
                            </div>
                        """, unsafe_allow_html=True)
                        scanner.print_results(vulnerabilities)
                    else:
                        progress_placeholder.markdown("""
                            <div style='
                                background: rgba(0,0,0,0.2);
                                padding: 20px;
                                border-radius: 10px;
                                border: 1px solid #00ff00;
                                margin-bottom: 20px;
                            '>
                                <h3 style='color: #00ff00; margin: 0;'>Analysis Complete - No Vulnerabilities</h3>
                                <div style='color: white; margin-top: 10px;'>
                                    No vulnerabilities were found in the URL.
                                </div>
                            </div>
                        """, unsafe_allow_html=True)
                else:
                    st.warning("Please enter a URL to analyze.")

    with tabs[2]:
        st.markdown("""
            <div style='margin-bottom: 20px;'>
                <h2 style='color: #00ffff;'>Log Analysis</h2>
                <p>Enter your logs below or upload a log file to analyze for potential security issues.</p>
            </div>
        """, unsafe_allow_html=True)
        
        # Log input area
        logs_input = st.text_area("Enter your logs here:", height=200)
        logs_file = st.file_uploader("Or upload a log file:", type=['log', 'txt'])
        
        if st.button("📋 ANALYZE LOGS", key="analyze_logs", use_container_width=True):
            # Create a progress placeholder
            progress_placeholder = st.empty()
            progress_placeholder.markdown("""
                <div style='
                    background: rgba(0,0,0,0.2);
                    padding: 20px;
                    border-radius: 10px;
                    border: 1px solid #00ffff;
                    margin-bottom: 20px;
                '>
                    <h3 style='color: #00ffff; margin: 0;'>Log Analysis Progress</h3>
                    <div style='color: white; margin-top: 10px;'>
                        Preparing to analyze logs...
                    </div>
                </div>
            """, unsafe_allow_html=True)
            
            with st.spinner("Analyzing logs..."):
                filename = None
                if logs_file is not None:
                    progress_placeholder.markdown(f"""
                        <div style='
                            background: rgba(0,0,0,0.2);
                            padding: 20px;
                            border-radius: 10px;
                            border: 1px solid #00ffff;
                            margin-bottom: 20px;
                        '>
                            <h3 style='color: #00ffff; margin: 0;'>Log Analysis Progress</h3>
                            <div style='color: white; margin-top: 10px;'>
                                Reading log file: <span style='color: #00ffff;'>{logs_file.name}</span>
                            </div>
                        </div>
                    """, unsafe_allow_html=True)
                    logs_input = logs_file.getvalue().decode()
                    filename = logs_file.name
                
                if logs_input:
                    progress_placeholder.markdown("""
                        <div style='
                            background: rgba(0,0,0,0.2);
                            padding: 20px;
                            border-radius: 10px;
                            border: 1px solid #00ffff;
                            margin-bottom: 20px;
                        '>
                            <h3 style='color: #00ffff; margin: 0;'>Log Analysis Progress</h3>
                            <div style='color: white; margin-top: 10px;'>
                                Scanning logs for security issues...
                            </div>
                        </div>
                    """, unsafe_allow_html=True)
                    
                    vulnerabilities = scanner.analyze_logs(logs_input, filename)
                    
                    if vulnerabilities:
                        progress_placeholder.markdown(f"""
                            <div style='
                                background: rgba(0,0,0,0.2);
                                padding: 20px;
                                border-radius: 10px;
                                border: 1px solid #ff0000;
                                margin-bottom: 20px;
                            '>
                                <h3 style='color: #ff0000; margin: 0;'>Analysis Complete - Issues Found</h3>
                                <div style='color: white; margin-top: 10px;'>
                                    Found {len(vulnerabilities)} potential security issues in logs.
                                </div>
                            </div>
                        """, unsafe_allow_html=True)
                        scanner.print_results(vulnerabilities)
                    else:
                        progress_placeholder.markdown("""
                            <div style='
                                background: rgba(0,0,0,0.2);
                                padding: 20px;
                                border-radius: 10px;
                                border: 1px solid #00ff00;
                                margin-bottom: 20px;
                            '>
                                <h3 style='color: #00ff00; margin: 0;'>Analysis Complete - No Issues</h3>
                                <div style='color: white; margin-top: 10px;'>
                                    No security issues were found in the logs.
                                </div>
                            </div>
                        """, unsafe_allow_html=True)
                else:
                    st.warning("Please enter logs or upload a log file to analyze.")

    with tabs[3]:
        st.markdown("""
            <div style='margin-bottom: 20px;'>
                <h2 style='color: #00ffff;'>GitHub Analysis</h2>
                <p>Enter a GitHub repository URL and your Personal Access Token to analyze it for potential security vulnerabilities.</p>
            </div>
        """, unsafe_allow_html=True)
        
        # GitHub repo input
        repo_url = st.text_input("Enter GitHub repository URL:")
        token = st.text_input("Enter GitHub Personal Access Token:", type="password")
        
        if st.button("⚡ SCAN REPOSITORY", key="analyze_github", use_container_width=True):
            if not repo_url:
                st.error("Please enter a GitHub repository URL.")
            elif not token:
                st.error("Please enter your GitHub Personal Access Token.")
            elif not repo_url.startswith("https://github.com/"):
                st.error("Please enter a valid GitHub repository URL.")
            else:
                try:
                    # Extract owner and repo name from URL
                    parts = repo_url.split("/")
                    owner = parts[-2]
                    repo = parts[-1]
                    
                    # Create a placeholder for the progress display
                    progress_placeholder = st.empty()
                    progress_placeholder.markdown(f"""
                        <div style='
                            background: rgba(0,0,0,0.2);
                            padding: 20px;
                            border-radius: 10px;
                            border: 1px solid #00ffff;
                            margin-bottom: 20px;
                        '>
                            <h3 style='color: #00ffff; margin: 0;'>Repository Analysis Progress</h3>
                            <div style='color: white; margin-top: 10px;'>
                                Initializing analysis for repository: <span style='color: #00ffff;'>{owner}/{repo}</span>
                            </div>
                        </div>
                    """, unsafe_allow_html=True)
                    
                    with st.spinner(f"Analyzing repository: {owner}/{repo}"):
                        vulnerabilities = scanner.analyze_github_repo(owner, repo, token, progress_placeholder)
                        if vulnerabilities:
                            scanner.print_results(vulnerabilities)
                except Exception as e:
                    st.error(f"Error analyzing repository: {str(e)}")

    # Add custom CSS with animations
    st.markdown("""
        <style>
        /* Base theme */
        .stApp {
            background-color: #0a0a0a;
            color: #00ffff;
            font-family: 'Orbitron', sans-serif;
        }

        /* Import fonts */
        @import url('https://fonts.googleapis.com/css2?family=Orbitron:wght@400;500;600;700&display=swap');
        @import url('https://fonts.googleapis.com/css2?family=Fira+Code:wght@400;500&display=swap');

        /* Animations */
        @keyframes neonPulse {
            0% { filter: brightness(1) drop-shadow(0 0 5px #00ffff); }
            50% { filter: brightness(1.2) drop-shadow(0 0 15px #00ffff); }
            100% { filter: brightness(1) drop-shadow(0 0 5px #00ffff); }
        }

        @keyframes borderGlow {
            0% { box-shadow: 0 0 5px #00ffff, inset 0 0 5px #00ffff; }
            50% { box-shadow: 0 0 15px #00ffff, inset 0 0 10px #00ffff; }
            100% { box-shadow: 0 0 5px #00ffff, inset 0 0 5px #00ffff; }
        }

        @keyframes flash {
            0%, 100% { opacity: 0; }
            50% { opacity: 0.7; }
        }

        /* Lightning flash effect */
        .lightning-flash {
            position: fixed;
            top: 0;
            left: 0;
            width: 100%;
            height: 100%;
            background-color: rgba(0, 255, 255, 0.1);
            z-index: 9999;
            animation: flash 0.5s forwards;
            pointer-events: none;
        }

        /* Header styling */
        .header {
            text-align: center;
            margin: -4rem -4rem 2rem -4rem;
            padding: 3rem;
            background: linear-gradient(180deg, rgba(0,255,255,0.1) 0%, rgba(0,0,0,0) 100%);
            border-bottom: 1px solid rgba(0,255,255,0.2);
        }

        .header h1 {
            font-size: 3.5rem;
            margin-bottom: 0.5rem;
            text-transform: uppercase;
            letter-spacing: 4px;
            color: #00ffff;
            text-shadow: 0 0 10px #00ffff;
            animation: neonPulse 3s infinite;
        }

        .header h3 {
            font-size: 1.5rem;
            opacity: 0.9;
            letter-spacing: 2px;
            color: rgba(0,255,255,0.8);
            font-weight: 400;
        }

        /* Tab styling */
        .stTabs {
            background: rgba(10, 10, 30, 0.3);
            padding: 20px;
            border-radius: 15px;
            margin: 2rem 0;
            border: 1px solid rgba(0, 255, 255, 0.2);
        }

        .stTabs [data-baseweb="tab-list"] {
            gap: 15px;
            background: transparent;
            border-bottom: 1px solid rgba(0,255,255,0.2);
            padding-bottom: 1rem;
        }

        .stTabs [data-baseweb="tab"] {
            background: rgba(0, 255, 255, 0.1);
            border: 1px solid rgba(0, 255, 255, 0.3);
            border-radius: 8px;
            padding: 10px 20px;
            transition: all 0.3s ease;
            color: #00ffff !important;
        }

        .stTabs [data-baseweb="tab"]:hover {
            background: rgba(0, 255, 255, 0.2);
            transform: translateY(-2px);
        }

        .stTabs [aria-selected="true"] {
            background: rgba(0, 255, 255, 0.3) !important;
            border: 1px solid #00ffff !important;
            animation: borderGlow 2s infinite;
        }

        /* Input fields styling */
        .stTextInput > div > div > input,
        .stTextArea > div > div > textarea {
            background: rgba(10, 10, 30, 0.4);
            border: 1px solid rgba(0, 255, 255, 0.3);
            border-radius: 8px;
            color: #00ffff;
            font-family: 'Fira Code', monospace;
            padding: 12px;
            transition: all 0.3s ease;
        }

        .stTextInput > div > div > input:focus,
        .stTextArea > div > div > textarea:focus {
            background: rgba(10, 10, 30, 0.6);
            border: 1px solid #00ffff;
            box-shadow: 0 0 15px rgba(0, 255, 255, 0.3);
        }

        /* File uploader styling */
        .stFileUploader {
            padding: 1rem;
            background: rgba(10, 10, 30, 0.2);
            border-radius: 10px;
            border: 1px dashed rgba(0,255,255,0.3);
            transition: all 0.3s ease;
        }

        .stFileUploader:hover {
            border-color: #00ffff;
            background: rgba(10, 10, 30, 0.3);
        }

        /* Button styling */
        .stButton > button {
            background: linear-gradient(45deg, rgba(0, 255, 255, 0.1), rgba(0, 255, 255, 0.2));
            border: 1px solid #00ffff;
            color: #00ffff;
            font-family: 'Orbitron', sans-serif;
            font-weight: 500;
            padding: 12px 30px;
            border-radius: 8px;
            transition: all 0.3s ease;
            text-transform: uppercase;
            letter-spacing: 2px;
            position: relative;
            overflow: hidden;
            margin-top: 1rem;
            width: 100%;
            max-width: 300px;
            animation: borderColorChange 10s infinite;
        }

        .stButton > button:hover {
            transform: translateY(-2px);
            background: linear-gradient(45deg, rgba(0, 255, 255, 0.2), rgba(0, 255, 255, 0.3));
            box-shadow: 0 0 20px rgba(0, 255, 255, 0.4);
        }

        .stButton > button:active {
            transform: translateY(1px);
        }

        /* Results styling */
        .results-container {
            margin-top: 2rem;
            padding: 2rem;
            background: rgba(10, 10, 30, 0.3);
            border-radius: 15px;
            border: 1px solid rgba(0,255,255,0.2);
        }

        .results-container h2 {
            color: #00ffff;
            margin-bottom: 1.5rem;
            font-size: 1.8rem;
            letter-spacing: 2px;
        }

        /* Vulnerability cards */
        .vulnerability-card {
            background: rgba(10, 10, 30, 0.4);
            border-radius: 10px;
            padding: 1.5rem;
            margin: 1rem 0;
            border: 1px solid rgba(0,255,255,0.2);
            transition: all 0.3s ease;
        }

        .vulnerability-card:hover {
            transform: translateY(-3px);
            border-color: #00ffff;
            box-shadow: 0 0 20px rgba(0,255,255,0.2);
        }

        /* Success/warning messages */
        .stSuccess, .stWarning, .stError {
            background: rgba(10, 10, 30, 0.3);
            border: 1px solid;
            border-radius: 8px;
            padding: 1rem;
            margin: 1rem 0;
        }

        .stSuccess {
            border-color: rgba(0,255,0,0.3);
            color: #00ff00;
        }

        .stWarning {
            border-color: rgba(255,165,0,0.3);
            color: #ffa500;
        }

        .stError {
            border-color: rgba(255,0,0,0.3);
            color: #ff0000;
        }

        /* Spinner styling */
        .stSpinner > div > div {
            border-color: #00ffff transparent transparent transparent;
            width: 50px !important;
            height: 50px !important;
        }

        /* Progress bar */
        .stProgress > div > div > div {
            background: linear-gradient(90deg, #00ffff, #ff00ff);
            height: 6px;
            border-radius: 3px;
        }

        /* Scrollbar styling */
        ::-webkit-scrollbar {
            width: 8px;
            height: 8px;
        }

        ::-webkit-scrollbar-track {
            background: rgba(10, 10, 30, 0.2);
            border-radius: 4px;
        }

        ::-webkit-scrollbar-thumb {
            background: rgba(0,255,255,0.3);
            border-radius: 4px;
            border: 2px solid rgba(10, 10, 30, 0.2);
        }

        ::-webkit-scrollbar-thumb:hover {
            background: rgba(0,255,255,0.5);
        }

        /* Code block styling */
        pre {
            background: rgba(10, 10, 30, 0.4) !important;
            border: 1px solid rgba(0,255,255,0.2) !important;
            border-radius: 8px !important;
            padding: 1rem !important;
        }

        code {
            font-family: 'Fira Code', monospace !important;
            color: #00ffff !important;
        }
        
        /* Color-changing animations */
        @keyframes colorChange {
            0% { color: #00ffff; text-shadow: 0 0 10px #00ffff; }
            25% { color: #ff00ff; text-shadow: 0 0 10px #ff00ff; }
            50% { color: #00ff00; text-shadow: 0 0 10px #00ff00; }
            75% { color: #ff00ff; text-shadow: 0 0 10px #ff00ff; }
            100% { color: #00ffff; text-shadow: 0 0 10px #00ffff; }
        }

        @keyframes borderColorChange {
            0% { border-color: #00ffff; box-shadow: 0 0 10px #00ffff; }
            25% { border-color: #ff00ff; box-shadow: 0 0 10px #ff00ff; }
            50% { border-color: #00ff00; box-shadow: 0 0 10px #00ff00; }
            75% { border-color: #ff00ff; box-shadow: 0 0 10px #ff00ff; }
            100% { border-color: #00ffff; box-shadow: 0 0 10px #00ffff; }
        }

        .header h1 {
            animation: colorChange 10s infinite;
        }

        .stButton > button {
            animation: borderColorChange 10s infinite;
        }

        .stTabs [aria-selected="true"] {
            animation: borderColorChange 10s infinite;
        }
        </style>
    """, unsafe_allow_html=True)

if __name__ == '__main__':
    main()

# --- Privacy Self-Declaration Footer ---
def show_privacy_footer():
    st.markdown('''
        <div style="margin-top: 70px; margin-bottom: 40px; padding: 30px 0 20px 0; text-align: center; color: #00ffff; font-size: 1.08em; opacity: 0.92; background: transparent;">
            <hr style="border: 1px solid #00ffff33; margin-bottom: 18px;">
            <b>Privacy & Data Protection Notice</b><br>
            <span style="font-size: 1.01em; color: #b2f7ff;">
                SHASTRA does <b>not</b> store, log, or share any code, URLs, logs, or sensitive data submitted by users.<br>
                All analysis is performed in-memory and is <b>not retained</b> after your session ends.<br>
                <b>Your privacy and data security are of utmost importance.</b>
            </span>
            <br><br>
            <span style="font-size: 0.97em; color: #a0eaff;">
                For more details, please see our <a href="#" style="color:#00ffff; text-decoration:underline;">Privacy Policy</a> and <a href="#" style="color:#00ffff; text-decoration:underline;">Terms of Service</a>.
            </span>
        </div>
    ''', unsafe_allow_html=True)

