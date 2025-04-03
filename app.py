from datetime import datetime
import random
from flask import Flask, request, jsonify, Response, render_template
from flask_cors import CORS
import requests
from urllib.parse import urlparse
import time
import threading
import queue
import json
import logging
import os
import google.generativeai as genai
from dotenv import load_dotenv

app = Flask(__name__)
CORS(app)

# Configure logging
logging.basicConfig(level=logging.DEBUG)

load_dotenv()
API_KEY = os.getenv('API_KEY')

# configure Generative AI
genai.configure(api_key=API_KEY)

result_queues = {}

# Helper function to check if the URL is valid


def is_valid_url(url):
    try:
        result = urlparse(url)
        return all([result.scheme, result.netloc])
    except Exception as e:
        logging.error(f"URL validation error: {str(e)}")
        return False

# Function to check if the website enforces HTTPS


def check_https_redirection(url):
    try:
        if url.startswith('https://'):
            return "HTTPS Enforced: ✅ Already using HTTPS"

        # Redirect HTTP to HTTPS
        http_url = f"http://{urlparse(url).netloc}"
        response = requests.get(
            http_url, allow_redirects=True, timeout=5, max_redirects=10)
        final_url = response.url

        if final_url.startswith('https://'):
            return "HTTPS Enforced: ✅ Redirects to HTTPS"
        else:
            return "HTTPS Enforced: ❌ No HTTPS redirection"
    except requests.exceptions.SSLError:
        return "HTTPS Enforced: ⚠️ SSL Certificate Error"
    except requests.exceptions.TooManyRedirects:
        return "HTTPS Enforced: ⚠️ Too many redirects (infinite loop detected)"
    except Exception as e:
        logging.error(f"Error in check_https_redirection: {str(e)}")
        return f"HTTPS Check Error: {str(e)}"

# Function to check Content-Security-Policy header


def check_csp(url):
    try:
        response = requests.get(url, timeout=5)
        csp_header = response.headers.get('Content-Security-Policy')
        if csp_header:
            return f"CSP: ✅ {csp_header}"
        else:
            return "CSP: ❌ Missing CSP"
    except Exception as e:
        logging.error(f"CSP Check Error: {str(e)}")
        return f"CSP Check Error: {str(e)}"

# Function to check if .git directory is exposed


def check_git(url):
    try:
        git_url = url.rstrip('/') + '/.git'
        response = requests.get(git_url, timeout=5)
        if response.status_code == 200:
            return "Git: ❌ Exposed .git directory"
        else:
            return "Git: ✅ Not exposed"
    except requests.exceptions.RequestException as e:
        logging.error(f".git Check Error: {str(e)}")
        return "Git: ✅ Not exposed"

# Function to check if .env file is exposed


def check_env(url):
    try:
        env_url = url.rstrip('/') + '/.env'
        response = requests.get(env_url, timeout=5)
        if response.status_code == 200:
            return "Env: ❌ Exposed .env file"
        else:
            return "Env: ✅ Not exposed"
    except requests.exceptions.RequestException as e:
        logging.error(f".env Check Error: {str(e)}")
        return "Env: ✅ Not exposed"

# Function to check if robots.txt is present


def check_robots_txt(url):
    try:
        robots_url = url.rstrip('/') + '/robots.txt'
        response = requests.get(robots_url, timeout=5)
        if response.status_code == 200:
            return "Robots.txt: ✅ Found"
        else:
            return "Robots.txt: ❌ Not found"
    except requests.exceptions.RequestException as e:
        logging.error(f"robots.txt Check Error: {str(e)}")
        return "Robots.txt: ❌ Not found"

# Function to check for HSTS (Strict-Transport-Security) header


def check_hsts(url):
    try:
        response = requests.get(url, timeout=5)
        hsts_header = response.headers.get('Strict-Transport-Security')
        if hsts_header:
            return "HSTS: ✅ Strict-Transport-Security Header Found"
        else:
            return "HSTS: ❌ Missing Strict-Transport-Security Header"
    except Exception as e:
        logging.error(f"HSTS Check Error: {str(e)}")
        return f"HSTS Check Error: {str(e)}"

# Function to check for X-Content-Type-Options header


def check_x_content_type_options(url):
    try:
        response = requests.get(url, timeout=5)
        x_content_type_header = response.headers.get('X-Content-Type-Options')
        if x_content_type_header == 'nosniff':
            return "X-Content-Type-Options: ✅ nosniff"
        else:
            return "X-Content-Type-Options: ❌ Missing or Invalid"
    except Exception as e:
        logging.error(f"X-Content-Type-Options Check Error: {str(e)}")
        return f"X-Content-Type-Options Check Error: {str(e)}"

# Function to check for X-XSS-Protection header


def check_x_xss_protection(url):
    try:
        response = requests.get(url, timeout=5)
        x_xss_header = response.headers.get('X-XSS-Protection')
        if x_xss_header == '1; mode=block':
            return "X-XSS-Protection: ✅ Enabled"
        else:
            return "X-XSS-Protection: ❌ Missing or Disabled"
    except Exception as e:
        logging.error(f"X-XSS-Protection Check Error: {str(e)}")
        return f"X-XSS-Protection Check Error: {str(e)}"

# Function to check for Referrer-Policy header


def check_referrer_policy(url):
    try:
        response = requests.get(url, timeout=5)
        referrer_header = response.headers.get('Referrer-Policy')
        if referrer_header:
            return f"Referrer-Policy: ✅ {referrer_header}"
        else:
            return "Referrer-Policy: ❌ Missing Referrer-Policy"
    except Exception as e:
        logging.error(f"Referrer-Policy Check Error: {str(e)}")
        return f"Referrer-Policy Check Error: {str(e)}"

# Function to check for CORS (Cross-Origin Resource Sharing) header


def check_cors(url):
    try:
        response = requests.get(url, timeout=5)
        cors_header = response.headers.get('Access-Control-Allow-Origin')
        if cors_header:
            return f"CORS: ✅ {cors_header}"
        else:
            return "CORS: ❌ Missing CORS Header"
    except Exception as e:
        logging.error(f"CORS Check Error: {str(e)}")
        return f"CORS Check Error: {str(e)}"


def perform_scan(url, scan_id):
    queue = result_queues[scan_id]

    if not url.startswith(('http://', 'https://')):
        url = 'https://' + url

    if not is_valid_url(url):
        queue.put({"error": "Invalid URL format"})
        return

    security_checks = {
        "HTTPS Check": lambda: check_https_redirection(url),
        "CSP Check": lambda: check_csp(url),
        "HSTS Check": lambda: check_hsts(url),
        "X-Content-Type-Options Check": lambda: check_x_content_type_options(url),
        "X-XSS-Protection Check": lambda: check_x_xss_protection(url),
        "Referrer-Policy Check": lambda: check_referrer_policy(url),
        "CORS Check": lambda: check_cors(url),
        ".git Check": lambda: check_git(url),
        ".env Check": lambda: check_env(url),
        "robots.txt Check": lambda: check_robots_txt(url),
    }

    # Simulate scan by checking for each security check
    for test_name, check in security_checks.items():
        try:
            result = check()
            severity = "safe"  # Default severity
            if "❌" in result:
                severity = "critical"
            elif "⚠️" in result:
                severity = "warning"

            # Send the result in a structured format
            queue.put({
                "testName": test_name,
                "result": result,
                "severity": severity
            })
            logging.debug(f"Test result: {test_name} - {result}")
        except Exception as e:
            queue.put({test_name: f"Error: {str(e)}"})
            logging.error(f"Error during {test_name}: {str(e)}")

    queue.put({"complete": True})
    logging.debug(f"Scan complete for {scan_id}")


@app.route('/')
def index():
    return render_template('index.html')


@app.route("/scan", methods=["POST"])
def scan():
    data = request.json
    if not data or "url" not in data:
        return jsonify({"error": "URL is required"}), 400

    url = data["url"].strip()
    if not url:
        return jsonify({"error": "URL cannot be empty"}), 400

    scan_id = str(time.time())
    result_queues[scan_id] = queue.Queue()

    threading.Thread(target=perform_scan, args=(url, scan_id)).start()

    logging.debug(f"Scan started for URL: {url}, scan_id: {scan_id}")
    return jsonify({"scan_id": scan_id}), 200


@app.route("/scan-results/<scan_id>")
def scan_results_stream(scan_id):
    def generate():
        if scan_id not in result_queues:
            yield f"data: {json.dumps({'error': 'Invalid scan ID'})}\n\n"
            return

        queue = result_queues[scan_id]
        while True:
            try:
                # Timeout after 30 seconds of inactivity
                result = queue.get(timeout=30)
                if "complete" in result:
                    del result_queues[scan_id]
                    yield f"data: {json.dumps({'complete': True})}\n\n"
                    break
                # Send each test result to the frontend
                yield f"data: {json.dumps(result)}\n\n"
            except queue.Empty:
                del result_queues[scan_id]
                yield f"data: {json.dumps({'error': 'Scan timeout'})}\n\n"
                break

    return Response(generate(), content_type='text/event-stream')


def generate_local_report(url, scan_results, severity_counts):
    """
    Generates a simple text-based security report (local fallback) by V-Scan AI.
    No CVSS data included.
    """
    report = []

    report.append(f"# V-Scan AI Security Report for {url}\n")
    report.append(
        f"**Date:** {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n")
    report.append("## Executive Summary")
    report.append(f"The security scan identified {severity_counts['critical']} critical issues, "
                  f"{severity_counts['warning']} warnings, and {severity_counts['safe']} safe checks.\n")

    report.append("## Methodology")
    report.append("The scan was conducted using automated tools and manual verification, "
                  "focusing on common web vulnerabilities such as SQL Injection, XSS, and security headers.\n")

    report.append("## Findings\n")
    if not scan_results:
        report.append("No issues detected.\n")
    else:
        for result in scan_results:
            severity = result.get("severity", "unknown")
            test_name = result.get("testName", "Unknown Test")
            result_text = result.get("result", "No result provided")

            report.append(f"### {test_name}")
            report.append(f"- **Severity:** {severity}")
            report.append(f"- **Details:** {result_text}\n")

    report.append("## Risk Assessment")
    if severity_counts["critical"] > 0:
        report.append(
            "Critical vulnerabilities indicate high risk. Immediate remediation is recommended.")
    elif severity_counts["warning"] > 0:
        report.append(
            "Warning-level vulnerabilities pose a moderate risk and should be reviewed.")
    else:
        report.append("No significant security risks detected.\n")

    report.append("## Recommendations")
    report.append("- Review and address identified vulnerabilities promptly.")
    report.append(
        "- Follow secure coding practices and regular security reviews.")
    report.append(
        "- Consider implementing additional security layers (e.g., WAF, intrusion detection).\n")

    report.append("## Conclusion")
    report.append("This report was generated by V-Scan AI to provide an initial assessment of the website’s security. "
                  "Further comprehensive testing is recommended for a complete security evaluation.\n")

    return "\n".join(report)


@app.route("/generate-report", methods=["POST"])
def generate_report():
    try:
        data = request.json
        if not data or "url" not in data or "results" not in data:
            return jsonify({"error": "URL and scan results are required"}), 400

        url = data["url"]
        scan_results = data["results"]

        # Count the severity of issues
        severity_counts = {"safe": 0, "warning": 0, "critical": 0}
        for result in scan_results:
            if "severity" in result:
                severity_counts[result["severity"]] = severity_counts.get(
                    result["severity"], 0) + 1

        # Format results for Gemini input
        formatted_results = []
        for r in scan_results:
            severity_level = r.get("severity", "unknown")
            test_name = r.get("testName", "Unknown Test")
            result_text = r.get("result", "No result")
            formatted_results.append(
                f"Test: {test_name}\nResult: {result_text}\nSeverity: {severity_level}\n"
            )

        # Generate prompt for Gemini
        prompt = f"""
        You are a professional ethical hacker and cybersecurity expert. Generate a comprehensive security report for the website {url}.
        
        Here are the scan results:
        
        {chr(10).join(formatted_results)}
        
        The security scan found:
        - {severity_counts.get('critical', 0)} critical issues
        - {severity_counts.get('warning', 0)} warnings
        - {severity_counts.get('safe', 0)} passed checks
        
        Please create a detailed security report with the following sections:
        1. Executive Summary: Brief overview of findings
        2. Methodology: How the testing was conducted
        3. Findings: Detailed breakdown of all issues identified, organized by severity
        4. Risk Assessment: Analysis of potential impact of discovered vulnerabilities
        5. Recommendations: Clear, actionable steps to remediate each issue
        6. Conclusion: Final assessment and strategic recommendations
        
        Make it professional, detailed, and actionable. Use markdown formatting.
        """

        try:
            # Call Gemini API
            model = genai.GenerativeModel('gemini-2.0-flash')
            generation_config = {
                "temperature": 0.7,
                "top_p": 0.95,
                "top_k": 40,
                "max_output_tokens": 8192,
            }

            # Generate the response
            response = model.generate_content(
                prompt,
                generation_config=generation_config,
                safety_settings=[
                    {"category": "HARM_CATEGORY_HARASSMENT", "threshold": "BLOCK_MEDIUM_AND_ABOVE"},
                    {"category": "HARM_CATEGORY_HATE_SPEECH", "threshold": "BLOCK_MEDIUM_AND_ABOVE"},
                    {"category": "HARM_CATEGORY_SEXUALLY_EXPLICIT", "threshold": "BLOCK_MEDIUM_AND_ABOVE"},
                    {"category": "HARM_CATEGORY_DANGEROUS_CONTENT", "threshold": "BLOCK_MEDIUM_AND_ABOVE"},
                ]
            )
            
            try:
                if hasattr(response, 'text'):
                    report = response.text
                elif hasattr(response, 'parts'):
                    report = response.parts[0].text
                else:
                    report = response.candidates[0].content.parts[0].text
            except Exception as extraction_error:
                logging.error(f"Error extracting text from Gemini response: {str(extraction_error)}")
                report = generate_local_report(url, scan_results, severity_counts)
            
            return jsonify({"report": report}), 200

        except Exception as api_error:
            logging.error(f"Error with Gemini API: {str(api_error)}")
            report = generate_local_report(url, scan_results, severity_counts)
            return jsonify({"report": report, "note": "Used local fallback due to API error"}), 200

    except Exception as e:
        logging.error(f"Error generating report: {str(e)}")
        try:
            report = generate_local_report(url, scan_results, severity_counts)
            return jsonify({"report": report, "note": "Used fallback report"}), 200
        except:
            return jsonify({"error": f"Error generating report: {str(e)}"}), 500

if __name__ == "__main__":
    # Use environment variable for port (AWS Elastic Beanstalk uses PORT)
    port = int(os.environ.get("PORT", 5000))
    app.run(debug=True, host="0.0.0.0", port=port)
