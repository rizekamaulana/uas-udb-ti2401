"""
Clickjacking Vulnerability Checker
A simple web application to check if a website is vulnerable to clickjacking attacks.
"""

import requests
from flask import Flask, render_template, request, jsonify
from urllib.parse import urlparse

app = Flask(__name__)


def normalize_url(url: str) -> str:
    """Normalize URL by adding scheme if missing."""
    url = url.strip()
    if not url.startswith(('http://', 'https://')):
        url = 'https://' + url
    return url


def check_clickjacking(url: str) -> dict:
    """
    Check if a website is vulnerable to clickjacking.
    
    Returns a dict with:
    - vulnerable: bool indicating if site is vulnerable
    - headers: dict of security headers found
    - message: explanation of the result
    """
    result = {
        'url': url,
        'vulnerable': True,
        'headers': {},
        'x_frame_options': None,
        'csp_frame_ancestors': None,
        'message': '',
        'error': None
    }
    
    try:
        # Normalize URL
        url = normalize_url(url)
        result['url'] = url
        
        # Parse URL to validate
        parsed = urlparse(url)
        if not parsed.netloc:
            result['error'] = 'URL tidak valid'
            return result
        
        # Make request with timeout
        headers = {
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36'
        }
        response = requests.get(url, headers=headers, timeout=10, allow_redirects=True)
        
        # Get all response headers (lowercase for comparison)
        response_headers = {k.lower(): v for k, v in response.headers.items()}
        result['headers'] = dict(response.headers)
        
        # Check X-Frame-Options header
        x_frame_options = response_headers.get('x-frame-options', '').upper()
        if x_frame_options:
            result['x_frame_options'] = x_frame_options
        
        # Check Content-Security-Policy for frame-ancestors
        csp = response_headers.get('content-security-policy', '')
        if 'frame-ancestors' in csp.lower():
            # Extract frame-ancestors value
            for directive in csp.split(';'):
                if 'frame-ancestors' in directive.lower():
                    result['csp_frame_ancestors'] = directive.strip()
                    break
        
        # Determine vulnerability status
        protected = False
        protection_reasons = []
        
        # X-Frame-Options protection
        if x_frame_options in ['DENY', 'SAMEORIGIN']:
            protected = True
            protection_reasons.append(f'X-Frame-Options: {x_frame_options}')
        elif x_frame_options.startswith('ALLOW-FROM'):
            protected = True
            protection_reasons.append(f'X-Frame-Options: {x_frame_options}')
        
        # CSP frame-ancestors protection
        if result['csp_frame_ancestors']:
            csp_value = result['csp_frame_ancestors'].lower()
            if "'none'" in csp_value or "'self'" in csp_value or 'https://' in csp_value:
                protected = True
                protection_reasons.append(f'CSP: {result["csp_frame_ancestors"]}')
        
        result['vulnerable'] = not protected
        
        if protected:
            result['message'] = f"✅ Website TERLINDUNGI dari clickjacking. Proteksi: {', '.join(protection_reasons)}"
        else:
            result['message'] = "⚠️ Website RENTAN terhadap clickjacking! Tidak ditemukan header X-Frame-Options atau CSP frame-ancestors."
        
    except requests.exceptions.Timeout:
        result['error'] = 'Timeout: Website tidak merespons dalam 10 detik'
    except requests.exceptions.SSLError:
        result['error'] = 'SSL Error: Masalah sertifikat SSL'
    except requests.exceptions.ConnectionError:
        result['error'] = 'Connection Error: Tidak dapat terhubung ke website'
    except requests.exceptions.RequestException as e:
        result['error'] = f'Request Error: {str(e)}'
    except Exception as e:
        result['error'] = f'Error: {str(e)}'
    
    return result


@app.route('/')
def index():
    """Render the main page."""
    return render_template('index.html')


@app.route('/check', methods=['POST'])
def check():
    """API endpoint to check clickjacking vulnerability."""
    data = request.get_json()
    url = data.get('url', '').strip()
    
    if not url:
        return jsonify({'error': 'URL tidak boleh kosong'}), 400
    
    result = check_clickjacking(url)
    return jsonify(result)


if __name__ == '__main__':
    app.run(host='0.0.0.0', port=8080, debug=False)
