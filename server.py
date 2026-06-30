import os
import re
import requests
from flask import Flask, request, jsonify, render_template

app = Flask(__name__, template_folder='templates', static_folder='static')

# Set template folder to current directory's templates folder
TEMPLATE_DIR = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'templates')
app.template_folder = TEMPLATE_DIR

@app.route('/')
def index():
    return render_template('index.html')

@app.route('/api/fetch-otp/outlook', methods=['POST'])
def fetch_otp_outlook():
    data = request.json or {}
    client_id = data.get('client_id')
    refresh_token = data.get('refresh_token')
    email = data.get('email')
    filter_keyword = data.get('filter_keyword', '')

    if not client_id or not refresh_token or not email:
        return jsonify({'success': False, 'error': 'Missing required fields (Client ID, Refresh Token, or Email)'}), 400

    # 1. Exchange Refresh Token for Access Token
    token_url = "https://login.microsoftonline.com/consumers/oauth2/v2.0/token"
    payload = {
        'client_id': client_id,
        'grant_type': 'refresh_token',
        'refresh_token': refresh_token,
        'scope': 'https://graph.microsoft.com/Mail.Read offline_access'
    }
    headers = {'Content-Type': 'application/x-www-form-urlencoded'}

    try:
        token_resp = requests.post(token_url, data=payload, headers=headers)
        if token_resp.status_code != 200:
            return jsonify({
                'success': False, 
                'error': f'Failed to retrieve access token: {token_resp.text}'
            }), 400
        
        token_data = token_resp.json()
        access_token = token_data.get('access_token')
        new_refresh_token = token_data.get('refresh_token', refresh_token)
    except Exception as e:
        return jsonify({'success': False, 'error': f'Token exchange error: {str(e)}'}), 500

    # 2. Query Microsoft Graph for Latest Emails
    graph_url = "https://graph.microsoft.com/v1.0/me/messages"
    graph_headers = {
        'Authorization': f'Bearer {access_token}',
        'Content-Type': 'application/json'
    }
    graph_params = {
        '$top': 5,
        '$select': 'subject,body,from,receivedDateTime',
        '$orderby': 'receivedDateTime desc'
    }

    try:
        msg_resp = requests.get(graph_url, headers=graph_headers, params=graph_params)
        if msg_resp.status_code != 200:
            return jsonify({
                'success': False, 
                'error': f'Failed to fetch messages from Microsoft Graph: {msg_resp.text}'
            }), 400
        
        messages = msg_resp.json().get('value', [])
        otp_code = None
        found_subject = ""
        found_sender = ""

        # Pass 1: ค้นหาจากหัวข้ออีเมล (Subject) ของทุกอีเมลก่อน เพื่อความแม่นยำสูงสุด (มักระบุรหัส OTP ในหัวข้อ)
        for msg in messages:
            sender = msg.get('from', {}).get('emailAddress', {}).get('address', '')
            subject = msg.get('subject', '')
            
            if not filter_keyword or filter_keyword.lower() in sender.lower() or filter_keyword.lower() in subject.lower():
                otp_match = re.search(r'\b\d{5,6}\b', subject)
                if otp_match:
                    otp_code = otp_match.group(0)
                    found_subject = subject
                    found_sender = sender
                    break

        # Pass 2: ถ้าไม่มีหัวข้ออีเมลไหนมีรหัสผ่านเลย ค่อยสแกนเนื้อหาอีเมล (Body)
        if not otp_code:
            for msg in messages:
                sender = msg.get('from', {}).get('emailAddress', {}).get('address', '')
                subject = msg.get('subject', '')
                body_content = msg.get('body', {}).get('content', '')
                
                if not filter_keyword or filter_keyword.lower() in sender.lower() or filter_keyword.lower() in subject.lower():
                    otp_match = re.search(r'\b\d{5,6}\b', body_content)
                    if otp_match:
                        otp_keywords = ["รหัส", "code", "otp", "ยืนยัน", "confirm", "security", "password", "reset", "verification"]
                        has_keyword = any(kw in subject.lower() or kw in body_content.lower() for kw in otp_keywords)
                        
                        if filter_keyword or has_keyword:
                            otp_code = otp_match.group(0)
                            found_subject = subject
                            found_sender = sender
                            break

        if otp_code:
            return jsonify({
                'success': True,
                'otp': otp_code,
                'subject': found_subject,
                'sender': found_sender,
                'new_refresh_token': new_refresh_token
            })
        else:
            filter_text = f"matching '{filter_keyword}'" if filter_keyword else "from any sender"
            return jsonify({
                'success': False, 
                'error': f'No OTP code (6-digit) {filter_text} found in the latest emails.'
            }), 404

    except Exception as e:
        return jsonify({'success': False, 'error': f'Graph API query error: {str(e)}'}), 500

@app.route('/api/fetch-otp/custom', methods=['POST'])
def fetch_otp_custom():
    data = request.json or {}
    api_url = data.get('api_url')
    token = data.get('token')

    if not api_url or not token:
        return jsonify({'success': False, 'error': 'Missing API URL or Token'}), 400

    headers = {
        'Authorization': f'Bearer {token}',
        'Accept': 'application/json'
    }

    try:
        resp = requests.get(api_url, headers=headers, timeout=10)
        if resp.status_code != 200:
            resp = requests.post(api_url, headers=headers, json={}, timeout=10)

        if resp.status_code != 200:
            return jsonify({
                'success': False, 
                'error': f'Custom API returned status code {resp.status_code}: {resp.text}'
            }), 400

        resp_data = resp.text
        otp_match = re.search(r'\b\d{5,6}\b', resp_data)
        
        if otp_match:
            return jsonify({
                'success': True,
                'otp': otp_match.group(0),
                'raw_response': resp_data[:500]
            })
        else:
            return jsonify({
                'success': False, 
                'error': 'No 5 or 6 digit OTP code found in the API response.',
                'raw_response': resp_data[:500]
            }), 404

    except Exception as e:
        return jsonify({'success': False, 'error': f'Custom API request error: {str(e)}'}), 500

if __name__ == '__main__':
    os.makedirs(TEMPLATE_DIR, exist_ok=True)
    print(f"Starting server on http://localhost:5000")
    app.run(host='0.0.0.0', port=5000, debug=True)
