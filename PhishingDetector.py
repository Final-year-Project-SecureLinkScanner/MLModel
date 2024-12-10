from flask import Flask, request, jsonify
from flask_cors import CORS

app = Flask(__name__)
CORS(app)  # Enable CORS for cross-origin requests

@app.route('/api/log-url', methods=['POST'])
def log_url():
    try:
        # Debug: Log request headers
        print(f"Request Headers: {request.headers}")
        
        # Retrieve the URL from the request
        data = request.json
        if not data or 'url' not in data:
            return jsonify({'error': 'URL is required'}), 400

        url = data['url'].strip()

        # Log the URL to the terminal
        print(f"Received URL: {url}")

        # Check if the URL matches the hardcoded unsafe URL
        if url == "https://customs-ie.com/ie/schedule":
            return jsonify({
                'status': 'Unsafe',
                'details': 'This URL has been flagged as potentially dangerous.'
            }), 200

        # Respond with a success message for other URLs
        return jsonify({
            'status': 'Safe',
            'details': f'The URL {url} is considered safe.'
        }), 200
    except Exception as e:
        # Handle exceptions and send an error response
        return jsonify({'error': f'An error occurred: {str(e)}'}), 500

if __name__ == '__main__':
    app.run(port=5000)
