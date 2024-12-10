from flask import Flask, request, jsonify
from flask_cors import CORS

app = Flask(__name__)
CORS(app)  # Enable CORS for cross-origin requests

@app.route('/api/log-url', methods=['POST'])
def log_url():
    try:
        # Retrieve the URL from the request
        data = request.json
        if not data or 'url' not in data:
            return jsonify({'error': 'URL is required'}), 400

        url = data['url']

        # Log the URL to the terminal
        print(f"Received URL: {url}")

        # Respond with success
        return jsonify({'message': f'URL received: {url}'}), 200
    except Exception as e:
        return jsonify({'error': str(e)}), 500
if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5000)
