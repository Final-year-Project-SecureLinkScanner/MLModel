# Phishing Detector

This project is a Flask-based web application that predicts whether a given URL is legitimate, suspicious, or a phishing attempt. It uses a trained machine learning model to analyse various features of the URL.

## Features

- **URL Feature Extraction**: Extracts various features from the URL, such as length, presence of IP address, subdomains, SSL state, and more.
- **Machine Learning Model**: Uses a pre-trained model (`Final_Grid_model3_IMP.pkl`) to classify URLs.
- **REST API**: Exposes an endpoint (`/api/predict-url`) to predict the legitimacy of a URL.
- **Flask Framework**: Built using Flask, with CORS enabled for cross-origin requests.

## File Structure

- `PhishingDetector.py`: Main application file containing the Flask app, feature extraction logic, and prediction endpoint.
- `Trained_Models/`: Directory containing the pre-trained machine learning models.
- `requirements.txt`: List of Python dependencies required to run the application.

## How It Works

1. **Feature Extraction**: The application extracts features from the input URL, such as:
   - Whether the URL contains an IP address.
   - The length of the URL.
   - The presence of suspicious characters like `@` or `-`.
   - SSL certificate validity.
   - Domain age and registration length.
   - External links and favicon presence.

2. **Prediction**: The extracted features are passed to the pre-trained machine learning model, which predicts:
   - `PHISHING`: The URL is likely a phishing attempt.
   - `SUSPICIOUS`: The URL has suspicious characteristics.
   - `LEGITIMATE`: The URL is safe.

3. **API Endpoint**: The `/api/predict-url` endpoint accepts a JSON payload with a `url` field and returns the prediction, and confidence scores.

## Steps to Run the Application

### 1. Clone the Repository
Clone this project to your machine.
git clone <https://github.com/Final-year-Project-SecureLinkScanner/MLModel>

### 2. Install dependencies
pip install requirements.txt

### 3. Load the trained model
For this project, Final_Grid_model3_IMP.pkl was used. To find the dataset used if you want to train your own please go to this repo https://github.com/Final-year-Project-SecureLinkScanner/training_model and download the dataset.

### 4. Start application
 - python /Phishingdetector.py
