import pandas as pd
from sklearn.model_selection import train_test_split
from sklearn.linear_model import LogisticRegression
from sklearn.metrics import accuracy_score

def preprocess_data(data):
    # Handle missing values
    data = data.fillna(method='ffill')
    
    # Convert categorical variables to numeric
    for column in data.select_dtypes(include=['object']).columns:
        data[column] = pd.factorize(data[column])[0]
    
    return data

# Load dataset
data = pd.read_csv('phishing_data.csv')

# Preprocess data
data = preprocess_data(data)

# Split data into features and target
X = data.drop('target', axis=1)
y = data['target']

# Split data into training and testing sets
X_train, X_test, y_train, y_test = train_test_split(X, y, test_size=0.2, random_state=42)

# Initialize and train the model
model = LogisticRegression()
model.fit(X_train, y_train)

# Make predictions
y_pred = model.predict(X_test)

# Output Safe or Not Safe
output = ['Safe' if pred == 0 else 'Not Safe' for pred in y_pred]

# Evaluate the model
accuracy = accuracy_score(y_test, y_pred)
print(f'Accuracy: {accuracy}')

# Print the output
for i, pred in enumerate(output):
    print(f'Instance {i}: {pred}')
