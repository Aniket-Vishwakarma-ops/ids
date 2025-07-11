from flask import Flask, render_template, request, jsonify, flash, redirect, url_for
import pandas as pd
import numpy as np
import joblib
import os
from datetime import datetime
import logging

app = Flask(__name__)
app.secret_key = 'your-secret-key-here'  # Change this to a secure secret key

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

# Global variables for loaded models
scaler = None
pca_model = None
best_model = None
label_encoder = None
model_info = None
feature_names = None

def load_models():
    """Load all saved models and components"""
    global scaler, pca_model, best_model, label_encoder, model_info, feature_names
    
    try:
        model_path = 'saved_models/'
        
        # Load all components
        scaler = joblib.load(f'{model_path}scaler.pkl')
        pca_model = joblib.load(f'{model_path}pca_model.pkl')
        label_encoder = joblib.load(f'{model_path}label_encoder.pkl')
        model_info = joblib.load(f'{model_path}model_info.pkl')
        
        # Load the best model
        best_model_name = model_info['best_model_name'].replace(" ", "_").lower()
        best_model = joblib.load(f'{model_path}best_model_{best_model_name}.pkl')
        
        # Get feature names
        feature_names = model_info['feature_names']
        
        logger.info("All models loaded successfully")
        return True
        
    except Exception as e:
        logger.error(f"Error loading models: {str(e)}")
        return False

def predict_threat(input_data, return_proba=True):
    """
    Predict threat from input data
    """
    try:
        # Define original features (before feature engineering)
        original_features = [
            'Flow Duration', 'Total Fwd Packets', 'Total Backward Packets',
            'Fwd Packets Length Total', 'Bwd Packets Length Total',
            'Flow Bytes/s', 'Flow Packets/s', 'Flow IAT Mean', 'Flow IAT Std',
            'Fwd IAT Mean', 'Fwd IAT Std', 'Bwd IAT Mean', 'Bwd IAT Std',
            'Fwd Header Length', 'Bwd Header Length',
            'Packet Length Mean', 'Packet Length Std',
            'FIN Flag Count', 'SYN Flag Count', 'RST Flag Count', 
            'PSH Flag Count', 'ACK Flag Count', 'URG Flag Count',
            'Avg Packet Size', 'Down/Up Ratio',
            'Init Fwd Win Bytes', 'Init Bwd Win Bytes'
        ]
        
        # Convert input to DataFrame with only original features
        df = pd.DataFrame([input_data], columns=original_features)
        
        # Apply the same feature engineering as training
        df_engineered = engineer_features(df)
        
        # Ensure all feature_names are present after engineering
        for feature in feature_names:
            if feature not in df_engineered.columns:
                df_engineered[feature] = 0.0
        
        # Reorder columns to match training data
        df_engineered = df_engineered[feature_names]
        
        # Scale the features
        data_scaled = scaler.transform(df_engineered)
        
        # Apply PCA
        data_pca = pca_model.transform(data_scaled)
        
        # Make prediction
        prediction = best_model.predict(data_pca)[0]
        prediction_label = label_encoder.inverse_transform([prediction])[0]
        
        # Get probabilities
        probabilities = best_model.predict_proba(data_pca)[0]
        confidence = max(probabilities) * 100
        
        # Create probability dictionary
        prob_dict = {}
        for i, class_name in enumerate(label_encoder.classes_):
            prob_dict[class_name] = probabilities[i] * 100
            
        return {
            'prediction': prediction_label,
            'confidence': confidence,
            'probabilities': prob_dict,
            'is_threat': prediction_label != 'Benign'
        }
        
    except Exception as e:
        logger.error(f"Error in prediction: {str(e)}")
        raise e

def engineer_features(df):
    """
    Apply the same feature engineering as in training
    """
    df_engineered = df.copy()
    
    # Packet ratio features
    df_engineered['Fwd_Bwd_Packet_Ratio'] = df_engineered['Total Fwd Packets'] / (df_engineered['Total Backward Packets'] + 1)
    df_engineered['Packet_Length_Ratio'] = df_engineered['Fwd Packets Length Total'] / (df_engineered['Bwd Packets Length Total'] + 1)
    
    # Flow efficiency features
    df_engineered['Bytes_Per_Packet'] = (df_engineered['Fwd Packets Length Total'] + df_engineered['Bwd Packets Length Total']) / (df_engineered['Total Fwd Packets'] + df_engineered['Total Backward Packets'] + 1)
    df_engineered['Header_Ratio'] = df_engineered['Fwd Header Length'] / (df_engineered['Bwd Header Length'] + 1)
    
    # Time-based features
    df_engineered['IAT_Ratio'] = df_engineered['Fwd IAT Mean'] / (df_engineered['Bwd IAT Mean'] + 1)
    df_engineered['Flow_Duration_Per_Packet'] = df_engineered['Flow Duration'] / (df_engineered['Total Fwd Packets'] + df_engineered['Total Backward Packets'] + 1)
    
    # Flag-based features
    flag_columns = ['FIN Flag Count', 'SYN Flag Count', 'RST Flag Count', 'PSH Flag Count', 'ACK Flag Count', 'URG Flag Count']
    df_engineered['Total_Flags'] = df_engineered[flag_columns].sum(axis=1)
    df_engineered['Suspicious_Flag_Ratio'] = (df_engineered['FIN Flag Count'] + df_engineered['RST Flag Count'] + df_engineered['URG Flag Count']) / (df_engineered['Total_Flags'] + 1)
    
    return df_engineered

@app.route('/')
def index():
    """Home page"""
    return render_template('index.html', model_info=model_info)

@app.route('/predict', methods=['GET', 'POST'])
def predict():
    """Prediction page"""
    if request.method == 'GET':
        # Define original features for the form
        original_features = [
            'Flow Duration', 'Total Fwd Packets', 'Total Backward Packets',
            'Fwd Packets Length Total', 'Bwd Packets Length Total',
            'Flow Bytes/s', 'Flow Packets/s', 'Flow IAT Mean', 'Flow IAT Std',
            'Fwd IAT Mean', 'Fwd IAT Std', 'Bwd IAT Mean', 'Bwd IAT Std',
            'Fwd Header Length', 'Bwd Header Length',
            'Packet Length Mean', 'Packet Length Std',
            'FIN Flag Count', 'SYN Flag Count', 'RST Flag Count', 
            'PSH Flag Count', 'ACK Flag Count', 'URG Flag Count',
            'Avg Packet Size', 'Down/Up Ratio',
            'Init Fwd Win Bytes', 'Init Bwd Win Bytes'
        ]
        return render_template('predict.html', feature_names=original_features)
    
    try:
        # Define original features
        original_features = [
            'Flow Duration', 'Total Fwd Packets', 'Total Backward Packets',
            'Fwd Packets Length Total', 'Bwd Packets Length Total',
            'Flow Bytes/s', 'Flow Packets/s', 'Flow IAT Mean', 'Flow IAT Std',
            'Fwd IAT Mean', 'Fwd IAT Std', 'Bwd IAT Mean', 'Bwd IAT Std',
            'Fwd Header Length', 'Bwd Header Length',
            'Packet Length Mean', 'Packet Length Std',
            'FIN Flag Count', 'SYN Flag Count', 'RST Flag Count', 
            'PSH Flag Count', 'ACK Flag Count', 'URG Flag Count',
            'Avg Packet Size', 'Down/Up Ratio',
            'Init Fwd Win Bytes', 'Init Bwd Win Bytes'
        ]
        
        # Get form data
        input_data = {}
        for feature in original_features:
            value = request.form.get(feature, 0)
            try:
                input_data[feature] = float(value) if value else 0.0
            except (ValueError, TypeError):
                input_data[feature] = 0.0
        
        # Make prediction
        result = predict_threat(input_data)
        
        # Ensure result is properly formatted
        if not result or 'prediction' not in result:
            raise ValueError("Invalid prediction result")
        
        # Add input data to result for display
        result['input_data'] = input_data
        
        return render_template('result.html', result=result)
        
    except Exception as e:
        logger.error(f"Prediction error: {str(e)}")
        flash(f'Error in prediction: {str(e)}', 'error')
        return redirect(url_for('predict'))

@app.route('/api/predict', methods=['POST'])
def api_predict():
    """API endpoint for predictions"""
    try:
        data = request.get_json()
        
        if not data:
            return jsonify({'error': 'No data provided'}), 400
        
        # Define original features
        original_features = [
            'Flow Duration', 'Total Fwd Packets', 'Total Backward Packets',
            'Fwd Packets Length Total', 'Bwd Packets Length Total',
            'Flow Bytes/s', 'Flow Packets/s', 'Flow IAT Mean', 'Flow IAT Std',
            'Fwd IAT Mean', 'Fwd IAT Std', 'Bwd IAT Mean', 'Bwd IAT Std',
            'Fwd Header Length', 'Bwd Header Length',
            'Packet Length Mean', 'Packet Length Std',
            'FIN Flag Count', 'SYN Flag Count', 'RST Flag Count', 
            'PSH Flag Count', 'ACK Flag Count', 'URG Flag Count',
            'Avg Packet Size', 'Down/Up Ratio',
            'Init Fwd Win Bytes', 'Init Bwd Win Bytes'
        ]
        
        # Validate input data
        input_data = {}
        for feature in original_features:
            if feature in data:
                try:
                    input_data[feature] = float(data[feature])
                except (ValueError, TypeError):
                    return jsonify({'error': f'Invalid value for feature: {feature}'}), 400
            else:
                input_data[feature] = 0.0
        
        # Make prediction
        result = predict_threat(input_data)
        
        return jsonify({
            'success': True,
            'prediction': result['prediction'],
            'confidence': round(result['confidence'], 2),
            'probabilities': {k: round(v, 2) for k, v in result['probabilities'].items()},
            'is_threat': result['is_threat'],
            'timestamp': datetime.now().isoformat()
        })
        
    except Exception as e:
        logger.error(f"API prediction error: {str(e)}")
        return jsonify({'error': str(e)}), 500

@app.route('/batch', methods=['GET', 'POST'])
def batch_predict():
    """Batch prediction page"""
    if request.method == 'GET':
        return render_template('batch.html')
    
    try:
        # Check if file was uploaded
        if 'file' not in request.files:
            flash('No file selected', 'error')
            return redirect(url_for('batch_predict'))
        
        file = request.files['file']
        if file.filename == '':
            flash('No file selected', 'error')
            return redirect(url_for('batch_predict'))
        
        if file and file.filename.endswith('.csv'):
            # Read CSV file
            df = pd.read_csv(file)
            
            # Define original features (before feature engineering)
            original_features = [
                'Flow Duration', 'Total Fwd Packets', 'Total Backward Packets',
                'Fwd Packets Length Total', 'Bwd Packets Length Total',
                'Flow Bytes/s', 'Flow Packets/s', 'Flow IAT Mean', 'Flow IAT Std',
                'Fwd IAT Mean', 'Fwd IAT Std', 'Bwd IAT Mean', 'Bwd IAT Std',
                'Fwd Header Length', 'Bwd Header Length',
                'Packet Length Mean', 'Packet Length Std',
                'FIN Flag Count', 'SYN Flag Count', 'RST Flag Count', 
                'PSH Flag Count', 'ACK Flag Count', 'URG Flag Count',
                'Avg Packet Size', 'Down/Up Ratio',
                'Init Fwd Win Bytes', 'Init Bwd Win Bytes'
            ]
            
            # Validate columns - only check for original features
            missing_features = set(original_features) - set(df.columns)
            if missing_features:
                flash(f'Missing features in CSV: {", ".join(missing_features)}', 'error')
                return redirect(url_for('batch_predict'))
            
            # Make predictions for each row
            results = []
            for index, row in df.iterrows():
                try:
                    # Only use original features for input
                    input_data = {feature: float(row[feature]) if pd.notna(row[feature]) else 0.0 
                                for feature in original_features}
                    
                    result = predict_threat(input_data)
                    results.append({
                        'index': index + 1,
                        'prediction': result['prediction'],
                        'confidence': round(result['confidence'], 2),
                        'is_threat': result['is_threat'],
                        'probabilities': {k: round(v, 2) for k, v in result['probabilities'].items()}
                    })
                except Exception as e:
                    logger.error(f"Error processing row {index + 1}: {str(e)}")
                    results.append({
                        'index': index + 1,
                        'prediction': 'Error',
                        'confidence': 0.0,
                        'is_threat': False,
                        'probabilities': {},
                        'error': str(e)
                    })
            
            return render_template('batch_result.html', results=results)
        
        else:
            flash('Please upload a CSV file', 'error')
            return redirect(url_for('batch_predict'))
            
    except Exception as e:
        logger.error(f"Batch prediction error: {str(e)}")
        flash(f'Error processing file: {str(e)}', 'error')
        return redirect(url_for('batch_predict'))

@app.route('/about')
def about():
    """About page"""
    return render_template('about.html', model_info=model_info)

@app.errorhandler(404)
def not_found(error):
    return render_template('404.html'), 404

@app.errorhandler(500)
def internal_error(error):
    return render_template('500.html'), 500

if __name__ == '__main__':
    # Load models on startup
    if load_models():
        print("✓ All models loaded successfully!")
        print(f"✓ Best model: {model_info['best_model_name']}")
        print(f"✓ Model accuracy: {model_info['best_model_score']:.4f}")
        print("✓ Starting Flask application...")
        app.run(debug=True, host='0.0.0.0', port=5000)
    else:
        print("❌ Failed to load models. Please check the saved_models directory.")
