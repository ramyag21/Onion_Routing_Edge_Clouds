"""
TinyML-based DDoS Detection for Edge Cloud API Gateways.

This module implements lightweight machine learning models (TinyML, LSTM, GRU)
for real-time DDoS attack detection in resource-constrained edge environments.
"""

import numpy as np
import pandas as pd
from typing import Dict, List, Tuple, Optional
import joblib
import logging
from datetime import datetime, timedelta
from dataclasses import dataclass

import tensorflow as tf
from tensorflow import keras
from tensorflow.keras import layers
from sklearn.preprocessing import StandardScaler, LabelEncoder
from sklearn.model_selection import train_test_split
from sklearn.metrics import classification_report, confusion_matrix
import shap
import lime
from lime.tabular import LimeTabularExplainer


@dataclass
class NetworkFeatures:
    """Network traffic features for DDoS detection."""
    packet_rate: float
    byte_rate: float
    flow_duration: float
    packet_size_variance: float
    protocol_distribution: Dict[str, float]
    port_distribution: Dict[int, float]
    timestamp_variance: float
    connection_count: int
    unique_source_ips: int
    payload_entropy: float


class FeatureExtractor:
    """Extract features from network traffic for ML model input."""
    
    def __init__(self):
        self.logger = logging.getLogger("FeatureExtractor")
        self.time_window_seconds = 10
        self.traffic_history = []
    
    def extract_features_from_message(self, message, agent_metrics) -> NetworkFeatures:
        """Extract features from a single message and agent metrics."""
        current_time = datetime.now()
        
        # Calculate packet rate (requests per second)
        packet_rate = agent_metrics.request_count / max(1, 
            (current_time - message.timestamp).total_seconds())
        
        # Calculate byte rate
        byte_rate = len(message.payload) / max(1,
            (current_time - message.timestamp).total_seconds())
        
        # Flow duration (time since first packet)
        flow_duration = (current_time - message.timestamp).total_seconds()
        
        # Packet size variance (simplified)
        packet_size_variance = len(message.payload) / 1000.0  # Normalized
        
        # Protocol distribution (simplified)
        protocol_distribution = {"http": 1.0, "https": 0.0}
        
        # Port distribution (mock data)
        port_distribution = {80: 0.8, 443: 0.2}
        
        # Timestamp variance
        timestamp_variance = 0.1  # Placeholder
        
        # Connection count
        connection_count = len(message.headers)
        
        # Unique source IPs (simplified)
        unique_source_ips = 1
        
        # Payload entropy (measure of randomness)
        payload_entropy = self._calculate_entropy(message.payload)
        
        return NetworkFeatures(
            packet_rate=packet_rate,
            byte_rate=byte_rate,
            flow_duration=flow_duration,
            packet_size_variance=packet_size_variance,
            protocol_distribution=protocol_distribution,
            port_distribution=port_distribution,
            timestamp_variance=timestamp_variance,
            connection_count=connection_count,
            unique_source_ips=unique_source_ips,
            payload_entropy=payload_entropy
        )
    
    def _calculate_entropy(self, data: bytes) -> float:
        """Calculate Shannon entropy of data."""
        if len(data) == 0:
            return 0.0
        
        # Count byte frequencies
        byte_counts = np.bincount(np.frombuffer(data, dtype=np.uint8))
        probabilities = byte_counts / len(data)
        
        # Remove zero probabilities
        probabilities = probabilities[probabilities > 0]
        
        # Calculate entropy
        entropy = -np.sum(probabilities * np.log2(probabilities))
        return entropy
    
    def features_to_array(self, features: NetworkFeatures) -> np.ndarray:
        """Convert NetworkFeatures to numpy array for ML model input."""
        return np.array([
            features.packet_rate,
            features.byte_rate,
            features.flow_duration,
            features.packet_size_variance,
            features.timestamp_variance,
            features.connection_count,
            features.unique_source_ips,
            features.payload_entropy,
            list(features.protocol_distribution.values())[0],  # HTTP ratio
            list(features.port_distribution.values())[0]       # Port 80 ratio
        ])


class TinyMLModel:
    """Lightweight TinyML model for resource-constrained edge devices."""
    
    def __init__(self, input_size: int = 10):
        self.input_size = input_size
        self.model = None
        self.scaler = StandardScaler()
        self.logger = logging.getLogger("TinyMLModel")
        
    def build_model(self) -> keras.Model:
        """Build a lightweight neural network model."""
        model = keras.Sequential([
            layers.Dense(16, activation='relu', input_shape=(self.input_size,)),
            layers.Dropout(0.2),
            layers.Dense(8, activation='relu'),
            layers.Dropout(0.1),
            layers.Dense(1, activation='sigmoid')  # Binary classification
        ])
        
        model.compile(
            optimizer='adam',
            loss='binary_crossentropy',
            metrics=['accuracy', 'precision', 'recall']
        )
        
        return model
    
    def train(self, X_train: np.ndarray, y_train: np.ndarray, 
              X_val: np.ndarray, y_val: np.ndarray) -> Dict:
        """Train the TinyML model."""
        self.logger.info("Training TinyML model...")
        
        # Scale features
        X_train_scaled = self.scaler.fit_transform(X_train)
        X_val_scaled = self.scaler.transform(X_val)
        
        # Build model
        self.model = self.build_model()
        
        # Train model
        history = self.model.fit(
            X_train_scaled, y_train,
            validation_data=(X_val_scaled, y_val),
            epochs=50,
            batch_size=32,
            verbose=0,
            callbacks=[
                keras.callbacks.EarlyStopping(patience=10, restore_best_weights=True)
            ]
        )
        
        # Evaluate model
        val_loss, val_acc, val_precision, val_recall = self.model.evaluate(
            X_val_scaled, y_val, verbose=0
        )
        
        # Calculate model size
        model_size = self.get_model_size()
        
        results = {
            'validation_accuracy': val_acc,
            'validation_precision': val_precision,
            'validation_recall': val_recall,
            'model_size_kb': model_size,
            'training_history': history.history
        }
        
        self.logger.info(f"TinyML training complete. Accuracy: {val_acc:.4f}, "
                        f"Size: {model_size:.2f} KB")
        
        return results
    
    def predict(self, features: np.ndarray) -> Tuple[float, float]:
        """Predict if traffic pattern indicates DDoS attack."""
        if self.model is None:
            raise ValueError("Model not trained yet")
        
        # Scale features
        features_scaled = self.scaler.transform(features.reshape(1, -1))
        
        # Get prediction
        prediction = self.model.predict(features_scaled, verbose=0)[0][0]
        confidence = abs(prediction - 0.5) * 2  # Convert to 0-1 confidence
        
        return float(prediction), float(confidence)
    
    def get_model_size(self) -> float:
        """Calculate model size in KB."""
        if self.model is None:
            return 0.0
        
        # Save model temporarily to calculate size
        temp_path = "/tmp/temp_model.h5"
        self.model.save(temp_path)
        
        import os
        size_bytes = os.path.getsize(temp_path)
        size_kb = size_bytes / 1024
        
        # Clean up
        os.remove(temp_path)
        
        return size_kb


class LSTMModel:
    """LSTM-based model for sequence analysis of network traffic."""
    
    def __init__(self, sequence_length: int = 10, input_features: int = 10):
        self.sequence_length = sequence_length
        self.input_features = input_features
        self.model = None
        self.scaler = StandardScaler()
        self.logger = logging.getLogger("LSTMModel")
    
    def build_model(self) -> keras.Model:
        """Build LSTM model for sequence-based DDoS detection."""
        model = keras.Sequential([
            layers.LSTM(32, return_sequences=True, 
                       input_shape=(self.sequence_length, self.input_features)),
            layers.Dropout(0.2),
            layers.LSTM(16, return_sequences=False),
            layers.Dropout(0.2),
            layers.Dense(8, activation='relu'),
            layers.Dense(1, activation='sigmoid')
        ])
        
        model.compile(
            optimizer='adam',
            loss='binary_crossentropy',
            metrics=['accuracy', 'precision', 'recall']
        )
        
        return model
    
    def prepare_sequences(self, X: np.ndarray, y: np.ndarray) -> Tuple[np.ndarray, np.ndarray]:
        """Prepare sequential data for LSTM training."""
        sequences_X = []
        sequences_y = []
        
        for i in range(len(X) - self.sequence_length + 1):
            sequences_X.append(X[i:i + self.sequence_length])
            sequences_y.append(y[i + self.sequence_length - 1])
        
        return np.array(sequences_X), np.array(sequences_y)
    
    def train(self, X_train: np.ndarray, y_train: np.ndarray,
              X_val: np.ndarray, y_val: np.ndarray) -> Dict:
        """Train the LSTM model."""
        self.logger.info("Training LSTM model...")
        
        # Scale features
        X_train_scaled = self.scaler.fit_transform(X_train)
        X_val_scaled = self.scaler.transform(X_val)
        
        # Prepare sequences
        X_train_seq, y_train_seq = self.prepare_sequences(X_train_scaled, y_train)
        X_val_seq, y_val_seq = self.prepare_sequences(X_val_scaled, y_val)
        
        # Build model
        self.model = self.build_model()
        
        # Train model
        history = self.model.fit(
            X_train_seq, y_train_seq,
            validation_data=(X_val_seq, y_val_seq),
            epochs=30,
            batch_size=32,
            verbose=0,
            callbacks=[
                keras.callbacks.EarlyStopping(patience=10, restore_best_weights=True)
            ]
        )
        
        # Evaluate model
        val_loss, val_acc, val_precision, val_recall = self.model.evaluate(
            X_val_seq, y_val_seq, verbose=0
        )
        
        results = {
            'validation_accuracy': val_acc,
            'validation_precision': val_precision,
            'validation_recall': val_recall,
            'training_history': history.history
        }
        
        self.logger.info(f"LSTM training complete. Accuracy: {val_acc:.4f}")
        
        return results


class GRUModel:
    """GRU-based model for sequence analysis (more efficient than LSTM)."""
    
    def __init__(self, sequence_length: int = 10, input_features: int = 10):
        self.sequence_length = sequence_length
        self.input_features = input_features
        self.model = None
        self.scaler = StandardScaler()
        self.logger = logging.getLogger("GRUModel")
    
    def build_model(self) -> keras.Model:
        """Build GRU model for sequence-based DDoS detection."""
        model = keras.Sequential([
            layers.GRU(32, return_sequences=True,
                      input_shape=(self.sequence_length, self.input_features)),
            layers.Dropout(0.2),
            layers.GRU(16, return_sequences=False),
            layers.Dropout(0.2),
            layers.Dense(8, activation='relu'),
            layers.Dense(1, activation='sigmoid')
        ])
        
        model.compile(
            optimizer='adam',
            loss='binary_crossentropy',
            metrics=['accuracy', 'precision', 'recall']
        )
        
        return model
    
    def prepare_sequences(self, X: np.ndarray, y: np.ndarray) -> Tuple[np.ndarray, np.ndarray]:
        """Prepare sequential data for GRU training."""
        sequences_X = []
        sequences_y = []
        
        for i in range(len(X) - self.sequence_length + 1):
            sequences_X.append(X[i:i + self.sequence_length])
            sequences_y.append(y[i + self.sequence_length - 1])
        
        return np.array(sequences_X), np.array(sequences_y)
    
    def train(self, X_train: np.ndarray, y_train: np.ndarray,
              X_val: np.ndarray, y_val: np.ndarray) -> Dict:
        """Train the GRU model."""
        self.logger.info("Training GRU model...")
        
        # Scale features
        X_train_scaled = self.scaler.fit_transform(X_train)
        X_val_scaled = self.scaler.transform(X_val)
        
        # Prepare sequences
        X_train_seq, y_train_seq = self.prepare_sequences(X_train_scaled, y_train)
        X_val_seq, y_val_seq = self.prepare_sequences(X_val_scaled, y_val)
        
        # Build model
        self.model = self.build_model()
        
        # Train model
        history = self.model.fit(
            X_train_seq, y_train_seq,
            validation_data=(X_val_seq, y_val_seq),
            epochs=30,
            batch_size=32,
            verbose=0,
            callbacks=[
                keras.callbacks.EarlyStopping(patience=10, restore_best_weights=True)
            ]
        )
        
        # Evaluate model
        val_loss, val_acc, val_precision, val_recall = self.model.evaluate(
            X_val_seq, y_val_seq, verbose=0
        )
        
        results = {
            'validation_accuracy': val_acc,
            'validation_precision': val_precision,
            'validation_recall': val_recall,
            'training_history': history.history
        }
        
        self.logger.info(f"GRU training complete. Accuracy: {val_acc:.4f}")
        
        return results


class ExplainableAI:
    """Explainable AI module using SHAP and LIME for model interpretability."""
    
    def __init__(self, model, feature_names: List[str]):
        self.model = model
        self.feature_names = feature_names
        self.logger = logging.getLogger("ExplainableAI")
    
    def explain_with_shap(self, X_test: np.ndarray, sample_size: int = 100) -> Dict:
        """Generate SHAP explanations for model predictions."""
        self.logger.info("Generating SHAP explanations...")
        
        # Create SHAP explainer
        explainer = shap.KernelExplainer(
            self.model.predict, 
            X_test[:sample_size]
        )
        
        # Calculate SHAP values
        shap_values = explainer.shap_values(X_test[:sample_size])
        
        # Feature importance
        feature_importance = np.abs(shap_values).mean(0)
        
        results = {
            'shap_values': shap_values.tolist(),
            'feature_importance': dict(zip(self.feature_names, feature_importance)),
            'expected_value': explainer.expected_value
        }
        
        return results
    
    def explain_with_lime(self, X_train: np.ndarray, X_test: np.ndarray, 
                         instance_idx: int = 0) -> Dict:
        """Generate LIME explanation for a specific instance."""
        self.logger.info("Generating LIME explanation...")
        
        # Create LIME explainer
        explainer = LimeTabularExplainer(
            X_train,
            feature_names=self.feature_names,
            class_names=['Normal', 'DDoS'],
            mode='classification'
        )
        
        # Explain instance
        explanation = explainer.explain_instance(
            X_test[instance_idx],
            self.model.predict,
            num_features=len(self.feature_names)
        )
        
        # Extract explanation data
        lime_data = explanation.as_list()
        
        results = {
            'instance_explanation': lime_data,
            'prediction_probability': explanation.predict_proba[1]  # DDoS probability
        }
        
        return results


class DDoSDetectionSystem:
    """Complete DDoS detection system integrating multiple ML models."""
    
    def __init__(self):
        self.feature_extractor = FeatureExtractor()
        self.tinyml_model = TinyMLModel()
        self.lstm_model = LSTMModel()
        self.gru_model = GRUModel()
        self.xai = None
        self.logger = logging.getLogger("DDoSDetectionSystem")
        
        self.feature_names = [
            'packet_rate', 'byte_rate', 'flow_duration', 'packet_size_variance',
            'timestamp_variance', 'connection_count', 'unique_source_ips',
            'payload_entropy', 'http_ratio', 'port_80_ratio'
        ]
    
    def generate_synthetic_data(self, num_samples: int = 10000) -> Tuple[np.ndarray, np.ndarray]:
        """Generate synthetic network traffic data for training."""
        self.logger.info(f"Generating {num_samples} synthetic data samples...")
        
        X = []
        y = []
        
        for i in range(num_samples):
            if i < num_samples // 2:  # Normal traffic
                features = np.array([
                    np.random.normal(10, 3),    # packet_rate
                    np.random.normal(1000, 200), # byte_rate
                    np.random.exponential(5),   # flow_duration
                    np.random.normal(0.5, 0.1), # packet_size_variance
                    np.random.normal(0.1, 0.02), # timestamp_variance
                    np.random.poisson(5),       # connection_count
                    np.random.poisson(3),       # unique_source_ips
                    np.random.normal(4, 1),     # payload_entropy
                    np.random.uniform(0.7, 1.0), # http_ratio
                    np.random.uniform(0.5, 1.0)  # port_80_ratio
                ])
                label = 0  # Normal
            else:  # DDoS traffic
                features = np.array([
                    np.random.normal(100, 20),   # packet_rate (higher)
                    np.random.normal(5000, 1000), # byte_rate (higher)
                    np.random.exponential(1),    # flow_duration (shorter)
                    np.random.normal(0.2, 0.05), # packet_size_variance (lower)
                    np.random.normal(0.05, 0.01), # timestamp_variance (lower)
                    np.random.poisson(20),       # connection_count (higher)
                    np.random.poisson(1),        # unique_source_ips (lower)
                    np.random.normal(2, 0.5),    # payload_entropy (lower)
                    np.random.uniform(0.9, 1.0), # http_ratio
                    np.random.uniform(0.8, 1.0)  # port_80_ratio
                ])
                label = 1  # DDoS
            
            X.append(features)
            y.append(label)
        
        return np.array(X), np.array(y)
    
    def train_all_models(self) -> Dict:
        """Train all ML models and compare their performance."""
        self.logger.info("Training all DDoS detection models...")
        
        # Generate training data
        X, y = self.generate_synthetic_data(10000)
        X_train, X_test, y_train, y_test = train_test_split(
            X, y, test_size=0.2, random_state=42, stratify=y
        )
        X_train, X_val, y_train, y_val = train_test_split(
            X_train, y_train, test_size=0.2, random_state=42, stratify=y_train
        )
        
        results = {}
        
        # Train TinyML model
        tinyml_results = self.tinyml_model.train(X_train, y_train, X_val, y_val)
        results['tinyml'] = tinyml_results
        
        # Train LSTM model
        lstm_results = self.lstm_model.train(X_train, y_train, X_val, y_val)
        results['lstm'] = lstm_results
        
        # Train GRU model
        gru_results = self.gru_model.train(X_train, y_train, X_val, y_val)
        results['gru'] = gru_results
        
        # Initialize XAI with TinyML model (most suitable for edge deployment)
        self.xai = ExplainableAI(self.tinyml_model.predict, self.feature_names)
        
        # Generate explanations
        xai_results = self.xai.explain_with_shap(X_test[:100])
        results['explainability'] = xai_results
        
        self.logger.info("All models trained successfully")
        
        return results
    
    def detect_ddos(self, message, agent_metrics) -> Tuple[bool, float, Dict]:
        """Detect DDoS attack using the trained models."""
        # Extract features
        features = self.feature_extractor.extract_features_from_message(
            message, agent_metrics
        )
        feature_array = self.feature_extractor.features_to_array(features)
        
        # Get predictions from TinyML model (primary model for edge deployment)
        prediction, confidence = self.tinyml_model.predict(feature_array)
        
        # Determine if it's a DDoS attack (threshold = 0.5)
        is_ddos = prediction > 0.5
        
        detection_info = {
            'prediction_score': prediction,
            'confidence': confidence,
            'features_used': features,
            'model_type': 'TinyML'
        }
        
        return is_ddos, confidence, detection_info
