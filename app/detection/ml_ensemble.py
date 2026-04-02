import random
import numpy as np
from typing import Dict

class RandomForestSimulation:
    def __init__(self, n_trees=100):
        self.n_trees = n_trees
    
    def predict(self, heuristics: Dict) -> float:
        scores = []
        for _ in range(self.n_trees):
            score = self._simulate_tree(heuristics)
            scores.append(score)
        return np.mean(scores)
    
    def _simulate_tree(self, heuristics: Dict) -> float:
        base_score = heuristics.get('total_score', 0.5)
        noise = random.gauss(0, 0.1)
        tree_score = base_score + noise
        return max(0, min(1, tree_score))

class XGBoostSimulation:
    def __init__(self, n_rounds=50):
        self.n_rounds = n_rounds
    
    def predict(self, heuristics: Dict) -> float:
        score = heuristics.get('total_score', 0.5)
        
        for _ in range(self.n_rounds):
            gradient = self._calculate_gradient(score)
            hessian = self._calculate_hessian(score)
            learning_rate = 0.1
            score += learning_rate * gradient / (hessian + 1e-6)
        
        return max(0, min(1, score))
    
    def _calculate_gradient(self, score):
        return (0.5 - score) * random.uniform(0.8, 1.2)
    
    def _calculate_hessian(self, score):
        return abs(score - 0.5) + 0.5

class LSTMSimulation:
    def __init__(self, sequence_length=10):
        self.sequence_length = sequence_length
    
    def predict(self, heuristics: Dict) -> float:
        url = heuristics.get('url', '')
        if not url:
            return heuristics.get('total_score', 0.5)
        
        sequence_scores = []
        for i in range(min(len(url), self.sequence_length)):
            char_score = self._char_to_score(url[i])
            sequence_scores.append(char_score)
        
        if sequence_scores:
            lstm_score = np.mean(sequence_scores)
            base_score = heuristics.get('total_score', 0.5)
            return (base_score * 0.7) + (lstm_score * 0.3)
        
        return heuristics.get('total_score', 0.5)
    
    def _char_to_score(self, char):
        suspicious_chars = '@#$%^&*!~`|/\\:;"\'<>?'
        if char in suspicious_chars:
            return random.uniform(0.6, 0.9)
        elif char.isdigit():
            return random.uniform(0.3, 0.6)
        return random.uniform(0.1, 0.4)

class BERTSimulation:
    def __init__(self):
        self.urgency_patterns = [
            'urgent', 'immediately', 'action required', 'verify',
            'suspended', 'locked', 'unauthorized', 'expire'
        ]
        self.brand_patterns = [
            'google', 'facebook', 'amazon', 'paypal', 'bank',
            'microsoft', 'apple', 'netflix', 'chase'
        ]
    
    def predict(self, heuristics: Dict) -> float:
        base_score = heuristics.get('total_score', 0.5)
        
        urgency_score = heuristics.get('urgency_words', 0)
        brand_score = heuristics.get('brand_impersonation', 0)
        login_form_score = heuristics.get('login_form', 0)
        
        bert_score = (
            base_score * 0.3 +
            urgency_score * 0.25 +
            brand_score * 0.25 +
            login_form_score * 0.2
        )
        
        noise = random.gauss(0, 0.05)
        return max(0, min(1, bert_score + noise))

class MLEnsemble:
    def __init__(self, weights=None):
        self.random_forest = RandomForestSimulation()
        self.xgboost = XGBoostSimulation()
        self.lstm = LSTMSimulation()
        self.bert = BERTSimulation()
        
        self.weights = weights or {
            'random_forest': 0.25,
            'xgboost': 0.25,
            'lstm': 0.25,
            'bert': 0.25
        }
    
    def predict(self, heuristics: Dict) -> Dict:
        rf_score = self.random_forest.predict(heuristics)
        xgb_score = self.xgboost.predict(heuristics)
        lstm_score = self.lstm.predict(heuristics)
        bert_score = self.bert.predict(heuristics)
        
        ensemble_score = (
            rf_score * self.weights['random_forest'] +
            xgb_score * self.weights['xgboost'] +
            lstm_score * self.weights['lstm'] +
            bert_score * self.weights['bert']
        )
        
        return {
            'random_forest': rf_score,
            'xgboost': xgb_score,
            'lstm': lstm_score,
            'bert': bert_score,
            'ensemble': ensemble_score,
            'confidence': min(ensemble_score * 1.1, 1.0)
        }
    
    def adjust_weights(self, feedback_type: str, model_name: str):
        if feedback_type == 'fp':
            self.weights[model_name] *= 0.9
        elif feedback_type == 'fn':
            self.weights[model_name] *= 1.1
        
        total = sum(self.weights.values())
        self.weights = {k: v/total for k, v in self.weights.items()}

ensemble = MLEnsemble()