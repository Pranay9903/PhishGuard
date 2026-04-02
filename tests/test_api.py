import pytest
from app.models import User, Analysis

def test_analyze_endpoint_no_auth(client):
    response = client.get('/api/analyze/https://google.com')
    # API allows unauthenticated access but doesn't save results
    assert response.status_code == 200
    data = response.get_json()
    assert 'result' in data

def test_analyze_endpoint_with_auth(auth_client):
    response = auth_client.get('/api/analyze/https://google.com')
    assert response.status_code == 200
    data = response.get_json()
    assert 'result' in data
    assert 'confidence' in data

def test_watchlist_get(auth_client, app):
    response = auth_client.get('/api/watchlist')
    assert response.status_code == 200

def test_watchlist_add(auth_client):
    response = auth_client.post('/api/watchlist', json={'url': 'http://test.com'})
    assert response.status_code == 201