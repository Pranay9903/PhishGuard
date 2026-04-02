import pytest
from app.models import User

def test_register(client):
    response = client.post('/auth/register', data={
        'username': 'newuser',
        'email': 'new@example.com',
        'password': 'StrongPassword123!'
    })
    assert response.status_code == 302

def test_login_success(client, app):
    from app.models import db
    from app.auth.utils import hash_password
    
    with app.app_context():
        user = User(
            username='testuser',
            email='test@example.com',
            password_hash=hash_password('TestPassword123!')
        )
        db.session.add(user)
        db.session.commit()
    
    response = client.post('/auth/login', data={
        'username': 'testuser',
        'password': 'TestPassword123!'
    })
    assert response.status_code == 302

def test_login_invalid_password(client, app):
    from app.models import db
    from app.auth.utils import hash_password
    
    with app.app_context():
        user = User(
            username='testuser',
            email='test@example.com',
            password_hash=hash_password('TestPassword123!')
        )
        db.session.add(user)
        db.session.commit()
    
    response = client.post('/auth/login', data={
        'username': 'testuser',
        'password': 'WrongPassword'
    })
    assert b'Invalid' in response.data

def test_logout(auth_client):
    response = auth_client.get('/auth/logout')
    assert response.status_code == 302