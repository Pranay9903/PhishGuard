import pytest
from app.detection.heuristics import analyze_url, shannon_entropy, levenshtein_distance

def test_shannon_entropy():
    assert shannon_entropy('aaaa') == 0  # All same chars = 0 entropy
    assert shannon_entropy('abcdefgh') > 0  # Different chars = > 0 entropy
    assert shannon_entropy('abcdefgh') > shannon_entropy('aabb')

def test_levenshtein_distance():
    assert levenshtein_distance('hello', 'hello') == 0
    assert levenshtein_distance('hello', 'hallo') == 1
    assert levenshtein_distance('hello', 'world') == 4

def test_analyze_url_safe():
    result = analyze_url('https://google.com')
    assert result['result'] in ['safe', 'suspicious', 'phishing']
    assert 'url_length' in result
    assert 'entropy' in result

def test_analyze_url_phishing():
    result = analyze_url('http://192.168.1.1/login.php?redirect=http://fake.com')
    assert 'total_score' in result
    assert result['total_score'] > 0

def test_special_char_detection():
    result = analyze_url('http://example.com/@admin/verify')
    assert result['special_chars'] > 0