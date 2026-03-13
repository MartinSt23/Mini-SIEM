import pytest
from siem.normalizer.apache_parser import ApacheParser

parser = ApacheParser()

def test_parser_valid_line():
    line = '192.168.1.1 - - [01/Mar/2026:10:00:00 +0000] "GET /login HTTP/1.1" 401 512'
    result = parser.parse(line)
    assert result["source_ip"] == "192.168.1.1"
    assert result["event_type"] == "LOGIN_FAILED"
    
def test_returns_none_for_garbage():
    assert parser.parse("da ist kein log") is None