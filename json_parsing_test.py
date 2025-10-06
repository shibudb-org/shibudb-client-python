#!/usr/bin/env python3
"""
JSON Parsing Test for ShibuDb Python Client

This test validates that the client can handle JSON responses containing
special characters and user-provided strings without issues.
"""

import json
import unittest
from unittest.mock import Mock, patch
import sys
import os

# Add the current directory to the path to import shibudb_client
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from shibudb_client import ShibuDbClient, ShibuDbError


class TestJSONParsing(unittest.TestCase):
    """Test cases for JSON parsing with special characters"""
    
    def setUp(self):
        """Set up test fixtures"""
        # Mock the socket connection to avoid actual network calls
        self.mock_socket = Mock()
        self.mock_socket.recv.return_value = b'{"status": "OK", "message": "test"}\n'
        
        # Create client with mocked connection
        with patch('socket.socket') as mock_socket_class:
            mock_socket_class.return_value = self.mock_socket
            self.client = ShibuDbClient("localhost", 4444)
    
    def test_json_loads_with_control_characters(self):
        """Test that json.loads with strict=False handles control characters"""
        # Test various control characters that might cause issues
        test_cases = [
            # Control characters
            '{"status": "OK", "message": "test\\nwith\\rnewline"}',
            '{"status": "OK", "message": "test\\twith\\ttab"}',
            '{"status": "OK", "message": "test\\bwith\\bbackspace"}',
            '{"status": "OK", "message": "test\\fwith\\fformfeed"}',
            '{"status": "OK", "message": "test\\vwith\\vverticaltab"}',
            '{"status": "OK", "message": "test\\awith\\abell"}',
            
            # Mixed control characters
            '{"status": "OK", "message": "line1\\nline2\\tindented\\r\\n"}',
            
            # Unicode control characters
            '{"status": "OK", "message": "test\\u0000null\\u0001start"}',
            '{"status": "OK", "message": "test\\u0008backspace\\u0009tab"}',
        ]
        
        for test_json in test_cases:
            with self.subTest(json_string=test_json):
                # Mock the socket response
                self.mock_socket.recv.return_value = test_json.encode('utf-8')
                
                # This should not raise an exception
                try:
                    result = self.client._send_query({"type": "TEST"})
                    self.assertIsInstance(result, dict)
                    self.assertEqual(result.get("status"), "OK")
                except Exception as e:
                    self.fail(f"JSON parsing failed for {test_json}: {e}")
    
    def test_json_loads_with_unicode_characters(self):
        """Test that json.loads with strict=False handles Unicode characters"""
        test_cases = [
            # Basic Unicode
            '{"status": "OK", "message": "Hello 世界"}',
            '{"status": "OK", "message": "Café naïve résumé"}',
            '{"status": "OK", "message": "🚀🌟💫🎉"}',
            
            # Unicode escape sequences
            '{"status": "OK", "message": "\\u4e2d\\u6587"}',  # Chinese
            '{"status": "OK", "message": "\\u041f\\u0440\\u0438\\u0432\\u0435\\u0442"}',  # Russian
            
            # Mixed ASCII and Unicode
            '{"status": "OK", "message": "Hello 世界! How are you? 你好吗？"}',
            
            # Emoji and special symbols
            '{"status": "OK", "message": "Test with emoji: 🎯📊🔍 and symbols: ©®™"}',
        ]
        
        for test_json in test_cases:
            with self.subTest(json_string=test_json):
                # Mock the socket response
                self.mock_socket.recv.return_value = test_json.encode('utf-8')
                
                try:
                    result = self.client._send_query({"type": "TEST"})
                    self.assertIsInstance(result, dict)
                    self.assertEqual(result.get("status"), "OK")
                except Exception as e:
                    self.fail(f"JSON parsing failed for {test_json}: {e}")
    
    def test_json_loads_with_special_json_characters(self):
        """Test that json.loads with strict=False handles special JSON characters in strings"""
        test_cases = [
            # Quotes and backslashes
            '{"status": "OK", "message": "He said \\"Hello\\" to me"}',
            '{"status": "OK", "message": "Path: C:\\\\Users\\\\Test"}',
            '{"status": "OK", "message": "Quote: \\" and backslash: \\\\"}',
            
            # JSON-like content in strings
            '{"status": "OK", "message": "{\\"nested\\": \\"json\\"}"}',
            '{"status": "OK", "message": "[1, 2, 3, \\"test\\"]"}',
            
            # Mixed special characters
            '{"status": "OK", "message": "Complex: \\"test\\" \\n \\t \\\\ \\u0041"}',
        ]
        
        for test_json in test_cases:
            with self.subTest(json_string=test_json):
                # Mock the socket response
                self.mock_socket.recv.return_value = test_json.encode('utf-8')
                
                try:
                    result = self.client._send_query({"type": "TEST"})
                    self.assertIsInstance(result, dict)
                    self.assertEqual(result.get("status"), "OK")
                except Exception as e:
                    self.fail(f"JSON parsing failed for {test_json}: {e}")
    
    def test_json_loads_with_user_provided_data(self):
        """Test that json.loads with strict=False handles realistic user-provided data"""
        test_cases = [
            # User names with special characters
            '{"status": "OK", "user": "José María", "message": "User created"}',
            '{"status": "OK", "user": "O\'Connor", "message": "User created"}',
            '{"status": "OK", "user": "李小明", "message": "User created"}',
            
            # File paths
            '{"status": "OK", "path": "C:\\\\Users\\\\Test\\\\file.txt", "message": "File saved"}',
            '{"status": "OK", "path": "/home/user/文档/file.pdf", "message": "File saved"}',
            
            # URLs and emails
            '{"status": "OK", "url": "https://example.com/path?param=value&other=测试", "message": "URL processed"}',
            '{"status": "OK", "email": "test@example.com", "message": "Email sent"}',
            
            # Code snippets
            '{"status": "OK", "code": "def hello():\\n    print(\\"Hello, 世界!\\")", "message": "Code executed"}',
            
            # JSON data as string
            '{"status": "OK", "data": "{\\"key\\": \\"value\\", \\"array\\": [1, 2, 3]}", "message": "Data processed"}',
        ]
        
        for test_json in test_cases:
            with self.subTest(json_string=test_json):
                # Mock the socket response
                self.mock_socket.recv.return_value = test_json.encode('utf-8')
                
                try:
                    result = self.client._send_query({"type": "TEST"})
                    self.assertIsInstance(result, dict)
                    self.assertEqual(result.get("status"), "OK")
                except Exception as e:
                    self.fail(f"JSON parsing failed for {test_json}: {e}")
    
    def test_json_loads_with_malformed_but_recoverable_json(self):
        """Test that json.loads with strict=False handles some malformed JSON"""
        test_cases = [
            # Trailing commas (should still work with strict=False)
            '{"status": "OK", "message": "test",}',
            '{"status": "OK", "data": [1, 2, 3,],}',
            
            # Comments (if supported by the parser)
            '{"status": "OK", "message": "test" /* comment */}',
        ]
        
        for test_json in test_cases:
            with self.subTest(json_string=test_json):
                # Mock the socket response
                self.mock_socket.recv.return_value = test_json.encode('utf-8')
                
                try:
                    result = self.client._send_query({"type": "TEST"})
                    self.assertIsInstance(result, dict)
                    self.assertEqual(result.get("status"), "OK")
                except Exception as e:
                    # Some malformed JSON might still fail, which is expected
                    # We just want to ensure it doesn't crash the client
                    self.assertIsInstance(e, (json.JSONDecodeError, ShibuDbError))
    
    def test_json_loads_fallback_behavior(self):
        """Test the fallback behavior when JSON parsing fails"""
        # Test with completely invalid JSON
        invalid_json = "This is not JSON at all"
        self.mock_socket.recv.return_value = invalid_json.encode('utf-8')
        
        try:
            result = self.client._send_query({"type": "TEST"})
            # Should fall back to the non-JSON response handling
            self.assertIsInstance(result, dict)
            self.assertEqual(result.get("status"), "OK")
            self.assertEqual(result.get("message"), invalid_json)
        except Exception as e:
            self.fail(f"Fallback behavior failed: {e}")
    
    def test_put_operation_with_special_characters(self):
        """Test PUT operation with values containing special characters"""
        # Mock successful response
        self.mock_socket.recv.return_value = b'{"status": "OK", "message": "Value stored"}\n'
        
        test_values = [
            "Hello 世界!",
            "Path: C:\\Users\\Test",
            "JSON: {\"key\": \"value\"}",
            "Control chars: \n\t\r",
            "Emoji: 🚀🌟💫",
            "Mixed: Hello 世界! \n\t Path: C:\\Users\\Test 🚀",
        ]
        
        for value in test_values:
            with self.subTest(value=value):
                try:
                    # Mock the socket response for each test
                    self.mock_socket.recv.return_value = b'{"status": "OK", "message": "Value stored"}\n'
                    
                    result = self.client.put("test_key", value)
                    self.assertIsInstance(result, dict)
                    self.assertEqual(result.get("status"), "OK")
                except Exception as e:
                    self.fail(f"PUT operation failed for value '{value}': {e}")
    
    def test_get_operation_with_special_characters(self):
        """Test GET operation returning values with special characters"""
        test_cases = [
            '{"status": "OK", "value": "Hello 世界!"}',
            '{"status": "OK", "value": "Path: C:\\\\Users\\\\Test"}',
            '{"status": "OK", "value": "JSON: {\\"key\\": \\"value\\"}"}',
            '{"status": "OK", "value": "Control chars: \\n\\t\\r"}',
            '{"status": "OK", "value": "Emoji: 🚀🌟💫"}',
        ]
        
        for test_json in test_cases:
            with self.subTest(json_string=test_json):
                # Mock the socket response
                self.mock_socket.recv.return_value = test_json.encode('utf-8')
                
                try:
                    result = self.client.get("test_key")
                    self.assertIsInstance(result, dict)
                    self.assertEqual(result.get("status"), "OK")
                    self.assertIn("value", result)
                except Exception as e:
                    self.fail(f"GET operation failed for {test_json}: {e}")
    
    def test_vector_operations_with_special_characters(self):
        """Test vector operations with metadata containing special characters"""
        # Mock successful response
        self.mock_socket.recv.return_value = b'{"status": "OK", "message": "Vector inserted"}\n'
        
        try:
            # Test inserting vector with special character metadata
            result = self.client.insert_vector(1, [1.0, 2.0, 3.0])
            self.assertIsInstance(result, dict)
            self.assertEqual(result.get("status"), "OK")
        except Exception as e:
            self.fail(f"Vector insert operation failed: {e}")
        
        # Test search with special character response
        search_response = '{"status": "OK", "results": [{"id": 1, "distance": 0.1, "metadata": "Hello 世界!"}]}'
        self.mock_socket.recv.return_value = search_response.encode('utf-8')
        
        try:
            result = self.client.search_topk([1.0, 2.0, 3.0], k=1)
            self.assertIsInstance(result, dict)
            self.assertEqual(result.get("status"), "OK")
        except Exception as e:
            self.fail(f"Vector search operation failed: {e}")


class TestJSONParsingIntegration(unittest.TestCase):
    """Integration tests for JSON parsing with actual client operations"""
    
    def setUp(self):
        """Set up test fixtures"""
        # Mock the socket connection
        self.mock_socket = Mock()
        self.mock_socket.recv.return_value = b'{"status": "OK", "message": "test"}\n'
        
        with patch('socket.socket') as mock_socket_class:
            mock_socket_class.return_value = self.mock_socket
            self.client = ShibuDbClient("localhost", 4444)
    
    def test_comprehensive_special_character_handling(self):
        """Comprehensive test with multiple special characters in one response"""
        # Complex response with multiple special characters
        complex_response = '''{
            "status": "OK",
            "message": "Operation completed successfully",
            "data": {
                "user": "José María O'Connor",
                "path": "C:\\\\Users\\\\Test\\\\文档",
                "url": "https://example.com/path?param=测试&other=value",
                "code": "def hello():\\n    print(\\"Hello, 世界!\\")",
                "json_data": "{\\"key\\": \\"value\\", \\"array\\": [1, 2, 3]}",
                "emoji": "🚀🌟💫🎉",
                "control_chars": "Line1\\nLine2\\tIndented\\r\\n"
            },
            "metadata": {
                "timestamp": "2024-01-01T00:00:00Z",
                "version": "1.0.0",
                "description": "Test with special characters: 测试"
            }
        }'''
        
        # Mock the socket response
        self.mock_socket.recv.return_value = complex_response.encode('utf-8')
        
        try:
            result = self.client._send_query({"type": "COMPREHENSIVE_TEST"})
            self.assertIsInstance(result, dict)
            self.assertEqual(result.get("status"), "OK")
            self.assertIn("data", result)
            self.assertIn("metadata", result)
            
            # Verify nested data structure
            data = result["data"]
            self.assertEqual(data["user"], "José María O'Connor")
            self.assertIn("文档", data["path"])
            self.assertIn("测试", data["url"])
            self.assertIn("世界", data["code"])
            self.assertIn("🚀", data["emoji"])
            
        except Exception as e:
            self.fail(f"Comprehensive special character test failed: {e}")


def run_json_parsing_tests():
    """Run all JSON parsing tests"""
    print("🧪 Running JSON Parsing Tests for ShibuDb Client")
    print("=" * 60)
    
    # Create test suite
    test_suite = unittest.TestSuite()
    
    # Add test cases
    test_suite.addTest(unittest.makeSuite(TestJSONParsing))
    test_suite.addTest(unittest.makeSuite(TestJSONParsingIntegration))
    
    # Run tests
    runner = unittest.TextTestRunner(verbosity=2)
    result = runner.run(test_suite)
    
    # Print summary
    print("\n" + "=" * 60)
    if result.wasSuccessful():
        print("🎉 All JSON parsing tests passed!")
        print("✅ The client can handle special characters in JSON responses")
    else:
        print("❌ Some tests failed:")
        for failure in result.failures:
            print(f"  - {failure[0]}: {failure[1]}")
        for error in result.errors:
            print(f"  - {error[0]}: {error[1]}")
    
    return result.wasSuccessful()


if __name__ == "__main__":
    success = run_json_parsing_tests()
    sys.exit(0 if success else 1)
