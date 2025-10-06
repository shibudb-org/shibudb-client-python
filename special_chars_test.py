#!/usr/bin/env python3
"""
Special Characters Test for ShibuDb Python Client

A simple test script to validate that the client can handle special characters
in JSON responses without issues.
"""

import json
import sys
import os
from unittest.mock import Mock, patch

# Add the current directory to the path to import shibudb_client
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from shibudb_client import ShibuDbClient


def test_json_parsing_with_special_chars():
    """Test JSON parsing with various special characters"""
    print("🧪 Testing JSON Parsing with Special Characters")
    print("=" * 50)
    
    # Mock the socket connection
    mock_socket = Mock()
    
    with patch('socket.socket') as mock_socket_class:
        mock_socket_class.return_value = mock_socket
        client = ShibuDbClient("localhost", 4444)
        
        # Test cases with different types of special characters
        test_cases = [
            {
                "name": "Control Characters",
                "json": '{"status": "OK", "message": "test\\nwith\\rnewline\\tand\\ttab"}',
                "description": "Testing newlines, carriage returns, and tabs"
            },
            {
                "name": "Unicode Characters",
                "json": '{"status": "OK", "message": "Hello 世界! Café naïve"}',
                "description": "Testing Unicode characters and accented letters"
            },
            {
                "name": "Emoji and Symbols",
                "json": '{"status": "OK", "message": "🚀🌟💫🎉 Test with emoji and ©®™ symbols"}',
                "description": "Testing emoji and special symbols"
            },
            {
                "name": "JSON-like Content",
                "json": '{"status": "OK", "message": "He said \\"Hello\\" and path is C:\\\\Users\\\\Test"}',
                "description": "Testing quotes, backslashes, and JSON-like strings"
            },
            {
                "name": "Mixed Special Characters",
                "json": '{"status": "OK", "message": "Complex: \\"test\\" \\n \\t \\\\ Hello 世界! 🚀"}',
                "description": "Testing combination of all special character types"
            },
            {
                "name": "User Data Simulation",
                "json": '{"status": "OK", "user": "José María", "path": "/home/user/文档", "message": "User created successfully"}',
                "description": "Testing realistic user-provided data"
            },
            {
                "name": "Code Snippet",
                "json": '{"status": "OK", "code": "def hello():\\n    print(\\"Hello, 世界!\\")", "message": "Code executed"}',
                "description": "Testing code snippets with special characters"
            },
            {
                "name": "URL with Parameters",
                "json": '{"status": "OK", "url": "https://example.com/path?param=测试&other=value", "message": "URL processed"}',
                "description": "Testing URLs with Unicode parameters"
            }
        ]
        
        passed_tests = 0
        total_tests = len(test_cases)
        
        for i, test_case in enumerate(test_cases, 1):
            print(f"\n{i}. {test_case['name']}")
            print(f"   Description: {test_case['description']}")
            print(f"   JSON: {test_case['json'][:60]}{'...' if len(test_case['json']) > 60 else ''}")
            
            try:
                # Mock the socket response
                mock_socket.recv.return_value = test_case['json'].encode('utf-8')
                
                # Test the _send_query method
                result = client._send_query({"type": "TEST"})
                
                # Verify the result
                if isinstance(result, dict) and result.get("status") == "OK":
                    print("   ✅ PASSED - JSON parsed successfully")
                    passed_tests += 1
                else:
                    print(f"   ❌ FAILED - Unexpected result: {result}")
                    
            except Exception as e:
                print(f"   ❌ FAILED - Exception: {e}")
        
        print(f"\n{'='*50}")
        print(f"Test Results: {passed_tests}/{total_tests} tests passed")
        
        if passed_tests == total_tests:
            print("🎉 All tests passed! The client handles special characters correctly.")
            return True
        else:
            print("❌ Some tests failed. Check the implementation.")
            return False


def test_fallback_behavior():
    """Test the fallback behavior when JSON parsing fails"""
    print("\n🔄 Testing Fallback Behavior")
    print("=" * 30)
    
    # Mock the socket connection
    mock_socket = Mock()
    
    with patch('socket.socket') as mock_socket_class:
        mock_socket_class.return_value = mock_socket
        client = ShibuDbClient("localhost", 4444)
        
        # Test with non-JSON response
        non_json_response = "This is not JSON at all"
        mock_socket.recv.return_value = non_json_response.encode('utf-8')
        
        try:
            result = client._send_query({"type": "TEST"})
            if isinstance(result, dict) and result.get("status") == "OK" and result.get("message") == non_json_response:
                print("✅ PASSED - Fallback behavior works correctly")
                return True
            else:
                print(f"❌ FAILED - Unexpected fallback result: {result}")
                return False
        except Exception as e:
            print(f"❌ FAILED - Exception in fallback test: {e}")
            return False


def test_put_get_operations():
    """Test PUT and GET operations with special characters"""
    print("\n📝 Testing PUT/GET Operations with Special Characters")
    print("=" * 50)
    
    # Mock the socket connection
    mock_socket = Mock()
    
    with patch('socket.socket') as mock_socket_class:
        mock_socket_class.return_value = mock_socket
        client = ShibuDbClient("localhost", 4444)
        
        # Mock authentication first
        mock_socket.recv.return_value = b'{"status": "OK", "message": "Authentication successful"}\n'
        client.authenticate("admin", "admin")
        
        # Test values with special characters
        test_values = [
            "Hello 世界!",
            "Path: C:\\Users\\Test",
            "JSON: {\"key\": \"value\"}",
            "Control chars: \n\t\r",
            "Emoji: 🚀🌟💫",
            "Mixed: Hello 世界! \n\t Path: C:\\Users\\Test 🚀",
        ]
        
        passed_tests = 0
        total_tests = len(test_values)
        
        for i, value in enumerate(test_values, 1):
            print(f"\n{i}. Testing value: {repr(value)}")
            
            try:
                # Mock successful space creation and selection
                mock_socket.recv.return_value = b'{"status": "OK", "message": "Space created"}\n'
                client.create_space("test_space", "key-value")
                
                mock_socket.recv.return_value = b'{"status": "OK", "message": "Space selected"}\n'
                client.use_space("test_space")
                
                # Mock successful PUT response
                mock_socket.recv.return_value = b'{"status": "OK", "message": "Value stored"}\n'
                put_result = client.put("test_key", value)
                
                if isinstance(put_result, dict) and put_result.get("status") == "OK":
                    print("   ✅ PUT operation successful")
                    
                    # Mock successful GET response with the value
                    get_response = f'{{"status": "OK", "value": {json.dumps(value)}}}\n'
                    mock_socket.recv.return_value = get_response.encode('utf-8')
                    get_result = client.get("test_key")
                    
                    if isinstance(get_result, dict) and get_result.get("status") == "OK":
                        print("   ✅ GET operation successful")
                        passed_tests += 1
                    else:
                        print(f"   ❌ GET operation failed: {get_result}")
                else:
                    print(f"   ❌ PUT operation failed: {put_result}")
                    
            except Exception as e:
                print(f"   ❌ Exception: {e}")
        
        print(f"\n{'='*50}")
        print(f"PUT/GET Test Results: {passed_tests}/{total_tests} tests passed")
        
        return passed_tests == total_tests


def main():
    """Main test function"""
    print("🚀 Starting Special Characters Test for ShibuDb Client")
    print("=" * 60)
    
    # Run all tests
    test1_passed = test_json_parsing_with_special_chars()
    test2_passed = test_fallback_behavior()
    test3_passed = test_put_get_operations()
    
    # Summary
    print("\n" + "=" * 60)
    print("📊 FINAL TEST SUMMARY")
    print("=" * 60)
    
    tests = [
        ("JSON Parsing with Special Characters", test1_passed),
        ("Fallback Behavior", test2_passed),
        ("PUT/GET Operations", test3_passed)
    ]
    
    passed_count = sum(1 for _, passed in tests if passed)
    total_count = len(tests)
    
    for test_name, passed in tests:
        status = "✅ PASSED" if passed else "❌ FAILED"
        print(f"{test_name}: {status}")
    
    print(f"\nOverall: {passed_count}/{total_count} test suites passed")
    
    if passed_count == total_count:
        print("\n🎉 All tests passed! The client is robust against special characters.")
        print("✅ The json.loads(response, strict=False) implementation works correctly.")
    else:
        print("\n❌ Some tests failed. Please check the implementation.")
    
    return passed_count == total_count


if __name__ == "__main__":
    success = main()
    sys.exit(0 if success else 1)
