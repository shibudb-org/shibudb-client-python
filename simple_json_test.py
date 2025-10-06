#!/usr/bin/env python3
"""
Simple JSON Parsing Test for ShibuDb Python Client

This test focuses specifically on validating that json.loads with strict=False
can handle special characters in JSON responses.
"""

import json
import sys
import os
from unittest.mock import Mock, patch

# Add the current directory to the path to import shibudb_client
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from shibudb_client import ShibuDbClient


def test_json_loads_directly():
    """Test json.loads with strict=False directly"""
    print("🧪 Testing json.loads with strict=False directly")
    print("=" * 50)
    
    # Test cases that should work with strict=False
    test_cases = [
        {
            "name": "Control Characters",
            "json": '{"status": "OK", "message": "test\\nwith\\rnewline\\tand\\ttab"}',
            "description": "Newlines, carriage returns, and tabs"
        },
        {
            "name": "Unicode Characters", 
            "json": '{"status": "OK", "message": "Hello 世界! Café naïve"}',
            "description": "Unicode characters and accented letters"
        },
        {
            "name": "Emoji and Symbols",
            "json": '{"status": "OK", "message": "🚀🌟💫🎉 Test with emoji and ©®™ symbols"}',
            "description": "Emoji and special symbols"
        },
        {
            "name": "JSON-like Content",
            "json": '{"status": "OK", "message": "He said \\"Hello\\" and path is C:\\\\Users\\\\Test"}',
            "description": "Quotes, backslashes, and JSON-like strings"
        },
        {
            "name": "Mixed Special Characters",
            "json": '{"status": "OK", "message": "Complex: \\"test\\" \\n \\t \\\\ Hello 世界! 🚀"}',
            "description": "Combination of all special character types"
        },
        {
            "name": "User Data Simulation",
            "json": '{"status": "OK", "user": "José María", "path": "/home/user/文档", "message": "User created successfully"}',
            "description": "Realistic user-provided data"
        },
        {
            "name": "Code Snippet",
            "json": '{"status": "OK", "code": "def hello():\\n    print(\\"Hello, 世界!\\")", "message": "Code executed"}',
            "description": "Code snippets with special characters"
        },
        {
            "name": "URL with Parameters",
            "json": '{"status": "OK", "url": "https://example.com/path?param=测试&other=value", "message": "URL processed"}',
            "description": "URLs with Unicode parameters"
        }
    ]
    
    passed_tests = 0
    total_tests = len(test_cases)
    
    for i, test_case in enumerate(test_cases, 1):
        print(f"\n{i}. {test_case['name']}")
        print(f"   Description: {test_case['description']}")
        print(f"   JSON: {test_case['json'][:60]}{'...' if len(test_case['json']) > 60 else ''}")
        
        try:
            # Test with strict=False (our implementation)
            result_strict_false = json.loads(test_case['json'], strict=False)
            print("   ✅ PASSED with strict=False")
            
            # Test with strict=True (default) for comparison
            try:
                result_strict_true = json.loads(test_case['json'], strict=True)
                print("   ✅ Also works with strict=True")
            except json.JSONDecodeError as e:
                print(f"   ⚠️  Would fail with strict=True: {e}")
            
            # Verify the result structure
            if isinstance(result_strict_false, dict) and result_strict_false.get("status") == "OK":
                print("   ✅ Result structure is correct")
                passed_tests += 1
            else:
                print(f"   ❌ Unexpected result structure: {result_strict_false}")
                
        except json.JSONDecodeError as e:
            print(f"   ❌ FAILED - JSON decode error: {e}")
        except Exception as e:
            print(f"   ❌ FAILED - Unexpected error: {e}")
    
    print(f"\n{'='*50}")
    print(f"Direct JSON Test Results: {passed_tests}/{total_tests} tests passed")
    
    return passed_tests == total_tests


def test_client_json_parsing():
    """Test the client's _send_query method with special characters"""
    print("\n🔧 Testing Client's _send_query Method")
    print("=" * 40)
    
    # Mock the socket connection
    mock_socket = Mock()
    
    with patch('socket.socket') as mock_socket_class:
        mock_socket_class.return_value = mock_socket
        client = ShibuDbClient("localhost", 4444)
        
        # Test cases for client's JSON parsing
        test_cases = [
            '{"status": "OK", "message": "Hello 世界!"}',
            '{"status": "OK", "message": "Path: C:\\\\Users\\\\Test"}',
            '{"status": "OK", "message": "JSON: {\\"key\\": \\"value\\"}"}',
            '{"status": "OK", "message": "Control chars: \\n\\t\\r"}',
            '{"status": "OK", "message": "Emoji: 🚀🌟💫"}',
            '{"status": "OK", "message": "Complex: \\"test\\" \\n \\t \\\\ Hello 世界! 🚀"}',
        ]
        
        passed_tests = 0
        total_tests = len(test_cases)
        
        for i, test_json in enumerate(test_cases, 1):
            print(f"\n{i}. Testing JSON response: {test_json[:50]}{'...' if len(test_json) > 50 else ''}")
            
            try:
                # Mock the socket response
                mock_socket.recv.return_value = test_json.encode('utf-8')
                
                # Test the _send_query method
                result = client._send_query({"type": "TEST"})
                
                if isinstance(result, dict) and result.get("status") == "OK":
                    print("   ✅ PASSED - Client parsed JSON successfully")
                    passed_tests += 1
                else:
                    print(f"   ❌ FAILED - Unexpected result: {result}")
                    
            except Exception as e:
                print(f"   ❌ FAILED - Exception: {e}")
        
        print(f"\n{'='*40}")
        print(f"Client JSON Test Results: {passed_tests}/{total_tests} tests passed")
        
        return passed_tests == total_tests


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


def main():
    """Main test function"""
    print("🚀 Starting Simple JSON Parsing Test for ShibuDb Client")
    print("=" * 60)
    
    # Run all tests
    test1_passed = test_json_loads_directly()
    test2_passed = test_client_json_parsing()
    test3_passed = test_fallback_behavior()
    
    # Summary
    print("\n" + "=" * 60)
    print("📊 FINAL TEST SUMMARY")
    print("=" * 60)
    
    tests = [
        ("Direct JSON Parsing with strict=False", test1_passed),
        ("Client _send_query Method", test2_passed),
        ("Fallback Behavior", test3_passed)
    ]
    
    passed_count = sum(1 for _, passed in tests if passed)
    total_count = len(tests)
    
    for test_name, passed in tests:
        status = "✅ PASSED" if passed else "❌ FAILED"
        print(f"{test_name}: {status}")
    
    print(f"\nOverall: {passed_count}/{total_count} test suites passed")
    
    if passed_count == total_count:
        print("\n🎉 All tests passed! The json.loads(response, strict=False) implementation works correctly.")
        print("✅ The client can handle special characters in JSON responses without issues.")
    else:
        print("\n❌ Some tests failed. Please check the implementation.")
    
    return passed_count == total_count


if __name__ == "__main__":
    success = main()
    sys.exit(0 if success else 1)
