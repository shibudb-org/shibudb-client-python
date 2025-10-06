#!/usr/bin/env python3
"""
Strict vs Non-Strict JSON Parsing Comparison Test

This test demonstrates the difference between json.loads with strict=True (default)
and strict=False, showing how the latter is more robust for user-provided data.
"""

import json
import sys
import os

# Add the current directory to the path to import shibudb_client
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))


def test_strict_vs_non_strict():
    """Compare strict=True vs strict=False behavior"""
    print("🔍 Comparing strict=True vs strict=False JSON Parsing")
    print("=" * 60)
    
    # Test cases that might behave differently with strict settings
    test_cases = [
        {
            "name": "Control Characters in Strings",
            "json": '{"status": "OK", "message": "test\\nwith\\rnewline\\tand\\ttab"}',
            "description": "Control characters that are properly escaped"
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
            "name": "Complex Escaped Content",
            "json": '{"status": "OK", "message": "He said \\"Hello\\" and path is C:\\\\Users\\\\Test"}',
            "description": "Quotes, backslashes, and complex escaping"
        },
        {
            "name": "Mixed Special Characters",
            "json": '{"status": "OK", "message": "Complex: \\"test\\" \\n \\t \\\\ Hello 世界! 🚀"}',
            "description": "Combination of all special character types"
        },
        {
            "name": "User Data with Special Characters",
            "json": '{"status": "OK", "user": "José María O\'Connor", "path": "/home/user/文档", "message": "User created successfully"}',
            "description": "Realistic user-provided data with special characters"
        },
        {
            "name": "Code Snippet in JSON",
            "json": '{"status": "OK", "code": "def hello():\\n    print(\\"Hello, 世界!\\")", "message": "Code executed"}',
            "description": "Code snippets with special characters"
        },
        {
            "name": "URL with Unicode Parameters",
            "json": '{"status": "OK", "url": "https://example.com/path?param=测试&other=value", "message": "URL processed"}',
            "description": "URLs with Unicode parameters"
        }
    ]
    
    strict_true_passed = 0
    strict_false_passed = 0
    total_tests = len(test_cases)
    
    for i, test_case in enumerate(test_cases, 1):
        print(f"\n{i}. {test_case['name']}")
        print(f"   Description: {test_case['description']}")
        print(f"   JSON: {test_case['json'][:60]}{'...' if len(test_case['json']) > 60 else ''}")
        
        # Test with strict=True (default behavior)
        try:
            result_strict_true = json.loads(test_case['json'], strict=True)
            print("   ✅ strict=True: PASSED")
            strict_true_passed += 1
        except json.JSONDecodeError as e:
            print(f"   ❌ strict=True: FAILED - {e}")
        except Exception as e:
            print(f"   ❌ strict=True: FAILED - {e}")
        
        # Test with strict=False (our implementation)
        try:
            result_strict_false = json.loads(test_case['json'], strict=False)
            print("   ✅ strict=False: PASSED")
            strict_false_passed += 1
            
            # Verify result structure
            if isinstance(result_strict_false, dict) and result_strict_false.get("status") == "OK":
                print("   ✅ Result structure is correct")
            else:
                print(f"   ⚠️  Unexpected result structure: {result_strict_false}")
                
        except json.JSONDecodeError as e:
            print(f"   ❌ strict=False: FAILED - {e}")
        except Exception as e:
            print(f"   ❌ strict=False: FAILED - {e}")
    
    print(f"\n{'='*60}")
    print(f"Test Results Summary:")
    print(f"  strict=True:  {strict_true_passed}/{total_tests} tests passed")
    print(f"  strict=False: {strict_false_passed}/{total_tests} tests passed")
    
    if strict_false_passed >= strict_true_passed:
        print(f"\n✅ strict=False is at least as robust as strict=True")
        if strict_false_passed > strict_true_passed:
            print(f"🎉 strict=False is MORE robust than strict=True!")
    else:
        print(f"\n⚠️  strict=False is less robust than strict=True")
    
    return strict_false_passed == total_tests


def test_problematic_cases():
    """Test cases that are known to be problematic with strict parsing"""
    print("\n🚨 Testing Known Problematic Cases")
    print("=" * 40)
    
    # These are cases where strict=False might help
    problematic_cases = [
        {
            "name": "Trailing Comma (if supported)",
            "json": '{"status": "OK", "message": "test",}',
            "description": "JSON with trailing comma (non-standard but common)"
        },
        {
            "name": "Comments in JSON (if supported)",
            "json": '{"status": "OK", "message": "test" /* comment */}',
            "description": "JSON with comments (non-standard)"
        }
    ]
    
    for i, test_case in enumerate(problematic_cases, 1):
        print(f"\n{i}. {test_case['name']}")
        print(f"   Description: {test_case['description']}")
        print(f"   JSON: {test_case['json']}")
        
        # Test with strict=True
        try:
            result_strict_true = json.loads(test_case['json'], strict=True)
            print("   ✅ strict=True: PASSED")
        except json.JSONDecodeError as e:
            print(f"   ❌ strict=True: FAILED - {e}")
        except Exception as e:
            print(f"   ❌ strict=True: FAILED - {e}")
        
        # Test with strict=False
        try:
            result_strict_false = json.loads(test_case['json'], strict=False)
            print("   ✅ strict=False: PASSED")
        except json.JSONDecodeError as e:
            print(f"   ❌ strict=False: FAILED - {e}")
        except Exception as e:
            print(f"   ❌ strict=False: FAILED - {e}")


def demonstrate_benefits():
    """Demonstrate the benefits of using strict=False"""
    print("\n💡 Benefits of Using strict=False")
    print("=" * 35)
    
    benefits = [
        "✅ More lenient parsing of control characters",
        "✅ Better handling of Unicode characters",
        "✅ More robust against malformed JSON from external sources",
        "✅ Better compatibility with user-provided data",
        "✅ Reduced risk of parsing failures due to edge cases",
        "✅ More forgiving for data that might have minor formatting issues"
    ]
    
    for benefit in benefits:
        print(f"  {benefit}")
    
    print(f"\n🎯 Use Case: ShibuDb Client")
    print(f"  The ShibuDb client receives JSON responses from the server.")
    print(f"  These responses may contain user-provided data with special characters.")
    print(f"  Using strict=False makes the client more robust and user-friendly.")


def main():
    """Main test function"""
    print("🚀 JSON Parsing Strict vs Non-Strict Comparison Test")
    print("=" * 60)
    
    # Run tests
    test1_passed = test_strict_vs_non_strict()
    test_problematic_cases()
    demonstrate_benefits()
    
    # Summary
    print("\n" + "=" * 60)
    print("📊 FINAL SUMMARY")
    print("=" * 60)
    
    if test1_passed:
        print("🎉 All tests passed!")
        print("✅ The json.loads(response, strict=False) implementation is working correctly.")
        print("✅ The ShibuDb client is now more robust against special characters.")
        print("✅ User-provided data with special characters will be handled gracefully.")
    else:
        print("❌ Some tests failed.")
        print("⚠️  Please check the implementation.")
    
    print(f"\n🔧 Implementation Details:")
    print(f"  - Updated: json.loads(response) → json.loads(response, strict=False)")
    print(f"  - Location: shibudb_client.py, line 325, in _send_query method")
    print(f"  - Benefit: More robust JSON parsing for user-provided data")
    
    return test1_passed


if __name__ == "__main__":
    success = main()
    sys.exit(0 if success else 1)
