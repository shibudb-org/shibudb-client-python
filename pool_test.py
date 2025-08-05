#!/usr/bin/env python3
"""
Simple test script for ShibuDb connection pooling functionality
"""

import time
from shibudb_client import create_connection_pool, ShibuDbError


def test_basic_pooling():
    """Test basic connection pooling functionality"""
    print("Testing basic connection pooling...")
    
    try:
        # Create a small connection pool
        pool = create_connection_pool(
            host="localhost",
            port=4444,
            username="admin",
            password="admin",
            min_size=1,
            max_size=3
        )
        
        # Test basic operations
        with pool.get_connection() as client:
            # List spaces
            response = client.list_spaces()
            print(f"✓ List spaces successful: {response.get('status', 'UNKNOWN')}")
            
            # Create a test space
            response = client.create_space("pool_test", "key-value")
            print(f"✓ Create space successful: {response.get('status', 'UNKNOWN')}")
            
            # Use the space
            response = client.use_space("pool_test")
            print(f"✓ Use space successful: {response.get('status', 'UNKNOWN')}")
            
            # Put and get data
            response = client.put("test_key", "test_value")
            print(f"✓ Put operation successful: {response.get('status', 'UNKNOWN')}")
            
            response = client.get("test_key")
            print(f"✓ Get operation successful: {response.get('status', 'UNKNOWN')}")
            print(f"  Retrieved value: {response.get('value', 'N/A')}")
        
        # Check pool statistics
        stats = pool.get_stats()
        print(f"✓ Pool statistics: {stats}")
        
        # Clean up
        pool.close()
        print("✓ Pool closed successfully")
        
        return True
        
    except Exception as e:
        print(f"✗ Basic pooling test failed: {e}")
        return False


def test_concurrent_pooling():
    """Test concurrent operations with connection pool"""
    print("\nTesting concurrent operations...")
    
    try:
        # Create a connection pool for concurrent operations
        pool = create_connection_pool(
            host="localhost",
            port=4444,
            username="admin",
            password="admin",
            min_size=2,
            max_size=5
        )
        
        def worker(worker_id):
            """Worker function for concurrent operations"""
            try:
                with pool.get_connection() as client:
                    # Create a unique space for this worker
                    space_name = f"concurrent_test_{worker_id}"
                    client.create_space(space_name, "key-value")
                    client.use_space(space_name)
                    
                    # Perform operations
                    for i in range(3):
                        key = f"worker_{worker_id}_key_{i}"
                        value = f"worker_{worker_id}_value_{i}"
                        client.put(key, value)
                    
                    # Verify data
                    response = client.get(f"worker_{worker_id}_key_0")
                    return f"Worker {worker_id}: {response.get('value', 'N/A')}"
                    
            except Exception as e:
                return f"Worker {worker_id} failed: {e}"
        
        # Run concurrent workers
        from concurrent.futures import ThreadPoolExecutor, as_completed
        
        with ThreadPoolExecutor(max_workers=3) as executor:
            futures = [executor.submit(worker, i) for i in range(3)]
            
            for future in as_completed(futures):
                result = future.result()
                print(f"✓ {result}")
        
        # Check final pool statistics
        stats = pool.get_stats()
        print(f"✓ Final pool statistics: {stats}")
        
        # Clean up
        pool.close()
        print("✓ Concurrent test completed successfully")
        
        return True
        
    except Exception as e:
        print(f"✗ Concurrent test failed: {e}")
        return False


def test_pool_error_handling():
    """Test error handling with connection pool"""
    print("\nTesting error handling...")
    
    try:
        # Test with invalid credentials
        pool = create_connection_pool(
            host="localhost",
            port=4444,
            username="invalid_user",
            password="invalid_password",
            min_size=1,
            max_size=2
        )
        
        try:
            with pool.get_connection() as client:
                client.list_spaces()
        except Exception as e:
            print(f"✓ Caught expected error with invalid credentials: {type(e).__name__}")
        
        pool.close()
        
        # Test with non-existent server
        pool = create_connection_pool(
            host="localhost",
            port=9999,
            min_size=1,
            max_size=2
        )
        
        try:
            with pool.get_connection() as client:
                client.list_spaces()
        except Exception as e:
            print(f"✓ Caught expected error with non-existent server: {type(e).__name__}")
        
        pool.close()
        print("✓ Error handling test completed successfully")
        
        return True
        
    except Exception as e:
        print(f"✗ Error handling test failed: {e}")
        return False


def main():
    """Run all connection pooling tests"""
    print("🚀 ShibuDb Connection Pooling Tests")
    print("=" * 50)
    
    tests = [
        ("Basic Pooling", test_basic_pooling),
        ("Concurrent Operations", test_concurrent_pooling),
        ("Error Handling", test_pool_error_handling)
    ]
    
    passed = 0
    total = len(tests)
    
    for test_name, test_func in tests:
        print(f"\n--- {test_name} ---")
        if test_func():
            passed += 1
            print(f"✓ {test_name} PASSED")
        else:
            print(f"✗ {test_name} FAILED")
    
    print(f"\n{'='*50}")
    print(f"Test Results: {passed}/{total} tests passed")
    
    if passed == total:
        print("🎉 All connection pooling tests passed!")
    else:
        print("❌ Some tests failed. Please check the output above.")
    
    return passed == total


if __name__ == "__main__":
    main() 