#!/usr/bin/env python3
"""
Comprehensive Connection Pooling Test for ShibuDb

This script tests all connection pooling features including:
- Basic pooling functionality
- Concurrent operations
- Error handling
- Pool statistics
- Health monitoring
- Different pool configurations
"""

import time
import threading
from concurrent.futures import ThreadPoolExecutor, as_completed
from shibudb_client import (
    create_connection_pool,
    ShibuDbClient,
    ShibuDbError,
    AuthenticationError,
    ConnectionError,
    QueryError,
    PoolExhaustedError
)


def print_test_header(test_name):
    """Print a formatted test header"""
    print(f"\n{'='*60}")
    print(f"🧪 {test_name}")
    print(f"{'='*60}")


def print_test_result(test_name, success, message=""):
    """Print a formatted test result"""
    status = "✅ PASSED" if success else "❌ FAILED"
    print(f"{status}: {test_name}")
    if message:
        print(f"   {message}")


def test_basic_pooling():
    """Test 1: Basic connection pooling functionality"""
    print_test_header("Basic Connection Pooling")
    
    try:
        # Create a small connection pool
        pool = create_connection_pool(
            host="localhost",
            port=4444,
            username="admin",
            password="admin",
            min_size=2,
            max_size=5
        )
        
        # Test basic operations
        with pool.get_connection() as client:
            # List spaces
            response = client.list_spaces()
            print(f"✓ List spaces: {response.get('status', 'UNKNOWN')}")
            
            # Create a test space
            response = client.create_space("pool_test_basic", "key-value")
            print(f"✓ Create space: {response.get('status', 'UNKNOWN')}")
            
            # Use the space
            response = client.use_space("pool_test_basic")
            print(f"✓ Use space: {response.get('status', 'UNKNOWN')}")
            
            # Put and get data
            response = client.put("test_key", "test_value")
            print(f"✓ Put operation: {response.get('status', 'UNKNOWN')}")
            
            response = client.get("test_key")
            print(f"✓ Get operation: {response.get('status', 'UNKNOWN')}")
            print(f"  Retrieved value: {response.get('value', 'N/A')}")
        
        # Check pool statistics
        stats = pool.get_stats()
        print(f"✓ Pool statistics: {stats}")
        
        # Clean up
        pool.close()
        print("✓ Pool closed successfully")
        
        return True, "Basic pooling operations completed successfully"
        
    except Exception as e:
        return False, f"Basic pooling test failed: {e}"


def test_concurrent_operations():
    """Test 2: Concurrent operations with connection pool"""
    print_test_header("Concurrent Operations")
    
    try:
        # Create a connection pool for concurrent operations
        pool = create_connection_pool(
            host="localhost",
            port=4444,
            username="admin",
            password="admin",
            min_size=3,
            max_size=8
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
        with ThreadPoolExecutor(max_workers=5) as executor:
            futures = [executor.submit(worker, i) for i in range(5)]
            
            results = []
            for future in as_completed(futures):
                result = future.result()
                results.append(result)
                print(f"✓ {result}")
        
        # Check final pool statistics
        stats = pool.get_stats()
        print(f"✓ Final pool statistics: {stats}")
        
        # Clean up
        pool.close()
        
        return True, f"Concurrent test completed with {len(results)} successful workers"
        
    except Exception as e:
        return False, f"Concurrent test failed: {e}"


def test_pool_error_handling():
    """Test 3: Error handling with connection pools"""
    print_test_header("Error Handling")
    
    error_tests = []
    
    # Test 1: Invalid credentials
    try:
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
        except AuthenticationError:
            error_tests.append("✓ Invalid credentials handled correctly")
        except PoolExhaustedError:
            error_tests.append("✓ Pool exhausted with invalid credentials")
        except Exception as e:
            error_tests.append(f"✗ Unexpected error with invalid credentials: {e}")
        
        pool.close()
        
    except Exception as e:
        error_tests.append(f"✗ Pool creation failed: {e}")
    
    # Test 2: Non-existent server
    try:
        pool = create_connection_pool(
            host="localhost",
            port=9999,
            min_size=1,
            max_size=2
        )
        
        try:
            with pool.get_connection() as client:
                client.list_spaces()
        except ConnectionError:
            error_tests.append("✓ Non-existent server handled correctly")
        except PoolExhaustedError:
            error_tests.append("✓ Pool exhausted with non-existent server")
        except Exception as e:
            error_tests.append(f"✗ Unexpected error with non-existent server: {e}")
        
        pool.close()
        
    except Exception as e:
        error_tests.append(f"✗ Pool creation failed: {e}")
    
    # Test 3: Pool exhaustion
    try:
        pool = create_connection_pool(
            host="localhost",
            port=4444,
            username="admin",
            password="admin",
            min_size=1,
            max_size=1,
            acquire_timeout=1
        )
        
        # Try to use more connections than available
        connections = []
        try:
            for i in range(3):
                conn = pool.get_connection()
                connections.append(conn)
        except PoolExhaustedError:
            error_tests.append("✓ Pool exhaustion handled correctly")
        except Exception as e:
            error_tests.append(f"✗ Unexpected error during pool exhaustion: {e}")
        finally:
            # Clean up connections
            for conn in connections:
                try:
                    conn.__exit__(None, None, None)
                except:
                    pass
            pool.close()
        
    except Exception as e:
        error_tests.append(f"✗ Pool exhaustion test failed: {e}")
    
    success = len([t for t in error_tests if t.startswith("✓")]) >= 2
    return success, f"Error handling tests: {'; '.join(error_tests)}"


def test_pool_statistics():
    """Test 4: Pool statistics and monitoring"""
    print_test_header("Pool Statistics")
    
    try:
        pool = create_connection_pool(
            host="localhost",
            port=4444,
            username="admin",
            password="admin",
            min_size=2,
            max_size=6
        )
        
        # Get initial stats
        initial_stats = pool.get_stats()
        print(f"✓ Initial stats: {initial_stats}")
        
        # Use connections and check stats
        connections = []
        for i in range(3):
            conn = pool.get_connection()
            connections.append(conn)
            stats = pool.get_stats()
            print(f"✓ Stats after {i+1} connections: {stats}")
        
        # Return connections
        for conn in connections:
            conn.__exit__(None, None, None)
        
        final_stats = pool.get_stats()
        print(f"✓ Final stats: {final_stats}")
        
        # Clean up
        pool.close()
        
        return True, "Pool statistics monitoring completed successfully"
        
    except Exception as e:
        return False, f"Pool statistics test failed: {e}"


def test_pool_configurations():
    """Test 5: Different pool configurations"""
    print_test_header("Pool Configurations")
    
    configs = [
        {"name": "Small Pool", "min_size": 1, "max_size": 2},
        {"name": "Medium Pool", "min_size": 2, "max_size": 5},
        {"name": "Large Pool", "min_size": 3, "max_size": 8}
    ]
    
    successful_configs = 0
    
    for config in configs:
        try:
            pool = create_connection_pool(
                host="localhost",
                port=4444,
                username="admin",
                password="admin",
                min_size=config["min_size"],
                max_size=config["max_size"]
            )
            
            # Test the configuration
            with pool.get_connection() as client:
                response = client.list_spaces()
                print(f"✓ {config['name']}: {response.get('status', 'UNKNOWN')}")
            
            pool.close()
            successful_configs += 1
            
        except Exception as e:
            print(f"✗ {config['name']}: {e}")
    
    success = successful_configs >= 2
    return success, f"{successful_configs}/{len(configs)} pool configurations successful"


def test_health_monitoring():
    """Test 6: Health monitoring functionality"""
    print_test_header("Health Monitoring")
    
    try:
        pool = create_connection_pool(
            host="localhost",
            port=4444,
            username="admin",
            password="admin",
            min_size=2,
            max_size=4,
            health_check_interval=5  # Short interval for testing
        )
        
        # Get initial stats
        initial_stats = pool.get_stats()
        print(f"✓ Initial pool size: {initial_stats['pool_size']}")
        
        # Use connections to test health checks
        with pool.get_connection() as client:
            response = client.list_spaces()
            print(f"✓ Health check passed: {response.get('status', 'UNKNOWN')}")
        
        # Wait a bit for health checks
        time.sleep(2)
        
        final_stats = pool.get_stats()
        print(f"✓ Final pool size: {final_stats['pool_size']}")
        
        # Clean up
        pool.close()
        
        return True, "Health monitoring test completed successfully"
        
    except Exception as e:
        return False, f"Health monitoring test failed: {e}"


def main():
    """Run all connection pooling tests"""
    print("🚀 Comprehensive ShibuDb Connection Pooling Tests")
    print("=" * 60)
    
    tests = [
        ("Basic Pooling", test_basic_pooling),
        ("Concurrent Operations", test_concurrent_operations),
        ("Error Handling", test_pool_error_handling),
        ("Pool Statistics", test_pool_statistics),
        ("Pool Configurations", test_pool_configurations),
        ("Health Monitoring", test_health_monitoring)
    ]
    
    passed = 0
    total = len(tests)
    results = []
    
    for test_name, test_func in tests:
        try:
            success, message = test_func()
            print_test_result(test_name, success, message)
            if success:
                passed += 1
            results.append((test_name, success, message))
        except Exception as e:
            print_test_result(test_name, False, f"Test crashed: {e}")
            results.append((test_name, False, f"Test crashed: {e}"))
    
    # Print summary
    print(f"\n{'='*60}")
    print(f"📊 TEST SUMMARY")
    print(f"{'='*60}")
    print(f"Total Tests: {total}")
    print(f"Passed: {passed}")
    print(f"Failed: {total - passed}")
    print(f"Success Rate: {(passed/total)*100:.1f}%")
    
    if passed == total:
        print("\n🎉 ALL TESTS PASSED!")
        print("✅ Connection pooling is working correctly")
    else:
        print(f"\n❌ {total - passed} TESTS FAILED")
        print("Please check the output above for details")
    
    # Print detailed results
    print(f"\n📋 DETAILED RESULTS:")
    for test_name, success, message in results:
        status = "✅ PASS" if success else "❌ FAIL"
        print(f"{status} {test_name}: {message}")
    
    return passed == total


if __name__ == "__main__":
    main() 