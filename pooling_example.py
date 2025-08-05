#!/usr/bin/env python3
"""
ShibuDb Connection Pooling Example

This example demonstrates how to use connection pooling with the ShibuDb client:
- Creating and configuring connection pools
- Using pooled connections for operations
- Pool statistics and monitoring
- Error handling with connection pools
"""

import time
import threading
from concurrent.futures import ThreadPoolExecutor, as_completed
from shibudb_client import (
    create_connection_pool, 
    ShibuDbError, 
    AuthenticationError, 
    ConnectionError, 
    QueryError,
    PoolExhaustedError
)


def print_pool_stats(pool, operation=""):
    """Print pool statistics"""
    stats = pool.get_stats()
    print(f"\n=== {operation} ===")
    print(f"Pool Size: {stats['pool_size']}")
    print(f"Active Connections: {stats['active_connections']}")
    print(f"Min Size: {stats['min_size']}")
    print(f"Max Size: {stats['max_size']}")
    print(f"Shutdown: {stats['shutdown']}")
    print("=" * 50)


def example_basic_pooling():
    """Example of basic connection pooling usage"""
    print("\n🔗 BASIC CONNECTION POOLING EXAMPLE")
    print("=" * 50)

    try:
        # Create a connection pool
        pool = create_connection_pool(
            host="localhost",
            port=4444,
            username="admin",
            password="admin",
            min_size=2,
            max_size=5
        )

        print_pool_stats(pool, "Initial Pool State")

        # Use the pool for operations
        with pool.get_connection() as client:
            # List spaces
            response = client.list_spaces()
            print(f"List Spaces Response: {response.get('status', 'UNKNOWN')}")

            # Create a test space
            response = client.create_space("test_pool", engine_type="key-value")
            print(f"Create Space Response: {response.get('status', 'UNKNOWN')}")

            # Use the space
            response = client.use_space("test_pool")
            print(f"Use Space Response: {response.get('status', 'UNKNOWN')}")

            # Put some data
            response = client.put("pool_test_key", "pool_test_value")
            print(f"Put Response: {response.get('status', 'UNKNOWN')}")

            # Get the data
            response = client.get("pool_test_key")
            print(f"Get Response: {response.get('status', 'UNKNOWN')}")
            print(f"Retrieved Value: {response.get('value', 'N/A')}")

        print_pool_stats(pool, "After Operations")

        # Clean up
        pool.close()
        print_pool_stats(pool, "After Close")

    except (ConnectionError, AuthenticationError, PoolExhaustedError) as e:
        print(f"❌ Pool operation failed: {e}")
    except Exception as e:
        print(f"❌ Unexpected error: {e}")


def example_concurrent_operations():
    """Example of concurrent operations using connection pool"""
    print("\n⚡ CONCURRENT OPERATIONS EXAMPLE")
    print("=" * 50)

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

        print_pool_stats(pool, "Initial Pool State")

        def worker(worker_id):
            """Worker function for concurrent operations"""
            try:
                with pool.get_connection() as client:
                    # Create a unique space for this worker
                    space_name = f"worker_{worker_id}_space"
                    client.create_space(space_name, engine_type="key-value")
                    client.use_space(space_name)

                    # Perform some operations
                    for i in range(5):
                        key = f"worker_{worker_id}_key_{i}"
                        value = f"worker_{worker_id}_value_{i}"
                        client.put(key, value)
                        
                        # Simulate some work
                        time.sleep(0.1)
                    
                    # Verify our data
                    response = client.get(f"worker_{worker_id}_key_0")
                    return f"Worker {worker_id}: {response.get('value', 'N/A')}"
                    
            except Exception as e:
                return f"Worker {worker_id} failed: {e}"

        # Run concurrent operations
        with ThreadPoolExecutor(max_workers=5) as executor:
            futures = [executor.submit(worker, i) for i in range(5)]
            
            for future in as_completed(futures):
                result = future.result()
                print(f"Result: {result}")

        print_pool_stats(pool, "After Concurrent Operations")

        # Clean up
        pool.close()

    except Exception as e:
        print(f"❌ Concurrent operations failed: {e}")


def example_pool_monitoring():
    """Example of monitoring pool statistics"""
    print("\n📊 POOL MONITORING EXAMPLE")
    print("=" * 50)

    try:
        # Create a connection pool
        pool = create_connection_pool(
            host="localhost",
            port=4444,
            username="admin",
            password="admin",
            min_size=2,
            max_size=6
        )

        def monitor_pool():
            """Monitor pool statistics"""
            for i in range(10):
                stats = pool.get_stats()
                print(f"Monitor {i+1}: Pool size={stats['pool_size']}, "
                      f"Active={stats['active_connections']}")
                time.sleep(1)

        def load_pool():
            """Create load on the pool"""
            for i in range(8):
                try:
                    with pool.get_connection() as client:
                        client.list_spaces()
                        time.sleep(0.5)
                except Exception as e:
                    print(f"Load operation {i} failed: {e}")

        # Start monitoring in background
        monitor_thread = threading.Thread(target=monitor_pool)
        monitor_thread.start()

        # Create load
        load_thread = threading.Thread(target=load_pool)
        load_thread.start()

        # Wait for completion
        monitor_thread.join()
        load_thread.join()

        print_pool_stats(pool, "Final Pool State")
        pool.close()

    except Exception as e:
        print(f"❌ Pool monitoring failed: {e}")


def example_error_handling():
    """Example of error handling with connection pools"""
    print("\n⚠️ ERROR HANDLING EXAMPLE")
    print("=" * 50)

    try:
        # Create a pool with invalid credentials to test error handling
        pool = create_connection_pool(
            host="localhost",
            port=4444,
            username="invalid_user",
            password="invalid_password",
            min_size=1,
            max_size=3
        )

        print("Testing pool with invalid credentials...")
        
        try:
            with pool.get_connection() as client:
                client.list_spaces()
        except AuthenticationError as e:
            print(f"✅ Caught authentication error: {e}")
        except PoolExhaustedError as e:
            print(f"✅ Caught pool exhausted error: {e}")

        pool.close()

        # Test with non-existent server
        print("\nTesting pool with non-existent server...")
        pool = create_connection_pool(
            host="localhost",
            port=9999,
            min_size=1,
            max_size=3
        )

        try:
            with pool.get_connection() as client:
                client.list_spaces()
        except ConnectionError as e:
            print(f"✅ Caught connection error: {e}")
        except PoolExhaustedError as e:
            print(f"✅ Caught pool exhausted error: {e}")

        pool.close()

    except Exception as e:
        print(f"❌ Error handling test failed: {e}")


def example_pool_configuration():
    """Example of different pool configurations"""
    print("\n⚙️ POOL CONFIGURATION EXAMPLE")
    print("=" * 50)

    configs = [
        {
            "name": "Small Pool",
            "min_size": 1,
            "max_size": 3,
            "acquire_timeout": 10
        },
        {
            "name": "Medium Pool",
            "min_size": 3,
            "max_size": 8,
            "acquire_timeout": 30
        },
        {
            "name": "Large Pool",
            "min_size": 5,
            "max_size": 15,
            "acquire_timeout": 60
        }
    ]

    for config in configs:
        print(f"\n--- {config['name']} ---")
        try:
            pool = create_connection_pool(
                host="localhost",
                port=4444,
                username="admin",
                password="admin",
                min_size=config["min_size"],
                max_size=config["max_size"],
                acquire_timeout=config["acquire_timeout"]
            )

            print_pool_stats(pool, f"{config['name']} Stats")

            # Test the pool
            with pool.get_connection() as client:
                response = client.list_spaces()
                print(f"Operation successful: {response.get('status', 'UNKNOWN')}")

            pool.close()

        except Exception as e:
            print(f"❌ {config['name']} failed: {e}")


def main():
    """Main example function"""
    print("🚀 ShibuDb Connection Pooling Examples")
    print("=" * 60)

    # Example 1: Basic Pooling
    example_basic_pooling()

    # Example 2: Concurrent Operations
    example_concurrent_operations()

    # Example 3: Pool Monitoring
    example_pool_monitoring()

    # Example 4: Error Handling
    example_error_handling()

    # Example 5: Pool Configuration
    example_pool_configuration()

    print("\n✅ Connection pooling examples completed!")


if __name__ == "__main__":
    main() 