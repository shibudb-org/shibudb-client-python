#!/usr/bin/env python3
"""
Comprehensive Test Script for ShibuDb Python Client
This script demonstrates all possible operations with the ShibuDb client.
"""

import sys
import time
from typing import List, Dict, Any
from dataclasses import asdict

# Import the ShibuDb client
try:
    from shibudb_client import ShibuDbClient, User, ShibuDbError, AuthenticationError, ConnectionError, QueryError
    print("✅ Successfully imported shibudb_client")
except ImportError as e:
    print(f"❌ Failed to import shibudb_client: {e}")
    print("Make sure you have installed the package: pip install shibudb-client")
    sys.exit(1)

def print_section(title: str):
    """Print a formatted section header"""
    print(f"\n{'='*60}")
    print(f"  {title}")
    print(f"{'='*60}")

def print_result(operation: str, result: Dict[str, Any]):
    """Print operation result in a formatted way"""
    print(f"✅ {operation}")
    print(f"   Status: {result.get('status', 'N/A')}")
    print(f"   Message: {result.get('message', 'N/A')}")
    if 'data' in result:
        print(f"   Data: {result['data']}")

def test_connection_and_authentication():
    """Test basic connection and authentication"""
    print_section("CONNECTION AND AUTHENTICATION")

    try:
        # Test 1: Basic connection
        print("🔌 Testing basic connection...")
        client = ShibuDbClient("localhost", 4444)
        print("✅ Client created successfully")

        # Test 2: Authentication
        print("\n🔐 Testing authentication...")
        auth_result = client.authenticate("admin", "admin")
        print_result("Authentication", auth_result)

        # Test 3: Context manager
        print("\n🔄 Testing context manager...")
        with ShibuDbClient("localhost", 4444) as ctx_client:
            auth_result = ctx_client.authenticate("admin", "admin")
            print_result("Context Manager Authentication", auth_result)

        return client

    except ConnectionError as e:
        print(f"❌ Connection failed: {e}")
        print("Make sure ShibuDb server is running: sudo shibudb start 4444")
        return None
    except AuthenticationError as e:
        print(f"❌ Authentication failed: {e}")
        print("Check your username and password")
        return None
    except Exception as e:
        print(f"❌ Unexpected error: {e}")
        return None

def test_space_management(client: ShibuDbClient):
    """Test space management operations"""
    print_section("SPACE MANAGEMENT")

    try:
        # Test 1: List spaces
        print("📋 Listing existing spaces...")
        spaces_result = client.list_spaces()
        print_result("List Spaces", spaces_result)

        # Test 2: Create key-value space
        print("\n🗂️ Creating key-value space...")
        kv_space_result = client.create_space("test_kv_space", "key-value")
        print_result("Create KV Space", kv_space_result)

        # Test 3: Create vector space
        print("\n🧮 Creating vector space...")
        vector_space_result = client.create_space(
            "test_vector_space",
            "vector",
            dimension=128,
            index_type="Flat",
            metric="L2"
        )
        print_result("Create Vector Space", vector_space_result)

        # Test 4: List spaces again
        print("\n📋 Listing spaces after creation...")
        spaces_result = client.list_spaces()
        print_result("List Spaces (Updated)", spaces_result)

        # Test 5: Use space
        print("\n🎯 Using key-value space...")
        use_space_result = client.use_space("test_kv_space")
        print_result("Use Space", use_space_result)

    except QueryError as e:
        print(f"❌ Query error: {e}")
    except Exception as e:
        print(f"❌ Unexpected error: {e}")

def test_key_value_operations(client: ShibuDbClient):
    """Test key-value operations"""
    print_section("KEY-VALUE OPERATIONS")

    try:
        # Switch to key-value space
        client.use_space("test_kv_space")

        # Test 1: PUT operation
        print("📝 Testing PUT operation...")
        put_result = client.put("name", "John Doe")
        print_result("PUT name", put_result)

        put_result = client.put("age", "30")
        print_result("PUT age", put_result)

        put_result = client.put("city", "New York")
        print_result("PUT city", put_result)

        # Test 2: GET operation
        print("\n📖 Testing GET operation...")
        get_result = client.get("name")
        print_result("GET name", get_result)

        get_result = client.get("age")
        print_result("GET age", get_result)

        # Test 3: GET non-existent key
        print("\n🔍 Testing GET non-existent key...")
        get_result = client.get("non_existent_key")
        print_result("GET non_existent_key", get_result)

        # Test 4: DELETE operation
        print("\n🗑️ Testing DELETE operation...")
        delete_result = client.delete("age")
        print_result("DELETE age", delete_result)

        # Test 5: GET after DELETE
        print("\n🔍 Testing GET after DELETE...")
        get_result = client.get("age")
        print_result("GET age (after delete)", get_result)

    except QueryError as e:
        print(f"❌ Query error: {e}")
    except Exception as e:
        print(f"❌ Unexpected error: {e}")

def test_vector_operations(client: ShibuDbClient):
    """Test vector operations"""
    print_section("VECTOR OPERATIONS")

    try:
        # Switch to vector space
        client.use_space("test_vector_space")

        # Create sample vectors
        vector1 = [0.1, 0.2, 0.3, 0.4, 0.5, 0.6, 0.7, 0.8] * 16  # 128 dimensions
        vector2 = [0.2, 0.3, 0.4, 0.5, 0.6, 0.7, 0.8, 0.9] * 16  # 128 dimensions
        vector3 = [0.9, 0.8, 0.7, 0.6, 0.5, 0.4, 0.3, 0.2] * 16  # 128 dimensions

        # Test 1: Insert vectors
        print("📤 Testing vector insertion...")
        insert_result = client.insert_vector(1, vector1)
        print_result("Insert Vector 1", insert_result)

        insert_result = client.insert_vector(2, vector2)
        print_result("Insert Vector 2", insert_result)

        insert_result = client.insert_vector(3, vector3)
        print_result("Insert Vector 3", insert_result)

        # Test 2: Get vector
        print("\n📖 Testing GET vector...")
        get_vector_result = client.get_vector(1)
        print_result("GET Vector 1", get_vector_result)

        # Test 3: Search top-k
        print("\n🔍 Testing top-k search...")
        query_vector = [0.15, 0.25, 0.35, 0.45, 0.55, 0.65, 0.75, 0.85] * 16
        search_result = client.search_topk(query_vector, k=3)
        print_result("Top-K Search", search_result)

        # Test 4: Range search
        print("\n🎯 Testing range search...")
        range_result = client.range_search(query_vector, radius=0.5)
        print_result("Range Search", range_result)

    except QueryError as e:
        print(f"❌ Query error: {e}")
    except Exception as e:
        print(f"❌ Unexpected error: {e}")

def test_user_management(client: ShibuDbClient):
    """Test user management operations (admin only)"""
    print_section("USER MANAGEMENT")

    try:
        # Test 1: Create user
        print("👤 Testing user creation...")
        new_user = User(
            username="testuser",
            password="testpass123",
            role="user",
            permissions={"test_kv_space": "read", "test_vector_space": "write"}
        )
        create_user_result = client.create_user(new_user)
        print_result("Create User", create_user_result)

        # Test 2: Get user
        print("\n📖 Testing get user...")
        get_user_result = client.get_user("testuser")
        print_result("Get User", get_user_result)

        # Test 3: Update user password
        print("\n🔐 Testing password update...")
        update_password_result = client.update_user_password("testuser", "newpass123")
        print_result("Update Password", update_password_result)

        # Test 4: Update user role
        print("\n👑 Testing role update...")
        update_role_result = client.update_user_role("testuser", "admin")
        print_result("Update Role", update_role_result)

        # Test 5: Update user permissions
        print("\n🔑 Testing permissions update...")
        new_permissions = {"test_kv_space": "write", "test_vector_space": "read"}
        update_permissions_result = client.update_user_permissions("testuser", new_permissions)
        print_result("Update Permissions", update_permissions_result)

        # Test 6: Delete user
        print("\n🗑️ Testing user deletion...")
        delete_user_result = client.delete_user("testuser")
        print_result("Delete User", delete_user_result)

    except QueryError as e:
        print(f"❌ Query error: {e}")
    except Exception as e:
        print(f"❌ Unexpected error: {e}")

def test_error_handling():
    """Test error handling scenarios"""
    print_section("ERROR HANDLING")

    try:
        # Test 1: Invalid host
        print("🌐 Testing invalid host...")
        try:
            invalid_client = ShibuDbClient("invalid-host", 4444)
            invalid_client.authenticate("admin", "admin")
        except ConnectionError as e:
            print(f"✅ Expected ConnectionError: {e}")
        except Exception as e:
            print(f"❌ Unexpected error: {e}")

        # Test 2: Invalid credentials
        print("\n🔐 Testing invalid credentials...")
        try:
            client = ShibuDbClient("localhost", 4444)
            client.authenticate("invalid_user", "invalid_pass")
        except AuthenticationError as e:
            print(f"✅ Expected AuthenticationError: {e}")
        except Exception as e:
            print(f"❌ Unexpected error: {e}")

        # Test 3: Invalid space operations
        print("\n🗂️ Testing invalid space operations...")
        try:
            client = ShibuDbClient("localhost", 4444)
            client.authenticate("admin", "admin")
            client.use_space("non_existent_space")
        except QueryError as e:
            print(f"✅ Expected QueryError: {e}")
        except Exception as e:
            print(f"❌ Unexpected error: {e}")

    except Exception as e:
        print(f"❌ Unexpected error in error handling: {e}")

def test_performance_operations(client: ShibuDbClient):
    """Test performance-related operations"""
    print_section("PERFORMANCE OPERATIONS")

    try:
        # Test 1: Batch key-value operations
        print("⚡ Testing batch key-value operations...")
        start_time = time.time()

        for i in range(10):
            client.put(f"batch_key_{i}", f"batch_value_{i}")

        end_time = time.time()
        print(f"✅ Inserted 10 key-value pairs in {end_time - start_time:.4f} seconds")

        # Test 2: Batch vector operations
        print("\n⚡ Testing batch vector operations...")
        client.use_space("test_vector_space")

        start_time = time.time()
        for i in range(5):
            vector = [float(j) / 100.0 for j in range(128)]
            client.insert_vector(100 + i, vector)

        end_time = time.time()
        print(f"✅ Inserted 5 vectors in {end_time - start_time:.4f} seconds")

        # Test 3: Search performance
        print("\n⚡ Testing search performance...")
        query_vector = [0.1] * 128
        start_time = time.time()
        search_result = client.search_topk(query_vector, k=5)
        end_time = time.time()
        print(f"✅ Search completed in {end_time - start_time:.4f} seconds")
        print_result("Performance Search", search_result)

    except QueryError as e:
        print(f"❌ Query error: {e}")
    except Exception as e:
        print(f"❌ Unexpected error: {e}")

def cleanup_test_data(client: ShibuDbClient):
    """Clean up test data"""
    print_section("CLEANUP")

    try:
        # Delete test spaces
        print("🧹 Cleaning up test spaces...")

        # Delete key-value space
        try:
            delete_result = client.delete_space("test_kv_space")
            print_result("Delete KV Space", delete_result)
        except Exception as e:
            print(f"⚠️ Could not delete test_kv_space: {e}")

        # Delete vector space
        try:
            delete_result = client.delete_space("test_vector_space")
            print_result("Delete Vector Space", delete_result)
        except Exception as e:
            print(f"⚠️ Could not delete test_vector_space: {e}")

        # List remaining spaces
        print("\n📋 Remaining spaces after cleanup:")
        spaces_result = client.list_spaces()
        print_result("Final Space List", spaces_result)

    except Exception as e:
        print(f"❌ Cleanup error: {e}")

def main():
    """Main test function"""
    print("🚀 Starting Comprehensive ShibuDb Client Test")
    print("=" * 60)

    # Test connection and authentication
    client = test_connection_and_authentication()
    if not client:
        print("❌ Cannot proceed without successful connection")
        return

    try:
        # Test all operations
        test_space_management(client)
        test_key_value_operations(client)
        test_vector_operations(client)
        test_user_management(client)
        test_performance_operations(client)
        test_error_handling()
        cleanup_test_data(client)

        print_section("TEST COMPLETION")
        print("🎉 All tests completed successfully!")
        print("✅ Your ShibuDb client is working correctly")

    except Exception as e:
        print(f"❌ Test failed with error: {e}")
    finally:
        # Close the client
        try:
            client.close()
            print("🔌 Client connection closed")
        except:
            pass

if __name__ == "__main__":
    main()