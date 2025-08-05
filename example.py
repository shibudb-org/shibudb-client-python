#!/usr/bin/env python3
"""
ShibuDb Python Client Example

This example demonstrates all the features of the ShibuDb Python client:
- Authentication and user management
- Key-value operations
- Vector similarity search
- Space management
"""

import json
import sys
from shibudb_client import ShibuDbClient, User, ShibuDbError, AuthenticationError, ConnectionError, QueryError


def print_response(response, operation=""):
    """Print server response in a formatted way"""
    print(f"\n=== {operation} ===")
    print(f"Status: {response.get('status', 'UNKNOWN')}")

    if 'message' in response:
        print(f"Message: {response['message']}")

    if 'value' in response:
        print(f"Value: {response['value']}")

    if 'spaces' in response:
        print(f"Spaces: {response['spaces']}")

    print("=" * 50)


def example_authentication():
    """Example of authentication"""
    print("\n🔐 AUTHENTICATION EXAMPLE")
    print("=" * 50)

    try:
        # Connect to server
        client = ShibuDbClient("localhost", 4444)

        # Authenticate (you'll need to provide valid credentials)
        print("Attempting to authenticate...")
        response = client.authenticate("admin", "admin")
        print_response(response, "Authentication")

        return client

    except AuthenticationError as e:
        print(f"❌ Authentication failed: {e}")
        print("Please ensure you have valid credentials and the server is running.")
        return None
    except ConnectionError as e:
        print(f"❌ Connection failed: {e}")
        print("Please ensure the ShibuDb server is running on localhost:4444")
        return None


def example_user_management(client):
    """Example of user management operations (admin only)"""
    print("\n👥 USER MANAGEMENT EXAMPLE")
    print("=" * 50)

    try:
        # Create a new user
        new_user = User(
            username="testuser",
            password="testpass",
            role="user",
            permissions={"mytable": "read", "vectortable": "write"}
        )

        response = client.create_user(new_user)
        print_response(response, "Create User")

        # Get user information
        response = client.get_user("testuser")
        print_response(response, "Get User")

        # Update user password
        response = client.update_user_password("testuser", "newpassword")
        print_response(response, "Update Password")

        # Update user role
        response = client.update_user_role("testuser", "admin")
        print_response(response, "Update Role")

        # Update user permissions
        new_permissions = {"mytable": "write", "vectortable": "read"}
        response = client.update_user_permissions("testuser", new_permissions)
        print_response(response, "Update Permissions")

        # Delete user
        response = client.delete_user("testuser")
        print_response(response, "Delete User")

    except QueryError as e:
        print(f"❌ User management operation failed: {e}")


def example_space_management(client):
    """Example of space management operations"""
    print("\n🗂️ SPACE MANAGEMENT EXAMPLE")
    print("=" * 50)

    try:
        # List existing spaces
        response = client.list_spaces()
        print_response(response, "List Spaces")

        # Create a key-value space
        response = client.create_space("mytable", engine_type="key-value")
        print_response(response, "Create Key-Value Space")

        # Create a vector space
        response = client.create_space(
            "vectortable",
            engine_type="vector",
            dimension=128,
            index_type="Flat",
            metric="L2"
        )
        print_response(response, "Create Vector Space")

        # List spaces again
        response = client.list_spaces()
        print_response(response, "List Spaces After Creation")

        # Use a space
        response = client.use_space("mytable")
        print_response(response, "Use Space")

        # Delete a space
        response = client.delete_space("vectortable")
        print_response(response, "Delete Space")

    except QueryError as e:
        print(f"❌ Space management operation failed: {e}")


def example_key_value_operations(client):
    """Example of key-value operations"""
    print("\n🔑 KEY-VALUE OPERATIONS EXAMPLE")
    print("=" * 50)

    try:
        # Ensure we're using the right space
        client.use_space("mytable")

        # Put key-value pairs
        response = client.put("name", "John Doe")
        print_response(response, "Put Key-Value")

        response = client.put("age", "30")
        print_response(response, "Put Key-Value")

        response = client.put("city", "New York")
        print_response(response, "Put Key-Value")

        # Get values
        response = client.get("name")
        print_response(response, "Get Value")

        response = client.get("age")
        print_response(response, "Get Value")

        response = client.get("city")
        print_response(response, "Get Value")

        # Try to get non-existent key
        response = client.get("nonexistent")
        print_response(response, "Get Non-existent Key")

        # Delete a key
        response = client.delete("age")
        print_response(response, "Delete Key")

        # Try to get deleted key
        response = client.get("age")
        print_response(response, "Get Deleted Key")

    except QueryError as e:
        print(f"❌ Key-value operation failed: {e}")


def example_vector_operations(client):
    """Example of vector operations"""
    print("\n🧮 VECTOR OPERATIONS EXAMPLE")
    print("=" * 50)

    try:
        # Create a vector space
        response = client.create_space(
            "vectortable",
            engine_type="vector",
            dimension=3,  # Small dimension for example
            index_type="Flat",
            metric="L2"
        )
        print_response(response, "Create Vector Space")

        # Use the vector space
        client.use_space("vectortable")

        # Insert vectors
        vectors = [
            (1, [1.0, 2.0, 3.0]),
            (2, [4.0, 5.0, 6.0]),
            (3, [7.0, 8.0, 9.0]),
            (4, [1.1, 2.1, 3.1]),  # Similar to vector 1
            (5, [10.0, 11.0, 12.0])
        ]

        for vector_id, vector in vectors:
            response = client.insert_vector(vector_id, vector)
            print_response(response, f"Insert Vector {vector_id}")

        # Search for top-k similar vectors
        query_vector = [1.0, 2.0, 3.0]
        response = client.search_topk(query_vector, k=3)
        print_response(response, "Top-K Search")

        # Range search
        response = client.range_search(query_vector, radius=2.0)
        print_response(response, "Range Search")

        # Get a specific vector
        response = client.get_vector(1)
        print_response(response, "Get Vector")

        # Get another vector
        response = client.get_vector(4)
        print_response(response, "Get Vector")

    except QueryError as e:
        print(f"❌ Vector operation failed: {e}")


def example_advanced_usage(client):
    """Example of advanced usage patterns"""
    print("\n🚀 ADVANCED USAGE EXAMPLE")
    print("=" * 50)

    try:
        # Create multiple spaces for different purposes
        spaces = [
            ("users", "key-value"),
            ("products", "key-value"),
            ("embeddings", "vector", 128),
            ("recommendations", "vector", 256)
        ]

        for space_name, engine_type, *args in spaces:
            if engine_type == "vector":
                dimension = args[0] if args else 128
                response = client.create_space(space_name, engine_type, dimension)
            else:
                response = client.create_space(space_name, engine_type)
            print_response(response, f"Create {space_name} Space")

        # Store user data
        client.use_space("users")
        user_data = {
            "user1": "Alice Johnson",
            "user2": "Bob Smith",
            "user3": "Carol Davis"
        }

        for user_id, user_name in user_data.items():
            response = client.put(user_id, user_name)
            print_response(response, f"Store User {user_id}")

        # Store product data
        client.use_space("products")
        product_data = {
            "prod1": "Laptop",
            "prod2": "Smartphone",
            "prod3": "Tablet"
        }

        for prod_id, prod_name in product_data.items():
            response = client.put(prod_id, prod_name)
            print_response(response, f"Store Product {prod_id}")

        # Store embeddings
        client.use_space("embeddings")
        embeddings = [
            (1, [0.1, 0.2, 0.3, 0.4, 0.5] + [0.0] * 123),  # 128-dim
            (2, [0.6, 0.7, 0.8, 0.9, 1.0] + [0.0] * 123),
            (3, [1.1, 1.2, 1.3, 1.4, 1.5] + [0.0] * 123)
        ]

        for emb_id, embedding in embeddings:
            response = client.insert_vector(emb_id, embedding)
            print_response(response, f"Store Embedding {emb_id}")

        # Search for similar embeddings
        query_embedding = [0.1, 0.2, 0.3, 0.4, 0.5] + [0.0] * 123
        response = client.search_topk(query_embedding, k=2)
        print_response(response, "Search Similar Embeddings")

        # List all spaces
        response = client.list_spaces()
        print_response(response, "List All Spaces")

    except QueryError as e:
        print(f"❌ Advanced operation failed: {e}")


def example_error_handling():
    """Example of error handling"""
    print("\n⚠️ ERROR HANDLING EXAMPLE")
    print("=" * 50)

    try:
        # Try to connect to non-existent server
        client = ShibuDbClient("localhost", 9999)
    except ConnectionError as e:
        print(f"✅ Caught connection error: {e}")

    try:
        # Try to authenticate with wrong credentials
        client = ShibuDbClient("localhost", 4444)
        client.authenticate("wronguser", "wrongpass")
    except AuthenticationError as e:
        print(f"✅ Caught authentication error: {e}")
    except ConnectionError as e:
        print(f"✅ Caught connection error: {e}")

    try:
        # Try to use non-existent space
        client = ShibuDbClient("localhost", 4444)
        client.authenticate("admin", "admin")
        client.use_space("nonexistent")
    except QueryError as e:
        print(f"✅ Caught query error: {e}")
    except (AuthenticationError, ConnectionError) as e:
        print(f"✅ Caught other error: {e}")


def main():
    """Main example function"""
    print("🚀 ShibuDb Python Client Examples")
    print("=" * 60)

    # Example 1: Authentication
    client = example_authentication()
    if not client:
        print("❌ Cannot proceed without authentication")
        return

    try:
        # Example 2: User Management
        example_user_management(client)

        # Example 3: Space Management
        example_space_management(client)

        # Example 4: Key-Value Operations
        example_key_value_operations(client)

        # Example 5: Vector Operations
        example_vector_operations(client)

        # Example 6: Advanced Usage
        example_advanced_usage(client)

        # Example 7: Error Handling
        example_error_handling()

    finally:
        # Clean up
        client.close()
        print("\n✅ Examples completed successfully!")


if __name__ == "__main__":
    main()