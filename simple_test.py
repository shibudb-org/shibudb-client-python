#!/usr/bin/env python3
"""
Simple ShibuDb Python Client Test

A simple script to test basic ShibuDb operations.
"""

from shibudb_client import ShibuDbClient, User


def simple_test():
    """Simple test of basic operations"""
    print("🧪 Simple ShibuDb Test")
    print("=" * 40)

    try:
        # Connect and authenticate
        client = ShibuDbClient("localhost", 4444)
        response = client.authenticate("admin", "admin")
        print(f"✅ Authentication: {response.get('status')}")

        # Create a test space
        response = client.create_space("testspace", "key-value")
        print(f"✅ Create Space: {response.get('status')}")

        # Use the space
        response = client.use_space("testspace")
        print(f"✅ Use Space: {response.get('status')}")

        # Put some data
        response = client.put("hello", "world")
        print(f"✅ Put: {response.get('status')}")

        # Get the data
        response = client.get("hello")
        print(f"✅ Get: {response.get('status')} - Value: {response.get('value')}")

        # List spaces
        response = client.list_spaces()
        print(f"✅ List Spaces: {response.get('spaces', [])}")

        # Clean up
        client.close()
        print("✅ Test completed successfully!")

    except Exception as e:
        print(f"❌ Test failed: {e}")


def vector_test():
    """Test vector operations"""
    print("\n🧮 Vector Test")
    print("=" * 40)

    try:
        # Connect and authenticate
        client = ShibuDbClient("localhost", 4444)
        response = client.authenticate("admin", "admin")
        print(f"✅ Authentication: {response.get('status')}")

        # Create a vector space
        response = client.create_space("vectest", "vector", dimension=3)
        print(f"✅ Create Vector Space: {response.get('status')}")

        # Use the space
        response = client.use_space("vectest")
        print(f"✅ Use Space: {response.get('status')}")

        # Insert vectors
        vectors = [
            (1, [1.0, 2.0, 3.0]),
            (2, [4.0, 5.0, 6.0]),
            (3, [1.1, 2.1, 3.1])  # Similar to vector 1
        ]

        for vector_id, vector in vectors:
            response = client.insert_vector(vector_id, vector)
            print(f"✅ Insert Vector {vector_id}: {response.get('status')}")

        # Search for similar vectors
        query_vector = [1.0, 2.0, 3.0]
        response = client.search_topk(query_vector, k=2)
        print(f"✅ Search: {response.get('message')}")

        # Clean up
        client.close()
        print("✅ Vector test completed successfully!")

    except Exception as e:
        print(f"❌ Vector test failed: {e}")


if __name__ == "__main__":
    simple_test()
    vector_test()