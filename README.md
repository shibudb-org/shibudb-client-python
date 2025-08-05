# shibudb-client-python
ShibuDb client library for python

# ShibuDb Python Client

A comprehensive Python client for ShibuDb database that supports authentication, key-value operations, vector similarity search, space management, and connection pooling.

## Features

- 🔐 **Authentication & User Management**: Secure login with role-based access control
- 🔑 **Key-Value Operations**: Traditional key-value storage with PUT, GET, DELETE operations
- 🧮 **Vector Similarity Search**: Advanced vector operations with multiple index types
- 🗂️ **Space Management**: Create, delete, and manage different storage spaces
- 🛡️ **Error Handling**: Comprehensive error handling with custom exceptions
- 📊 **Connection Management**: Automatic connection handling with context managers
- 🔗 **Connection Pooling**: High-performance connection pooling for concurrent operations

## Installation

### Prerequisites

1. **ShibuDb Server**: Ensure the ShibuDb server is running
   ```bash
   # Start the server (requires sudo)
   sudo shibudb start 4444
   ```

2. **Python Requirements**: The client uses only standard library modules
    - Python 3.7+
    - No external dependencies required

### Setup

1. **Clone or download the client files**:
   ```bash
   # Copy the client files to your project
   cp shibudb_client.py your_project/
   ```

2. **Import the client**:
   ```python
   from shibudb_client import ShibuDbClient, User, connect
   ```

## Quick Start

### Basic Connection and Authentication

```python
from shibudb_client import ShibuDbClient

# Create client and authenticate
client = ShibuDbClient("localhost", 4444)
client.authenticate("admin", "admin")

# Use context manager for automatic cleanup
with ShibuDbClient("localhost", 4444) as client:
    client.authenticate("admin", "admin")
    # Your operations here
```

### Connection Pooling

```python
from shibudb_client import create_connection_pool

# Create a connection pool
pool = create_connection_pool(
    host="localhost",
    port=4444,
    username="admin",
    password="admin",
    min_size=2,
    max_size=10
)

# Use pooled connections
with pool.get_connection() as client:
    response = client.list_spaces()
    print(f"Available spaces: {response}")

# Pool automatically manages connections
pool.close()
```

### Key-Value Operations

```python
# Create and use a space
client.create_space("mytable", "key-value")
client.use_space("mytable")

# Basic operations
client.put("name", "John Doe")
response = client.get("name")
print(response["value"])  # "John Doe"

client.delete("name")
```

### Vector Operations

```python
# Create a vector space
client.create_space("vectors", "vector", dimension=128, index_type="Flat", metric="L2")
client.use_space("vectors")

# Insert vectors
client.insert_vector(1, [0.1, 0.2, 0.3, ...])
client.insert_vector(2, [0.4, 0.5, 0.6, ...])

# Search for similar vectors
results = client.search_topk([0.1, 0.2, 0.3, ...], k=5)
print(results["message"])  # Search results

# Range search
results = client.range_search([0.1, 0.2, 0.3, ...], radius=0.5)
```

## API Reference

### ShibuDbClient

#### Constructor
```python
ShibuDbClient(host="localhost", port=4444, timeout=30)
```

#### Authentication
```python
client.authenticate(username: str, password: str) -> Dict[str, Any]
```

#### Space Management
```python
client.create_space(name: str, engine_type: str, dimension: Optional[int] = None, 
                   index_type: str = "Flat", metric: str = "L2") -> Dict[str, Any]
client.delete_space(name: str) -> Dict[str, Any]
client.list_spaces() -> Dict[str, Any]
client.use_space(name: str) -> Dict[str, Any]
```

#### Key-Value Operations
```python
client.put(key: str, value: str, space: Optional[str] = None) -> Dict[str, Any]
client.get(key: str, space: Optional[str] = None) -> Dict[str, Any]
client.delete(key: str, space: Optional[str] = None) -> Dict[str, Any]
```

#### Vector Operations
```python
client.insert_vector(vector_id: int, vector: List[float], space: Optional[str] = None) -> Dict[str, Any]
client.search_topk(query_vector: List[float], k: int = 1, space: Optional[str] = None) -> Dict[str, Any]
client.range_search(query_vector: List[float], radius: float, space: Optional[str] = None) -> Dict[str, Any]
client.get_vector(vector_id: int, space: Optional[str] = None) -> Dict[str, Any]
```

#### User Management (Admin Only)
```python
client.create_user(user: User) -> Dict[str, Any]
client.update_user_password(username: str, new_password: str) -> Dict[str, Any]
client.update_user_role(username: str, new_role: str) -> Dict[str, Any]
client.update_user_permissions(username: str, permissions: Dict[str, str]) -> Dict[str, Any]
client.delete_user(username: str) -> Dict[str, Any]
client.get_user(username: str) -> Dict[str, Any]
```

### Data Models

#### User
```python
@dataclass
class User:
    username: str
    password: str
    role: str = "user"
    permissions: Dict[str, str] = None
```

#### SpaceInfo
```python
@dataclass
class SpaceInfo:
    name: str
    engine_type: str
    dimension: Optional[int] = None
    index_type: Optional[str] = None
    metric: Optional[str] = None
```

### Exceptions

- `ShibuDbError`: Base exception for all client errors
- `AuthenticationError`: Raised when authentication fails
- `ConnectionError`: Raised when connection fails
- `QueryError`: Raised when query execution fails
- `PoolExhaustedError`: Raised when connection pool is exhausted

## Examples

### Complete Example

```python
from shibudb_client import ShibuDbClient, User

def main():
    # Connect and authenticate
    with ShibuDbClient("localhost", 4444) as client:
        client.authenticate("admin", "admin")
        
        # Create spaces
        client.create_space("users", "key-value")
        client.create_space("embeddings", "vector", dimension=128)
        
        # Store user data
        client.use_space("users")
        client.put("user1", "Alice Johnson")
        client.put("user2", "Bob Smith")
        
        # Store embeddings
        client.use_space("embeddings")
        client.insert_vector(1, [0.1, 0.2, 0.3, ...])
        client.insert_vector(2, [0.4, 0.5, 0.6, ...])
        
        # Search for similar embeddings
        results = client.search_topk([0.1, 0.2, 0.3, ...], k=5)
        print(f"Search results: {results}")

if __name__ == "__main__":
    main()
```

### Error Handling

```python
from shibudb_client import ShibuDbClient, AuthenticationError, ConnectionError, QueryError

try:
    client = ShibuDbClient("localhost", 4444)
    client.authenticate("admin", "admin")
    
    # Your operations here
    
except AuthenticationError as e:
    print(f"Authentication failed: {e}")
except ConnectionError as e:
    print(f"Connection failed: {e}")
except QueryError as e:
    print(f"Query failed: {e}")
finally:
    client.close()
```

### Advanced Usage

```python
from shibudb_client import ShibuDbClient, User

# Create admin user
admin_user = User(
    username="admin",
    password="adminpass",
    role="admin"
)

# Create regular user with permissions
user = User(
    username="user1",
    password="userpass",
    role="user",
    permissions={"mytable": "read", "vectortable": "write"}
)

with ShibuDbClient("localhost", 4444) as client:
    client.authenticate("admin", "admin")
    
    # Create users
    client.create_user(user)
    
    # Create spaces for different purposes
    client.create_space("users", "key-value")
    client.create_space("products", "key-value")
    client.create_space("embeddings", "vector", dimension=256)
    client.create_space("recommendations", "vector", dimension=512)
    
    # Store data in different spaces
    client.use_space("users")
    client.put("user1", "Alice Johnson")
    
    client.use_space("embeddings")
    client.insert_vector(1, [0.1, 0.2, 0.3, ...])
    
    # Search for recommendations
    query_vector = [0.1, 0.2, 0.3, ...]
    results = client.search_topk(query_vector, k=10)
```

## Running Examples

### Simple Test
```bash
python simple_test.py
```

### Comprehensive Examples
```bash
python example.py
```

### Connection Pooling Examples
```bash
python pooling_example.py
```

### Comprehensive Connection Pooling Tests
```bash
python comprehensive_pool_test.py
```

## Connection Pooling

The ShibuDb client supports connection pooling for high-performance concurrent operations. Connection pooling provides:

- **Connection Reuse**: Efficiently reuse database connections
- **Concurrent Operations**: Support for multiple simultaneous operations
- **Automatic Health Checks**: Background health monitoring of connections
- **Configurable Pool Size**: Adjustable minimum and maximum pool sizes
- **Timeout Handling**: Configurable connection acquisition timeouts

### Pool Configuration

```python
from shibudb_client import create_connection_pool, ConnectionConfig

# Create pool with custom configuration
pool = create_connection_pool(
    host="localhost",
    port=4444,
    username="admin",
    password="admin",
    min_size=2,              # Minimum connections in pool
    max_size=10,             # Maximum connections in pool
    acquire_timeout=30,      # Timeout for acquiring connection (seconds)
    health_check_interval=60 # Health check interval (seconds)
)
```

### Using Connection Pools

```python
# Basic usage
with pool.get_connection() as client:
    response = client.list_spaces()
    print(f"Spaces: {response}")

# Concurrent operations
import threading
from concurrent.futures import ThreadPoolExecutor

def worker(worker_id):
    with pool.get_connection() as client:
        client.create_space(f"space_{worker_id}", "key-value")
        client.use_space(f"space_{worker_id}")
        client.put(f"key_{worker_id}", f"value_{worker_id}")
        return client.get(f"key_{worker_id}")

# Run concurrent workers
with ThreadPoolExecutor(max_workers=5) as executor:
    futures = [executor.submit(worker, i) for i in range(5)]
    for future in as_completed(futures):
        result = future.result()
        print(f"Result: {result}")
```

### Pool Statistics

```python
# Get pool statistics
stats = pool.get_stats()
print(f"Pool size: {stats['pool_size']}")
print(f"Active connections: {stats['active_connections']}")
print(f"Min size: {stats['min_size']}")
print(f"Max size: {stats['max_size']}")
```

### Error Handling with Pools

```python
from shibudb_client import PoolExhaustedError

try:
    with pool.get_connection() as client:
        # Your operations here
        pass
except PoolExhaustedError as e:
    print(f"Pool exhausted: {e}")
except AuthenticationError as e:
    print(f"Authentication failed: {e}")
except ConnectionError as e:
    print(f"Connection failed: {e}")
```

## Engine Types

### Key-Value Engine
- Traditional key-value storage
- Supports PUT, GET, DELETE operations
- No dimension required

### Vector Engine
- Vector similarity search
- Multiple index types:
    - **Flat**: Exact search (default)
    - **HNSW**: Hierarchical Navigable Small World
    - **IVF**: Inverted File Index
    - **IVF with PQ**: Product Quantization
- Distance metrics:
    - **L2**: Euclidean distance (default)
    - **IP**: Inner product
    - **COS**: Cosine similarity

## Security

- **Authentication Required**: All operations require valid credentials
- **Role-Based Access**: Admin and user roles with different permissions
- **Space-Level Permissions**: Read/write permissions per space
- **Connection Security**: TCP-based communication with timeout handling

## Troubleshooting

### Common Issues

1. **Connection Failed**
    - Ensure ShibuDb server is running: `sudo shibudb start 4444`
    - Check server port and host settings
    - Verify firewall settings

2. **Authentication Failed**
    - Verify username and password
    - Ensure user exists in the system
    - Check user permissions

3. **Space Not Found**
    - Use `list_spaces()` to see available spaces
    - Create space before using: `create_space()`
    - Use `use_space()` to switch to a space

4. **Vector Dimension Mismatch**
    - Ensure vector dimension matches space dimension
    - Check space creation parameters
    - Verify vector format (comma-separated floats)

### Debug Mode

Enable debug logging:
```python
import logging
logging.basicConfig(level=logging.DEBUG)
```

## Contributing

1. Fork the repository
2. Create a feature branch
3. Add tests for new functionality
4. Submit a pull request

## License

This client is provided as-is for use with ShibuDb database.
