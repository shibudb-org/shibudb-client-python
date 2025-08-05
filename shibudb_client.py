#!/usr/bin/env python3
"""
ShibuDb Python Client

A comprehensive Python client for ShibuDb database that supports:
- Authentication and user management
- Key-value operations
- Vector similarity search
- Space management
- Connection management
"""

import json
import socket
import time
from typing import Dict, List, Optional, Tuple, Union, Any
from dataclasses import dataclass
import logging

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)


@dataclass
class User:
    """User model for ShibuDb"""
    username: str
    password: str
    role: str = "user"
    permissions: Dict[str, str] = None

    def __post_init__(self):
        if self.permissions is None:
            self.permissions = {}


@dataclass
class SpaceInfo:
    """Space information model"""
    name: str
    engine_type: str
    dimension: Optional[int] = None
    index_type: Optional[str] = None
    metric: Optional[str] = None


class ShibuDbError(Exception):
    """Base exception for ShibuDb client errors"""
    pass


class AuthenticationError(ShibuDbError):
    """Raised when authentication fails"""
    pass


class ConnectionError(ShibuDbError):
    """Raised when connection fails"""
    pass


class QueryError(ShibuDbError):
    """Raised when query execution fails"""
    pass


class ShibuDbClient:
    """
    ShibuDb Python Client

    Provides a comprehensive interface to ShibuDb database with support for:
    - Authentication and user management
    - Key-value operations
    - Vector similarity search
    - Space management
    - Connection management
    """

    def __init__(self, host: str = "localhost", port: int = 9090, timeout: int = 30):
        """
        Initialize ShibuDb client

        Args:
            host: Database server host
            port: Database server port
            timeout: Connection timeout in seconds
        """
        self.host = host
        self.port = port
        self.timeout = timeout
        self.socket = None
        self.reader = None
        self.writer = None
        self.authenticated = False
        self.current_user = None
        self.current_space = None
        self._connect()

    def _connect(self):
        """Establish connection to ShibuDb server"""
        try:
            self.socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            self.socket.settimeout(self.timeout)
            self.socket.connect((self.host, self.port))
            logger.info(f"Connected to ShibuDb server at {self.host}:{self.port}")
        except Exception as e:
            raise ConnectionError(f"Failed to connect to ShibuDb server: {e}")

    def _send_query(self, query: Dict[str, Any]) -> Dict[str, Any]:
        """
        Send a query to the server and receive response

        Args:
            query: Query dictionary to send

        Returns:
            Response dictionary from server
        """
        try:
            # Convert query to JSON and add newline
            query_json = json.dumps(query) + '\n'
            self.socket.send(query_json.encode('utf-8'))

            # Receive response
            response = self.socket.recv(4096).decode('utf-8').strip()

            try:
                return json.loads(response)
            except json.JSONDecodeError:
                # Handle non-JSON responses (like simple OK messages)
                return {"status": "OK", "message": response}

        except Exception as e:
            raise QueryError(f"Failed to execute query: {e}")

    def authenticate(self, username: str, password: str) -> Dict[str, Any]:
        """
        Authenticate with the ShibuDb server

        Args:
            username: Username for authentication
            password: Password for authentication

        Returns:
            Authentication response
        """
        login_query = {
            "username": username,
            "password": password
        }

        response = self._send_query(login_query)

        if response.get("status") == "OK":
            self.authenticated = True
            self.current_user = response.get("user", {})
            logger.info(f"Successfully authenticated as {username}")
        else:
            raise AuthenticationError(f"Authentication failed: {response.get('message', 'Unknown error')}")

        return response

    def use_space(self, space_name: str) -> Dict[str, Any]:
        """
        Switch to a specific space (table)

        Args:
            space_name: Name of the space to use

        Returns:
            Response from server
        """
        query = {
            "type": "USE_SPACE",
            "space": space_name,
            "user": self.current_user.get("username", "")
        }

        response = self._send_query(query)

        if response.get("status") == "OK":
            self.current_space = space_name
            logger.info(f"Switched to space: {space_name}")

        return response

    def create_space(self, space_name: str, engine_type: str = "key-value",
                     dimension: Optional[int] = None, index_type: str = "Flat",
                     metric: str = "L2") -> Dict[str, Any]:
        """
        Create a new space

        Args:
            space_name: Name of the space to create
            engine_type: Type of engine ("key-value" or "vector")
            dimension: Vector dimension (required for vector spaces)
            index_type: Index type for vector spaces
            metric: Distance metric for vector spaces

        Returns:
            Response from server
        """
        query = {
            "type": "CREATE_SPACE",
            "space": space_name,
            "user": self.current_user.get("username", ""),
            "engine_type": engine_type,
            "index_type": index_type,
            "metric": metric
        }

        if dimension:
            query["dimension"] = dimension

        return self._send_query(query)

    def delete_space(self, space_name: str) -> Dict[str, Any]:
        """
        Delete a space

        Args:
            space_name: Name of the space to delete

        Returns:
            Response from server
        """
        query = {
            "type": "DELETE_SPACE",
            "data": space_name,
            "user": self.current_user.get("username", "")
        }

        return self._send_query(query)

    def list_spaces(self) -> Dict[str, Any]:
        """
        List all available spaces

        Returns:
            Response containing list of spaces
        """
        query = {
            "type": "LIST_SPACES",
            "user": self.current_user.get("username", "")
        }

        return self._send_query(query)

    def put(self, key: str, value: str, space: Optional[str] = None) -> Dict[str, Any]:
        """
        Put a key-value pair

        Args:
            key: Key to store
            value: Value to store
            space: Space name (uses current space if not specified)

        Returns:
            Response from server
        """
        space_name = space or self.current_space
        if not space_name:
            raise QueryError("No space selected. Use use_space() first or specify space parameter.")

        query = {
            "type": "PUT",
            "key": key,
            "value": value,
            "space": space_name,
            "user": self.current_user.get("username", "")
        }

        return self._send_query(query)

    def get(self, key: str, space: Optional[str] = None) -> Dict[str, Any]:
        """
        Get a value by key

        Args:
            key: Key to retrieve
            space: Space name (uses current space if not specified)

        Returns:
            Response containing the value
        """
        space_name = space or self.current_space
        if not space_name:
            raise QueryError("No space selected. Use use_space() first or specify space parameter.")

        query = {
            "type": "GET",
            "key": key,
            "space": space_name,
            "user": self.current_user.get("username", "")
        }

        return self._send_query(query)

    def delete(self, key: str, space: Optional[str] = None) -> Dict[str, Any]:
        """
        Delete a key-value pair

        Args:
            key: Key to delete
            space: Space name (uses current space if not specified)

        Returns:
            Response from server
        """
        space_name = space or self.current_space
        if not space_name:
            raise QueryError("No space selected. Use use_space() first or specify space parameter.")

        query = {
            "type": "DELETE",
            "key": key,
            "space": space_name,
            "user": self.current_user.get("username", "")
        }

        return self._send_query(query)

    def insert_vector(self, vector_id: int, vector: List[float], space: Optional[str] = None) -> Dict[str, Any]:
        """
        Insert a vector into a vector space

        Args:
            vector_id: ID for the vector
            vector: List of float values representing the vector
            space: Space name (uses current space if not specified)

        Returns:
            Response from server
        """
        space_name = space or self.current_space
        if not space_name:
            raise QueryError("No space selected. Use use_space() first or specify space parameter.")

        # Convert vector to comma-separated string
        vector_str = ",".join(map(str, vector))

        query = {
            "type": "INSERT_VECTOR",
            "key": str(vector_id),
            "value": vector_str,
            "space": space_name,
            "user": self.current_user.get("username", "")
        }

        return self._send_query(query)

    def search_topk(self, query_vector: List[float], k: int = 1, space: Optional[str] = None) -> Dict[str, Any]:
        """
        Search for top-k similar vectors

        Args:
            query_vector: Query vector to search for
            k: Number of top results to return
            space: Space name (uses current space if not specified)

        Returns:
            Response containing search results
        """
        space_name = space or self.current_space
        if not space_name:
            raise QueryError("No space selected. Use use_space() first or specify space parameter.")

        # Convert vector to comma-separated string
        vector_str = ",".join(map(str, query_vector))

        query = {
            "type": "SEARCH_TOPK",
            "value": vector_str,
            "space": space_name,
            "user": self.current_user.get("username", ""),
            "dimension": k
        }

        return self._send_query(query)

    def range_search(self, query_vector: List[float], radius: float, space: Optional[str] = None) -> Dict[str, Any]:
        """
        Search for vectors within a radius

        Args:
            query_vector: Query vector to search for
            radius: Search radius
            space: Space name (uses current space if not specified)

        Returns:
            Response containing search results
        """
        space_name = space or self.current_space
        if not space_name:
            raise QueryError("No space selected. Use use_space() first or specify space parameter.")

        # Convert vector to comma-separated string
        vector_str = ",".join(map(str, query_vector))

        query = {
            "type": "RANGE_SEARCH",
            "value": vector_str,
            "space": space_name,
            "user": self.current_user.get("username", ""),
            "radius": radius
        }

        return self._send_query(query)

    def get_vector(self, vector_id: int, space: Optional[str] = None) -> Dict[str, Any]:
        """
        Get a vector by ID

        Args:
            vector_id: ID of the vector to retrieve
            space: Space name (uses current space if not specified)

        Returns:
            Response containing the vector
        """
        space_name = space or self.current_space
        if not space_name:
            raise QueryError("No space selected. Use use_space() first or specify space parameter.")

        query = {
            "type": "GET_VECTOR",
            "key": str(vector_id),
            "space": space_name,
            "user": self.current_user.get("username", "")
        }

        return self._send_query(query)

    def create_user(self, user: User) -> Dict[str, Any]:
        """
        Create a new user (admin only)

        Args:
            user: User object with user details

        Returns:
            Response from server
        """
        query = {
            "type": "CREATE_USER",
            "user": self.current_user.get("username", ""),
            "new_user": {
                "username": user.username,
                "password": user.password,
                "role": user.role,
                "permissions": user.permissions
            }
        }

        return self._send_query(query)

    def update_user_password(self, username: str, new_password: str) -> Dict[str, Any]:
        """
        Update user password (admin only)

        Args:
            username: Username to update
            new_password: New password

        Returns:
            Response from server
        """
        query = {
            "type": "UPDATE_USER_PASSWORD",
            "user": self.current_user.get("username", ""),
            "new_user": {
                "username": username,
                "password": new_password
            }
        }

        return self._send_query(query)

    def update_user_role(self, username: str, new_role: str) -> Dict[str, Any]:
        """
        Update user role (admin only)

        Args:
            username: Username to update
            new_role: New role

        Returns:
            Response from server
        """
        query = {
            "type": "UPDATE_USER_ROLE",
            "user": self.current_user.get("username", ""),
            "new_user": {
                "username": username,
                "role": new_role
            }
        }

        return self._send_query(query)

    def update_user_permissions(self, username: str, permissions: Dict[str, str]) -> Dict[str, Any]:
        """
        Update user permissions (admin only)

        Args:
            username: Username to update
            permissions: New permissions dictionary

        Returns:
            Response from server
        """
        query = {
            "type": "UPDATE_USER_PERMISSIONS",
            "user": self.current_user.get("username", ""),
            "new_user": {
                "username": username,
                "permissions": permissions
            }
        }

        return self._send_query(query)

    def delete_user(self, username: str) -> Dict[str, Any]:
        """
        Delete a user (admin only)

        Args:
            username: Username to delete

        Returns:
            Response from server
        """
        query = {
            "type": "DELETE_USER",
            "user": self.current_user.get("username", ""),
            "delete_user": {
                "username": username
            }
        }

        return self._send_query(query)

    def get_user(self, username: str) -> Dict[str, Any]:
        """
        Get user information (admin only)

        Args:
            username: Username to get information for

        Returns:
            Response containing user information
        """
        query = {
            "type": "GET_USER",
            "user": self.current_user.get("username", ""),
            "data": username
        }

        return self._send_query(query)

    def close(self):
        """Close the connection to the server"""
        if self.socket:
            self.socket.close()
            logger.info("Connection closed")

    def __enter__(self):
        """Context manager entry"""
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        """Context manager exit"""
        self.close()


# Convenience functions for quick operations
def connect(host: str = "localhost", port: int = 9090, username: str = None,
            password: str = None, timeout: int = 30) -> ShibuDbClient:
    """
    Create and optionally authenticate a ShibuDb client

    Args:
        host: Database server host
        port: Database server port
        username: Username for authentication
        password: Password for authentication
        timeout: Connection timeout in seconds

    Returns:
        Authenticated ShibuDb client
    """
    client = ShibuDbClient(host, port, timeout)

    if username and password:
        client.authenticate(username, password)

    return client