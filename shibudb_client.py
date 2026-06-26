#!/usr/bin/env python3
"""
ShibuDb Python Client

A comprehensive Python client for ShibuDb database that supports:
- Authentication and user management
- Key-value operations
- Vector similarity search
- Space management
- Connection management
- Connection pooling
"""

import json
import socket
import time
import threading
from typing import Dict, List, Optional, Tuple, Union, Any
from dataclasses import dataclass
import logging
from queue import Queue, Empty
from contextlib import contextmanager

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


# Metadata field types supported by filterable Flat vector spaces.
# Numeric values (int and float) are indexed and compared as float64 on the
# server, which is exact for integers up to 2^53.
METADATA_TYPE_STRING = "string"
METADATA_TYPE_INT = "int"
METADATA_TYPE_FLOAT = "float"
_VALID_METADATA_TYPES = (METADATA_TYPE_STRING, METADATA_TYPE_INT, METADATA_TYPE_FLOAT)


@dataclass
class MetadataFieldSpec:
    """
    Declares one indexable metadata field for a filterable Flat vector space.

    Args:
        name: Field name (must be unique within the space).
        type: One of ``"string"``, ``"int"``, or ``"float"``.
    """
    name: str
    type: str = METADATA_TYPE_STRING

    def to_dict(self) -> Dict[str, str]:
        if self.type not in _VALID_METADATA_TYPES:
            raise ValueError(
                f"invalid metadata field type {self.type!r} for {self.name!r} "
                f"(allowed: {', '.join(_VALID_METADATA_TYPES)})"
            )
        if not self.name:
            raise ValueError("metadata field name must not be empty")
        return {"name": self.name, "type": self.type}


@dataclass
class SpaceInfo:
    """Space information model"""
    name: str
    engine_type: str
    dimension: Optional[int] = None
    index_type: Optional[str] = None
    metric: Optional[str] = None
    indexed_metadata_fields: Optional[List[MetadataFieldSpec]] = None


@dataclass
class ConnectionConfig:
    """Configuration for database connections"""
    host: str = "localhost"
    port: int = 4444
    timeout: int = 30
    username: Optional[str] = None
    password: Optional[str] = None


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


class PoolExhaustedError(ShibuDbError):
    """Raised when connection pool is exhausted"""
    pass


class FilterError(ShibuDbError):
    """Raised when a metadata filter expression is invalid"""
    pass


# Filter operators understood by the server's filterable Flat vector engine.
_OP_EQ = "eq"
_OP_IN = "in"
_OP_AND = "and"
_OP_OR = "or"
_OP_NOT = "not"
_OP_GT = "gt"
_OP_GTE = "gte"
_OP_LT = "lt"
_OP_LTE = "lte"
_OP_BETWEEN = "between"


class Filter:
    """
    Builder for metadata filter expressions used to pre-filter vector searches
    on filterable Flat spaces.

    A ``Filter`` compiles to the server's recursive filter AST. Build leaf
    predicates with the class methods and combine them with ``&`` (AND),
    ``|`` (OR), and ``~`` (NOT), or with :meth:`and_`, :meth:`or_`, :meth:`not_`.

    Examples::

        # field comparisons
        Filter.eq("user_id", "alice")
        Filter.gt("price", 10)
        Filter.in_("category", ["books", "toys"])
        Filter.between("year", 2021, 2023)

        # composition
        f = (Filter.eq("user_id", "alice") | Filter.eq("user_id", "bob")) \
            & Filter.lt("price", 40)

        # from a SQL-like WHERE string (mirrors the CLI --where syntax)
        f = Filter.parse("(user_id=alice OR user_id=bob) AND price<40")

    Pass the resulting ``Filter`` (or its :meth:`to_dict`) to
    :meth:`ShibuDbClient.search_topk` / :meth:`ShibuDbClient.range_search`.
    """

    def __init__(self, ast: Dict[str, Any]):
        self._ast = ast

    def to_dict(self) -> Dict[str, Any]:
        """Return the underlying filter AST as a JSON-serializable dict."""
        return self._ast

    def __repr__(self) -> str:
        return f"Filter({self._ast!r})"

    # --- leaf predicates ---
    @staticmethod
    def eq(field: str, value: Any) -> "Filter":
        """``field == value`` (string or numeric)."""
        return Filter({"op": _OP_EQ, "field": field, "value": value})

    @staticmethod
    def ne(field: str, value: Any) -> "Filter":
        """``field != value`` (compiles to ``NOT(field == value)``)."""
        return Filter.not_(Filter.eq(field, value))

    @staticmethod
    def gt(field: str, value: Any) -> "Filter":
        """``field > value`` (numeric fields only)."""
        return Filter({"op": _OP_GT, "field": field, "value": value})

    @staticmethod
    def gte(field: str, value: Any) -> "Filter":
        """``field >= value`` (numeric fields only)."""
        return Filter({"op": _OP_GTE, "field": field, "value": value})

    @staticmethod
    def lt(field: str, value: Any) -> "Filter":
        """``field < value`` (numeric fields only)."""
        return Filter({"op": _OP_LT, "field": field, "value": value})

    @staticmethod
    def lte(field: str, value: Any) -> "Filter":
        """``field <= value`` (numeric fields only)."""
        return Filter({"op": _OP_LTE, "field": field, "value": value})

    @staticmethod
    def in_(field: str, values: List[Any]) -> "Filter":
        """``field IN (values...)`` — matches any of the listed values."""
        values = list(values)
        if not values:
            raise FilterError(f"IN filter on {field!r} requires a non-empty list of values")
        return Filter({"op": _OP_IN, "field": field, "values": values})

    @staticmethod
    def between(field: str, low: Any, high: Any) -> "Filter":
        """``field BETWEEN low AND high`` — inclusive, numeric fields only."""
        return Filter({"op": _OP_BETWEEN, "field": field, "values": [low, high]})

    # --- combinators ---
    @staticmethod
    def and_(*filters: Union["Filter", Dict[str, Any]]) -> "Filter":
        """Logical AND of two or more filters."""
        return Filter._combine(_OP_AND, filters)

    @staticmethod
    def or_(*filters: Union["Filter", Dict[str, Any]]) -> "Filter":
        """Logical OR of two or more filters."""
        return Filter._combine(_OP_OR, filters)

    @staticmethod
    def not_(filter: Union["Filter", Dict[str, Any]]) -> "Filter":
        """Logical negation of a filter."""
        return Filter({"op": _OP_NOT, "filters": [Filter._as_dict(filter)]})

    @staticmethod
    def parse(expr: str) -> "Filter":
        """
        Parse a SQL-like WHERE expression into a :class:`Filter`.

        Mirrors the server CLI ``--where`` grammar (keywords are
        case-insensitive)::

            field = value | field != value | field > value | >= | < | <=
            field IN (v1, v2, ...)
            field BETWEEN low AND high
            AND, OR, NOT, and ( ... ) for grouping

        Bare/quoted words are treated as strings; numeric literals are numbers
        (quote a numeric-looking string to force a string, e.g. ``user_id='123'``).
        """
        return Filter(_parse_where(expr))

    # --- operator overloads ---
    def __and__(self, other: "Filter") -> "Filter":
        return Filter.and_(self, other)

    def __or__(self, other: "Filter") -> "Filter":
        return Filter.or_(self, other)

    def __invert__(self) -> "Filter":
        return Filter.not_(self)

    # --- helpers ---
    @staticmethod
    def _as_dict(filter: Union["Filter", Dict[str, Any]]) -> Dict[str, Any]:
        if isinstance(filter, Filter):
            return filter._ast
        if isinstance(filter, dict):
            return filter
        raise FilterError(f"expected a Filter or dict, got {type(filter).__name__}")

    @staticmethod
    def _combine(op: str, filters: Tuple[Union["Filter", Dict[str, Any]], ...]) -> "Filter":
        if len(filters) < 2:
            raise FilterError(f"{op.upper()} requires at least two filters")
        children: List[Dict[str, Any]] = []
        for f in filters:
            d = Filter._as_dict(f)
            # Flatten same-op children to keep the AST shallow.
            if d.get("op") == op and "filters" in d:
                children.extend(d["filters"])
            else:
                children.append(d)
        return Filter({"op": op, "filters": children})


# === WHERE expression parser (mirrors the server CLI --where grammar) ===

def _tokenize_where(s: str) -> List[Dict[str, Any]]:
    special = set("(),=<>!'\"")
    toks: List[Dict[str, Any]] = []
    i, n = 0, len(s)
    while i < n:
        c = s[i]
        if c in " \t\n\r":
            i += 1
            continue
        if c == "(":
            toks.append({"kind": "lparen", "text": "("}); i += 1; continue
        if c == ")":
            toks.append({"kind": "rparen", "text": ")"}); i += 1; continue
        if c == ",":
            toks.append({"kind": "comma", "text": ","}); i += 1; continue
        if c == "=":
            i += 2 if (i + 1 < n and s[i + 1] == "=") else 1
            toks.append({"kind": "op", "text": "="}); continue
        if c == "!":
            if i + 1 < n and s[i + 1] == "=":
                toks.append({"kind": "op", "text": "!="}); i += 2; continue
            raise FilterError("unexpected '!' (did you mean '!='?)")
        if c == "<":
            if i + 1 < n and s[i + 1] == "=":
                toks.append({"kind": "op", "text": "<="}); i += 2
            else:
                toks.append({"kind": "op", "text": "<"}); i += 1
            continue
        if c == ">":
            if i + 1 < n and s[i + 1] == "=":
                toks.append({"kind": "op", "text": ">="}); i += 2
            else:
                toks.append({"kind": "op", "text": ">"}); i += 1
            continue
        if c == "'" or c == '"':
            quote = c
            i += 1
            buf = []
            while i < n and s[i] != quote:
                if s[i] == "\\" and i + 1 < n:
                    buf.append(s[i + 1]); i += 2; continue
                buf.append(s[i]); i += 1
            if i >= n:
                raise FilterError("unterminated string literal")
            i += 1  # consume closing quote
            toks.append({"kind": "string", "text": "".join(buf)})
            continue

        start = i
        while i < n and s[i] not in " \t\n\r" and s[i] not in special:
            i += 1
        word = s[start:i]
        upper = word.upper()
        if upper in ("AND", "OR", "NOT", "IN", "BETWEEN"):
            toks.append({"kind": upper.lower(), "text": upper})
        else:
            try:
                num = float(word)
                toks.append({"kind": "number", "text": word, "num": num})
            except ValueError:
                toks.append({"kind": "ident", "text": word})
    toks.append({"kind": "eof", "text": "end of input"})
    return toks


class _WhereParser:
    def __init__(self, toks: List[Dict[str, Any]]):
        self.toks = toks
        self.pos = 0

    def peek(self) -> Dict[str, Any]:
        return self.toks[self.pos]

    def next(self) -> Dict[str, Any]:
        t = self.toks[self.pos]
        if self.pos < len(self.toks) - 1:
            self.pos += 1
        return t

    def parse_expr(self) -> Dict[str, Any]:
        return self.parse_or()

    def parse_or(self) -> Dict[str, Any]:
        left = self.parse_and()
        while self.peek()["kind"] == "or":
            self.next()
            right = self.parse_and()
            left = _combine_ast(_OP_OR, left, right)
        return left

    def parse_and(self) -> Dict[str, Any]:
        left = self.parse_not()
        while self.peek()["kind"] == "and":
            self.next()
            right = self.parse_not()
            left = _combine_ast(_OP_AND, left, right)
        return left

    def parse_not(self) -> Dict[str, Any]:
        if self.peek()["kind"] == "not":
            self.next()
            sub = self.parse_not()
            return {"op": _OP_NOT, "filters": [sub]}
        return self.parse_primary()

    def parse_primary(self) -> Dict[str, Any]:
        if self.peek()["kind"] == "lparen":
            self.next()
            inner = self.parse_expr()
            if self.peek()["kind"] != "rparen":
                raise FilterError(f"expected ')', got {self.peek()['text']!r}")
            self.next()
            return inner
        return self.parse_predicate()

    def parse_predicate(self) -> Dict[str, Any]:
        field_tok = self.next()
        if field_tok["kind"] != "ident":
            raise FilterError(f"expected a field name, got {field_tok['text']!r}")
        field = field_tok["text"]

        op_tok = self.next()
        kind = op_tok["kind"]
        if kind == "op":
            val = _token_value(self.next())
            text = op_tok["text"]
            if text == "=":
                return {"op": _OP_EQ, "field": field, "value": val}
            if text == "!=":
                return {"op": _OP_NOT, "filters": [{"op": _OP_EQ, "field": field, "value": val}]}
            if text == ">":
                return {"op": _OP_GT, "field": field, "value": val}
            if text == ">=":
                return {"op": _OP_GTE, "field": field, "value": val}
            if text == "<":
                return {"op": _OP_LT, "field": field, "value": val}
            if text == "<=":
                return {"op": _OP_LTE, "field": field, "value": val}
            raise FilterError(f"unsupported operator {text!r}")
        if kind == "in":
            if self.peek()["kind"] != "lparen":
                raise FilterError(f"expected '(' after IN, got {self.peek()['text']!r}")
            self.next()
            values: List[Any] = []
            while True:
                values.append(_token_value(self.next()))
                sep = self.next()
                if sep["kind"] == "comma":
                    continue
                if sep["kind"] == "rparen":
                    break
                raise FilterError(f"expected ',' or ')' in IN list, got {sep['text']!r}")
            return {"op": _OP_IN, "field": field, "values": values}
        if kind == "between":
            lo = _token_value(self.next())
            if self.peek()["kind"] != "and":
                raise FilterError(f"expected AND in BETWEEN, got {self.peek()['text']!r}")
            self.next()
            hi = _token_value(self.next())
            return {"op": _OP_BETWEEN, "field": field, "values": [lo, hi]}
        raise FilterError(f"expected an operator after field {field!r}, got {op_tok['text']!r}")


def _token_value(t: Dict[str, Any]) -> Any:
    if t["kind"] in ("string", "ident"):
        return t["text"]
    if t["kind"] == "number":
        return t["num"]
    raise FilterError(f"expected a value, got {t['text']!r}")


def _combine_ast(op: str, left: Dict[str, Any], right: Dict[str, Any]) -> Dict[str, Any]:
    if left.get("op") == op and "filters" in left:
        left["filters"].append(right)
        return left
    return {"op": op, "filters": [left, right]}


def _parse_where(expr: str) -> Dict[str, Any]:
    if not expr or not expr.strip():
        raise FilterError("empty expression")
    parser = _WhereParser(_tokenize_where(expr))
    ast = parser.parse_expr()
    if parser.peek()["kind"] != "eof":
        raise FilterError(f"unexpected {parser.peek()['text']!r}")
    return ast


def _normalize_field_specs(
    fields: Union[None, Dict[str, str], List[Any]]
) -> Optional[List[Dict[str, str]]]:
    """
    Normalize indexed metadata field specs into the wire format.

    Accepts any of:
      - None
      - dict mapping ``{name: type}``
      - list of ``MetadataFieldSpec``
      - list of ``(name, type)`` tuples
      - list of ``{"name": ..., "type": ...}`` dicts
    """
    if fields is None:
        return None
    specs: List[Dict[str, str]] = []
    if isinstance(fields, dict):
        items = fields.items()
        for name, typ in items:
            specs.append(MetadataFieldSpec(name=name, type=typ).to_dict())
        return specs
    for field in fields:
        if isinstance(field, MetadataFieldSpec):
            specs.append(field.to_dict())
        elif isinstance(field, dict):
            specs.append(MetadataFieldSpec(name=field["name"], type=field.get("type", METADATA_TYPE_STRING)).to_dict())
        elif isinstance(field, (tuple, list)) and len(field) == 2:
            specs.append(MetadataFieldSpec(name=field[0], type=field[1]).to_dict())
        else:
            raise FilterError(
                "indexed_metadata_fields entries must be MetadataFieldSpec, "
                "{'name','type'} dict, or (name, type) tuple"
            )
    return specs


def _normalize_filter(
    filter: Union[None, "Filter", Dict[str, Any]] = None,
    where: Optional[str] = None,
) -> Optional[Dict[str, Any]]:
    """Normalize a filter argument (Filter, dict, or WHERE string) into the wire AST."""
    if where is not None:
        if filter is not None:
            raise FilterError("pass either 'filter' or 'where', not both")
        return _parse_where(where)
    if filter is None:
        return None
    if isinstance(filter, Filter):
        return filter.to_dict()
    if isinstance(filter, dict):
        return filter
    raise FilterError(f"filter must be a Filter, dict, or None, got {type(filter).__name__}")


class ConnectionPool:
    """
    Connection pool for ShibuDb clients
    
    Manages a pool of database connections to improve performance
    and provide connection reuse capabilities.
    """
    
    def __init__(self, config: ConnectionConfig, min_size: int = 2, max_size: int = 10, 
                 acquire_timeout: int = 30, health_check_interval: int = 60):
        """
        Initialize connection pool
        
        Args:
            config: Connection configuration
            min_size: Minimum number of connections in pool
            max_size: Maximum number of connections in pool
            acquire_timeout: Timeout for acquiring connection (seconds)
            health_check_interval: Interval for health checks (seconds)
        """
        self.config = config
        self.min_size = min_size
        self.max_size = max_size
        self.acquire_timeout = acquire_timeout
        self.health_check_interval = health_check_interval
        
        self._pool = Queue()
        self._active_connections = 0
        self._lock = threading.Lock()
        self._shutdown = False
        
        # Initialize pool with minimum connections
        self._initialize_pool()
        
        # Start health check thread
        self._health_check_thread = threading.Thread(target=self._health_check_worker, daemon=True)
        self._health_check_thread.start()
    
    def _initialize_pool(self):
        """Initialize the pool with minimum connections"""
        for _ in range(self.min_size):
            try:
                connection = self._create_connection()
                self._pool.put(connection)
                self._active_connections += 1
            except Exception as e:
                logger.warning(f"Failed to create initial connection: {e}")
    
    def _create_connection(self) -> 'ShibuDbClient':
        """Create a new database connection"""
        client = ShibuDbClient(
            host=self.config.host,
            port=self.config.port,
            timeout=self.config.timeout
        )
        
        # Authenticate if credentials provided
        if self.config.username and self.config.password:
            try:
                client.authenticate(self.config.username, self.config.password)
            except AuthenticationError as e:
                logger.warning(f"Failed to authenticate connection: {e}")
                client.close()
                raise
        
        return client
    
    def _health_check_worker(self):
        """Background worker for health checks"""
        while not self._shutdown:
            time.sleep(self.health_check_interval)
            self._perform_health_check()
    
    def _perform_health_check(self):
        """Perform health check on pool connections"""
        with self._lock:
            # Check if we need to add more connections
            if self._active_connections < self.min_size:
                try:
                    connection = self._create_connection()
                    self._pool.put(connection)
                    self._active_connections += 1
                    logger.debug("Added connection to pool during health check")
                except Exception as e:
                    logger.warning(f"Failed to add connection during health check: {e}")
    
    @contextmanager
    def get_connection(self):
        """
        Get a connection from the pool
        
        Yields:
            ShibuDbClient: Database client connection
            
        Raises:
            PoolExhaustedError: If no connections available within timeout
        """
        connection = None
        try:
            # Try to get connection from pool
            try:
                connection = self._pool.get(timeout=self.acquire_timeout)
            except Empty:
                # Pool is empty, try to create new connection
                with self._lock:
                    if self._active_connections < self.max_size:
                        try:
                            connection = self._create_connection()
                            self._active_connections += 1
                            logger.debug("Created new connection for pool")
                        except Exception as e:
                            raise PoolExhaustedError(f"Failed to create new connection: {e}")
                    else:
                        raise PoolExhaustedError("Connection pool exhausted")
            
            # Test connection health
            try:
                # Simple health check - try to list spaces
                connection.list_spaces()
            except Exception as e:
                logger.warning(f"Connection health check failed, creating new connection: {e}")
                connection.close()
                connection = self._create_connection()
            
            yield connection
            
        except Exception as e:
            if connection:
                try:
                    connection.close()
                except:
                    pass
                with self._lock:
                    self._active_connections -= 1
            raise
        else:
            # Return connection to pool if it's still healthy
            try:
                # Quick health check before returning to pool
                connection.list_spaces()
                self._pool.put(connection)
            except Exception as e:
                logger.warning(f"Connection unhealthy, not returning to pool: {e}")
                connection.close()
                with self._lock:
                    self._active_connections -= 1
    
    def close(self):
        """Close all connections in the pool"""
        self._shutdown = True
        
        # Close all connections in the pool
        while not self._pool.empty():
            try:
                connection = self._pool.get_nowait()
                connection.close()
            except Empty:
                break
        
        with self._lock:
            self._active_connections = 0
        
        logger.info("Connection pool closed")
    
    def get_stats(self) -> Dict[str, Any]:
        """Get pool statistics"""
        with self._lock:
            return {
                "pool_size": self._pool.qsize(),
                "active_connections": self._active_connections,
                "min_size": self.min_size,
                "max_size": self.max_size,
                "shutdown": self._shutdown
            }


class ShibuDbClient:
    """
    ShibuDb Python Client

    Provides a comprehensive interface to ShibuDb database with support for:
    - Authentication and user management
    - Key-value operations
    - Vector similarity search
    - Space management
    - Connection management
    - Connection pooling
    """

    def __init__(self, host: str = "localhost", port: int = 4444, timeout: int = 30):
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
        self._io_lock = threading.Lock()
        self.authenticated = False
        # Ensure current_user is always a safe dictionary to avoid attribute errors
        self.current_user = {"username": "", "role": "", "permissions": {}}
        self.current_space = None
        self._connect()

    def _connect(self):
        """Establish connection to ShibuDb server"""
        try:
            self.close()
            self.socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            self.socket.settimeout(self.timeout)
            self.socket.connect((self.host, self.port))
            # Use file-like wrappers so we can safely read newline-delimited responses.
            # The server protocol is line-based (client sends '\n' terminated JSON).
            self.reader = self.socket.makefile("r", encoding="utf-8", newline="\n")
            self.writer = self.socket.makefile("w", encoding="utf-8", newline="\n")
            logger.info(f"Connected to ShibuDb server at {self.host}:{self.port}")
        except Exception as e:
            raise ConnectionError(f"Failed to connect to ShibuDb server: {e}")

    def _reconnect(self):
        """Reconnect socket and reset stream wrappers."""
        self._connect()

    def _send_query(self, query: Dict[str, Any]) -> Dict[str, Any]:
        """
        Send a query to the server and receive response

        Args:
            query: Query dictionary to send

        Returns:
            Response dictionary from server
        """
        # NOTE: A single recv() is not a message boundary. Under load, responses can be split
        # across packets or multiple responses can coalesce. The protocol is newline-delimited,
        # so we always read exactly one line for one response.
        def _do_io() -> str:
            if not self.socket or not self.reader or not self.writer:
                self._reconnect()
            query_json = json.dumps(query, separators=(",", ":")) + "\n"
            self.writer.write(query_json)
            self.writer.flush()
            line = self.reader.readline()
            if line == "":
                # EOF -> server closed connection
                raise ConnectionError("Server closed connection (EOF)")
            return line.strip()

        with self._io_lock:
            try:
                response = _do_io()
            except (BrokenPipeError, ConnectionResetError, ConnectionAbortedError, socket.timeout, OSError) as e:
                # One reconnect attempt for transient socket failures.
                logger.warning(f"Socket error, reconnecting once: {e}")
                try:
                    self._reconnect()
                    response = _do_io()
                except Exception as e2:
                    raise QueryError(f"Failed to execute query after reconnect: {e2}") from e2
            except Exception as e:
                raise QueryError(f"Failed to execute query: {e}") from e

        try:
            return json.loads(response, strict=False)
        except json.JSONDecodeError:
            # Handle non-JSON responses (like simple OK messages)
            return {"status": "OK", "message": response}

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
            # Capture basic user context for downstream operations
            # Prefer values returned by server if available; otherwise use provided credentials
            user_info = response.get("user") or {}
            username_from_response = user_info.get("username") if isinstance(user_info, dict) else None
            role_from_response = user_info.get("role") if isinstance(user_info, dict) else None
            permissions_from_response = user_info.get("permissions") if isinstance(user_info, dict) else None

            self.current_user = {
                "username": username_from_response or username,
                "role": role_from_response or user_info.get("role", "" ) if isinstance(user_info, dict) else "",
                "permissions": permissions_from_response or user_info.get("permissions", {}) if isinstance(user_info, dict) else {},
            }
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
                     metric: str = "L2",
                     indexed_metadata_fields: Union[None, Dict[str, str], List[Any]] = None,
                     enable_wal: Optional[bool] = None) -> Dict[str, Any]:
        """
        Create a new space

        Args:
            space_name: Name of the space to create
            engine_type: Type of engine ("key-value" or "vector")
            dimension: Vector dimension (required for vector spaces)
            index_type: Index type for vector spaces
            metric: Distance metric for vector spaces
            indexed_metadata_fields: Declare indexable metadata fields to enable
                metadata-filtered search. **Only valid for vector spaces with
                ``index_type="Flat"``.** Accepts a ``{name: type}`` dict, a list
                of :class:`MetadataFieldSpec`, a list of ``(name, type)`` tuples,
                or a list of ``{"name", "type"}`` dicts. ``type`` is one of
                ``"string"``, ``"int"``, or ``"float"``.
            enable_wal: Optionally enable/disable the write-ahead log for the
                space (defaults to the server default when omitted).

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

        specs = _normalize_field_specs(indexed_metadata_fields)
        if specs:
            query["indexed_metadata_fields"] = specs

        if enable_wal is not None:
            query["enable_wal"] = enable_wal

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

    def insert_vector(self, vector_id: int, vector: List[float], space: Optional[str] = None,
                      metadata: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
        """
        Insert (or upsert) a vector into a vector space

        Args:
            vector_id: ID for the vector
            vector: List of float values representing the vector
            space: Space name (uses current space if not specified)
            metadata: Optional ``{field: value}`` metadata to attach to the
                vector. **Only supported on Flat spaces created with
                ``indexed_metadata_fields``.** Values should match the declared
                field types (strings for ``string`` fields, numbers for
                ``int``/``float`` fields). Re-inserting an existing ID updates
                both the vector and its metadata.

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

        if metadata:
            query["metadata"] = metadata

        return self._send_query(query)

    def search_topk(self, query_vector: List[float], k: int = 1, space: Optional[str] = None,
                    filter: Union[None, "Filter", Dict[str, Any]] = None,
                    where: Optional[str] = None) -> Dict[str, Any]:
        """
        Search for top-k similar vectors, optionally pre-filtered by metadata

        Args:
            query_vector: Query vector to search for
            k: Number of top results to return
            space: Space name (uses current space if not specified)
            filter: Optional metadata pre-filter as a :class:`Filter` (or a raw
                filter-AST dict). **Only supported on Flat spaces created with
                ``indexed_metadata_fields``.** Similarity is computed only over
                vectors matching the filter (exact search over the subset).
            where: Optional SQL-like WHERE string (e.g.
                ``"user_id=alice AND price<40"``) parsed via
                :meth:`Filter.parse`. Mutually exclusive with ``filter``.

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

        filter_ast = _normalize_filter(filter, where)
        if filter_ast is not None:
            query["filter"] = filter_ast

        return self._send_query(query)

    def range_search(self, query_vector: List[float], radius: float, space: Optional[str] = None,
                     filter: Union[None, "Filter", Dict[str, Any]] = None,
                     where: Optional[str] = None) -> Dict[str, Any]:
        """
        Search for vectors within a radius, optionally pre-filtered by metadata

        Args:
            query_vector: Query vector to search for
            radius: Search radius
            space: Space name (uses current space if not specified)
            filter: Optional metadata pre-filter as a :class:`Filter` (or a raw
                filter-AST dict). **Only supported on Flat spaces created with
                ``indexed_metadata_fields``.**
            where: Optional SQL-like WHERE string parsed via
                :meth:`Filter.parse`. Mutually exclusive with ``filter``.

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

        filter_ast = _normalize_filter(filter, where)
        if filter_ast is not None:
            query["filter"] = filter_ast

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

    def delete_vector(self, vector_id: int, space: Optional[str] = None) -> Dict[str, Any]:
        """
        Delete a vector by ID from a vector space

        Args:
            vector_id: ID of the vector to delete
            space: Space name (uses current space if not specified)

        Returns:
            Response from server
        """
        space_name = space or self.current_space
        if not space_name:
            raise QueryError("No space selected. Use use_space() first or specify space parameter.")

        query = {
            "type": "DELETE_VECTOR",
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
        try:
            if self.writer:
                try:
                    self.writer.close()
                except Exception:
                    pass
            if self.reader:
                try:
                    self.reader.close()
                except Exception:
                    pass
            if self.socket:
                try:
                    self.socket.close()
                except Exception:
                    pass
        finally:
            self.socket = None
            self.reader = None
            self.writer = None
            logger.info("Connection closed")

    def __enter__(self):
        """Context manager entry"""
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        """Context manager exit"""
        self.close()


# Convenience functions for quick operations
def connect(host: str = "localhost", port: int = 4444, username: str = None,
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


def create_connection_pool(host: str = "localhost", port: int = 4444, username: str = None,
                          password: str = None, timeout: int = 30, min_size: int = 2,
                          max_size: int = 10, acquire_timeout: int = 30,
                          health_check_interval: int = 60) -> ConnectionPool:
    """
    Create a connection pool for ShibuDb clients

    Args:
        host: Database server host
        port: Database server port
        username: Username for authentication
        password: Password for authentication
        timeout: Connection timeout in seconds
        min_size: Minimum number of connections in pool
        max_size: Maximum number of connections in pool
        acquire_timeout: Timeout for acquiring connection (seconds)
        health_check_interval: Interval for health checks (seconds)

    Returns:
        ConnectionPool: Configured connection pool
    """
    config = ConnectionConfig(
        host=host,
        port=port,
        timeout=timeout,
        username=username,
        password=password
    )
    
    return ConnectionPool(
        config=config,
        min_size=min_size,
        max_size=max_size,
        acquire_timeout=acquire_timeout,
        health_check_interval=health_check_interval
    )