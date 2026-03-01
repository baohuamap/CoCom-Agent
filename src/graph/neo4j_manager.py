# File: src/graph/neo4j_manager.py

import os

from neo4j import Driver, GraphDatabase


class Neo4jConnectionManager:
    """
    Process-scoped singleton for the Neo4j driver.

    Callers use ``Neo4jConnectionManager.get_driver()`` instead of creating
    individual ``GraphDatabase.driver(...)`` instances, ensuring at most one
    live connection per worker process.
    """

    _driver: Driver | None = None

    @classmethod
    def get_driver(cls) -> Driver:
        """Returns the shared driver, initializing it on the first call."""
        if cls._driver is None:
            uri = os.getenv("NEO4J_URI", "bolt://localhost:7687")
            user = os.getenv("NEO4J_USER", "neo4j")
            password = os.getenv("NEO4J_PASSWORD", "cocom_secure_password")
            cls._driver = GraphDatabase.driver(uri, auth=(user, password))
        return cls._driver

    @classmethod
    def close(cls) -> None:
        """Closes the shared driver and resets the singleton for re-initialization."""
        if cls._driver is not None:
            cls._driver.close()
            cls._driver = None
