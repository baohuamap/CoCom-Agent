# File: tests/test_neo4j_manager.py

"""
Unit tests for Neo4jConnectionManager.

GraphDatabase is mocked throughout — no live database required.
"""

from unittest.mock import MagicMock, patch

import pytest

from src.graph.neo4j_manager import Neo4jConnectionManager


@pytest.fixture(autouse=True)
def reset_singleton():
    """Ensure the singleton is reset between every test."""
    Neo4jConnectionManager._driver = None
    yield
    Neo4jConnectionManager._driver = None


class TestNeo4jConnectionManager:

    @patch("src.graph.neo4j_manager.GraphDatabase")
    def test_get_driver_returns_driver(self, MockGDB):
        mock_driver = MagicMock()
        MockGDB.driver.return_value = mock_driver

        result = Neo4jConnectionManager.get_driver()
        assert result is mock_driver

    @patch("src.graph.neo4j_manager.GraphDatabase")
    def test_get_driver_is_singleton(self, MockGDB):
        mock_driver = MagicMock()
        MockGDB.driver.return_value = mock_driver

        d1 = Neo4jConnectionManager.get_driver()
        d2 = Neo4jConnectionManager.get_driver()
        assert d1 is d2
        MockGDB.driver.assert_called_once()  # initialized only once

    @patch("src.graph.neo4j_manager.GraphDatabase")
    def test_close_resets_singleton(self, MockGDB):
        mock_driver = MagicMock()
        MockGDB.driver.return_value = mock_driver

        Neo4jConnectionManager.get_driver()
        Neo4jConnectionManager.close()

        assert Neo4jConnectionManager._driver is None
        mock_driver.close.assert_called_once()

    @patch("src.graph.neo4j_manager.GraphDatabase")
    def test_close_when_no_driver_is_noop(self, MockGDB):
        """close() must not raise when called before get_driver()."""
        Neo4jConnectionManager.close()  # should not raise
        MockGDB.driver.assert_not_called()

    @patch("src.graph.neo4j_manager.GraphDatabase")
    def test_uses_env_credentials(self, MockGDB, monkeypatch):
        monkeypatch.setenv("NEO4J_URI", "bolt://custom:9999")
        monkeypatch.setenv("NEO4J_USER", "testuser")
        monkeypatch.setenv("NEO4J_PASSWORD", "testpass")

        Neo4jConnectionManager.get_driver()
        MockGDB.driver.assert_called_once_with(
            "bolt://custom:9999", auth=("testuser", "testpass")
        )
