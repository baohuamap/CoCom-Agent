# File: tests/test_alignment.py

"""
Unit tests for CPGAlignmentLayer.

The Neo4j driver is mocked throughout — no live database required.
"""

from unittest.mock import MagicMock, patch

import pytest

from src.core.alignment import CPGAlignmentLayer

# ---------------------------------------------------------------------------
# CPGAlignmentLayer
# ---------------------------------------------------------------------------


class TestCPGAlignmentLayer:

    @patch("src.core.alignment.Neo4jConnectionManager")
    def test_get_joern_nodes_returns_set_of_ids(self, MockManager):
        mock_driver = MagicMock()
        MockManager.get_driver.return_value = mock_driver

        mock_session = MagicMock()
        mock_driver.session.return_value.__enter__ = MagicMock(
            return_value=mock_session
        )
        mock_driver.session.return_value.__exit__ = MagicMock(return_value=False)

        mock_session.run.return_value = [
            {"node_id": 101},
            {"node_id": 202},
        ]

        aligner = CPGAlignmentLayer()
        result = aligner.get_joern_nodes("app/views.py", 42)

        assert result == {101, 202}
        mock_session.run.assert_called_once()
        call_kwargs = mock_session.run.call_args
        assert call_kwargs[1]["line"] == 42
        assert call_kwargs[1]["file"] == "app/views.py"  # full relative path

    @patch("src.core.alignment.Neo4jConnectionManager")
    def test_get_joern_nodes_returns_empty_set_when_no_match(self, MockManager):
        mock_driver = MagicMock()
        MockManager.get_driver.return_value = mock_driver

        mock_session = MagicMock()
        mock_driver.session.return_value.__enter__ = MagicMock(
            return_value=mock_session
        )
        mock_driver.session.return_value.__exit__ = MagicMock(return_value=False)
        mock_session.run.return_value = []

        aligner = CPGAlignmentLayer()
        result = aligner.get_joern_nodes("unknown/file.py", 999)
        assert result == set()

    @patch("src.core.alignment.Neo4jConnectionManager")
    def test_close_delegates_to_manager(self, MockManager):
        MockManager.get_driver.return_value = MagicMock()
        aligner = CPGAlignmentLayer()
        aligner.close()
        MockManager.close.assert_called_once()

    @patch("src.core.alignment.Neo4jConnectionManager")
    def test_uses_neo4j_connection_manager(self, MockManager):
        mock_driver = MagicMock()
        MockManager.get_driver.return_value = mock_driver
        aligner = CPGAlignmentLayer()
        MockManager.get_driver.assert_called_once()
        assert aligner.driver is mock_driver
