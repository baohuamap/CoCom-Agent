# File: src/core/alignment.py

from typing import Set

from src.graph.neo4j_manager import Neo4jConnectionManager


class CPGAlignmentLayer:
    """
    Bridge layer used by CoComOrchestrator to resolve (file_path, line_number)
    coordinates from CodeQL SARIF output into sets of Joern CPG Node IDs stored
    in Neo4j.  Returns all matching nodes at a given location so the AACC engine
    can use them as source/sink seeds.
    """

    _NODE_QUERY = """
    MATCH (n)
    WHERE n.filename ENDS WITH $file AND n.lineNumber = $line
    RETURN id(n) AS node_id
    ORDER BY n.columnNumber
    """

    def __init__(self):
        self.driver = Neo4jConnectionManager.get_driver()

    def close(self) -> None:
        """Closes the shared Neo4j driver via the connection manager."""
        Neo4jConnectionManager.close()

    def get_joern_nodes(self, file_path: str, line_number: int) -> Set[int]:
        """
        Returns all Joern CPG Node IDs whose filename ends with ``file_path``
        and whose lineNumber equals ``line_number``.

        Using the full relative path (not just the basename) avoids false
        matches across files with the same name in different packages.
        Returns an empty set when no matching nodes are found.
        """
        with self.driver.session() as session:
            result = session.run(self._NODE_QUERY, file=file_path, line=line_number)
            return {record["node_id"] for record in result}
