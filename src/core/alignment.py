# File: src/core/alignment.py

import json
import os
from pathlib import Path
from typing import Dict, List, Optional, Set

from neo4j import GraphDatabase


class CodeQLToJoernAligner:
    """
    Maps CodeQL findings (file path, line number, column) to
    corresponding Joern Node IDs in the Neo4j CPG.
    """

    def __init__(self):
        uri = os.getenv("NEO4J_URI", "bolt://localhost:7687")
        user = os.getenv("NEO4J_USER", "neo4j")
        password = os.getenv("NEO4J_PASSWORD", "cocom_secure_password")
        self.driver = GraphDatabase.driver(uri, auth=(user, password))

    def close(self):
        self.driver.close()

    def load_sarif(self, sarif_path: str) -> List[Dict]:
        """Extracts findings (file, line, col, rule) from a SARIF report."""
        with open(sarif_path) as f:
            sarif = json.load(f)

        findings = []
        for run in sarif.get("runs", []):
            for result in run.get("results", []):
                rule_id = result.get("ruleId", "unknown")
                for location in result.get("locations", []):
                    phys = location.get("physicalLocation", {})
                    artifact = phys.get("artifactLocation", {}).get("uri", "")
                    region = phys.get("region", {})
                    findings.append({
                        "rule_id": rule_id,
                        "file": artifact,
                        "line": region.get("startLine"),
                        "col": region.get("startColumn"),
                    })
        return findings

    def resolve_node_ids(self, findings: List[Dict]) -> List[Dict]:
        """
        For each CodeQL finding, queries Neo4j to find the closest CPG node
        matching the file path and line number.

        Returns findings enriched with `joern_node_id`.
        """
        query = """
        MATCH (n)
        WHERE n.filename CONTAINS $file AND n.lineNumber = $line
        RETURN id(n) AS node_id, n.code AS code, labels(n)[0] AS label
        ORDER BY n.columnNumber
        LIMIT 1
        """
        enriched = []
        with self.driver.session() as session:
            for finding in findings:
                result = session.run(query, file=Path(finding["file"]).name, line=finding["line"])
                record = result.single()
                finding["joern_node_id"] = record["node_id"] if record else None
                finding["joern_code"] = record["code"] if record else None
                enriched.append(finding)

        return enriched


class CPGAlignmentLayer:
    """
    Bridge layer used by CoComOrchestrator to resolve (file_path, line_number)
    coordinates from CodeQL SARIF output into sets of Joern CPG Node IDs stored
    in Neo4j.  Returns all matching nodes at a given location so the AACC engine
    can use them as source/sink seeds.
    """

    _NODE_QUERY = """
    MATCH (n)
    WHERE n.filename CONTAINS $file AND n.lineNumber = $line
    RETURN id(n) AS node_id
    ORDER BY n.columnNumber
    """

    def __init__(self):
        uri = os.getenv("NEO4J_URI", "bolt://localhost:7687")
        user = os.getenv("NEO4J_USER", "neo4j")
        password = os.getenv("NEO4J_PASSWORD", "cocom_secure_password")
        self.driver = GraphDatabase.driver(uri, auth=(user, password))

    def close(self) -> None:
        """Closes the Neo4j driver connection."""
        self.driver.close()

    def get_joern_nodes(self, file_path: str, line_number: int) -> Set[int]:
        """
        Returns all Joern CPG Node IDs whose filename contains the basename of
        ``file_path`` and whose lineNumber equals ``line_number``.

        Returns an empty set when no matching nodes are found.
        """
        file_name = Path(file_path).name
        with self.driver.session() as session:
            result = session.run(self._NODE_QUERY, file=file_name, line=line_number)
            return {record["node_id"] for record in result}
