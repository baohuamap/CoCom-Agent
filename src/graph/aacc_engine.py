# File: src/graph/aacc_engine.py

from typing import List

import networkx as nx

from src.graph.neo4j_manager import Neo4jConnectionManager


class AACCEngine:
    """
    Implements Analysis-Aware Context Compression.
    Executes reachability queries in Neo4j and returns a compressed NetworkX graph.
    """

    def __init__(self, depth_limit: int = 15):
        """
        Args:
            depth_limit: Maximum traversal depth for forward/backward reachability.
                         Default of 15 is empirically sufficient for typical
                         inter-procedural taint flows without over-capturing.
        """
        self.driver = Neo4jConnectionManager.get_driver()
        self.depth_limit = depth_limit

    def close(self) -> None:
        """Closes the shared Neo4j driver via the connection manager."""
        Neo4jConnectionManager.close()

    def extract_compressed_graph(
        self,
        source_ids: List[int],
        sink_ids: List[int],
        depth_limit: int | None = None,
    ) -> nx.DiGraph:
        """Computes R_s ∩ R_t and returns the induced subgraph G'."""
        effective_depth = depth_limit if depth_limit is not None else self.depth_limit
        query = """
        // Forward Reachability
        MATCH (source) WHERE id(source) IN $source_ids
        CALL apoc.path.subgraphNodes(source, {
            relationshipFilter: "CFG>|REACHING_DEF>|CALL>|AST>",
            maxLevel: $depth_limit
        }) YIELD node AS forward_node
        WITH collect(DISTINCT id(forward_node)) AS Rs

        // Backward Reachability
        MATCH (sink) WHERE id(sink) IN $sink_ids
        CALL apoc.path.subgraphNodes(sink, {
            relationshipFilter: "<CFG|<REACHING_DEF|<CALL|<AST",
            maxLevel: $depth_limit
        }) YIELD node AS backward_node
        WITH Rs, collect(DISTINCT id(backward_node)) AS Rt

        // Intersection via APOC (O(n) vs O(n²) list comprehension)
        WITH apoc.coll.intersection(Rs, Rt) AS corridor_node_ids

        // Induced Subgraph Extraction
        MATCH (n) WHERE id(n) IN corridor_node_ids
        OPTIONAL MATCH (n)-[r]->(m) WHERE id(m) IN corridor_node_ids
        RETURN
            id(n) AS node_id,
            labels(n)[0] AS node_type,
            n.code AS code,
            n.lineNumber AS line_number,
            n.filename AS file_name,
            collect({target_id: id(m), edge_type: type(r)}) AS edges
        """

        G_prime = nx.DiGraph()

        with self.driver.session() as session:
            result = session.run(
                query,
                source_ids=source_ids,
                sink_ids=sink_ids,
                depth_limit=effective_depth,
            )

            for record in result:
                node_id = record["node_id"]
                G_prime.add_node(
                    node_id,
                    type=record["node_type"],
                    code=record["code"],
                    line=record["line_number"],
                    file=record["file_name"],
                )

                for edge in record["edges"]:
                    if edge["target_id"] is not None:
                        G_prime.add_edge(
                            node_id,
                            edge["target_id"],
                            type=edge["edge_type"],
                        )

        return G_prime

    def format_for_llm(self, G_prime: nx.DiGraph) -> str:
        """Serializes G' into a condensed string for LLM prompting."""
        prompt_context = "--- COMPRESSED REPOSITORY CONTEXT (G') ---\n"
        sorted_nodes = sorted(
            G_prime.nodes(data=True),
            key=lambda x: (x[1].get("file") or "", x[1].get("line", 0) or 0),
        )

        current_file = ""
        for node_id, data in sorted_nodes:
            file_val = data.get("file") or "unknown"
            if file_val != current_file:
                current_file = file_val
                prompt_context += f"\nFile: {current_file}\n"

            line_str = f"L{data['line']}" if data.get("line") else "L?"
            prompt_context += (
                f"[{line_str}] ({data.get('type', '')}): {data.get('code', '')}\n"
            )

        return prompt_context
