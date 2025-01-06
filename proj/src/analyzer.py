from dataclasses import dataclass
from typing import List, Dict, Set, Optional

@dataclass
class Trace:
    """Represents a single execution trace through the program."""
    steps: List[str]
    
    def __str__(self) -> str:
        return " -> ".join(self.steps)

class ASTAnalyzer:

    def __init__(self, ast):
        self.ast = ast

    def traverse_ast(self, node=None, depth=0):
        """
        Recursively traverses an AST and prints the node type and starting line number.
        :param node: Current AST node (dictionary or list).
        :param depth: Current depth in the tree (used for indentation).
        """
        if node is None:
            node = self.ast

        if isinstance(node, dict):
            # Print node type and line number
            node_type = node.get('type')
            if node_type:
                loc = node.get('loc', {}).get('start', {}).get('line', 'N/A')
                print(f"{' ' * depth}- {node_type} (Line: {loc})")

            # Recursively traverse children
            for _, value in node.items():
                self.traverse_ast(value, depth + 2)

        elif isinstance(node, list):
            # Traverse each element in the list
            for item in node:
                self.traverse_ast(item, depth)

    def trace_execution_paths(self, node=None, max_repetitions=2):
        """
        Traverse an AST and print all possible execution traces. Handles loops by limiting
        repetitions to a fixed constant.
        :param node: Current AST node (dictionary or list).
        :param max_repetitions: Maximum number of loop repetitions to consider.
        """
        if node is None:
            node = self.ast

        def helper(node, path):
            if isinstance(node, dict):
                node_type = node.get('type')
                if node_type == 'WhileStatement':
                    condition = node.get('test', {}).get('raw', 'condition')
                    body = node.get('body', {}).get('body', [])

                    for i in range(max_repetitions + 1):
                        path.append(f"WHILE ({condition}) iteration {i}")
                        for statement in body:
                            helper(statement, path)
                        if i < max_repetitions:
                            path.pop()
                    path.append(f"EXIT WHILE ({condition})")

                elif node_type == 'IfStatement':
                    test = node.get('test', {}).get('raw', 'condition')
                    path.append(f"IF ({test})")

                    # Traverse the 'consequent' branch
                    consequent = node.get('consequent', {}).get('body', [])
                    for statement in consequent:
                        helper(statement, path)

                    # Traverse the 'alternate' branch, if present
                    alternate = node.get('alternate', {}).get('body', [])
                    if alternate:
                        path.append("ELSE")
                        for statement in alternate:
                            helper(statement, path)

                    path.append("END IF")

                else:
                    path.append(f"NODE: {node_type}")

                # Traverse children of generic nodes
                for key, value in node.items():
                    if isinstance(value, dict) or isinstance(value, list):
                        if value and key != 'loc':
                            helper(value, path)

            elif isinstance(node, list):
                for item in node:
                    helper(item, path)

        # Initialize and print paths
        execution_path = []
        helper(node, execution_path)
        print("Execution Trace:")
        for step in execution_path:
            print(step)

