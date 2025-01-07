from dataclasses import dataclass
from typing import List, Dict, Optional, Callable
from src.classes import Policy, MultiLabelling, Vulnerabilities, MultiLabel

@dataclass
class Trace:
    """Represents a single execution trace through the program."""
    steps: List[str]
    
    def __str__(self) -> str:
        return " -> ".join(self.steps)

class ASTAnalyzer:
    def __init__(self, ast, policy: Policy, multilabelling: MultiLabelling, vulnerabilities: Vulnerabilities):
        self.ast = ast
        self.policy = policy
        self.multillabeling = multilabelling
        self.vulnerabilites = vulnerabilities

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
    
    def visit_while(self, node, path, max_repetitions, depth=0):
        condition = node.get('test', {}).get('raw', 'condition')
        body = node.get('body', {}).get('body', [])

        for i in range(max_repetitions + 1):
            path.append(" " * depth + f"WHILE ({condition}) iteration {i}")
            for statement in body:
                self.trace_helper(statement, path, depth + 2)
            if i < max_repetitions:
                path.pop()
        path.append(" " * depth + f"EXIT WHILE ({condition})")

    def visit_if(self, node: Dict, path: List, depth=0):
        test = node.get('test', {}).get('raw', 'condition')
        path.append(" " * depth + f"IF ({test})")

        
        
        # Traverse the 'consequent' branch
        consequent = node.get('consequent', {}).get('body', [])
        for statement in consequent:
            self.trace_helper(statement, path, depth + 2)

        # Traverse the 'alternate' branch, if present
        alternate = node.get('alternate', {}).get('body', [])
        if alternate:
            path.append(" " * depth + "ELSE")
            for statement in alternate:
                self.trace_helper(statement, path, depth + 2)

        path.append(" " * depth + "END IF")

    def visit_literal(self, node: Dict, path: List[str], depth=0) :
        """Visit a literal node (numbers, strings, booleans, etc.)"""
        value = node.get('value', 'unknown')
        raw = node.get('raw', str(value))
        path.append(" " * depth + f"LITERAL: {raw}")


    def visit_identifier(self, node: Dict, path: List[str], depth=0):
        """Visit an identifier node (variable names)"""
        name = node.get('name', 'unknown')
        path.append(" " * depth + f"IDENTIFIER: {name}")
        lbl = MultiLabel(list(self.policy.patterns.values()))
        self.multillabeling.update_label(name, lbl)
        return lbl

    def visit_unary_expression(self, node: Dict, path: List[str], depth=0):
        """Visit a unary expression (e.g., !x, -y)"""
        operator = node.get('operator', '')
        path.append(f"UNARY {operator}")
        
        argument = node.get('argument', {})
        self.trace_helper(argument, path)
    
    def visit_binary_expression(self, node: Dict, path: List[str], depth=0):
        """Visit a binary expression (e.g., x + y, a < b)"""
        operator = node.get('operator', '')
        path.append(f"BINARY {operator}")
        
        left = node.get('left', {})
        right = node.get('right', {})
        
        self.trace_helper(right, path)
        self.trace_helper(left, path)

    def visit_call_expression(self, node: Dict, path: List[str], depth=0):
        """Visit a function call expression"""
        callee = node.get('callee', {})
        arguments = node.get('arguments', [])
        
        path.append("CALL")
        self.trace_helper(callee, path)
        
        # This callee is a sink - if it's arguments are tainted we have an illegal flow.
        path.append("ARGUMENTS")
        for arg in arguments:
            self.trace_helper(arg, path)

    def visit_expression_statement(self, node: Dict, path: List, depth=0):
        expression = node.get('expression', {})
        path.append("EXPRESSION")
        self.trace_helper(expression, path)

    def visit_member_expression(self, node: Dict, path: List[str], depth=0) -> None:
        """Visit a member access expression (e.g., obj.prop)"""
        object_node = node.get('object', {})
        property_node = node.get('property', {})
        computed = node.get('computed', False)
        
        path.append("MEMBER ACCESS")
        self.trace_helper(object_node, path)
        path.append("." if not computed else "[")
        self.trace_helper(property_node, path)
        if computed:
            path.append("]")
            
    def visit_block_statement(self, node: Dict, path: List[str], depth=0) -> None:
        """Visit a block statement (sequence of statements)"""
        body = node.get('body', [])
        
        path.append("BLOCK START")
        for statement in body:
            self.trace_helper(statement, path)
        path.append("BLOCK END")

    def visit_assignment_expression(self, node: Dict, path: List[str], depth=0) -> None:
        """Visit an assignment expression"""
        operator = node.get('operator', '=')
        left = node.get('left', {})
        right = node.get('right', {})
        
        path.append(f"ASSIGNMENT {operator}")
        left_label = self.trace_helper(left, path)
        right_label = self.trace_helper(right, path)
        

    def visit_program(self, node: Dict, path: List[str], depth=0):
        path.append("PROGRAM")
        for n in node["body"]:
            self.trace_helper(n,path)

    def trace_helper(self, node: Dict, path: List[str], max_repetitions: int = 2, depth=0) -> None:
        """trace_helper method to dispatch to appropriate visitor based on node type"""
        if not isinstance(node, dict):
            return

        node_type = node.get('type', '')
        
        # Expression visitors
        if node_type == 'Program':
            self.visit_program(node, path, depth)
        elif node_type == 'Literal':
            self.visit_literal(node, path, depth)
        elif node_type == 'Identifier':
            self.visit_identifier(node, path, depth)
        elif node_type == 'UnaryExpression':
            self.visit_unary_expression(node, path, depth)
        elif node_type == 'BinaryExpression':
            self.visit_binary_expression(node, path, depth)
        elif node_type == 'CallExpression':
            self.visit_call_expression(node, path, depth)
        elif node_type == 'MemberExpression':
            self.visit_member_expression(node, path, depth)
        elif node_type == 'AssignmentExpression':
            self.visit_assignment_expression(node, path, depth)
        
        # Statement visitors
        elif node_type == 'BlockStatement':
            self.visit_block_statement(node, path, depth)
        elif node_type == 'ExpressionStatement':
            self.visit_expression_statement(node, path, depth)
        elif node_type == 'IfStatement':
            self.visit_if(node, path, depth)
        elif node_type == 'WhileStatement':
            self.visit_while(node, path, max_repetitions, depth)
        else:
            path.append(" " * depth + f"-UNKNOWN NODE TYPE: {node_type}")

    def trace_execution_paths(self, node=None):
        """
        Traverse an AST and print all possible execution traces. Handles loops by limiting
        repetitions to a fixed constant.
        :param node: Current AST node (dictionary or list).
        :param max_repetitions: Maximum number of loop repetitions to consider.
        """
        if node is None:
            node = self.ast

        # Initialize and print paths
        execution_path = []
        self.trace_helper(node, execution_path)
        print("Execution Trace:")
        for step in execution_path:
            print(step)
