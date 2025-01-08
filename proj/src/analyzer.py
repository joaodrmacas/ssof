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
    MAX_LOOP_DEPTH = 3

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
    
    def visit_while_statement(self, node: Dict, mlbl_ing: MultiLabelling, path: List, max_repetitions=2, depth=0):
        condition = node.get('test', {}).get('raw', 'condition')
        body = node.get('body', {}).get('body', [])

        final_mlbl_ing = mlbl_ing.create_copy()
        for i in range(max_repetitions + 1):
            path.append(" " * depth + f"WHILE ({condition}) iteration {i}")
            for statement in body:
                mlbl_ing = self.visit_statement(statement, mlbl_ing, path, depth + 2)
            
            final_mlbl_ing = final_mlbl_ing.combine(mlbl_ing)
        path.append(" " * depth + f"EXIT WHILE ({condition})")
        return mlbl_ing

    def visit_if_statement(self, node: Dict, mlbl_ing: MultiLabelling, path: List, depth=0):
        test = node.get('test', {}).get('raw', 'condition')
        path.append(" " * depth + f"IF ({test})")

        alt_mlbl_ing = mlbl_ing.create_copy()

        # Traverse the 'consequent' branch
        consequent = node.get('consequent', {}).get('body', [])
        for statement in consequent:
            mlbl_ing = self.visit_statement(statement, mlbl_ing, path, depth + 2)

        # Traverse the 'alternate' branch, if present
        alternate = node.get('alternate', {}).get('body', [])
        if alternate:
            path.append(" " * depth + "ELSE")
            for statement in alternate:
                alt_mlbl_ing = self.visit_statement(statement, alt_mlbl_ing, path, depth + 2)

        path.append(" " * depth + "END IF")

        return mlbl_ing.combine(alt_mlbl_ing)

    def visit_literal(self, node: Dict, mlbl_ing: MultiLabelling, path: List[str], depth=0) :
        """Visit a literal node (numbers, strings, booleans, etc.)"""
        value = node.get('value', 'unknown')
        raw = node.get('raw', str(value))
        path.append(" " * depth + f"LITERAL: {raw}")
        lbl = MultiLabel(list(self.policy.patterns.values()))
        #TODO: aqui é value ou raw?
        lbl.add_source(value, get_line(node))
        return lbl

    def visit_identifier(self, node: Dict,mlbl_ing: MultiLabelling, path: List[str], depth=0):
        """Visit an identifier node (variable names)"""
        name = node.get('name', 'unknown')
        path.append(" " * depth + f"IDENTIFIER: {name}")

        # Check if this identifier exists in the multilabelling
        lbl = self.multillabeling.get_label(name)
        if lbl:
            return lbl

        # FIXME TODO: unknown variables should be added as sources ALWAYS.
        lbl = MultiLabel(list(self.policy.patterns.values()))
        lbl.add_source(name, get_line(node))
        self.multillabeling.update_label(name, lbl)
        return lbl
        
    def visit_unary_expression(self, node: Dict, mlbl_ing: MultiLabelling, path: List[str], depth=0):
        """Visit a unary expression (e.g., !x, -y)"""
        operator = node.get('operator', '')
        path.append(" " * depth + f"UNARY {operator}")
        argument = node.get('argument', {})
        return self.visit_expression(argument, mlbl_ing, path, depth + 2)
    
    def visit_binary_expression(self, node: Dict, mlbl_ing: MultiLabelling, path: List[str], depth=0):
        """Visit a binary expression (e.g., x + y, a < b)"""
        operator = node.get('operator', '')
        path.append(" " * depth + f"BINARY {operator}")
        
        left = node.get('left', {})
        right = node.get('right', {})
        
        right_lbl = self.visit_expression(right,mlbl_ing, path, depth + 2)
        left_lbl = self.visit_expression(left,mlbl_ing, path, depth + 2)

        if right_lbl and left_lbl:
            return left_lbl.combine(right_lbl)
        elif right_lbl:
            return right_lbl
        return left_lbl

    def visit_call_expression(self, node: Dict, mlbl_ing: MultiLabelling, path: List[str], depth=0) -> MultiLabel:
        """Visit a function call expression"""
        callee = node.get('callee', {})
        arguments = node.get('arguments', [])
        
        path.append(" " * depth + "CALL")
        
        # First evaluate the callee expression to get its label
        callee_lbl = self.visit_expression(callee, mlbl_ing, path, depth + 2)
        
        # Get arguments' labels
        args_mlbls: List[MultiLabel] = []
        for arg in arguments:
            arg_lbl = self.visit_expression(arg, mlbl_ing, path, depth + 2)
            if arg_lbl:
                args_mlbls.append(arg_lbl)

        # Get the function name - handle both direct calls and member expressions
        func_name = None
        if callee.get('type') == 'Identifier':
            func_name = callee.get('name')
        elif callee.get('type') == 'MemberExpression':
            # Handle cases like document.write
            property_node = callee.get('property', {})
            if property_node.get('type') == 'Identifier':
                func_name = property_node.get('name')
                
                # For member expressions, also include the full path (e.g., "document.write")
                object_name = callee.get('object', {}).get('name')
                if object_name:
                    full_name = f"{object_name}.{func_name}"
                    # Check if the full name is a sink or sanitizer
                    if (self.policy.get_vulnerabilities_for_sink(full_name) or 
                        self.policy.get_vulnerabilities_for_sanitizer(full_name)):
                        func_name = full_name

        if func_name:
            # Check if this is a sanitizer call
            vuln_patterns = self.policy.get_vulnerabilities_for_sanitizer(func_name)
            if vuln_patterns and args_mlbls:
                # Create a new label to represent sanitized output
                sanitized_lbl = MultiLabel(list(self.policy.patterns.values()))
                
                # For each argument that was passed to the sanitizer
                for arg_lbl in args_mlbls:
                    # Transfer sources and add sanitizer to each source's flow
                    for pattern_name, pattern in self.policy.patterns.items():
                        if pattern_name in vuln_patterns:
                            label = arg_lbl.get_label_for_pattern(pattern_name)
                            if label:
                                for source in label.get_sources():
                                    sanitized_lbl.labels[pattern_name].add_source(source, get_line(node))
                                    sanitized_lbl.labels[pattern_name].add_sanitizer(
                                        source, 
                                        func_name,
                                        node.get('loc', {}).get('start', {}).get('line', -1)
                                    )
                return sanitized_lbl

            # Check if this is a sink call
            vuln_patterns = self.policy.get_vulnerabilities_for_sink(func_name)
            if vuln_patterns:
                # Combine all argument labels to check what's flowing into the sink
                combined_lbl = None
                for arg_lbl in args_mlbls:
                    if combined_lbl is None:
                        combined_lbl = arg_lbl
                    else:
                        combined_lbl = combined_lbl.combine(arg_lbl)
                
                if combined_lbl:
                    # Add this sink usage to the vulnerabilities tracking
                    self.vulnerabilites.add_illegal_flows(
                        func_name,
                        combined_lbl
                    )

        # For non-sanitizer function calls, combine all labels (callee + args)
        result_lbl = callee_lbl if callee_lbl else MultiLabel(list(self.policy.patterns.values()))
        for arg_lbl in args_mlbls:
            result_lbl = result_lbl.combine(arg_lbl)
        
        return result_lbl 
        

    def visit_expression_statement(self, node: Dict, mlbl_ing: MultiLabelling, path: List, depth=0) -> MultiLabelling:
        expression = node.get('expression', {})
        path.append(" " * depth + "EXPRESSION")
        self.visit_expression(expression, mlbl_ing, path, depth + 2)
        return mlbl_ing


    def visit_member_expression(self, node: Dict,mlbl_ing: MultiLabelling, path: List[str], depth=0) -> MultiLabel:
        """Visit a member access expression (e.g., obj.prop)"""
        object_node = node.get('object', {})
        property_node = node.get('property', {})
        
        path.append(" " * depth + "MEMBER ACCESS")
        
        # Get labels from both object and property
        object_label = self.visit_expression(object_node,mlbl_ing, path, depth + 2)
        property_label = self.visit_expression(property_node,mlbl_ing, path, depth + 2)
        
        # Both object and property access are considered tainted
        if not object_label:
            object_name = object_node.get('name', 'unknown_object')
            object_label = MultiLabel(list(self.policy.patterns.values()))
            

        if not property_label and not node.get('computed', False):
            prop_name = property_node.get('name', 'unknown_property')
            property_label = MultiLabel(list(self.policy.patterns.values()))
        
        # Combine labels
        #TODO: checkar se isso é o certo
        if object_label and property_label:
            return object_label.combine(property_label)
        return object_label or property_label


    def visit_block_statement(self, node: Dict, mlbl_ing: MultiLabelling, path: List[str], depth=0) ->  MultiLabelling:
        """Visit a block statement (sequence of statements)"""
        body = node.get('body', [])
        
        path.append(" " * depth + "BLOCK START")
        for statement in body:
            mlbl_ing = self.visit_statement(statement, mlbl_ing, path, depth + 2)
        path.append(" " * depth + "BLOCK END")

        return mlbl_ing

    def visit_assignment_expression(self, node: Dict, mlbl_ing: MultiLabelling, path: List[str], depth=0) -> MultiLabel:
        """Visit an assignment expression"""
        operator = node.get('operator', '=')
        left = node.get('left', {})
        right = node.get('right', {})
        
        path.append(" " * depth + f"ASSIGNMENT {operator}")
        #recieves a label (could be a combined multilabel and assigns it to the left)
        right_label = self.visit_expression(right, mlbl_ing, path)

        if right_label:
            if isinstance(left, dict) and left.get('type') == 'Identifier':
                left_name = left.get('name')
                if left_name:
                    self.multillabeling.update_label(left_name, right_label)
        return MultiLabel([])
        

    def visit_program(self, node: Dict, path: List[str], depth=0):
        path.append(" " * depth + "PROGRAM")

        mlbl_ing = MultiLabelling()
        for n in node["body"]:
            if "statement" in n.get('type').lower():
                mulbl_ing = self.visit_statement(n, mlbl_ing, path, depth + 2)
                
            else:
                print("NOT A STATEMENT ABORTING")
                print("NOT A STATEMENT ABORTING")
                print("NOT A STATEMENT ABORTING")


    def visit_statement(self, node: Dict, mlbl_ing: MultiLabelling, path: List[str], depth=0) -> MultiLabelling:
        if not isinstance(node, dict):
            return
        
        node_type = node.get('type', '')

        # Statement visitors
        if node_type == 'BlockStatement':
            return self.visit_block_statement(node, mlbl_ing, path, depth)
        elif node_type == 'ExpressionStatement':
            return self.visit_expression_statement(node, mlbl_ing, path, depth)
        elif node_type == 'IfStatement':
            return self.visit_if_statement(node, mlbl_ing, path, depth)
        elif node_type == 'WhileStatement':
            return self.visit_while_statement(node, mlbl_ing, path, self.MAX_LOOP_DEPTH, depth)
        else:
            path.append(" " * depth + f"-UNKNOWN NODE TYPE: {node_type}")
            return mlbl_ing

    

    def visit_expression(self,node: Dict, mlbl_ing: MultiLabelling, path: List[str], depth=0) -> MultiLabel:

        if not isinstance(node, dict):
            return

        node_type = node.get('type', '')
        

        if node_type == 'Literal':
            return self.visit_literal(node,mlbl_ing, path, depth)
        elif node_type == 'Identifier':
            return self.visit_identifier(node,mlbl_ing, path, depth)
        elif node_type == 'UnaryExpression':
            return self.visit_unary_expression(node,mlbl_ing, path, depth)
        elif node_type == 'BinaryExpression':
            return self.visit_binary_expression(node,mlbl_ing, path, depth)
        elif node_type == 'CallExpression':
            return self.visit_call_expression(node,mlbl_ing, path, depth)
        elif node_type == 'MemberExpression':
            return self.visit_member_expression(node,mlbl_ing, path, depth)
        elif node_type == 'AssignmentExpression':
            return self.visit_assignment_expression(node,mlbl_ing, path, depth)

        else:
            path.append(" " * depth + f"-UNKNOWN NODE TYPE: {node_type}")
            return MultiLabel([])

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
        self.visit_program(node, execution_path)
        for key, value in self.vulnerabilites.get_report().items():
            for idx, event in enumerate(value):
                print(f"Vulnerability: {key+"_"+str(idx+1)}")
                print(event)
        print("Execution Trace:")
        for step in execution_path:
            print(step)

    
def get_line(node):
    return node.get("loc").get("start").get("line")
