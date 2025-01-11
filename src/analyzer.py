import copy
from dataclasses import dataclass
from typing import List, Dict
from src.classes import Policy, MultiLabelling, Vulnerabilities, MultiLabel, Label
from src.output import *


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

    def visit_literal(self, node: Dict, mlbl_ing: MultiLabelling, path: List[str], depth=0):
        """Visit a literal node (numbers, strings, booleans, etc.)"""
        value = node.get('value', 'unknown')
        raw = node.get('raw', str(value))
        path.append(" " * depth + f"LITERAL: {raw}")
        lbl = MultiLabel(list(self.policy.patterns.values()))
        # TODO: aqui é value ou raw?
        lbl.add_source(value, get_line(node))
        return copy.deepcopy(lbl)

    def visit_identifier(self, node: Dict, mlbl_ing: MultiLabelling, path: List[str], depth=0):
        """Visit an identifier node (variable names)"""
        name = node.get('name', 'unknown')
        path.append(" " * depth + f"IDENTIFIER: {name}")

        # Check if this identifier exists in the multilabelling
        mlbl = copy.deepcopy(mlbl_ing.get_label(name))
        if not mlbl:
            mlbl = MultiLabel(list(self.policy.patterns.values()))

        if not mlbl_ing.is_initialized_vars(name):
            mlbl.add_global_source(name, get_line(node))
        else:
            mlbl.add_source(name, get_line(node))
        mlbl_ing.update_label(name, mlbl)
        return mlbl

    def visit_unary_expression(self, node: Dict, mlbl_ing: MultiLabelling, path: List[str], depth=0):
        """Visit a unary expression (e.g., !x, -y)"""
        operator = node.get('operator', '')
        path.append(" " * depth + f"UNARY {operator}")
        argument = node.get('argument', {})
        return copy.deepcopy(self.visit_expression(argument, mlbl_ing, path, depth + 2))

    def visit_binary_expression(self, node: Dict, mlbl_ing: MultiLabelling, path: List[str], depth=0):
        """Visit a binary expression (e.g., x + y, a < b)"""
        operator = node.get('operator', '')
        path.append(" " * depth + f"BINARY {operator}")

        left = node.get('left', {})
        right = node.get('right', {})

        right_lbl = self.visit_expression(right, mlbl_ing, path, depth + 2)
        left_lbl = self.visit_expression(left, mlbl_ing, path, depth + 2)

        if right_lbl and left_lbl:
            return copy.deepcopy(left_lbl.combine(right_lbl))
        elif right_lbl:
            return copy.deepcopy(right_lbl)
        return copy.deepcopy(left_lbl)

    def visit_call_expression(self, node: Dict, mlbl_ing: MultiLabelling, path: List[str], depth=0) -> MultiLabel:
        """Visit a function call expression"""
        callee = node.get('callee', {})
        arguments = node.get('arguments', [])

        path.append(" " * depth + "CALL")

        # Get the function name - handle both direct calls and member expressions
        func_name = None
        property_node = None
        object_name = None
        if callee.get('type') == 'Identifier':
            func_name = callee.get('name')
            mlbl_ing.add_initialized_vars(func_name)
        elif callee.get('type') == 'MemberExpression':
            # Handle cases like document.write
            property_node = callee.get('property', {})
            object_name = callee.get('object', {}).get('name', 'unknown')
            func_name = f"{object_name}.{property_node.get('name', 'unknown')}"
            # funcs are not treated as unitialized vars
            mlbl_ing.add_initialized_vars(func_name)
            mlbl_ing.add_initialized_vars(property_node.get('name', 'unknown'))

        # Evaluate the callee expression to get its label
        callee_lbl = self.visit_expression(callee, mlbl_ing, path, depth + 2)

        print(f"Calling {func_name} at line {get_line(node)}")
        # Get arguments' labels
        print("START ARGS LABELS: ")
        args_mlbls: List[MultiLabel] = []
        for arg in arguments:
            arg_lbl = self.visit_expression(arg, mlbl_ing, path, depth + 2)
            print(arg_lbl)
            args_mlbls.append(arg_lbl)
        print("END ARGS LABELS")
        sanitized_mlbl = None
        if func_name:
            # Check if this is a sanitizer call
            vuln_patterns = self.policy.get_vulnerabilities_for_sanitizer(
                func_name)
            if vuln_patterns and args_mlbls:

                # Create a new label to represent sanitized output
                sanitized_mlbl = MultiLabel(self.policy.patterns.values())

                print('BEFORE - SANITIZED LABEL: ', sanitized_mlbl)
                # For each argument that was passed to the sanitizer
                for arg_mlbl in args_mlbls:
                    sanitized_mlbl = sanitized_mlbl.combine(arg_mlbl)

                print('BETWEEN - SANITIZED LABEL: ', sanitized_mlbl)
                for arg_mlbl in args_mlbls:
                    for pattern_name in vuln_patterns:
                        label = copy.deepcopy(
                            arg_mlbl.get_label_for_pattern(pattern_name))
                        if not label:
                            continue

                        # FIXME: what if there's two sources in the same line
                        for source, src_line in label.get_sources():
                            print("SOURCES: ", source, src_line)
                            sanitized_mlbl.labels[pattern_name].add_source(
                                source, src_line)
                            sanitized_mlbl.labels[pattern_name].add_sanitizer(
                                source,
                                src_line,
                                func_name,
                                get_line(node)
                            )

                print('AFTER - SANITIZED LABEL: ', sanitized_mlbl)

            # Check if this is a sink call
            vuln_patterns = self.policy.get_vulnerabilities_for_sink(func_name)
            if vuln_patterns:
                # Combine all argument labels to check what's flowing into the sink
                combined_lbl = None

                # print(f"CALLEE {callee} LABEL : ", callee_lbl)
                # print(f"\nINI ARGS LABELS : ")
                for arg_lbl in args_mlbls:
                    if combined_lbl is None:
                        combined_lbl = copy.deepcopy(arg_lbl)
                    else:
                        combined_lbl = combined_lbl.combine(arg_lbl)
                #     print(arg_lbl)
                # print(f"END ARGS LABELS\n")

                # print("******** COMBINED : ", combined_lbl)

                if combined_lbl:
                    # Add this sink usage to the vulnerabilities tracking
                    self.vulnerabilites.add_illegal_flows(
                        func_name,
                        get_line(node),
                        combined_lbl
                    )
                    if property_node:
                        self.vulnerabilites.add_illegal_flows(
                            property_node.get('name', 'unknown'),
                            get_line(node),
                            combined_lbl
                        )
                    if object_name:
                        self.vulnerabilites.add_illegal_flows(
                            object_name, get_line(node), combined_lbl
                        )

        # For non-sanitizer function calls or after sanitization, combine all labels (callee + args)
        result_lbl = callee_lbl if callee_lbl else MultiLabel(
            list(self.policy.patterns.values()))

        # If we have a sanitized label, use that instead of combining the raw argument labels
        if sanitized_mlbl:
            result_lbl = result_lbl.combine(sanitized_mlbl)
        else:
            # Otherwise combine with the original argument labels
            for arg_lbl in args_mlbls:
                result_lbl = result_lbl.combine(arg_lbl)

        print(f"\n{func_name} : RETURN VISIT CALL : {result_lbl}")
        return copy.deepcopy(result_lbl)

    def visit_expression_statement(self, node: Dict, mlbl_ing: MultiLabelling, path: List, depth=0) -> MultiLabelling:
        expression = node.get('expression', {})
        path.append(" " * depth + "EXPRESSION")
        self.visit_expression(expression, mlbl_ing, path, depth + 2)
        return copy.deepcopy(mlbl_ing)

    def visit_member_expression(self, node: Dict, mlbl_ing: MultiLabelling, path: List[str], depth=0) -> MultiLabel:
        """
        Visit a member access expression (e.g., obj.prop).
        This should behave similarly to visit_identifier, but for 'obj.prop'.
        We do NOT do sink checks here (that's in call or assignment).
        """
        path.append(" " * depth + "MEMBER ACCESS")

        object_node = node.get('object', {})
        property_node = node.get('property', {})
        line_no = get_line(node)

        # 1) Recursively visit the object and property sub-expressions
        object_label = self.visit_expression(
            object_node, mlbl_ing, path, depth + 2)
        property_label = self.visit_expression(
            property_node, mlbl_ing, path, depth + 2)

        # 2) Combine object_label and property_label
        combined_label = MultiLabel(list(self.policy.patterns.values()))
        if object_label:
            combined_label = combined_label.combine(object_label)
        if property_label:
            combined_label = combined_label.combine(property_label)

        # 3) Create a "name" for this member expression (similar to how we do in visit_identifier)
        #    For example, if both are Identifiers:
        if (object_node.get('type') == 'Identifier' and
                property_node.get('type') == 'Identifier'):
            full_name = f"{object_node.get('name')}.{property_node.get('name')}"
        else:
            # If object or property are more complex, fallback to something unique
            full_name = f"member@line{line_no}"
            print('WARNING: NOT SUPPOSE TO HAPPEN?')
            print('WARNING: NOT SUPPOSE TO HAPPEN?')
            print('WARNING: NOT SUPPOSE TO HAPPEN?')

        # 4) Retrieve the current label for this "variable" (if any)
        existing_label = mlbl_ing.get_label(full_name)

        if existing_label:
            # Combine existing label with whatever we found above
            new_label = existing_label.combine(combined_label)
        else:
            # Otherwise, we'll treat combined_label as the new label
            new_label = combined_label

        # 5) Mirroring visit_identifier: if we haven't seen full_name yet, treat as "global source"
        #    (This is optional, depending on how your analysis rules define uninitialized members.)
        if not mlbl_ing.is_initialized_vars(full_name):
            new_label.add_global_source(full_name, line_no)
            new_label.add_global_source(object_node.get('name'), line_no)
            mlbl_ing.add_initialized_vars(full_name)
        else:
            # Otherwise, treat it like a known source
            new_label.add_source(object_node.get('name'), line_no)
            new_label.add_source(full_name, line_no)

        # 6) Update MultiLabelling
        print(f"MEMBER EXPR LBL: {new_label}")
        mlbl_ing.update_label(full_name, new_label)

        return copy.deepcopy(new_label)

    def visit_block_statement(self, node: Dict, mlbl_ing: MultiLabelling, path: List[str], depth=0) -> MultiLabelling:
        """Visit a block statement (sequence of statements)"""
        body = node.get('body', [])

        path.append(" " * depth + "BLOCK START")
        for statement in body:
            mlbl_ing = self.visit_statement(
                statement, mlbl_ing, path, depth + 2)
        path.append(" " * depth + "BLOCK END")

        return copy.deepcopy(mlbl_ing)

    def visit_assignment_expression(self, node: Dict, mlbl_ing: MultiLabelling, path: List[str], depth=0) -> MultiLabel:
        """Visit an assignment expression and check for illegal flows to sink variables"""
        operator = node.get('operator', '=')
        left = node.get('left', {})
        right = node.get('right', {})

        path.append(" " * depth + f"ASSIGNMENT {operator}")

        # Get the label from the right-hand expression
        right_label = self.visit_expression(right, mlbl_ing, path)

        if not right_label:
            return MultiLabel([])

        # Handle assignment to identifiers
        if isinstance(left, dict) and left.get('type') == 'Identifier':
            left_name = left.get('name')
            mlbl_ing.add_initialized_vars(left_name)
            if left_name:
                # Check if the left-hand variable is a sink
                vuln_patterns = self.policy.get_vulnerabilities_for_sink(
                    left_name)
                left_label = copy.deepcopy(right_label)

                if vuln_patterns:
                    # Check for illegal flows to this sink
                    self.vulnerabilites.add_illegal_flows(
                        left_name,
                        get_line(node),
                        left_label
                    )

                # # Update the variable's label in the multilabelling
                left_label.add_source(left_name, -1)
                mlbl_ing.update_label(left_name, left_label)

        # Handle assignment to member expressions (e.g., obj.prop = value)
        # TODO:
        elif isinstance(left, dict) and left.get('type') == 'MemberExpression':
            property_node = left.get('property', {})
            object_node = left.get('object', {})
            if property_node.get('type') == 'Identifier' and object_node.get('type') == 'Identifier':
                prop_name = property_node.get('name')
                object_name = object_node.get('name')
                left_name = f"{object_name}.{prop_name}"
                left_label = copy.deepcopy(right_label)

                # Mark it as initialized so that future uses of obj.prop won't be treated as entirely uninitialized
                mlbl_ing.add_initialized_vars(left_name)
                mlbl_ing.add_initialized_vars(prop_name)

                # Check if full_name OR just object_name OR just prop_name is a sink
                # (Depending on how you want to handle patterns—some treat `obj.prop`
                # as the sink, others treat just `prop_name` as a sink, etc.)
                combined_sinks = (
                    self.policy.get_vulnerabilities_for_sink(left_name)
                    | self.policy.get_vulnerabilities_for_sink(prop_name)
                    | self.policy.get_vulnerabilities_for_sink(object_name)
                )
                if combined_sinks:
                    print("SINKS:", combined_sinks)
                    # If any pattern sees this as a sink, record the flows
                    self.vulnerabilites.add_illegal_flows(
                        object_name,                # or just `prop_name`, whichever you prefer
                        get_line(node),
                        left_label
                    )

                    self.vulnerabilites.add_illegal_flows(
                        prop_name,                # or just `prop_name`, whichever you prefer
                        get_line(node),
                        left_label
                    )
                    print(self.vulnerabilites.get_report())

                left_label.add_source(left_name, -1)
                left_label.add_source(object_name, -1)
                print(f"LEFT LABEL: {left_label}")
                mlbl_ing.update_label(left_name, left_label)

        # FIXME: why return a empty multilabel
        return copy.deepcopy(MultiLabel([]))

    def visit_while_statement(self, node: Dict, mlbl_ing: MultiLabelling, path: List, max_repetitions=2, depth=0):
        condition = node.get('test', {}).get('raw', 'condition')
        body = node.get('body', {}).get('body', [])

        final_mlbl_ing = mlbl_ing.create_copy()
        for i in range(max_repetitions + 1):
            path.append(" " * depth + f"WHILE ({condition}) iteration {i}")
            for statement in body:
                mlbl_ing = self.visit_statement(
                    statement, mlbl_ing, path, depth + 2)

            final_mlbl_ing = final_mlbl_ing.combine(mlbl_ing)
        path.append(" " * depth + f"EXIT WHILE ({condition})")
        return copy.deepcopy(mlbl_ing)

    def visit_if_statement(self, node: Dict, mlbl_ing: MultiLabelling, path: List, depth=0):
        test = node.get('test', {}).get('raw', 'condition')
        path.append(" " * depth + f"IF ({test})")

        if_ing = copy.deepcopy(mlbl_ing)
        else_ing = copy.deepcopy(mlbl_ing)

        # Traverse the 'consequent' branch
        consequent = node.get('consequent', {}).get('body', [])
        for statement in consequent:
            if_ing = self.visit_statement(
                statement, if_ing, path, depth + 2)

        # Traverse the 'alternate' branch, if present
        alternate = node.get('alternate', {}).get('body', [])
        if alternate:
            path.append(" " * depth + "ELSE")
            for statement in alternate:
                else_ing = self.visit_statement(
                    statement, else_ing, path, depth + 2)

        path.append(" " * depth + "END IF")

        print("#####################")
        print("VISIT IF:", get_line(node))
        print("BEFORE ING: ", mlbl_ing)
        print("IF ING: ", if_ing)
        print("ELSE ING: ", else_ing, get_line(node))
        print("IF ING COMBINE ELSE ING: ", if_ing.combine(else_ing))
        print("#####################")

        return copy.deepcopy(if_ing.combine(else_ing))

    def visit_program(self, node: Dict, path: List[str], depth=0):
        path.append(" " * depth + "PROGRAM")

        mlbl_ing = MultiLabelling()
        for n in node["body"]:
            if "statement" in n.get('type').lower():
                mlbl_ing = self.visit_statement(n, mlbl_ing, path, depth + 2)

            else:
                print("NOT A STATEMENT ABORTING")
                print("NOT A STATEMENT ABORTING")
                print("NOT A STATEMENT ABORTING")

    def visit_statement(self, node: Dict, mlbl_ing: MultiLabelling, path: List[str], depth=0) -> MultiLabelling:
        if not isinstance(node, dict):
            print("**** FATAL ERROR ****")
            return copy.deepcopy(mlbl_ing)

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
            return copy.deepcopy(mlbl_ing)

    def visit_expression(self, node: Dict, mlbl_ing: MultiLabelling, path: List[str], depth=0) -> MultiLabel:

        if not isinstance(node, dict):
            return copy.deepcopy(MultiLabel([]))

        node_type = node.get('type', '')

        if node_type == 'Literal':
            return self.visit_literal(node, mlbl_ing, path, depth)
        elif node_type == 'Identifier':
            return self.visit_identifier(node, mlbl_ing, path, depth)
        elif node_type == 'UnaryExpression':
            return self.visit_unary_expression(node, mlbl_ing, path, depth)
        elif node_type == 'BinaryExpression':
            return self.visit_binary_expression(node, mlbl_ing, path, depth)
        elif node_type == 'CallExpression':
            return self.visit_call_expression(node, mlbl_ing, path, depth)
        elif node_type == 'MemberExpression':
            return self.visit_member_expression(node, mlbl_ing, path, depth)
        elif node_type == 'AssignmentExpression':
            return self.visit_assignment_expression(node, mlbl_ing, path, depth)

        else:
            path.append(" " * depth + f"-UNKNOWN NODE TYPE: {node_type}")
            return copy.deepcopy(MultiLabel([]))

    def trace_execution_paths(self, node=None) -> Vulnerabilities:
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

        print_json(self.vulnerabilites)

        # print("Execution Trace:")
        # for step in execution_path:
        #     print(step)

        return copy.deepcopy(self.vulnerabilites)


def get_line(node):
    return node.get("loc").get("start").get("line")


def is_part_of(member, full):
    # Split `f` into segments by '.' and check if `m` is a valid sequence of segments
    f_segments = full.split('.')
    m_segments = member.split('.')

    # Traverse `f` as a sequence to find if `m` exists
    for i in range(len(f_segments) - len(m_segments) + 1):
        if f_segments[i:i+len(m_segments)] == m_segments:
            return True
    return False
