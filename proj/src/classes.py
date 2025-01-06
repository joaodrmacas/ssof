from typing import List


class Pattern:
    vuln_name = ""
    source_names = []
    sanitizer_names = []
    sink_names = []

    def __init__(
        self,
        vuln_name: str,
        source_names: List[str],
        sanitizer_names: List[str],
        sink_names: List[str],
    ):
        self.vuln_name = vuln_name
        self.source_names = source_names
        self.sanitizer_names = sanitizer_names
        self.sink_names = sink_names

    def is_source(self, source_name: str):
        return source_name in self.source_names

    def is_sanitizer(self, sanitizer_name: str):
        return sanitizer_name in self.sanitizer_names

    def is_sink(self, sink_name: str):
        return sink_name in self.sink_names

    def __repr__(self):
        return f"Pattern(name={self.name}, sources={self.sources}, sanitizers={self.sanitizers}, sinks={self.sinks})"


class Label:
    def __init__(self):
        self.sources = {}
        self.sanitizers = {}

    def add_source(self, source):
        if source not in self.sources:
            self.sources[source] = []

    def add_sanitizer(self, source, sanitizer):
        if source in self.sources:
            self.sources[source].append(sanitizer)

    def get_sources(self):
        return list(self.sources.keys())

    def get_sanitizers(self, source):
        return self.sources.get(source, [])

    def combine(self, other):
        new_label = Label()
        new_label.sources = {**self.sources}
        for source, sanitizers in other.sources.items():
            if source not in new_label.sources:
                new_label.sources[source] = []
            new_label.sources[source].extend(sanitizers)
        return new_label

    def __repr__(self):
        return f"Label(sources={self.sources})"


class MultiLabel:
    def __init__(self):
        self.labels = {}

    def add_label(self, pattern_name):
        if pattern_name not in self.labels:
            self.labels[pattern_name] = Label()

    def add_source(self, pattern_name, source):
        if pattern_name in self.labels:
            self.labels[pattern_name].add_source(source)

    def add_sanitizer(self, pattern_name, source, sanitizer):
        if pattern_name in self.labels:
            self.labels[pattern_name].add_sanitizer(source, sanitizer)

    def get_sources(self, pattern_name):
        if pattern_name in self.labels:
            return self.labels[pattern_name].get_sources()
        return []

    def get_sanitizers(self, pattern_name, source):
        if pattern_name in self.labels:
            return self.labels[pattern_name].get_sanitizers(source)
        return []

    def combine(self, other):
        new_multilabel = MultiLabel()
        for pattern_name, label in self.labels.items():
            if pattern_name not in new_multilabel.labels:
                new_multilabel.add_label(pattern_name)
            new_multilabel.labels[pattern_name] = label.combine(
                other.labels.get(pattern_name, Label())
            )
        return new_multilabel

    def __repr__(self):
        return f"MultiLabel(labels={self.labels})"


class Policy:
    def __init__(self, patterns):
        """
        Constructor: Initializes the Policy with vulnerability patterns.
        :param patterns: List of Pattern objects.
        """
        self.patterns = patterns

    def get_vulnerability_names(self):
        """Returns all vulnerability names in the policy."""
        return [pattern.name for pattern in self.patterns]

    def get_sources(self, name):
        """Returns vulnerabilities for which the given name is a source."""
        return [pattern for pattern in self.patterns if pattern.is_source(name)]

    def get_sanitizers(self, name):
        """Returns vulnerabilities for which the given name is a sanitizer."""
        return [pattern for pattern in self.patterns if pattern.is_sanitizer(name)]

    def get_sinks(self, name):
        """Returns vulnerabilities for which the given name is a sink."""
        return [pattern for pattern in self.patterns if pattern.is_sink(name)]

    def detect_illegal_flows(self, name, multilabel):
        """
        Detects illegal flows by checking which part of the multilabel has the given name as a sink.
        :param name: Name to check for sinks.
        :param multilabel: MultiLabel object representing flows.
        :return: MultiLabel with only the illegal flows.
        """
        illegal_flows = MultiLabel()
        for pattern_name, label in multilabel.labels.items():
            if any(
                pattern.is_sink(name)
                for pattern in self.patterns
                if pattern.name == pattern_name
            ):
                illegal_flows.labels[pattern_name] = label
        return illegal_flows


class MultiLabelling:
    def __init__(self):
        """
        Constructor: Initializes the mapping from variable names to MultiLabels.
        """
        self.mapping = {}

    def get_multilabel(self, var_name):
        """
        Retrieves the MultiLabel assigned to a variable.
        :param var_name: Variable name.
        :return: MultiLabel object or None if not assigned.
        """
        return self.mapping.get(var_name)

    def update_multilabel(self, var_name, multilabel):
        """
        Updates the MultiLabel assigned to a variable.
        :param var_name: Variable name.
        :param multilabel: MultiLabel object.
        """
        self.mapping[var_name] = multilabel

    def __repr__(self):
        return f"MultiLabelling(mapping={self.mapping})"


class Vulnerabilities:
    def __init__(self):
        """
        Constructor: Initializes the vulnerabilities collection.
        """
        self.data = {}

    def add_illegal_flow(self, multilabel, sink_name):
        """
        Records illegal flows detected for a sink.
        :param multilabel: MultiLabel with the sources and sanitizers for illegal flows.
        :param sink_name: Name of the sink.
        """
        for pattern_name, label in multilabel.labels.items():
            if pattern_name not in self.data:
                self.data[pattern_name] = []
            self.data[pattern_name].append(
                {
                    "sink": sink_name,
                    "sources": label.get_sources(),
                    "sanitizers": {
                        source: label.get_sanitizers(source)
                        for source in label.get_sources()
                    },
                }
            )

    def generate_report(self):
        """
        Generates a summary report of vulnerabilities.
        :return: Dictionary of vulnerabilities grouped by pattern.
        """
        return self.data

    def __repr__(self):
        return f"Vulnerabilities(data={self.data})"


class Node:
    def __init__(self, identifier, node_type, ast_node, line_num):
        self.identifier = identifier  # Unique identifier for the node
        self.node_type = node_type  # Type of node (variable, literal, expression, etc)
        self.ast_node = ast_node  # Reference to original AST node
        self.line_num = line_num  # Line number for reporting
        self.incoming_flows = []  # List of nodes that flow into this node
        self.outgoing_flows = []  # List of nodes this flows into
        self.sanitized_by = []  # List of sanitizer functions applied


class FlowGraph:
    def __init__(self):
        self.nodes = {}  # Dictionary of nodes by identifier
        self.variables = {}  # Track latest assignment to each variable
        self.sources = set()  # Track identified source nodes
        self.sinks = set()  # Track identified sink nodes

    def __str__(self):
        graph_str = ["FlowGraph:"]

        # Nodes
        graph_str.append("Nodes:")
        for node_id, node in self.nodes.items():
            graph_str.append(
                f"  {node_id} ({node.node_type}, line {node.line_num}): "
                f"incoming={len(node.incoming_flows)}, outgoing={len(node.outgoing_flows)}"
            )

        # Flows
        graph_str.append("\nFlows:")
        for node_id, node in self.nodes.items():
            for out_node in node.outgoing_flows:
                graph_str.append(f"  {node_id} -> {out_node.identifier}")

        # Sources and Sinks
        graph_str.append("\nSources:")
        for source in self.sources:
            graph_str.append(f"  {source.identifier} (line {source.line_num})")

        graph_str.append("\nSinks:")
        for sink in self.sinks:
            graph_str.append(f"  {sink.identifier} (line {sink.line_num})")

        return "\n".join(graph_str)

    def find_paths(self, source, sink, visited=None):
        """Find all paths between source and sink nodes"""
        if visited is None:
            visited = set()

        if source == sink:
            return [[source]]

        paths = []
        visited.add(source)

        for next_node in source.outgoing_flows:
            if next_node not in visited:
                for path in self.find_paths(next_node, sink, visited):
                    paths.append([source] + path)

        visited.remove(source)
        return paths

    def check_sanitization(self, path, sanitizers):
        """Check if path contains any sanitizers"""
        sanitized_flows = []
        for node in path:
            if node.node_type == "call":
                callee_str = self.get_callee_string(node.ast_node["callee"])
                if callee_str in sanitizers:
                    sanitized_flows.append([callee_str, node.line_num])
        return sanitized_flows


class FlowGraphBuilder:
    def __init__(self, sources, sinks, patterns):
        self.sinks: set = sinks
        self.sources: set = sources
        self.graph = FlowGraph()
        self.current_scope = []  # Track variables in scope for implicit flows

    def build(self, ast):
        self.visit_node(ast)
        return self.graph

    def visit_node(self, ast_node):
        # Handle different node types
        if ast_node["type"] == "Program":
            self.handle_program(ast_node)
        if ast_node["type"] == "Identifier":
            self.handle_identifier(ast_node)
        if ast_node["type"] == "Literal":
            self.handle_literal(ast_node)
        if ast_node["type"] == "ExpressionStatement":
            self.handle_expression_statement(ast_node)
        elif ast_node["type"] == "AssignmentExpression":
            self.handle_assignment(ast_node)
        elif ast_node["type"] == "CallExpression":
            self.handle_call_expression(ast_node)
        # ... handle other node types

        # Recursively visit child nodes
        for key, dictionary in ast_node.items():
            if isinstance(dictionary, dict):
                if key != "loc":
                    self.visit_node(dictionary)
            elif isinstance(dictionary, list):
                for item in dictionary:
                    if isinstance(item, dict):
                        self.visit_node(item)

    def handle_literal(self, node):
        print("Handle literal")
        # Create node for literal
        literal_node = Node(
            identifier=f"lit_{len(self.graph.nodes)}",
            node_type="literal",
            ast_node=node,
            line_num=node["loc"]["start"]["line"],
        )
        self.graph.nodes[literal_node.identifier] = literal_node
        return literal_node

    def handle_expression_statement(self, node):
        print("Handle expression statement")
        return self.visit_node(node["expression"])

    def handle_identifier(self, node):
        print("Handle identifier")
        # Check if identifier is a variable
        var_name = node["name"]
        for var in self.graph.variables:
            if var[""] == var_name:
                return self.graph.variables[var]
        var_node = Node(
            identifier=make_identifier("var", var_name),
            node_type="variable",
            ast_node=node,
            line_num=node["loc"]["start"]["line"],
        )
        self.graph.nodes[var_node.identifier] = var_node
        return var_node

    def handle_program(self, node):
        print("Handle program")
        for statement in node["body"]:
            self.visit_node(statement)

    def handle_variable_declaration(self, node):
        print("handle_variable_declaration")
        for declarator in node["declarations"]:
            var_name = declarator["id"]["name"]

            # Create node for variable
            var_node = Node(
                identifier=f"var_{var_name}",
                node_type="variable",
                ast_node=declarator["id"],
                line_num=declarator["id"]["loc"]["start"]["line"],
            )
            self.graph.nodes[var_node.identifier] = var_node

            # Handle initialization if present
            if declarator.get("init"):
                init_node = self.visit_node(declarator["init"])
                if init_node:
                    self.add_flow(init_node, var_node)

            # Update variable tracking
            self.graph.variables[var_name] = var_node

    def handle_assignment(self, node):
        print("handle_assignment")
        # Handle right side of assignment
        right_node = self.visit_node(node["right"])

        # Handle left side of assignment
        left_node = self.visit_node(node["left"])
        if left_node:
            self.add_flow(right_node, left_node)

    def handle_call_expression(self, node):
        print("handle_call_expression")
        # Create node for the call
        call_node = Node(
            identifier=f"call_{len(self.graph.nodes)}",
            node_type="call",
            ast_node=node,
            line_num=node["loc"]["start"]["line"],
        )
        self.graph.nodes[call_node.identifier] = call_node

        # Handle callee (could be member expression or identifier)
        callee = self.visit_node(node["callee"])
        if callee:
            self.add_flow(callee, call_node)

        # Check if this is a source or sink
        # callee_str = self.get_callee_string(node["callee"])
        n = node["callee"]["name"]
        if self.is_source(n):
            self.graph.sources.add(call_node)
        elif self.is_sink(n):
            self.graph.sinks.add(call_node)

        # Handle arguments
        for arg in node["arguments"]:
            arg_node = self.visit_node(arg)
            if arg_node:
                self.add_flow(arg_node, call_node)

        return call_node

    def add_flow(self, from_node, to_node):
        print("add_flow")
        """Add a flow edge between nodes"""
        if from_node not in to_node.incoming_flows:
            to_node.incoming_flows.append(from_node)
        if to_node not in from_node.outgoing_flows:
            from_node.outgoing_flows.append(to_node)

    def is_sink(self, node):
        return node in self.sinks

    def is_source(self, node):
        return node in self.sources


def analyze_vulnerabilities(ast, patterns):
    # Build flow graph
    builder = FlowGraphBuilder()
    graph = builder.build(ast)

    vulnerabilities = []

    # Check each pattern
    for pattern in patterns:
        # Find flows between sources and sinks
        for source_node in graph.sources:
            for sink_node in graph.sinks:
                # Get source and sink strings
                source_str = graph.get_callee_string(source_node.ast_node["callee"])
                sink_str = graph.get_callee_string(sink_node.ast_node["callee"])

                # Check if they match pattern
                if source_str in pattern["sources"] and sink_str in pattern["sinks"]:

                    # Find all paths
                    paths = graph.find_paths(source_node, sink_node)
                    if paths:
                        # Check sanitization
                        sanitized_paths = []
                        has_unsanitized = False

                        for path in paths:
                            sanitizers = graph.check_sanitization(
                                path, pattern["sanitizers"]
                            )
                            if sanitizers:
                                sanitized_paths.append(sanitizers)
                            else:
                                has_unsanitized = True

                        # Add vulnerability
                        vulnerabilities.append(
                            {
                                "vulnerability": pattern["vulnerability"],
                                "source": [source_str, source_node.line_num],
                                "sink": [sink_str, sink_node.line_num],
                                "implicit_flows": (
                                    "yes" if graph.has_implicit_flow(path) else "no"
                                ),
                                "unsanitized_flows": "yes" if has_unsanitized else "no",
                                "sanitized_flows": sanitized_paths,
                            }
                        )

    return vulnerabilities


def make_identifier(node_type, name):
    opts = {
        "var": "var_" + name,
        # etc
    }

    if node_type not in opts:
        return f"NOT_A_VALID_TYPE_({name})"

    return opts[node_type]
