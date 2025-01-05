from typing import List, Dict, Set, Optional
from copy import deepcopy
from dataclasses import dataclass
import json
import esprima
import sys
import os

class Pattern:
    def __init__(self, vulnerability: str, sources: List[str], sanitizers: List[str], sinks: List[str], implicit: bool):
        self.vulnerability = vulnerability
        # Handle empty strings in sources/sanitizers
        self.sources = {s for s in sources if s}  # Remove empty strings
        self.sanitizers = {s for s in sanitizers if s}  # Remove empty strings
        self.sinks = set(sinks)
        self.implicit = implicit

    def is_source(self, name: str) -> bool:
        # If sources is empty, everything is considered a source
        if not self.sources:
            return True
        return name in self.sources

    def is_sanitizer(self, name: str) -> bool:
        # If sanitizers is empty, nothing is considered a sanitizer
        if not self.sanitizers:
            return False
        return name in self.sanitizers

    def is_sink(self, name: str) -> bool:
        return name in self.sinks

class Label:
    def __init__(self):
        self.source_sanitizers: Dict[str, Set[str]] = {}
        self.line_numbers: Dict[str, int] = {}

    def add_source(self, source: str, line: int):
        if source not in self.source_sanitizers:
            self.source_sanitizers[source] = set()
            self.line_numbers[source] = line

    def add_sanitizer(self, sanitizer: str, line: int):
        for source in self.source_sanitizers:
            self.source_sanitizers[source].add(sanitizer)
            if sanitizer not in self.line_numbers:
                self.line_numbers[sanitizer] = line

    def get_sources(self) -> Set[str]:
        return set(self.source_sanitizers.keys())

    def get_sanitizers_for_source(self, source: str) -> Set[str]:
        return self.source_sanitizers.get(source, set())

    def get_line_number(self, identifier: str) -> Optional[int]:
        return self.line_numbers.get(identifier)

    def combine(self, other: 'Label') -> 'Label':
        combined = Label()
        combined.source_sanitizers = deepcopy(self.source_sanitizers)
        combined.line_numbers = deepcopy(self.line_numbers)
        
        for source, sanitizers in other.source_sanitizers.items():
            if source in combined.source_sanitizers:
                combined.source_sanitizers[source] |= sanitizers  # Use union instead of intersection
            else:
                combined.source_sanitizers[source] = sanitizers.copy()
                combined.line_numbers[source] = other.line_numbers[source]
        
        for identifier, line in other.line_numbers.items():
            if identifier not in combined.line_numbers:
                combined.line_numbers[identifier] = line
                
        return combined

class MultiLabel:
    def __init__(self, patterns: List[Pattern]):
        self.labels = {pattern.vulnerability: Label() for pattern in patterns}
        self.patterns = {pattern.vulnerability: pattern for pattern in patterns}

    def add_source(self, vulnerability: str, source: str, line: int):
        if vulnerability in self.labels:
            self.labels[vulnerability].add_source(source, line)

    def add_sanitizer(self, vulnerability: str, sanitizer: str, line: int):
        if vulnerability in self.labels:
            self.labels[vulnerability].add_sanitizer(sanitizer, line)

    def get_label(self, vulnerability: str) -> Optional[Label]:
        return self.labels.get(vulnerability)

    def combine(self, other: 'MultiLabel') -> 'MultiLabel':
        combined = MultiLabel(list(self.patterns.values()))
        for vulnerability, label in self.labels.items():
            if vulnerability in other.labels:
                combined.labels[vulnerability] = label.combine(other.labels[vulnerability])
        return combined

class Vulnerabilities:
    def __init__(self):
        self.vulnerabilities: List[Dict] = []

    def add_vulnerability(self, pattern: Pattern, sink_name: str, sink_line: int, label: Label):
        for source in label.get_sources():
            source_line = label.get_line_number(source)
            sanitized_flows = []
            
            source_sanitizers = label.get_sanitizers_for_source(source)
            if source_sanitizers:
                sanitizer_group = []
                for sanitizer in source_sanitizers:
                    sanitizer_line = label.get_line_number(sanitizer)
                    sanitizer_group.append([sanitizer, sanitizer_line])
                sanitized_flows.append(sanitizer_group)

            self.vulnerabilities.append({
                "vulnerability": pattern.vulnerability,
                "source": [source, source_line],
                "sink": [sink_name, sink_line],
                "implicit_flows": "yes" if pattern.implicit else "no",
                "unsanitized_flows": "yes" if not source_sanitizers else "no",
                "sanitized_flows": sanitized_flows
            })

    def get_report(self) -> List[Dict]:
        return sorted(self.vulnerabilities, key=lambda x: (x["vulnerability"], x["source"][0], x["sink"][0]))

class JSAnalyzer:
    def __init__(self):
        self.current_conditions = []
        self.variable_labels: Dict[str, MultiLabel] = {}
        self.vulnerabilities = Vulnerabilities()

    def analyze(self, source_code: str, patterns: List[Pattern]) -> List[Dict]:
        try:
            tree = esprima.parseScript(source_code, loc=True)
            self._analyze_node(tree, patterns)
            return self.vulnerabilities.get_report()
        except Exception as e:
            print(f"Error analyzing code: {e}")
            return []

    def _get_node_line(self, node) -> int:
        return node.loc.start.line if hasattr(node, 'loc') else 0

    def _analyze_node(self, node, patterns: List[Pattern]):
        if node.type == 'Program':
            for statement in node.body:
                self._analyze_node(statement, patterns)
                
        elif node.type == 'VariableDeclaration':
            for declarator in node.declarations:
                self._analyze_node(declarator, patterns)
                
        elif node.type == 'VariableDeclarator':
            if node.init:
                init_label = self._analyze_expression(node.init, patterns)
                if node.id.type == 'Identifier':
                    self.variable_labels[node.id.name] = init_label
                    
        elif node.type == 'ExpressionStatement':
            self._analyze_expression(node.expression, patterns)
            
        elif node.type == 'AssignmentExpression':
            value_label = self._analyze_expression(node.right, patterns)
            if node.left.type == 'Identifier':
                self.variable_labels[node.left.name] = value_label
            self._check_sink_assignment(node.left, value_label, patterns)

    def _analyze_expression(self, node, patterns: List[Pattern]) -> MultiLabel:
        if node.type == 'CallExpression':
            func_name = ""
            if node.callee.type == 'MemberExpression':
                func_name = self._get_member_expr_name(node.callee)
            elif node.callee.type == 'Identifier':
                func_name = node.callee.name

            # Analyze arguments
            arg_labels = [self._analyze_expression(arg, patterns) for arg in node.arguments]
            combined_label = MultiLabel(patterns)
            
            # First, check if the function itself is a source
            for pattern in patterns:
                if pattern.is_source(func_name):
                    combined_label.add_source(pattern.vulnerability, func_name, self._get_node_line(node))

            # Then check if it's a sink or sanitizer
            for pattern in patterns:
                if pattern.is_sink(func_name):
                    for arg_label in arg_labels:
                        if pattern.vulnerability in arg_label.labels:
                            self.vulnerabilities.add_vulnerability(
                                pattern,
                                func_name,
                                self._get_node_line(node),
                                arg_label.labels[pattern.vulnerability]
                            )
                elif pattern.is_sanitizer(func_name):
                    for arg_label in arg_labels:
                        if pattern.vulnerability in arg_label.labels:
                            combined_label.add_sanitizer(pattern.vulnerability, func_name, self._get_node_line(node))
            
            return combined_label

        elif node.type == 'Literal':
            return MultiLabel(patterns)

        elif node.type == 'Identifier':
            if node.name in self.variable_labels:
                return self.variable_labels[node.name]
            # If variable is undefined, it might be a source
            combined_label = MultiLabel(patterns)
            for pattern in patterns:
                if pattern.is_source(""):  # Check if undefined variables should be considered sources
                    combined_label.add_source(pattern.vulnerability, node.name, self._get_node_line(node))
            return combined_label

        return MultiLabel(patterns)

    def _get_member_expr_name(self, node) -> str:
        if node.type == 'MemberExpression':
            object_name = self._get_member_expr_name(node.object)
            return f"{object_name}.{node.property.name}"
        elif node.type == 'Identifier':
            return node.name
        return ""

    def _check_sink_assignment(self, node, value_label: MultiLabel, patterns: List[Pattern]):
        if node.type == 'Identifier':
            var_name = node.name
            for pattern in patterns:
                if pattern.is_sink(var_name):
                    if pattern.vulnerability in value_label.labels:
                        self.vulnerabilities.add_vulnerability(
                            pattern,
                            var_name,
                            self._get_node_line(node),
                            value_label.labels[pattern.vulnerability]
                        )

def main():
    if len(sys.argv) != 3:
        print("Usage: python js_analyser.py <source_code.js> <patterns.json>")
        return

    source_path = sys.argv[1]
    patterns_path = sys.argv[2]

    try:
        with open(source_path, 'r') as source_file:
            source_code = source_file.read()

        with open(patterns_path, 'r') as patterns_file:
            patterns_data = json.load(patterns_file)
            # Convert 'implicit' from bool/str to bool
            for p in patterns_data:
                if isinstance(p['implicit'], str):
                    p['implicit'] = p['implicit'].lower() == 'true'
            patterns = [Pattern(**p) for p in patterns_data]

        analyzer = JSAnalyzer()
        report = analyzer.analyze(source_code, patterns)

        output_path = f"./output/{source_path.split('/')[-1]}.output.json"
        os.makedirs("./output", exist_ok=True)
        
        with open(output_path, 'w') as output_file:
            json.dump(report, output_file, indent=2)

    except Exception as e:
        print(f"Error: {e}")
        sys.exit(1)

if __name__ == "__main__":
    main()