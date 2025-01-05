from typing import List, Dict, Set, Optional
from copy import deepcopy
from dataclasses import dataclass
import json
import esprima

class Pattern:
    def __init__(self, vulnerability: str, sources: List[str], sanitizers: List[str], sinks: List[str], implicit: bool):
        self.name = vulnerability
        self.sources = set(sources)
        self.sanitizers = set(sanitizers)
        self.sinks = set(sinks)
        self.implicit = implicit

    def is_source(self, name: str) -> bool:
        return name in self.sources

    def is_sanitizer(self, name: str) -> bool:
        return name in self.sanitizers

    def is_sink(self, name: str) -> bool:
        return name in self.sinks

class Label:
    def __init__(self):
        self.source_sanitizers: Dict[str, Set[str]] = {}

    def add_source(self, source: str):
        if source not in self.source_sanitizers:
            self.source_sanitizers[source] = set()

    def add_sanitizer(self, sanitizer: str):
        for source in self.source_sanitizers:
            self.source_sanitizers[source].add(sanitizer)

    def get_sources(self) -> Set[str]:
        return set(self.source_sanitizers.keys())

    def get_sanitizers_for_source(self, source: str) -> Set[str]:
        return self.source_sanitizers.get(source, set())

    def combine(self, other: 'Label') -> 'Label':
        combined = Label()
        combined.source_sanitizers = deepcopy(self.source_sanitizers)
        for source, sanitizers in other.source_sanitizers.items():
            if source in combined.source_sanitizers:
                combined.source_sanitizers[source] &= sanitizers
            else:
                combined.source_sanitizers[source] = sanitizers.copy()
        return combined

class MultiLabel:
    def __init__(self, patterns: List[Pattern]):
        self.labels = {pattern.name: Label() for pattern in patterns}

    def add_source(self, pattern_name: str, source: str):
        if pattern_name in self.labels:
            self.labels[pattern_name].add_source(source)

    def add_sanitizer(self, pattern_name: str, sanitizer: str):
        if pattern_name in self.labels:
            self.labels[pattern_name].add_sanitizer(sanitizer)

    def get_label(self, pattern_name: str) -> Optional[Label]:
        return self.labels.get(pattern_name)

    def combine(self, other: 'MultiLabel') -> 'MultiLabel':
        combined = MultiLabel(list(self.labels.keys()))
        for pattern_name, label in self.labels.items():
            if pattern_name in other.labels:
                combined.labels[pattern_name] = label.combine(other.labels[pattern_name])
        return combined

class Vulnerabilities:
    def __init__(self):
        self.illegal_flows: Dict[str, List[Dict]] = {}

    def add_illegal_flows(self, name: str, multi_label: MultiLabel):
        for pattern_name, label in multi_label.labels.items():
            if label.get_sources():
                if pattern_name not in self.illegal_flows:
                    self.illegal_flows[pattern_name] = []
                self.illegal_flows[pattern_name].append({
                    'sink': name,
                    'sources': list(label.get_sources()),
                    'sanitizers': {
                        source: list(label.get_sanitizers_for_source(source))
                        for source in label.get_sources()
                    }
                })

    def get_report(self) -> Dict[str, List[Dict]]:
        return deepcopy(self.illegal_flows)

class ASTAnalyzer:
    def __init__(self):
        pass

    def analyze(self, source_code: str, patterns: List[Pattern]) -> Dict[str, List[Dict]]:
        tree = esprima.parseScript(source_code, loc=True).toDict()
        vulnerabilities = Vulnerabilities()
        labelling = MultiLabel(patterns)
        self._analyze_node(tree, labelling, vulnerabilities, patterns)
        return vulnerabilities.get_report()

    def _analyze_node(self, node: Dict, labelling: MultiLabel, vulnerabilities: Vulnerabilities, patterns: List[Pattern]):
        node_type = node.get("type")
        if node_type == "VariableDeclaration":
            self._analyze_variable_declaration(node, labelling, vulnerabilities, patterns)
        elif node_type == "CallExpression":
            self._analyze_call_expression(node, labelling, vulnerabilities, patterns)
        elif node_type == "Identifier":
            self._analyze_identifier(node, labelling, vulnerabilities, patterns)

        for child in node.get("body", []) + node.get("declarations", []) + node.get("arguments", []):
            if isinstance(child, dict):
                self._analyze_node(child, labelling, vulnerabilities, patterns)

    def _analyze_variable_declaration(self, node: Dict, labelling: MultiLabel, vulnerabilities: Vulnerabilities, patterns: List[Pattern]):
        for declaration in node.get("declarations", []):
            init = declaration.get("init", {})
            if init.get("type") == "CallExpression":
                func_name = init.get("callee", {}).get("name")
                for pattern in patterns:
                    if pattern.is_sanitizer(func_name):
                        var_name = declaration.get("id", {}).get("name")
                        labelling.add_sanitizer(pattern.name, func_name)
            elif declaration.get("id", {}).get("name"):
                var_name = declaration["id"]["name"]
                for pattern in patterns:
                    if pattern.is_source(var_name):
                        labelling.add_source(pattern.name, var_name)

    def _analyze_call_expression(self, node: Dict, labelling: MultiLabel, vulnerabilities: Vulnerabilities, patterns: List[Pattern]):
        func_name = node.get("callee", {}).get("name")
        for pattern in patterns:
            if pattern.is_sink(func_name):
                vulnerabilities.add_illegal_flows(func_name, labelling)

    def _analyze_identifier(self, node: Dict, labelling: MultiLabel, vulnerabilities: Vulnerabilities, patterns: List[Pattern]):
        var_name = node.get("name")
        for pattern in patterns:
            if pattern.is_source(var_name):
                labelling.add_source(pattern.name, var_name)

def main():
    import sys
    if len(sys.argv) != 3:
        print("Usage: python js_analyzer.py <source_code.js> <patterns.json>")
        return

    source_path = sys.argv[1]
    patterns_path = sys.argv[2]

    with open(source_path, 'r') as source_file:
        source_code = source_file.read()

    with open(patterns_path, 'r') as patterns_file:
        patterns_data = json.load(patterns_file)
        patterns = [Pattern(**p) for p in patterns_data]

    analyzer = ASTAnalyzer()
    report = analyzer.analyze(source_code, patterns)

    output_path = f"{source_path}.output.json"
    with open(output_path, 'w') as output_file:
        json.dump(report, output_file, indent=2)

if __name__ == "__main__":
    main()
