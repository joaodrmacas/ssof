import sys
import json
import esprima
from typing import List, Dict, Set
from dataclasses import dataclass
from all import FlowAnalyzer, Policy, MultiLabellingWithPaths, MultiLabel, Pattern, Vulnerabilities

class JSPattern(Pattern):
    """Extends Pattern class for JavaScript vulnerability patterns"""
    def __init__(self, vuln_dict: Dict):
        super().__init__(
            vuln_dict["vulnerability"],
            vuln_dict["sources"],
            vuln_dict["sanitizers"],
            vuln_dict["sinks"]
        )
        self.implicit = vuln_dict["implicit"] == "yes"

class JSAnalyzer:
    def __init__(self, ast_dict: Dict, patterns: List[Dict]):
        self.ast = ast_dict
        self.patterns = [JSPattern(p) for p in patterns]
        self.vulnerabilities = Vulnerabilities()
        self.current_line = 1
    
    def analyze(self) -> List[Dict]:
        """Main analysis entry point"""
        for pattern in self.patterns:
            labelling = MultiLabellingWithPaths(list(self.patterns))
            flow_analyzer = FlowAnalyzer(Policy([pattern]), max_loop_iterations=3)
            
            # Analyze the AST
            self._analyze_node(self.ast["body"], labelling, flow_analyzer)
            
        return self._format_output()
    
    def _analyze_node(self, node: Dict, labelling: MultiLabellingWithPaths, analyzer: FlowAnalyzer):
        """Recursively analyze AST nodes"""
        if not isinstance(node, list):
            node = [node]
            
        for n in node:
            self.current_line = n.get("loc", {}).get("start", {}).get("line", self.current_line)
            
            if n["type"] == "VariableDeclaration":
                self._handle_variable_declaration(n, labelling, analyzer)
            elif n["type"] == "ExpressionStatement":
                self._handle_expression(n["expression"], labelling, analyzer)
            elif n["type"] == "IfStatement":
                self._handle_if_statement(n, labelling, analyzer)
            elif n["type"] == "WhileStatement":
                self._handle_while_statement(n, labelling, analyzer)
    
    def _handle_variable_declaration(self, node: Dict, labelling: MultiLabellingWithPaths, analyzer: FlowAnalyzer):
        for decl in node["declarations"]:
            if decl["init"]:
                # Create label for RHS
                rhs_label = self._analyze_expression(decl["init"], labelling, analyzer)
                
                # Update labelling for variable
                if decl["id"]["type"] == "Identifier":
                    labelling.update_label(decl["id"]["name"], rhs_label)
    
    def _handle_expression(self, node: Dict, labelling: MultiLabellingWithPaths, analyzer: FlowAnalyzer):
        if node["type"] == "CallExpression":
            self._check_call_expression(node, labelling, analyzer)
        elif node["type"] == "AssignmentExpression":
            rhs_label = self._analyze_expression(node["right"], labelling, analyzer)
            if node["left"]["type"] == "Identifier":
                labelling.update_label(node["left"]["name"], rhs_label)
    
    def _analyze_expression(self, node: Dict, labelling: MultiLabellingWithPaths, analyzer: FlowAnalyzer) -> MultiLabel:
        if node["type"] == "Identifier":
            return labelling.get_label(node["name"]) or MultiLabel(self.patterns)
        elif node["type"] == "MemberExpression":
            return self._handle_member_expression(node, labelling, analyzer)
        elif node["type"] == "CallExpression":
            return self._handle_call_expression(node, labelling, analyzer)
        elif node["type"] in ["BinaryExpression", "UnaryExpression"]:
            return self._handle_operation(node, labelling, analyzer)
        
        return MultiLabel(self.patterns)
    
    def _handle_member_expression(self, node: Dict, labelling: MultiLabellingWithPaths, analyzer: FlowAnalyzer) -> MultiLabel:
        expr = self._get_member_expression_string(node)
        label = MultiLabel(self.patterns)
        
        # Check if member expression is a source
        for pattern in self.patterns:
            if pattern.is_source(expr):
                label.add_source(expr)
        
        return label
    
    def _get_member_expression_string(self, node: Dict) -> str:
        if node["type"] == "MemberExpression":
            obj = self._get_member_expression_string(node["object"])
            prop = node["property"]["name"] if node["property"]["type"] == "Identifier" else ""
            return f"{obj}.{prop}"
        elif node["type"] == "Identifier":
            return node["name"]
        return ""
    
    def _check_call_expression(self, node: Dict, labelling: MultiLabellingWithPaths, analyzer: FlowAnalyzer):
        func_name = self._get_member_expression_string(node["callee"])
        
        # Get labels for arguments
        arg_labels = []
        for arg in node["arguments"]:
            arg_label = self._analyze_expression(arg, labelling, analyzer)
            arg_labels.append(arg_label)
        
        # Combine argument labels
        combined_label = MultiLabel(self.patterns)
        for label in arg_labels:
            combined_label = combined_label.combine(label)
        
        # Check for illegal flows
        for pattern in self.patterns:
            if pattern.is_sink(func_name):
                flows = []
                has_unsanitized = False
                
                for source in combined_label.get_sources():
                    sanitizers = combined_label.get_sanitizers_for_source(source)
                    if not pattern.get_sanitizers().issubset(sanitizers):
                        has_unsanitized = True
                        flows.append({
                            "vulnerability": pattern.get_name(),
                            "source": [source, self._get_source_line(source)],
                            "sink": [func_name, self.current_line],
                            "implicit_flows": "yes" if pattern.implicit else "no",
                            "unsanitized_flows": "yes" if has_unsanitized else "no",
                            "sanitized_flows": [[s, self._get_sanitizer_line(s)] for s in sanitizers]
                        })
                
                if flows:
                    for flow in flows:
                        self.vulnerabilities.add_illegal_flows(func_name, combined_label)
    
    def _format_output(self) -> List[Dict]:
        report = self.vulnerabilities.get_report()
        output = []
        
        for vuln_name, flows in report.items():
            for flow in flows:
                output.append({
                    "vulnerability": vuln_name,
                    "source": flow["sources"],
                    "sink": [flow["sink"], flow.get("sink_line", 0)],
                    "implicit_flows": "yes" if any(p.implicit for p in self.patterns if p.get_name() == vuln_name) else "no",
                    "unsanitized_flows": "yes" if not flow["applied_sanitizers"] else "no",
                    "sanitized_flows": [[s, l] for s, l in flow["applied_sanitizers"].items()]
                })
        
        return output

def main():
    if len(sys.argv) != 3:
        print("Usage: python js_analyser.py <slice_file> <patterns_file>")
        sys.exit(1)
    
    # Read and parse input files
    with open(sys.argv[1], 'r') as f:
        js_code = f.read().strip()
    
    with open(sys.argv[2], 'r') as f:
        patterns = json.load(f)
    
    # Parse JavaScript to AST
    ast_dict = esprima.parseScript(js_code, loc=True).toDict()
    
    # Analyze the code
    analyzer = JSAnalyzer(ast_dict, patterns)
    vulnerabilities = analyzer.analyze()
    
    # Write output
    output_file = f"output/{sys.argv[1].split('/')[-1].replace('.js', '.output.json')}"
    with open(output_file, 'w') as f:
        json.dump(vulnerabilities, f, indent=2)

if __name__ == "__main__":
    main()