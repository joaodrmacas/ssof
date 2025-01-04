import sys
import json
import esprima
from typing import Dict, List, Set, Tuple
import os

class VulnerabilityAnalyzer:
    def __init__(self, patterns_file: str):
        self.patterns = self._load_patterns(patterns_file)
        # Track sources for each variable: var_name -> [(source_name, source_line)]
        self.tainted_vars: Dict[str, List[Tuple[str, int]]] = {}
        self.sanitized_vars: Dict[str, List[List[Tuple[str, int]]]] = {}
        self.vulnerabilities: List[Dict] = []
        
    def _load_patterns(self, patterns_file: str) -> List[Dict]:
        with open(patterns_file, 'r') as f:
            return json.load(f)
            
    def analyze_file(self, js_file: str):
        # Read and parse JavaScript file
        with open(js_file, 'r') as f:
            code = f.read().strip()
        
        ast = esprima.parseScript(code, loc=True)
        
        # Create output directory if it doesn't exist
        os.makedirs('./output', exist_ok=True)
        
        # Analyze AST for each vulnerability pattern
        for pattern in self.patterns:
            self._analyze_pattern(ast.toDict(), pattern)
            
        # Write results to output file
        output_file = f"./output/{os.path.basename(js_file)}.output.json"
        with open(output_file, 'w') as f:
            json.dump(self.vulnerabilities, f, indent=4)
            
    def _analyze_pattern(self, ast: Dict, pattern: Dict):
        self.tainted_vars.clear()
        self.sanitized_vars.clear()
        
        # Track information flows through AST
        self._analyze_node(ast, pattern)
        
    def _analyze_node(self, node: Dict, pattern: Dict):
        if not isinstance(node, dict):
            return
            
        node_type = node.get('type')
        
        if node_type == 'Program':
            for statement in node.get('body', []):
                self._analyze_node(statement, pattern)
                
        elif node_type == 'ExpressionStatement':
            self._analyze_node(node.get('expression'), pattern)
            
        elif node_type == 'VariableDeclaration':
            for decl in node.get('declarations', []):
                self._handle_variable_declaration(decl, pattern)
                
        elif node_type == 'AssignmentExpression':
            self._handle_assignment(node, pattern)
            
        elif node_type == 'CallExpression':
            self._handle_call_expression(node, pattern)
            
    def _handle_variable_declaration(self, node: Dict, pattern: Dict):
        if not node.get('id') or not node.get('init'):
            return
            
        var_name = node['id']['name']
        init = node['init']
        self._process_assignment_value(var_name, init, pattern)
        
    def _handle_assignment(self, node: Dict, pattern: Dict):
        if node['left']['type'] != 'Identifier':
            return
            
        var_name = node['left']['name']
        value = node['right']
        self._process_assignment_value(var_name, value, pattern)
        
    def _process_assignment_value(self, var_name: str, value: Dict, pattern: Dict):
        line = value['loc']['start']['line']
        
        # Clear previous taint status on reassignment
        if var_name in self.tainted_vars:
            del self.tainted_vars[var_name]
        
        # Case 1: Direct source (function call)
        if value['type'] == 'CallExpression':
            source_name = self._get_call_name(value)
            if source_name in pattern['sources']:
                self.tainted_vars[var_name] = [(source_name, line)]
                
        # Case 2: Literal source
        elif value['type'] == 'Literal' and str(value.get('value', '')) in pattern['sources']:
            self.tainted_vars[var_name] = [('""', line)]
            
        # Case 3: Variable reference (propagate taint)
        elif value['type'] == 'Identifier':
            ref_var = value['name']
            if ref_var in self.tainted_vars:
                self.tainted_vars[var_name] = self.tainted_vars[ref_var].copy()
                
    def _handle_call_expression(self, node: Dict, pattern: Dict):
        sink_name = self._get_call_name(node)
        if sink_name in pattern['sinks']:
            sink_line = node['loc']['start']['line']
            
            # Check if any arguments are tainted
            for arg in node['arguments']:
                if arg['type'] == 'Identifier' and arg['name'] in self.tainted_vars:
                    var_name = arg['name']
                    source_info = self.tainted_vars[var_name]
                    for source_name, source_line in source_info:
                        self._record_vulnerability(
                            pattern['vulnerability'],
                            source_name,
                            source_line,
                            sink_name,
                            sink_line,
                            self.sanitized_vars.get(var_name, [])
                        )
                        
    def _get_call_name(self, node: Dict) -> str:
        if node['callee']['type'] == 'Identifier':
            return node['callee']['name']
        elif node['callee']['type'] == 'MemberExpression':
            return self._get_member_expr_str(node['callee'])
        return ""
        
    def _get_member_expr_str(self, node: Dict) -> str:
        if node['type'] == 'MemberExpression':
            if node['object']['type'] == 'Identifier':
                return f"{node['object']['name']}.{node['property']['name']}"
            elif node['object']['type'] == 'MemberExpression':
                return f"{self._get_member_expr_str(node['object'])}.{node['property']['name']}"
        return ""
        
    def _record_vulnerability(self, vuln_name: str, source_name: str, source_line: int,
                            sink_name: str, sink_line: int, sanitized_info: List[List[Tuple[str, int]]]):
        self.vulnerabilities.append({
            "vulnerability": vuln_name,
            "source": [source_name, source_line],
            "sink": [sink_name, sink_line],
            "implicit_flows": "no",
            "unsanitized_flows": "yes" if not sanitized_info else "no",
            "sanitized_flows": sanitized_info if sanitized_info else []
        })

def main():
    if len(sys.argv) != 3:
        print("Usage: python js_analyser.py <js_file> <patterns_file>")
        sys.exit(1)
        
    js_file = sys.argv[1]
    patterns_file = sys.argv[2]
    
    analyzer = VulnerabilityAnalyzer(patterns_file)
    analyzer.analyze_file(js_file)

if __name__ == "__main__":
    main()