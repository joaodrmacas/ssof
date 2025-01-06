import esprima
from typing import List, Dict, Set, Optional
from copy import deepcopy
from dataclasses import dataclass
import json
import sys
from all import Pattern, Policy, MultiLabel, MultiLabelling, Vulnerabilities

# Keep existing Pattern, Label, MultiLabel classes as they are generic

class JSFlowAnalyzer:
    """
    Analyzes information flows in JavaScript ASTs.
    """
    def __init__(self, policy: Policy, max_loop_iterations: int = 3):
        self.policy = policy
        self.max_loop_iterations = max_loop_iterations
    
    def analyze_expression(
        self,
        node: dict,
        labelling: MultiLabelling,
        vulnerabilities: Vulnerabilities
    ) -> MultiLabel:
        """
        Analyze information flows in a JavaScript expression.
        
        Args:
            node: JavaScript AST node dictionary
            labelling: Current program state
            vulnerabilities: Collection of detected vulnerabilities
        Returns:
            MultiLabel representing information flow from expression
        """
        node_type = node.get('type')
        
        if node_type == 'Identifier':
            # Variable reference
            for pattern in self.policy.patterns.values():
                if pattern.is_source(node['name']):
                    return MultiLabel([pattern])
            return labelling.get_label(node['name']) or MultiLabel(self.policy.patterns.values())
            
        elif node_type == 'Literal':
            # Constants don't carry tainted information
            return MultiLabel(self.policy.patterns.values())
            
        elif node_type == 'BinaryExpression':
            # Binary operations
            left_label = self.analyze_expression(node['left'], labelling, vulnerabilities)
            right_label = self.analyze_expression(node['right'], labelling, vulnerabilities)
            return left_label.combine(right_label)
            
        elif node_type == 'UnaryExpression':
            # Unary operations
            return self.analyze_expression(node['argument'], labelling, vulnerabilities)
            
        elif node_type == 'CallExpression':
            # Function calls - check for sinks and analyze arguments
            arg_labels = []
            for arg in node['arguments']:
                arg_label = self.analyze_expression(arg, labelling, vulnerabilities)
                arg_labels.append(arg_label)
            
            combined_label = MultiLabel(self.policy.patterns.values())
            for label in arg_labels:
                combined_label = combined_label.combine(label)
            
            # Get function name, handling member expressions
            func_name = self._get_member_expr_name(node['callee'])
            if func_name:
                illegal_flows = self.policy.check_illegal_flows(func_name, combined_label)
                if any(label.get_sources() for label in illegal_flows.labels.values()):
                    vulnerabilities.add_illegal_flows(func_name, illegal_flows)
            
            return combined_label
            
        elif node_type == 'MemberExpression':
            # Handle property access (e.g., document.URL)
            full_name = self._get_member_expr_name(node)
            if full_name:
                # Check if this is a source
                source_label = MultiLabel(self.policy.patterns.values())
                for pattern in self.policy.patterns.values():
                    if pattern.is_source(full_name):
                        source_label.add_source(full_name)
                return source_label
            
            # If not a recognized source, analyze object and property
            obj_label = self.analyze_expression(node['object'], labelling, vulnerabilities)
            if not node['computed']:  # Simple property access
                return obj_label
            else:  # Computed property access - analyze property expression
                prop_label = self.analyze_expression(node['property'], labelling, vulnerabilities)
                return obj_label.combine(prop_label)
        
        # Default case
        return MultiLabel(self.policy.patterns.values())
    
    def analyze_statement(
        self,
        node: dict,
        labelling: MultiLabelling,
        vulnerabilities: Vulnerabilities
    ) -> MultiLabelling:
        """
        Analyze information flows in a JavaScript statement.
        
        Args:
            node: JavaScript AST node dictionary
            labelling: Current program state
            vulnerabilities: Collection of detected vulnerabilities
        Returns:
            Updated MultiLabelling after statement execution
        """
        node_type = node.get('type')
        
        if node_type == 'ExpressionStatement':
            # Expression statement
            self.analyze_expression(node['expression'], labelling, vulnerabilities)
            return labelling.create_copy()
            
        elif node_type == 'VariableDeclaration':
            # Variable declarations
            result_labelling = labelling.create_copy()
            for declarator in node['declarations']:
                if declarator['init']:
                    value_label = self.analyze_expression(declarator['init'], labelling, vulnerabilities)
                    if declarator['id']['type'] == 'Identifier':
                        result_labelling.update_label(declarator['id']['name'], value_label)
            return result_labelling
            
        elif node_type == 'AssignmentExpression':
            # Assignment
            value_label = self.analyze_expression(node['right'], labelling, vulnerabilities)
            result_labelling = labelling.create_copy()
            
            if node['left']['type'] == 'Identifier':
                result_labelling.update_label(node['left']['name'], value_label)
            
            return result_labelling
            
        elif node_type == 'IfStatement':
            # If statement
            condition_label = self.analyze_expression(node['test'], labelling, vulnerabilities)
            
            # Analyze consequent (true branch)
            true_labelling = self._analyze_block(
                [node['consequent']] if node['consequent']['type'] != 'BlockStatement' 
                else node['consequent']['body'],
                labelling,
                vulnerabilities
            )
            
            # Analyze alternate (false branch)
            false_labelling = labelling.create_copy()
            if node['alternate']:
                false_labelling = self._analyze_block(
                    [node['alternate']] if node['alternate']['type'] != 'BlockStatement'
                    else node['alternate']['body'],
                    labelling,
                    vulnerabilities
                )
            
            return true_labelling.combine_paths(false_labelling)
            
        elif node_type == 'WhileStatement':
            # While loop
            result_labelling = labelling.create_copy()
            prev_labelling = None
            iterations = 0
            
            while (prev_labelling is None or 
                   not self._labellings_equal(prev_labelling, result_labelling)) and \
                  iterations < self.max_loop_iterations:
                
                prev_labelling = result_labelling.create_copy()
                condition_label = self.analyze_expression(node['test'], result_labelling, vulnerabilities)
                
                body_labelling = self._analyze_block(
                    [node['body']] if node['body']['type'] != 'BlockStatement'
                    else node['body']['body'],
                    result_labelling,
                    vulnerabilities
                )
                
                result_labelling = result_labelling.combine_paths(body_labelling)
                iterations += 1
            
            return result_labelling
        
        # Default case
        return labelling.create_copy()
    
    def _analyze_block(
        self,
        nodes: List[dict],
        labelling: MultiLabelling,
        vulnerabilities: Vulnerabilities
    ) -> MultiLabelling:
        """Analyze a block of statements sequentially."""
        current_labelling = labelling.create_copy()
        for node in nodes:
            current_labelling = self.analyze_statement(node, current_labelling, vulnerabilities)
        return current_labelling
    
    def _get_member_expr_name(self, node: dict) -> Optional[str]:
        """
        Get the full name of a member expression (e.g., 'document.URL').
        Returns None if not a simple member access chain.
        """
        if node['type'] == 'Identifier':
            return node['name']
        elif node['type'] == 'MemberExpression' and not node['computed']:
            obj_name = self._get_member_expr_name(node['object'])
            if obj_name and node['property']['type'] == 'Identifier':
                return f"{obj_name}.{node['property']['name']}"
        return None

def analyze_js_file(js_file: str, patterns_file: str) -> dict:
    """
    Analyze a JavaScript file for vulnerabilities according to given patterns.
    
    Args:
        js_file: Path to JavaScript file
        patterns_file: Path to JSON patterns file
    Returns:
        Dictionary containing vulnerability report
    """
    # Load and parse patterns
    with open(patterns_file, 'r') as f:
        patterns_data = json.load(f)
    
    patterns = []
    for p in patterns_data:
        pattern = Pattern(
            name=p['vulnerability'],
            sources=p['sources'],
            sanitizers=p['sanitizers'],
            sinks=p['sinks']
        )
        patterns.append(pattern)
    
    # Load and parse JavaScript file
    with open(js_file, 'r') as f:
        js_code = f.read().strip()
    
    try:
        ast_dict = esprima.parseScript(js_code, loc=True).toDict()
    except Exception as e:
        print(f"Error parsing JavaScript file: {e}")
        return {}
    
    # Set up analysis
    policy = Policy(patterns)
    analyzer = JSFlowAnalyzer(policy)
    vulnerabilities = Vulnerabilities()
    initial_labelling = MultiLabelling(patterns)
    
    # Analyze the AST
    analyzer._analyze_block(ast_dict['body'], initial_labelling, vulnerabilities)
    
    # Get vulnerability report
    return vulnerabilities.get_report()

def main():
    if len(sys.argv) != 3:
        print("Usage: python js_analyser.py <js_file> <patterns_file>")
        sys.exit(1)
    
    js_file = sys.argv[1]
    patterns_file = sys.argv[2]
    
    # Get output filename
    import os
    js_filename = os.path.basename(js_file)
    output_filename = os.path.join('output', js_filename.replace('.js', '.output.json'))
    
    # Create output directory if it doesn't exist
    os.makedirs('output', exist_ok=True)
    
    # Analyze file and write report
    report = analyze_js_file(js_file, patterns_file)
    
    with open(output_filename, 'w') as f:
        json.dump(report, f ,indent=2, sort_keys=True, default=str)

if __name__ == "__main__":
    main()