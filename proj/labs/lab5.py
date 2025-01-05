import ast
from typing import Dict, Set, Optional, List, Tuple
from copy import deepcopy

class FlowAnalyzer:
    """
    Analyzes information flows in Python AST nodes.
    """
    def __init__(self, policy: Policy, max_loop_iterations: int = 3):
        """
        Initialize flow analyzer.
        
        Args:
            policy: Policy object for checking illegal flows
            max_loop_iterations: Maximum number of loop iterations to analyze
        """
        self.policy = policy
        self.max_loop_iterations = max_loop_iterations
    
    def analyze_expression(
        self,
        node: ast.AST,
        labelling: MultiLabelling,
        vulnerabilities: Vulnerabilities
    ) -> MultiLabel:
        """
        Analyze information flows in an expression.
        
        Args:
            node: AST expression node
            labelling: Current program state
            vulnerabilities: Collection of detected vulnerabilities
        Returns:
            MultiLabel representing information flow from expression
        """
        if isinstance(node, ast.Name):
            # Variable reference - get its current label
            return labelling.get_label(node.id) or MultiLabel(self.policy.patterns.values())
        
        elif isinstance(node, ast.Constant):
            # Constants don't carry tainted information
            return MultiLabel(self.policy.patterns.values())
        
        elif isinstance(node, ast.BinOp):
            # Binary operation - combine labels from both operands
            left_label = self.analyze_expression(node.left, labelling, vulnerabilities)
            right_label = self.analyze_expression(node.right, labelling, vulnerabilities)
            return left_label.combine(right_label)
        
        elif isinstance(node, ast.BoolOp):
            # Boolean operation - combine labels from all operands
            result_label = MultiLabel(self.policy.patterns.values())
            for value in node.values:
                value_label = self.analyze_expression(value, labelling, vulnerabilities)
                result_label = result_label.combine(value_label)
            return result_label
        
        elif isinstance(node, ast.UnaryOp):
            # Unary operation - pass through operand's label
            return self.analyze_expression(node.operand, labelling, vulnerabilities)
        
        elif isinstance(node, ast.Call):
            # Function call - check for illegal flows to sinks
            arg_labels = []
            for arg in node.args:
                arg_label = self.analyze_expression(arg, labelling, vulnerabilities)
                arg_labels.append(arg_label)
            
            # Combine all argument labels
            combined_label = MultiLabel(self.policy.patterns.values())
            for label in arg_labels:
                combined_label = combined_label.combine(label)
            
            # Check if this function is a sink for any vulnerability
            if isinstance(node.func, ast.Name):
                func_name = node.func.id
                illegal_flows = self.policy.check_illegal_flows(func_name, combined_label)
                if any(label.get_sources() for label in illegal_flows.labels.values()):
                    vulnerabilities.add_illegal_flows(func_name, illegal_flows)
            
            return combined_label
        
        elif isinstance(node, ast.Compare):
            # Comparison - combine labels from all parts
            labels = [self.analyze_expression(node.left, labelling, vulnerabilities)]
            for comparator in node.comparators:
                labels.append(self.analyze_expression(comparator, labelling, vulnerabilities))
            
            result_label = MultiLabel(self.policy.patterns.values())
            for label in labels:
                result_label = result_label.combine(label)
            return result_label
        
        # Default case - return empty label
        return MultiLabel(self.policy.patterns.values())
    
    def analyze_statement(
        self,
        node: ast.AST,
        labelling: MultiLabelling,
        vulnerabilities: Vulnerabilities
    ) -> MultiLabelling:
        """
        Analyze information flows in a statement.
        
        Args:
            node: AST statement node
            labelling: Current program state
            vulnerabilities: Collection of detected vulnerabilities
        Returns:
            Updated MultiLabelling after statement execution
        """
        if isinstance(node, ast.Assign):
            # Assignment statement
            value_label = self.analyze_expression(node.value, labelling, vulnerabilities)
            result_labelling = labelling.create_copy()
            
            # Update label for each target
            for target in node.targets:
                if isinstance(target, ast.Name):
                    result_labelling.update_label(target.id, value_label)
            
            return result_labelling
        
        elif isinstance(node, ast.If):
            # If statement - analyze both branches
            condition_label = self.analyze_expression(node.test, labelling, vulnerabilities)
            
            # Analyze true branch
            true_labelling = self._analyze_block(node.body, labelling, vulnerabilities)
            
            # Analyze false branch
            false_labelling = labelling.create_copy()
            if node.orelse:
                false_labelling = self._analyze_block(node.orelse, labelling, vulnerabilities)
            
            # Combine results from both branches
            return true_labelling.combine_paths(false_labelling)
        
        elif isinstance(node, ast.While):
            # While loop - analyze with fixed point computation
            result_labelling = labelling.create_copy()
            prev_labelling = None
            iterations = 0
            
            # Keep analyzing until fixed point or max iterations
            while (prev_labelling is None or 
                   not self._labellings_equal(prev_labelling, result_labelling)) and \
                  iterations < self.max_loop_iterations:
                
                prev_labelling = result_labelling.create_copy()
                
                # Analyze condition
                condition_label = self.analyze_expression(node.test, result_labelling, vulnerabilities)
                
                # Analyze body
                body_labelling = self._analyze_block(node.body, result_labelling, vulnerabilities)
                
                # Combine with previous state
                result_labelling = result_labelling.combine_paths(body_labelling)
                iterations += 1
            
            return result_labelling
        
        elif isinstance(node, ast.Expr):
            # Expression statement - analyze for side effects
            self.analyze_expression(node.value, labelling, vulnerabilities)
            return labelling.create_copy()
        
        # Default case - return copy of input labelling
        return labelling.create_copy()
    
    def _analyze_block(
        self,
        nodes: List[ast.AST],
        labelling: MultiLabelling,
        vulnerabilities: Vulnerabilities
    ) -> MultiLabelling:
        """Analyze a block of statements sequentially."""
        current_labelling = labelling.create_copy()
        for node in nodes:
            current_labelling = self.analyze_statement(node, current_labelling, vulnerabilities)
        return current_labelling
    
    def _labellings_equal(self, l1: MultiLabelling, l2: MultiLabelling) -> bool:
        """Check if two multilabellings are equivalent."""
        if set(l1.labelling.keys()) != set(l2.labelling.keys()):
            return False
        
        for name in l1.labelling:
            label1 = l1.get_label(name)
            label2 = l2.get_label(name)
            
            if label1.get_sources() != label2.get_sources():
                return False
            
            for source in label1.get_sources():
                if (label1.get_sanitizers_for_source(source) != 
                    label2.get_sanitizers_for_source(source)):
                    return False
        
        return True