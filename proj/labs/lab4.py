import ast
from typing import List, Dict, Set, Optional, Tuple
from copy import deepcopy

class FlowAnalyzer:
    """
    Analyzes information flows in Python ASTs.
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
            node: AST node representing the expression
            labelling: Current program state labelling
            vulnerabilities: Collector for detected vulnerabilities
        Returns:
            MultiLabel representing information contained in expression result
        """
        if isinstance(node, ast.Name):
            # Variable reference - get its current label
            return deepcopy(labelling.get_label(node.id) or MultiLabel(self.policy.patterns.values()))
        
        elif isinstance(node, ast.Constant):
            # Constants have no information flow
            return MultiLabel(self.policy.patterns.values())
        
        elif isinstance(node, ast.BinOp):
            # Binary operations - combine labels of both operands
            left_label = self.analyze_expression(node.left, labelling, vulnerabilities)
            right_label = self.analyze_expression(node.right, labelling, vulnerabilities)
            return left_label.combine(right_label)
        
        elif isinstance(node, ast.UnaryOp):
            # Unary operations - just pass through the operand's label
            return self.analyze_expression(node.operand, labelling, vulnerabilities)
        
        elif isinstance(node, ast.Compare):
            # Comparisons - combine all operands' labels
            labels = [self.analyze_expression(node.left, labelling, vulnerabilities)]
            for comparator in node.comparators:
                labels.append(self.analyze_expression(comparator, labelling, vulnerabilities))
            
            result = labels[0]
            for label in labels[1:]:
                result = result.combine(label)
            return result
        
        elif isinstance(node, ast.Call):
            # Function calls - analyze arguments and check for illegal flows
            func_name = node.func.id if isinstance(node.func, ast.Name) else str(node.func)
            
            # Analyze all arguments
            arg_labels = []
            for arg in node.args:
                arg_label = self.analyze_expression(arg, labelling, vulnerabilities)
                arg_labels.append(arg_label)
            
            # Combine all argument labels
            combined_label = MultiLabel(self.policy.patterns.values())
            for label in arg_labels:
                combined_label = combined_label.combine(label)
            
            # Check for illegal flows to this function
            if self.policy.get_vulnerabilities_for_sink(func_name):
                illegal_flows = self.policy.check_illegal_flows(func_name, combined_label)
                if any(label.get_sources() for label in illegal_flows.labels.values()):
                    vulnerabilities.add_illegal_flows(func_name, illegal_flows)
            
            return combined_label
        
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
            node: AST node representing the statement
            labelling: Current program state labelling
            vulnerabilities: Collector for detected vulnerabilities
        Returns:
            Updated MultiLabelling after statement execution
        """
        if isinstance(node, ast.Assign):
            # Handle assignment statements
            value_label = self.analyze_expression(node.value, labelling, vulnerabilities)
            result_labelling = labelling.create_copy()
            
            # Update label for each target
            for target in node.targets:
                if isinstance(target, ast.Name):
                    result_labelling.update_label(target.id, value_label)
            
            return result_labelling
        
        elif isinstance(node, ast.If):
            # Handle if statements by analyzing both branches
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
            # Handle while loops with fixed-point computation
            result_labelling = labelling.create_copy()
            
            # Analyze loop body multiple times until fixpoint or max iterations
            prev_labelling = None
            for _ in range(self.max_loop_iterations):
                condition_label = self.analyze_expression(node.test, result_labelling, vulnerabilities)
                body_labelling = self._analyze_block(node.body, result_labelling, vulnerabilities)
                
                # Combine with previous state (paths that skip or exit loop)
                result_labelling = result_labelling.combine_paths(body_labelling)
                
                # Check for fixed point
                if prev_labelling and self._labellings_equal(prev_labelling, result_labelling):
                    break
                
                prev_labelling = result_labelling.create_copy()
            
            return result_labelling
        
        elif isinstance(node, ast.Expr):
            # Expression statements (like function calls)
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
        """Check if two labellings are equivalent."""
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