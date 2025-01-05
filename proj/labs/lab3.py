import ast
from typing import List, Set, Dict, Optional
from astexport import export
import json
from copy import deepcopy
from dataclasses import dataclass

@dataclass
class Trace:
    """Represents a single execution trace through the program."""
    steps: List[str]
    
    def __str__(self) -> str:
        return " -> ".join(self.steps)

class ASTAnalyzer:
    """
    Analyzes Python ASTs for information flow tracking.
    """
    def __init__(self, max_loop_iterations: int = 3):
        """
        Initialize AST analyzer.
        
        Args:
            max_loop_iterations: Maximum number of times to unroll loops
        """
        self.max_loop_iterations = max_loop_iterations
    
    def ast_to_json(self, source_code: str) -> str:
        """
        Convert Python source code to AST JSON representation.
        
        Args:
            source_code: Python source code as string
        Returns:
            JSON string representing the AST
        """
        tree = ast.parse(source_code)
        ast_dict = export.export_dict(tree)
        return json.dumps(ast_dict, indent=2)
    
    def print_node_info(self, node: ast.AST, indent: int = 0):
        """
        Recursively print AST node information.
        
        Args:
            node: AST node to process
            indent: Current indentation level
        """
        # Get node type and line number
        node_type = node.__class__.__name__
        line_num = getattr(node, 'lineno', '?')
        
        # Print node information
        print(f"{'  ' * indent}{node_type} (line {line_num})")
        
        # Recursively process children
        for child in ast.iter_child_nodes(node):
            self.print_node_info(child, indent + 1)
    
    def get_execution_traces(self, node: ast.AST) -> List[Trace]:
        """
        Get all possible execution traces through the AST.
        Handles a subset of Python AST nodes focusing on control flow.
        
        Args:
            node: AST node to analyze
        Returns:
            List of possible execution traces
        """
        if isinstance(node, ast.Module):
            return self._process_block(node.body)
        
        elif isinstance(node, ast.Assign):
            target_names = []
            for target in node.targets:
                if isinstance(target, ast.Name):
                    target_names.append(target.id)
            return [Trace(steps=[f"Assign: {', '.join(target_names)}"])]
        
        elif isinstance(node, ast.While):
            return self._process_while(node)
        
        elif isinstance(node, ast.If):
            return self._process_if(node)
        
        elif isinstance(node, ast.Expr):
            if isinstance(node.value, ast.Call):
                if isinstance(node.value.func, ast.Name):
                    return [Trace(steps=[f"Call: {node.value.func.id}"])]
            
        return [Trace(steps=[f"Node: {node.__class__.__name__}"])]
    
    def _process_block(self, nodes: List[ast.AST]) -> List[Trace]:
        """Process a block of statements, combining their traces sequentially."""
        if not nodes:
            return [Trace(steps=[])]
        
        result_traces = []
        first_traces = self.get_execution_traces(nodes[0])
        
        if len(nodes) == 1:
            return first_traces
        
        remaining_traces = self._process_block(nodes[1:])
        
        for first in first_traces:
            for remaining in remaining_traces:
                combined_steps = first.steps + remaining.steps
                result_traces.append(Trace(steps=combined_steps))
        
        return result_traces
    
    def _process_while(self, node: ast.While) -> List[Trace]:
        """Process while loop, considering max iterations."""
        traces = []
        
        # Add trace for when condition is false immediately
        traces.append(Trace(steps=["While: skip"]))
        
        # Process body for each possible iteration count
        for i in range(1, self.max_loop_iterations + 1):
            current_trace = []
            for _ in range(i):
                current_trace.append("While: enter")
                body_traces = self._process_block(node.body)
                for body_trace in body_traces:
                    full_trace = current_trace + body_trace.steps
                    traces.append(Trace(steps=full_trace + ["While: exit"]))
        
        return traces
    
    def _process_if(self, node: ast.If) -> List[Trace]:
        """Process if statement, considering both branches."""
        traces = []
        
        # Process true branch
        true_traces = self._process_block(node.body)
        for trace in true_traces:
            traces.append(Trace(steps=["If: true"] + trace.steps))
        
        # Process false branch if it exists
        if node.orelse:
            false_traces = self._process_block(node.orelse)
            for trace in false_traces:
                traces.append(Trace(steps=["If: false"] + trace.steps))
        else:
            traces.append(Trace(steps=["If: false"]))
        
        return traces

class MultiLabellingWithPaths(MultiLabelling):
    """
    Extended MultiLabelling class that handles multiple execution paths.
    """
    def create_copy(self) -> 'MultiLabellingWithPaths':
        """
        Create a deep copy of the current multilabelling.
        
        Returns:
            New MultiLabellingWithPaths instance with copied data
        """
        new_labelling = MultiLabellingWithPaths(self.patterns)
        for name, multi_label in self.labelling.items():
            new_labelling.labelling[name] = deepcopy(multi_label)
        return new_labelling
    
    def combine_paths(self, other: 'MultiLabellingWithPaths') -> 'MultiLabellingWithPaths':
        """
        Combine two multilabellings to represent possible outcomes from different paths.
        
        Args:
            other: Another MultiLabellingWithPaths instance
        Returns:
            New MultiLabellingWithPaths combining both inputs
        """
        combined = MultiLabellingWithPaths(self.patterns)
        
        # Get all variable names from both labellings
        all_names = set(self.labelling.keys()) | set(other.labelling.keys())
        
        # For each variable, combine its labels from both paths
        for name in all_names:
            self_label = self.get_label(name)
            other_label = other.get_label(name)
            
            if self_label and other_label:
                # If variable exists in both paths, combine labels
                combined.update_label(name, self_label.combine(other_label))
            elif self_label:
                # If variable only exists in this path
                combined.update_label(name, deepcopy(self_label))
            else:
                # If variable only exists in other path
                combined.update_label(name, deepcopy(other_label))
        
        return combined