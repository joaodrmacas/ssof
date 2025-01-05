from typing import List, Dict, Set, Optional
from copy import deepcopy
from astexport import export
from dataclasses import dataclass
from typing import List, Dict, Set, Optional, Tuple
import ast
import json

class Pattern:
    """
    Represents a security vulnerability pattern with its sources, sanitizers, and sinks.
    """
    def __init__(self, name: str, sources: List[str], sanitizers: List[str], sinks: List[str]):
        """
        Initialize a Pattern object.
        
        Args:
            name: Name of the vulnerability
            sources: List of source function/variable names
            sanitizers: List of sanitizer function names
            sinks: List of sink function/variable names
        """
        self.name = name
        self.sources = set(sources)
        self.sanitizers = set(sanitizers)
        self.sinks = set(sinks)
    
    def get_name(self) -> str:
        """Return the vulnerability pattern name."""
        return self.name
    
    def get_sources(self) -> Set[str]:
        """Return the set of sources."""
        return self.sources
    
    def get_sanitizers(self) -> Set[str]:
        """Return the set of sanitizers."""
        return self.sanitizers
    
    def get_sinks(self) -> Set[str]:
        """Return the set of sinks."""
        return self.sinks
    
    def is_source(self, name: str) -> bool:
        """Check if a name is a source in this pattern."""
        return name in self.sources
    
    def is_sanitizer(self, name: str) -> bool:
        """Check if a name is a sanitizer in this pattern."""
        return name in self.sanitizers
    
    def is_sink(self, name: str) -> bool:
        """Check if a name is a sink in this pattern."""
        return name in self.sinks

class Label:
    """
    Represents the integrity of information in terms of its sources and applied sanitizers.
    """
    def __init__(self):
        """Initialize an empty Label."""
        # Dictionary mapping source names to sets of sanitizers applied to that source
        self.source_sanitizers: Dict[str, Set[str]] = {}
    
    def add_source(self, source: str):
        """Add a new source to the label if not already present."""
        if source not in self.source_sanitizers:
            self.source_sanitizers[source] = set()
    
    def add_sanitizer(self, sanitizer: str):
        """Add a sanitizer to all sources in the label."""
        for source in self.source_sanitizers:
            self.source_sanitizers[source].add(sanitizer)
    
    def get_sources(self) -> Set[str]:
        """Return all sources in the label."""
        return set(self.source_sanitizers.keys())
    
    def get_sanitizers_for_source(self, source: str) -> Set[str]:
        """Return sanitizers applied to a specific source."""
        return self.source_sanitizers.get(source, set())
    
    def get_all_sanitizers(self) -> Set[str]:
        """Return all sanitizers used in this label."""
        all_sanitizers = set()
        for sanitizers in self.source_sanitizers.values():
            all_sanitizers.update(sanitizers)
        return all_sanitizers
    
    def combine(self, other: 'Label') -> 'Label':
        """
        Combine this label with another label, creating a new independent label.
        """
        new_label = Label()
        # Copy all sources and their sanitizers from this label
        for source, sanitizers in self.source_sanitizers.items():
            new_label.source_sanitizers[source] = sanitizers.copy()
        
        # Add all sources and sanitizers from the other label
        for source, sanitizers in other.source_sanitizers.items():
            if source not in new_label.source_sanitizers:
                new_label.source_sanitizers[source] = sanitizers.copy()
            else:
                # For shared sources, take the intersection of sanitizers
                new_label.source_sanitizers[source] &= sanitizers
        
        return new_label

class MultiLabel:
    """
    Manages multiple labels for different vulnerability patterns.
    """
    def __init__(self, patterns: List[Pattern]):
        """
        Initialize MultiLabel with a list of patterns.
        
        Args:
            patterns: List of Pattern objects to track
        """
        self.patterns = {pattern.get_name(): pattern for pattern in patterns}
        self.labels = {pattern.get_name(): Label() for pattern in patterns}
    
    def add_source(self, source: str):
        """
        Add a source to relevant pattern labels.
        Only adds to patterns where the source is valid.
        """
        for pattern_name, pattern in self.patterns.items():
            if pattern.is_source(source):
                self.labels[pattern_name].add_source(source)
    
    def add_sanitizer(self, sanitizer: str):
        """
        Add a sanitizer to relevant pattern labels.
        Only adds to patterns where the sanitizer is valid.
        """
        for pattern_name, pattern in self.patterns.items():
            if pattern.is_sanitizer(sanitizer):
                self.labels[pattern_name].add_sanitizer(sanitizer)
    
    def get_label_for_pattern(self, pattern_name: str) -> Label:
        """Get the Label object for a specific pattern."""
        return self.labels.get(pattern_name)
    
    def combine(self, other: 'MultiLabel') -> 'MultiLabel':
        """
        Combine this MultiLabel with another MultiLabel.
        """
        # Create new MultiLabel with same patterns
        new_multilabel = MultiLabel(list(self.patterns.values()))
        
        # Combine labels for each pattern
        for pattern_name in self.patterns:
            new_multilabel.labels[pattern_name] = self.labels[pattern_name].combine(
                other.labels[pattern_name]
            )
        
        return new_multilabel

#LAB 2

class Policy:
    """
    Represents an information flow policy that uses patterns to recognize illegal flows.
    """
    def __init__(self, patterns: List[Pattern]):
        """
        Initialize a Policy with vulnerability patterns.
        
        Args:
            patterns: List of Pattern objects to be considered
        """
        self.patterns = {pattern.get_name(): pattern for pattern in patterns}
    
    def get_vulnerability_names(self) -> Set[str]:
        """Return all vulnerability pattern names being considered."""
        return set(self.patterns.keys())
    
    def get_vulnerabilities_for_source(self, name: str) -> Set[str]:
        """
        Return vulnerability names that have the given name as a source.
        
        Args:
            name: Name to check as a source
        Returns:
            Set of vulnerability pattern names
        """
        return {
            pattern_name
            for pattern_name, pattern in self.patterns.items()
            if pattern.is_source(name)
        }
    
    def get_vulnerabilities_for_sanitizer(self, name: str) -> Set[str]:
        """
        Return vulnerability names that have the given name as a sanitizer.
        
        Args:
            name: Name to check as a sanitizer
        Returns:
            Set of vulnerability pattern names
        """
        return {
            pattern_name
            for pattern_name, pattern in self.patterns.items()
            if pattern.is_sanitizer(name)
        }
    
    def get_vulnerabilities_for_sink(self, name: str) -> Set[str]:
        """
        Return vulnerability names that have the given name as a sink.
        
        Args:
            name: Name to check as a sink
        Returns:
            Set of vulnerability pattern names
        """
        return {
            pattern_name
            for pattern_name, pattern in self.patterns.items()
            if pattern.is_sink(name)
        }
    
    def check_illegal_flows(self, name: str, multi_label: MultiLabel) -> MultiLabel:
        """
        Determine which flows to the given name are illegal based on the multilabel.
        
        Args:
            name: Name to check as potential sink
            multi_label: MultiLabel describing the information flowing to the name
        Returns:
            MultiLabel containing only the illegal flows (patterns where name is a sink)
        """
        # Create new MultiLabel with same patterns
        illegal_flows = MultiLabel(list(self.patterns.values()))
        
        # Check each pattern where name is a sink
        for pattern_name in self.get_vulnerabilities_for_sink(name):
            pattern = self.patterns[pattern_name]
            label = multi_label.get_label_for_pattern(pattern_name)
            
            # If label has sources and not all required sanitizers, it's an illegal flow
            if label and label.get_sources():
                pattern_sanitizers = pattern.get_sanitizers()
                for source in label.get_sources():
                    source_sanitizers = label.get_sanitizers_for_source(source)
                    if not pattern_sanitizers.issubset(source_sanitizers):
                        # Copy the label to the illegal flows
                        illegal_flows.labels[pattern_name] = deepcopy(label)
                        break
        
        return illegal_flows

class MultiLabelling:
    """
    Represents a mapping from variable names to multilabels.
    """
    def __init__(self, patterns: List[Pattern]):
        """
        Initialize a MultiLabelling object.
        
        Args:
            patterns: List of Pattern objects for creating empty multilabels
        """
        self.patterns = patterns
        self.labelling: Dict[str, MultiLabel] = {}
    
    def get_label(self, name: str) -> Optional[MultiLabel]:
        """
        Get the multilabel assigned to a name.
        
        Args:
            name: Variable name to look up
        Returns:
            MultiLabel if name is mapped, None otherwise
        """
        return self.labelling.get(name)
    
    def update_label(self, name: str, multi_label: MultiLabel):
        """
        Update or set the multilabel for a name.
        
        Args:
            name: Variable name to update
            multi_label: New MultiLabel to assign
        """
        self.labelling[name] = multi_label

class Vulnerabilities:
    """
    Collects and organizes discovered illegal flows during program analysis.
    """
    def __init__(self):
        """Initialize an empty Vulnerabilities collector."""
        # Dictionary mapping vulnerability names to lists of illegal flow info
        self.illegal_flows: Dict[str, List[Dict]] = {}
    
    def add_illegal_flows(self, name: str, multi_label: MultiLabel):
        """
        Record illegal flows detected for a name.
        
        Args:
            name: Name that is the sink of the illegal flows
            multi_label: MultiLabel containing only the illegal flows to this sink
        """
        for pattern_name, label in multi_label.labels.items():
            if label.get_sources():  # Only process if there are sources
                if pattern_name not in self.illegal_flows:
                    self.illegal_flows[pattern_name] = []
                
                # Record the flow information
                flow_info = {
                    'sink': name,
                    'sources': list(label.get_sources()),
                    'applied_sanitizers': {
                        source: list(label.get_sanitizers_for_source(source))
                        for source in label.get_sources()
                    }
                }
                self.illegal_flows[pattern_name].append(flow_info)
    
    def get_report(self) -> Dict[str, List[Dict]]:
        """
        Get a report of all recorded illegal flows.
        
        Returns:
            Dictionary mapping vulnerability names to lists of flow information
        """
        return deepcopy(self.illegal_flows)

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