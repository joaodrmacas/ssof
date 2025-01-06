from typing import List, Dict, Set, Optional
from dataclasses import dataclass
from typing import List, Dict, Set, Optional
import copy
import json
import esprima

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
    
    def add_sanitizer(self, source, sanitizer):
        """
        Add a sanitizer that intercepts the flow from a specific source.

        :param source: The source to which the sanitizer applies.
        :param sanitizer: The sanitizer to be added.
        """
        if source in self.source_sanitizers.keys():
            self.source_sanitizers[source].update([sanitizer])
    
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

    def add_sanitizer(self, source: str, sanitizer: str):
        """
        Add a sanitizer to relevant pattern labels.
        Only adds to patterns where the source is valid.
        """
        for pattern_name, pattern in self.patterns.items():
            if pattern.is_source(source) and pattern.is_sanitizer(sanitizer):
                self.labels[pattern_name].add_sanitizer(source, sanitizer)
    
    def get_label_for_pattern(self, pattern_name: str):
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
        illegal_flows = MultiLabel([])
        
        for pattern_name in self.get_vulnerabilities_for_sink(name):
            illegal_flows.patterns[pattern_name] = self.patterns[pattern_name] 
            
            label = multi_label.get_label_for_pattern(pattern_name)
            if label != None:
                illegal_flows.labels[pattern_name] = copy.deepcopy(label)
        
        return illegal_flows

class MultiLabelling:
    """
    Represents a mapping from variable names to multilabels.
    """
    def __init__(self, patterns: List[Pattern] = []):
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

class Vulnerabilities: #TODO: guardar os unsanitized como os sanitized
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
                applied_sanitizers = {
                    source: list(label.get_sanitizers_for_source(source))
                    for source in label.get_sources()
                }
                flow_info = {
                    'sink': name,
                    'sources': list(label.get_sources()),
                    'sanitized_flows': [],

                }
                self.illegal_flows[pattern_name].append(flow_info)
    
    def get_report(self) -> Dict[str, List[Dict]]:
        """
        Get a report of all recorded illegal flows.
        
        Returns:
            Dictionary mapping vulnerability names to lists of flow information
        """
        return copy.deepcopy(self.illegal_flows)

@dataclass
class Trace:
    """Represents a single execution trace through the program."""
    steps: List[str]
    
    def __str__(self) -> str:
        return " -> ".join(self.steps)

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
            new_labelling.labelling[name] = copy.deepcopy(multi_label)
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
                combined.update_label(name, copy.deepcopy(self_label))
            elif other_label:
                # If variable only exists in other path
                combined.update_label(name, copy.deepcopy(other_label))
        
        return combined


def extract_ast(file_path, output_path):
    """
    Extracts the AST of a JavaScript file and outputs it as JSON.
    :param file_path: Path to the JavaScript file.
    :param output_path: Path to save the JSON representation of the AST.
    """
    with open(file_path, 'r') as js_file:
        code = js_file.read()

    # Parse the JavaScript code into an AST
    ast = esprima.parseScript(code, loc=True).toDict()

    # Save the AST as JSON
    with open(output_path, 'w') as json_file:
        json.dump(ast, json_file, indent=4)
    print(f"AST saved to {output_path}")


def traverse_ast(ast, depth=0):
    """
    Recursively traverses an AST and prints the node type and starting line number.
    :param ast: AST node (dictionary).
    :param depth: Current depth in the tree (used for indentation).
    """
    if isinstance(ast, dict):
        # Print node type and line number
        node_type = ast.get('type')
        if not node_type:
            return
        loc = ast.get('loc', {}).get('start', {}).get('line', 'N/A')
        print(f"{' ' * depth}- {node_type} (Line: {loc})")

        # Recursively traverse children
        for key, value in ast.items():
            traverse_ast(value, depth + 2)

    elif isinstance(ast, list):
        # Traverse each element in the list
        for item in ast:
            traverse_ast(item, depth)

    # Base case: primitive value (ignore)

extract_ast("../slices/1-basic-flow/1a-basic-flow.js", "../slices/1-basic-flow/1a-basic-flow.ast.js")
with open("../slices/1-basic-flow/1a-basic-flow.ast.js", "r") as file:
    ast = json.load(file)
    traverse_ast(ast)
