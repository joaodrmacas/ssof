from typing import List, Dict, Set, Optional
from copy import deepcopy

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