from typing import List, Dict, Set, Optional, Any
import copy


class Pattern:
    """
    Represents a security vulnerability pattern with its sources, sanitizers, and sinks.
    """
    def __init__(self, name: str, source_names: List[str], sanitizer_names: List[str], sink_names: List[str], implicit: bool):
        """
        Initialize a Pattern object.
        
        Args:
            name: Name of the vulnerability
            sources: List of source function/variable names
            sanitizers: List of sanitizer function names
            sinks: List of sink function/variable names
        """
        self.name = name
        self.source_names = set(source_names)
        self.sanitizer_names = set(sanitizer_names)
        self.sink_names = set(sink_names)
        self.implicit = implicit
    
    def get_name(self) -> str:
        """Return the vulnerability pattern name."""
        return self.name
    
    def get_source_names(self) -> Set[str]:
        """Return the set of sources."""
        return self.source_names
    
    def get_sanitizers(self) -> Set[str]:
        """Return the set of sanitizers."""
        return self.sanitizer_names
    
    def get_sinks(self) -> Set[str]:
        """Return the set of sinks."""
        return self.sink_names
    
    def is_source(self, name: str) -> bool:
        """Check if a name is a source in this pattern."""
        return name in self.source_names
    
    def is_sanitizer(self, name: str) -> bool:
        """Check if a name is a sanitizer in this pattern."""
        return name in self.sanitizer_names
    
    def is_sink(self, name: str) -> bool:
        """Check if a name is a sink in this pattern."""
        return name in self.sink_names

class Label:
    """
    Represents the integrity of information in terms of its sources and applied sanitizers.
    """
    def __init__(self):
        """Initialize an empty Label."""
        # Dictionary mapping source names to sets of sanitizers applied to that source
        self.source_sanitizers: Dict[str, List[List[List[Any]]]] = {}
        self.source_lines: Dict[str, Set[int]] = {}

    def is_tainted(self):
        return not self.source_sanitizers
    
    def add_source(self, source: str, line: int):
        """Add a new source to the label if not already present."""
        if source not in self.source_sanitizers:
            self.source_sanitizers[source] = [[]]

        if source not in self.source_lines.keys():
            self.source_lines[source] = set([line])
        else:
            self.source_lines[source].add(line)
    
    def add_sanitizer(self, source: str, sanitizer: str, line: int):
        """
        Add a sanitizer that intercepts the flow from a specific source.

        :param source: The source to which the sanitizer applies.
        :param sanitizer: The sanitizer to be added.
        """
        
        for flow in self.source_sanitizers[source]:
            flow.append([sanitizer, line])
    
    def get_sources(self) -> Dict[str, Set[int]]:
        """Return all sources in the label."""
        return self.source_lines
    
    def get_sanitizers_for_source(self, source: str) -> List[List[List[Any]]]:
        """Return sanitizers applied to a specific source."""
        return copy.deepcopy(self.source_sanitizers.get(source, list(list()) ))
    
    def combine(self, other: 'Label') -> 'Label':
        """
        Combine this label with another label, creating a new independent label.
        """
        def merge_empty_flows(flows):
            has_empty_flow = False
            i = 0
            while i < len(flows):
                if not flows[i] :
                    if has_empty_flow:
                        flows.pop(i)
                    has_empty_flow = True
                else:
                    i += 1

        new_label = Label()
        # Copy all sources and their sanitizers from this label
        for source, sanitizers in self.source_sanitizers.items():
            new_label.source_sanitizers[source] = copy.deepcopy(sanitizers)
            new_label.source_lines[source] = self.source_lines[source].copy()
        
        # Add all sources and sanitizers from the other label
        for source, sanitizers in other.source_sanitizers.items():
            if source not in new_label.source_sanitizers:
                new_label.source_sanitizers[source] = copy.deepcopy(sanitizers)
                new_label.source_lines[source] = other.source_lines[source].copy()
            else:
                new_label.source_sanitizers[source].extend(copy.deepcopy(sanitizers))
                new_label.source_lines[source].union(other.source_lines)
            merge_empty_flows(new_label.source_sanitizers[source])

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
    
    def add_source(self, source: str, line: int):
        """
        Add a source to relevant pattern labels.
        Only adds to patterns where the source is valid.
        """
        for pattern_name, pattern in self.patterns.items():
            if pattern.is_source(source):
                self.labels[pattern_name].add_source(source, line)

    def add_sanitizer(self, source: str, sanitizer: str, line: int):
        """
        Add a sanitizer to relevant pattern labels.
        Only adds to patterns where the source is valid.
        """
        for pattern_name, pattern in self.patterns.items():
            if pattern.is_source(source) and pattern.is_sanitizer(sanitizer):
                self.labels[pattern_name].add_sanitizer(source, sanitizer, line)
    
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
    def __init__(self):
        """
        Initialize a MultiLabelling object.        
        """
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
    
    def create_copy(self) -> 'MultiLabelling':
        """
        Create and return a deep copy of the current multilabelling.

        Returns:
            A new instance of MultiLabelling with all data deeply copied.
        """
        new_labelling = MultiLabelling()
        new_labelling.labelling = {
            name: copy.deepcopy(label) for name, label in self.labelling.items()
        }
        return new_labelling

    def combine(self, other: 'MultiLabelling') -> 'MultiLabelling':
        """
        Combine two multilabellings into a new one where labels reflect
        the possible outcomes of either multilabelling.

        Args:
            other: Another MultiLabelling instance to combine with.

        Returns:
            A new MultiLabelling instance representing the combination.
        """
        combined_labelling = MultiLabelling()

        # Combine labels for all variable names present in either of the labellings
        all_names = set(self.labelling.keys()) | set(other.labelling.keys())
        for name in all_names:
            label_self = self.get_label(name)
            label_other = other.get_label(name)

            if label_self and label_other:
                # If both exist, combine their MultiLabels
                combined_labelling.update_label(name, label_self.combine(label_other))
            elif label_self:
                # If only in self, copy it
                combined_labelling.update_label(name, copy.deepcopy(label_self))
            elif label_other:
                # If only in other, copy it
                combined_labelling.update_label(name, copy.deepcopy(label_other))

        return combined_labelling

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
            if label.get_sources().keys():  # Only process if there are sources
                if pattern_name not in self.illegal_flows:
                    self.illegal_flows[pattern_name] = []
                
                unsanitized_flag = False
                sanitized_flows = []
                for source in label.get_sources().keys():
                    unsanitized_flag = False
                    sanitized_flows = copy.deepcopy(label.get_sanitizers_for_source(source))

                    for flow in sanitized_flows:
                        if not flow:
                            unsanitized_flag = True
                            sanitized_flows.remove(flow)
                    
                    flow_info = {
                        'sink': [name, -1],
                        'source': [source, -1],
                        'unsanitized_flows': "yes" if unsanitized_flag else "no",
                        'sanitized_flows': sanitized_flows,
                        'implicit': "yes" if False else "no" # TODO FIXME: False needs to be the actual logic to have the implicit
                    }
                    self.illegal_flows[pattern_name].append(flow_info)
    
    def get_report(self) -> Dict[str, List[Dict]]:
        """
        Get a report of all recorded illegal flows.
        
        Returns:
            Dictionary mapping vulnerability names to lists of flow information
        """

        return copy.deepcopy(self.illegal_flows)
