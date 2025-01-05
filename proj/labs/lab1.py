from typing import List, Dict, Set
from copy import deepcopy

#TODO: implement implicit leaks

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