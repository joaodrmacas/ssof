import json
from src.classes import Pattern 

def load_patterns(file_path: str) -> list:
    """
    Load and validate vulnerability patterns from JSON file
    """
    try:
        with open(file_path, 'r') as f:
            patterns = json.load(f)
            
        # Basic validation of pattern structure
        patterns_to_create = []
        for pattern in patterns:
            if not all(key in pattern for key in ['vulnerability', 'sources', 'sanitizers', 'sinks', 'implicit']):
                raise ValueError("Invalid pattern structure")
            patterns_to_create.append(
                Pattern(
                    pattern['vulnerability'],
                    pattern['sources'],
                    pattern['sanitizers'],
                    pattern['sinks'],
                    True if pattern['implicit'] == 'yes' else False
                )
            )
                
        return patterns_to_create
    except Exception as e:
        raise Exception(f"Failed to load patterns - {str(e)}")