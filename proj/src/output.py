import json

def create_output(file_path, vulnerabilities):
    """
    Create JSON output file with vulnerability findings
    """
    try:
        with open(file_path, 'w') as f:
            json.dump(vulnerabilities, f, indent=4)
    except Exception as e:
        raise Exception(f"Failed to create output file: {str(e)}")