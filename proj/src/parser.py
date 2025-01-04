import esprima

def parse_javascript(file_path):
    """
    Parse JavaScript file and return AST
    """
    try:
        with open(file_path, 'r') as f:
            content = f.read().strip()
        return esprima.parseScript(content, loc=True).toDict()
    except Exception as e:
        raise Exception(f"Failed to parse JavaScript file: {str(e)}")