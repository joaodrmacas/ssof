import sys
import os
from src.parser import parse_javascript
from src.patterns import load_patterns
from src.output import create_output
from src.analyzer import analyze_ast
from src.classes import FlowGraphBuilder

def main():
    # Check if correct number of arguments
    if len(sys.argv) != 3:
        print("Usage: python js_analyser.py <path_to_slice>/<slice>.js <path_to_pattern>/<patterns>.json")
        sys.exit(1)

    # Get file paths
    js_file = sys.argv[1]
    pattern_file = sys.argv[2]

    # Validate files exist
    if not os.path.exists(js_file):
        print(f"Error: JavaScript file '{js_file}' not found")
        sys.exit(1)
    if not os.path.exists(pattern_file):
        print(f"Error: Pattern file '{pattern_file}' not found")
        sys.exit(1)

    # Create output directory if it doesn't exist
    output_dir = "output"
    os.makedirs(output_dir, exist_ok=True)

    # Generate output filename
    js_filename = os.path.basename(js_file)
    output_file = os.path.join(output_dir, f"{os.path.splitext(js_filename)[0]}.output.json")

    try:
        # Parse JavaScript file
        ast = parse_javascript(js_file)
        
        # Load patterns
        patterns = load_patterns(pattern_file)

        sources = {source for pattern in patterns for source in pattern['sources']}
        sinks = {sink for pattern in patterns for sink in pattern['sinks']}


        flowGraph = FlowGraphBuilder(sources,sinks,patterns).build(ast)
        print(flowGraph)

        exit(0)
        
        vulnerabilities = analyze_ast(ast, patterns)
        
        # Create output (placeholder for now)
        create_output(output_file, vulnerabilities)
        
    except Exception as e:
        print(f"Error processing files: {str(e)}")
        raise e
        sys.exit(1)

if __name__ == "__main__":
    main()