import sys
import os
import json
from pprint import pprint
from src.analyzer import ASTAnalyzer
from src.parser import parse_javascript
from src.patterns import load_patterns
from src.output import json_to_file
from src.classes import Policy, MultiLabelling, Vulnerabilities

def main():
    # Check if correct number of arguments
    if len(sys.argv) != 3:
        print(sys.argv)
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
#        with open(output_file.replace("output", "ast")) as f:
#           json.dump(ast, f)
        
        # Load patterns
        patterns = load_patterns(pattern_file)

        policy = Policy(patterns)
        multilabelling = MultiLabelling()
        vulnerabilities = Vulnerabilities()

        analyzer = ASTAnalyzer(ast, policy, multilabelling, vulnerabilities)
        output = analyzer.trace_execution_paths()

        # Write output to file
        print(f"Writing output to '{output_file}'")
        json_to_file(output_file,output)

        
    except Exception as e:
        raise e
        # print(f"Error processing files: {str(e)}")
        # exit(1)

if __name__ == "__main__":
    main()