import sys
import os
from pprint import pprint
from src.analyzer import ASTAnalyzer
from src.parser import parse_javascript
from src.patterns import load_patterns
from src.output import create_output

# def traverse_ast(ast, depth=0):
#     """
#     Recursively traverses an AST and prints the node type and starting line number.
#     :param ast: AST node (dictionary).
#     :param depth: Current depth in the tree (used for indentation).
#     """
#     if isinstance(ast, dict):
#         # Print node type and line number
#         node_type = ast.get('type', 'Unknown')
#         loc = ast.get('loc', {}).get('start', {}).get('line', 'N/A')
#         print(f"{' ' * depth}- {node_type} (Line: {loc})")

#         # Recursively traverse children
#         for key, value in ast.items():
#             traverse_ast(value, depth + 2)

#     elif isinstance(ast, list):
#         # Traverse each element in the list
#         for item in ast:
#             traverse_ast(item, depth)

#     # Base case: primitive value (ignore)


# MAX_LOOP_ITERATIONS = 5

# def trace_paths(ast, current_path=None, paths=None):
#     """
#     Traverses the AST to collect all possible execution paths.
#     :param ast: AST node (dictionary).
#     :param current_path: Current path being constructed.
#     :param paths: List of all paths (results).
#     :return: List of execution paths.
#     """
#     if current_path is None:
#         current_path = []
#     if paths is None:
#         paths = []

#     if isinstance(ast, dict):
#         node_type = ast.get('type', 'Unknown')
#         loc = ast.get('loc', {}).get('start', {}).get('line', 'N/A')
#         current_path.append(f"{node_type} (Line: {loc})")

#         # Handle control flow constructs
#         if node_type == 'IfStatement':
#             # Trace true and false branches
#             trace_paths(ast['consequent'], current_path[:], paths)
#             if 'alternate' in ast:
#                 trace_paths(ast['alternate'], current_path[:], paths)

#         elif node_type == 'WhileStatement':
#             # Simulate loop iterations
#             for _ in range(MAX_LOOP_ITERATIONS):
#                 trace_paths(ast['body'], current_path[:], paths)

#         else:
#             # Traverse children
#             for key, value in ast.items():
#                 trace_paths(value, current_path, paths)

#     elif isinstance(ast, list):
#         for item in ast:
#             trace_paths(item, current_path, paths)

#     # Base case: complete path
#     if not isinstance(ast, (dict, list)):
#         paths.append(current_path)

#     return paths



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

        analyzer = ASTAnalyzer(ast)
        analyzer.trace_execution_paths()

        analyzer.traverse_ast()

        
        # Create output (placeholder for now)
        create_output(output_file, "")
        
    except Exception as e:
        print(f"Error processing files: {str(e)}")
        exit(1)
        raise e

if __name__ == "__main__":
    main()