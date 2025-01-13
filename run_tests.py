import os
import subprocess
import sys
import json

class bcolors:
    # https://stackoverflow.com/questions/4842424/list-of-ansi-color-escape-sequences
    PURPLE =    '\033[95m'
    GREEN =     '\033[92m'
    YELLOW =    '\033[93m'
    RED =       '\033[91m'
    ENDC =      '\033[0m'
    BOLD =      '\033[1m'
    UNDERLINE = '\033[4m'

def run_tests(max_slice=-1):
    base_dir = os.path.dirname(os.path.abspath(__file__))
    slices_dir = os.path.join(base_dir, "slices")
    output_dir = os.path.join(base_dir, "output")

    for slice_folder in sorted(os.listdir(slices_dir)):
        slice_path = os.path.join(slices_dir, slice_folder)
        if not os.path.isdir(slice_path):
            continue

        try:
            slice_number = int(slice_folder.split('-')[0])
        except ValueError:
            print(f"Skipping {slice_folder}: Invalid folder name format.")
            continue

        if max_slice > 0 and slice_number > max_slice:
            break

        for filename in os.listdir(slice_path):
            if filename.endswith(".js"):
                js_file = os.path.join(slice_path, filename)
                base_name = os.path.splitext(filename)[0]
                patterns_file = os.path.join(
                    slice_path, f"{base_name}.patterns.json")
                expected_output_file = os.path.join(
                    slice_path, f"{base_name}.output.json")
                actual_output_file = os.path.join(
                    output_dir, f"{base_name}.actual.json")

                if not os.path.exists(patterns_file):
                    print(f"Skipping {js_file}: Patterns file not found.")
                    continue

                if not os.path.exists(expected_output_file):
                    print(
                        f"Skipping {js_file}: Expected output file not found.")
                    continue

                # Run the program
                command = [
                    "python3", "js_analyzer.py", js_file, patterns_file
                ]
                print("\n\n" + "#" * 80)
                print(f"{bcolors.PURPLE}[NEW TEST]{bcolors.ENDC} Running: {' '.join(command)}")

                try:
                    subprocess.run(command, check=True,
                                   stdout=subprocess.DEVNULL)
                except subprocess.CalledProcessError as e:
                    print(f"Error running {js_file}: {e}")
                    continue

                # Compare output
                try:
                    command = ["python3", "validate.py", "-o", actual_output_file, "-t", expected_output_file]
                    subprocess.run(command, check=True)
                except FileNotFoundError:
                    print(f"Actual output file not found for {js_file}")
                except json.JSONDecodeError as e:
                    print(f"Error decoding JSON for {js_file}: {e}")

def run_common_tests(test_name):
    base_dir = os.path.dirname(os.path.abspath(__file__))
    test_dir = os.path.join(base_dir, "common-tests/" + test_name)
    output_dir = os.path.join(base_dir, "output")

    for filename in os.listdir(test_dir):
        if filename.endswith(".js"):
            js_file = os.path.join(test_dir, filename)
            base_name = os.path.splitext(filename)[0]
            patterns_file = os.path.join(
                test_dir, f"{base_name}.patterns.json")
            expected_output_file = os.path.join(
                test_dir, f"{base_name}.output.json")
            actual_output_file = os.path.join(
                output_dir, f"{base_name}.actual.json")

            if not os.path.exists(patterns_file):
                print(f"Skipping {js_file}: Patterns file not found.")
                continue

            if not os.path.exists(expected_output_file):
                print(
                    f"Skipping {js_file}: Expected output file not found.")
                continue

            # Run the program
            command = [
                "python3", "js_analyzer.py", js_file, patterns_file
            ]
            print("\n\n" + "#" * 80)
            print(f"{bcolors.PURPLE}[NEW TEST]{bcolors.ENDC} Running: {' '.join(command)}")

            try:
                subprocess.run(command, check=True,
                                stdout=subprocess.DEVNULL)
            except subprocess.CalledProcessError as e:
                print(f"Error running {js_file}: {e}")
                continue

            # Compare output
            try:
                command = ["python3", "validate.py", "-o", actual_output_file, "-t", expected_output_file]
                subprocess.run(command, check=True)
            except FileNotFoundError:
                print(f"Actual output file not found for {js_file}")
            except json.JSONDecodeError as e:
                print(f"Error decoding JSON for {js_file}: {e}")

if __name__ == "__main__":
    if len(sys.argv) == 1:
        max_slice = -1
    elif len(sys.argv) == 2:
        max_slice = int(sys.argv[1])
    elif len(sys.argv) != 4 or sys.argv[1] != "-cmn":
        print("Usage: python3 run_tests.py <max_slice_number>")
        print("Usage: python3 run_tests.py -cmn <group> <test_number")
        sys.exit(1)
    
    try:
        if len(sys.argv) >= 2 and "-cmn" != sys.argv[2]:
            test_name = f"T{sys.argv[2]}-{sys.argv[3]}"
            run_common_tests(test_name)
        else:
            run_tests(max_slice)
    except ValueError:
        print("Invalid slice number. Please enter an integer.")
        sys.exit(1)
