import os
import subprocess
import sys
import json


def run_tests(max_slice):
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

        if slice_number > max_slice:
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
                print(f"Running: {' '.join(command)}")

                try:
                    subprocess.run(command, check=True,
                                   stdout=subprocess.DEVNULL)
                except subprocess.CalledProcessError as e:
                    print(f"Error running {js_file}: {e}")
                    continue

                # Compare output
                try:
                    with open(expected_output_file, "r") as expected, open(actual_output_file, "r") as actual:
                        expected_data = json.load(expected)
                        actual_data = json.load(actual)

                        if expected_data == actual_data:
                            print(f"Test passed for {js_file}\n")
                        else:
                            print(
                                f"Test failed for {js_file}: Output mismatch")
                            print("\nExpected:")
                            print(json.dumps(expected_data, indent=4))
                            print("\nActual:")
                            print(json.dumps(actual_data, indent=4))
                except FileNotFoundError:
                    print(f"Actual output file not found for {js_file}")
                except json.JSONDecodeError as e:
                    print(f"Error decoding JSON for {js_file}: {e}")


if __name__ == "__main__":
    if len(sys.argv) != 2:
        print("Usage: python3 run_tests.py <max_slice_number>")
        sys.exit(1)

    try:
        max_slice = int(sys.argv[1])
        run_tests(max_slice)
    except ValueError:
        print("Invalid slice number. Please enter an integer.")
        sys.exit(1)
