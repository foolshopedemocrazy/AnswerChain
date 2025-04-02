import os
import sys

SRC_DIR = r"C:\Users\deskt\Desktop\Project_SECQ_CLI\SECQ_CLI\SECQ_CLI\src"
OUTPUT_DIR = r"C:\Users\deskt\Desktop\Project_SECQ_CLI\SECQ_CLI\SECQ_CLI"
OUTPUT_FILE = os.path.join(OUTPUT_DIR, "all_python_code.txt")

def scan_python_files(directory):
    py_files = []
    for root, _, files in os.walk(directory):
        for file in files:
            if file.endswith(".py"):
                py_files.append(os.path.join(root, file))
    return py_files

def extract_filenames(file_paths):
    return sorted({os.path.basename(p) for p in file_paths})

def format_enforcement_block(filenames):
    file_list = "\n".join(filenames)
    return f'''"""
MANDATORY FILE LIST:
{file_list}

Before making any code updates, you are strictly required to confirm that all required files are present in the updated implementation. This verification is mandatory and must not be skipped under any circumstances.
"""
'''

def main():
    python_files = scan_python_files(SRC_DIR)
    file_names = extract_filenames(python_files)

    if not file_names:
        print("No Python files found. Aborting.")
        sys.exit(1)

    collected_code = []
    for file_path in python_files:
        try:
            with open(file_path, 'r', encoding='utf-8') as f:
                collected_code.append(f.read().rstrip())
        except Exception as e:
            print(f"Warning: Could not read {file_path} ({e})")

    enforcement_block = format_enforcement_block(file_names)

    with open(OUTPUT_FILE, 'w', encoding='utf-8') as out_file:
        out_file.write("\n\n\n\n\n".join(collected_code))
        out_file.write("\n\n\n\n\n")
        out_file.write(enforcement_block)

    print(f"\n✅ Output written to: {OUTPUT_FILE} (with dynamic mandatory file list)")

if __name__ == "__main__":
    main()
