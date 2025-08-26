import os
import hashlib
from datetime import datetime

# === Directories & Paths (Windows) ===
SRC_DIR = r"C:\Users\deskt\Desktop\Project_SECQ_CLI\SECQ_CLI\SECQ_CLI\src"
OUTPUT_DIR = r"C:\Users\deskt\Desktop\Project_SECQ_CLI\SECQ_CLI\SECQ_CLI"
# Specific JS file to include (as requested)
BRIDGE_JS_PATH = r"C:\Users\deskt\Desktop\Project_SECQ_CLI\SECQ_CLI\SECQ_CLI\bridge\sss-bridge.js"

def calculate_hash(content: str) -> str:
    """Compute SHA256 hash of given text content."""
    return hashlib.sha256(content.encode('utf-8')).hexdigest()

def scan_python_files(directory: str):
    """Recursively find all .py files in the specified directory."""
    py_files = []
    if not os.path.exists(directory):
        print(f"[ERROR] Directory not found: {directory}")
        return py_files

    for root, _, files in os.walk(directory):
        for file in files:
            if file.endswith(".py"):
                py_files.append(os.path.join(root, file))
    return py_files

def include_file(file_path: str, collected_content: list, timestamp: str) -> int:
    """
    Read a single text file and append a standardized section to collected_content.
    Returns the character count of the file content that was added.
    """
    try:
        with open(file_path, 'r', encoding='utf-8') as f:
            content = f.read()
    except Exception as e:
        print(f"[WARNING] Could not read {file_path}: {e}")
        return 0

    file_hash = calculate_hash(content)
    header_rule = "#" * 120
    collected_content.append(
        f"\n{header_rule}\n# FILE: {file_path}\n# HASH: {file_hash}\n# TIMESTAMP: {timestamp}\n{header_rule}\n"
    )
    collected_content.append(content)
    collected_content.append(f"\n{header_rule}\n# END OF FILE: {file_path}\n{header_rule}\n")
    return len(content)

def main():
    python_files = scan_python_files(SRC_DIR)
    collected_content = []
    total_chars = 0
    total_files = 0
    timestamp = datetime.now().strftime("%Y-%m-%d_%H-%M-%S")

    # Ensure output directory exists
    if not os.path.exists(OUTPUT_DIR):
        os.makedirs(OUTPUT_DIR)
        print(f"[INFO] Created output directory: {OUTPUT_DIR}")

    output_file = os.path.join(OUTPUT_DIR, f"all_python_files_{timestamp}.txt")

    if not python_files:
        print("[INFO] No Python files found in the specified directory.")

    # Document header
    collected_content.append(
        f"{'=' * 120}\n"
        f"PYTHON CODE COLLECTION (+ sss-bridge.js)\n"
        f"Timestamp: {timestamp}\n"
        f"{'=' * 120}\n"
    )

    # Include all Python files
    for file_path in python_files:
        added = include_file(file_path, collected_content, timestamp)
        if added > 0:
            total_chars += added
            total_files += 1

    # Include the specific JS file (if present)
    if BRIDGE_JS_PATH and os.path.exists(BRIDGE_JS_PATH):
        added = include_file(BRIDGE_JS_PATH, collected_content, timestamp)
        if added > 0:
            total_chars += added
            total_files += 1
            print(f"[INFO] Included JS file: {BRIDGE_JS_PATH}")
        else:
            print(f"[WARNING] JS file found but could not be added: {BRIDGE_JS_PATH}")
    else:
        print(f"[WARNING] JS file not found: {BRIDGE_JS_PATH}")

    # Final summary section
    collected_content.append(
        f"\n{'=' * 120}\n"
        f"SUMMARY\n"
        f"Total Files: {total_files}\n"
        f"Total Characters: {total_chars}\n"
        f"Timestamp: {timestamp}\n"
        f"{'=' * 120}\n"
    )

    # Write to file
    try:
        with open(output_file, 'w', encoding='utf-8') as out_file:
            out_file.write("\n".join(collected_content))
        print(f"[INFO] Source contents saved to: {output_file}")
        print(f"[INFO] Total Characters: {total_chars}")
    except Exception as e:
        print(f"[ERROR] Could not write to output file: {e}")

if __name__ == "__main__":
    main()
