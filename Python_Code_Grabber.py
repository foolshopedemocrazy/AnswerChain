import os
import hashlib
from datetime import datetime

# === ROOT & OUTPUT (Windows) ===
ROOT = r"C:\Users\deskt\Desktop\Project_SECQ_CLI\SECQ_CLI"
OUTPUT_DIR = ROOT  # Save the combined file here

# === Directories to include ===
BRIDGE_DIR   = os.path.join(ROOT, "bridge")
EXAMPLES_DIR = os.path.join(ROOT, "examples")
SRC_DIR      = os.path.join(ROOT, "src")
TESTS_DIR    = os.path.join(ROOT, "tests")

# Exclude this subtree entirely
EXCLUDE_PREFIXES = [os.path.abspath(os.path.join(BRIDGE_DIR, "vendor")).lower()]

HEADER_RULE = "#" * 120
BLOCK_RULE  = "=" * 120


def sha256_bytes(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def is_excluded_path(path: str) -> bool:
    ap = os.path.abspath(path).lower()
    return any(ap.startswith(prefix) for prefix in EXCLUDE_PREFIXES)


def iter_files(base_dir: str):
    """
    Yield absolute file paths under base_dir, skipping any excluded subtrees.
    """
    if not os.path.exists(base_dir):
        print(f"[WARNING] Missing directory: {base_dir}")
        return

    base_dir_abs = os.path.abspath(base_dir)
    for root, dirnames, filenames in os.walk(base_dir_abs, topdown=True):
        # Prune excluded directories
        pruned = []
        for d in list(dirnames):
            full = os.path.abspath(os.path.join(root, d))
            if is_excluded_path(full):
                pruned.append(d)
        if pruned:
            for d in pruned:
                dirnames.remove(d)

        for name in filenames:
            fpath = os.path.abspath(os.path.join(root, name))
            if is_excluded_path(fpath):
                continue
            yield fpath


def decode_text_or_mark_binary(data: bytes):
    """
    Return (text:str|None, is_binary:bool).
    Heuristic: if NUL byte appears in the sample, treat as binary.
    Otherwise try several encodings; fall back to UTF-8 with replacement.
    """
    sample = data[:65536]
    if b"\x00" in sample:
        return None, True

    for enc in ("utf-8", "utf-16", "utf-16le", "utf-16be", "cp1252", "latin-1"):
        try:
            return data.decode(enc), False
        except Exception:
            pass
    # Last resort: replace errors
    return data.decode("utf-8", errors="replace"), False


def include_file_block(file_path: str, collected: list, timestamp: str) -> int:
    """
    Append a standardized block for file_path to 'collected'.
    Returns number of characters added from file content (0 if binary or unreadable).
    """
    try:
        with open(file_path, "rb") as f:
            raw = f.read()
    except Exception as e:
        collected.append(
            f"\n{HEADER_RULE}\n"
            f"# FILE: {file_path}\n# ERROR: Could not read file: {e}\n"
            f"{HEADER_RULE}\n"
        )
        return 0

    file_hash = sha256_bytes(raw)
    size = len(raw)
    try:
        mtime = datetime.fromtimestamp(os.path.getmtime(file_path)).isoformat()
    except Exception:
        mtime = "unknown"

    text, is_binary = decode_text_or_mark_binary(raw)

    collected.append(
        f"\n{HEADER_RULE}\n"
        f"# FILE: {file_path}\n"
        f"# SIZE: {size} bytes\n"
        f"# HASH: {file_hash}\n"
        f"# MODIFIED: {mtime}\n"
        f"# BINARY: {'yes' if is_binary else 'no'}\n"
        f"# SNAPSHOT_TIMESTAMP: {timestamp}\n"
        f"{HEADER_RULE}\n"
    )

    added_chars = 0
    if is_binary or text is None:
        collected.append("[BINARY FILE CONTENT OMITTED]\n")
    else:
        collected.append(text)
        collected.append("\n")
        added_chars = len(text)

    collected.append(f"{HEADER_RULE}\n# END OF FILE: {file_path}\n{HEADER_RULE}\n")
    return added_chars


def main():
    timestamp = datetime.now().strftime("%Y-%m-%d_%H-%M-%S")
    out_path = os.path.join(OUTPUT_DIR, f"source_dump_{timestamp}.txt")

    targets = [BRIDGE_DIR, EXAMPLES_DIR, SRC_DIR, TESTS_DIR]

    # Gather files (deduplicated + sorted for stable order)
    files_set = set()
    for d in targets:
        for f in iter_files(d):
            files_set.add(f)
    all_files = sorted(files_set)

    collected = []
    total_chars = 0
    total_files = 0
    total_binaries = 0

    # Document header
    collected.append(
        f"{BLOCK_RULE}\n"
        f"PROJECT SNAPSHOT\n"
        f"Root: {ROOT}\n"
        f"Timestamp: {timestamp}\n"
        f"Included directories:\n"
        f" - {BRIDGE_DIR}  (excluding {os.path.join(BRIDGE_DIR, 'vendor')})\n"
        f" - {EXAMPLES_DIR}\n"
        f" - {SRC_DIR}\n"
        f" - {TESTS_DIR}\n"
        f"{BLOCK_RULE}\n"
    )

    if not all_files:
        collected.append("[INFO] No files found in the specified directories.\n")

    # Include files
    for path in all_files:
        before_len = len(collected)
        added = include_file_block(path, collected, timestamp)
        total_files += 1
        total_chars += added
        # Simple binary count heuristic: if nothing added to content, it may be binary or unreadable
        if added == 0:
            total_binaries += 1

    # Summary
    collected.append(
        f"\n{BLOCK_RULE}\n"
        f"SUMMARY\n"
        f"Total Files Processed: {total_files}\n"
        f"Binary/Unreadable Files: {total_binaries}\n"
        f"Total Text Characters Collected: {total_chars}\n"
        f"Snapshot: {timestamp}\n"
        f"Output: {out_path}\n"
        f"{BLOCK_RULE}\n"
    )

    # Ensure output directory exists
    os.makedirs(OUTPUT_DIR, exist_ok=True)

    # Write out
    try:
        with open(out_path, "w", encoding="utf-8") as out:
            out.write("\n".join(collected))
        print(f"[OK] Snapshot written to: {out_path}")
    except Exception as e:
        print(f"[ERROR] Could not write output file: {e}")


if __name__ == "__main__":
    main()
