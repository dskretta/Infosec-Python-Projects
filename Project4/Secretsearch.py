#Name: Krifon.py
#Author: DSkretta
#License: MIT
#Github: https://github.com/dskretta/Infosec-Python-Projects/blob/main/Project4/Secretsearch.py
#Description: This script is used to search for sensitive keywords in directories as well as list the size of them.

import os
import argparse
from tqdm import tqdm

GREEN = "\033[92m"
BLUE = "\033[94m"
RED = "\033[91m"
RESET = "\033[0m"


# list of default keywords that suggest sensitive files
SENSITIVE_KEYWORDS = [
    "username", "password", "passwd", "credentials", "creds", "secret",
    "web.config", "sitelist", "auth", "account", "login",
     "token", "apikey", "api",  "auth", 
]

# Load custom keywords from a file (override default)
def load_keywords(default_keywords, keyword_file):
    if keyword_file:
        if os.path.isfile(keyword_file):
            with open(keyword_file, "r") as f:
                return [line.strip().lower() for line in f if line.strip()]
        else:
            print(f"Keyword file not found: {keyword_file}")
            return default_keywords
    return default_keywords

# Utility: get the currect depth of directory
def get_depth(base, target):
    return os.path.relpath(target, base).count(os.sep)

# Scan filenames
def scan_filenames(base_dir, keywords, args):
    print(f"\n[FILENAME SCAN]")
    for root, dirs, files in os.walk(base_dir):
        if args.no_recursive:
            dirs.clear()
        elif args.depth_limit is not None:
            if get_depth(base_dir, root) >= args.depth_limit:
                dirs.clear()

        for name in files:
            lower_name = name.lower()
            for keyword in keywords:
                if keyword in lower_name:
                    tqdm.write(f"{GREEN}[MATCH]{RESET} {BLUE}{os.path.join(root, name)} {RESET}")
                    break


# Scan File contents
def scan_content(base_dir, keywords, args):
    print("\n[CONTENT SCAN]")

    # count the total files first
    file_paths = []
    for root, dirs, files in os.walk(base_dir):
        if args.no_recursive:
            dirs.clear()
        elif args.depth_limit is not None:
            if get_depth(base_dir, root) >= args.depth_limit:
                dirs.clear()

        for name in files:
            file_paths.append(os.path.join(root, name))

    # adding a progress bar, that counts the amount of matches
    matches = 0
    pbar = tqdm(file_paths, desc=f"{RED}Scanning files{RESET}", unit="file")
    for path in pbar:    
        try:
            with open(path, "r", errors="ignore") as f:
                for i, line in enumerate(f):
                    for keyword in keywords:
                        if keyword in line.lower():
                            matches+= 1
                            tqdm.write(f"{GREEN}[MATCH]{RESET} {BLUE}{path}{RESET} (line {i+1}): {GREEN}{line.strip()}{RESET}")
        except Exception:
            continue

        pbar.set_postfix(matches=matches)

# Calculate share size
def summarize_share_size(base_dir, args):
    print(f"\n{RED}[SIZE SCAN]{RESET}")
    total_bytes = 0
    file_count = 0

    for root, dirs, files in os.walk(base_dir):
        if args.no_recursive:
            dirs.clear()
        elif args.depth_limit is not None:
            if get_depth(base_dir, root) >= args.depth_limit:
                dirs.clear()

        for name in files:
            path = os.path.join(root, name)
            try:
                total_bytes += os.path.getsize(path)
                file_count += 1
            except Exception:
                continue

    print(f"{GREEN}Files found: {RED}{file_count}{RESET}")
    print(f"{GREEN}Total size: {RED}{total_bytes / (1024**3):.2f} GB{RESET}")

# Entry point
def main():
    parser = argparse.ArgumentParser(description="Looking for secrets: SMB/Local File Scanner")
    parser.add_argument("--path", required=True, help="Path to directory to scan")
    parser.add_argument("--scan-names", action="store_true", help="scan filenames for sensitive keywords")
    parser.add_argument("--scan-content", action="store_true", help="Scan file contents for sensitive keywords")
    parser.add_argument("--scan-size", action="store_true", help="Summarize size and count of all files")
    parser.add_argument("--keyword-file", help="File with custom keywords (one per line)")
    parser.add_argument("--no-recursive", action="store_true", help="Disable recursive scanning (only scan top level)")
    parser.add_argument("--depth-limit", type=int, help="Limit recursion depth (e.g., 2 = base directory + 2 subdirectory)")


    args = parser.parse_args()

    if not os.path.isdir(args.path):
        print("Invalid path. Please provide a valid directory.")
        return
    
    keywords = load_keywords(SENSITIVE_KEYWORDS, args.keyword_file)

    if args.scan_names:
        scan_filenames(args.path, keywords, args)
    if args.scan_content:
        scan_content(args.path, keywords, args)
    if args.scan_size:
        summarize_share_size(args.path, args)


    if not (args.scan_names or args.scan_content or args.scan_size):
        print("No scan type selected. Use one or more of: --scan-names, --scan-content, --scan-size")

if __name__ == "__main__":
    main()
