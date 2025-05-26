import os
import argparse

# list of default keywords that suggest sensitive files
SENSITIVE_KEYWORDS = [
    "username", "password", "passwd", "credentials", "creds", "secret",
    "web.config", "sitelist", "auth", "account", "login"
    "auth," "token", "apikey", "api", "login", "auth", 
]

# Load custom keywords from a file (override default)
def load_keywords(default_keywords, keyword_file):
    if keyword_file and os.path.isfile(keyword_file):
        with open(keyword_file, "r") as f:
            return [line.strip().lower() for line in f if line.strip()]
        return default_keywords

# Scan filenames
def scan_filenames(base_dir, keywords):
    print(f"\n[FILENAME SCAN]")
    for root, dirs, files in os.walk(base_dir):
        for name in files:
            lower_name = name.lower()
            for keyword in keywords:
                if keyword in lower_name:
                    print(f"[MATCH] {os.path.join(root, name)}")
                    break


# Scan File contents
def scan_contents(base_dir, keywords):
    print("\n[CONTENT SCAN]")
    for root, dirs, files in os.walk(base_dir):
        for name in files:
            path = os.path.join(root, name)
            try:
                with open(path, "r", errors="ignore") as f:
                    for i, line in enumerate(f):
                        for keyword in keywords:
                            if keyword in line.lower():
                                print(f"[MATCH] {path} (line {i+1}): {line.strip()}")
                                break
            except Exception:
                continue

# Calculate share size
def summarize_share_size(base_dir):
    print("\n[SIZE SCAN]")
    total_bytes = 0
    file_count = 0

    for root, dirs, files in os.walk(base_dir):
        for name in files:
            path = os.path.join(root, name)
            try:
                total_bytes += os.path.getsize(path)
                file_count += 1
            except Exception:
                continue

    print(f"Files found: {file_count}")
    print(f"Total size: {total_bytes / (1024**3):.2f} GB")

# Entry point
def main():
    parser = argparse.ArgumentParser(description="Pilfer for Passwords: SMB/Local File Scanner")

    parser.add_argument("--path", required=True, help="Path to directory to scan")

    parser.add_argument("--scan-names", action="store_true", help="scan filenames for sensitive keywords")
    parser.add_argument("--scan-content", action="store_true", help="Scan file contents for sensitive keywords")
    parser.add_argument("--scan-size", action="store_true", help="Summarize size and count of all files")

    parser.add_argument("--keyword-file", help="File with custom keywords (one per line)")


    args = parser.parse_args()

    if not os.path.isdir(args.path):
        print("Invalid path. Please provide a valid directory.")
        return
    
    keywords = load_keywords(SENSITIVE_KEYWORDS, args.keyword_file)

    if args.scan_names:
        scan_filenames(args.path, keywords)
    if args.scan_contents:
        scan_contents(args.path, keywords)
    if args.scan_size:
        summarize_share_size(args.path)


    if not (args.scan_name or args.scan_content or args.scan_size):
        print("No scan type selected. Use one or more of: --scan-names, --scan-content, --scan-size")

if __name__ == "__main__":
    main()
