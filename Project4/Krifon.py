import os

# list of keywords that suggest sensitive files
SENSITIVE_KEYWORDS = [
    "password", "passwd", "credentials", "creds", "secret",
    "web.config", "sitelist", "auth", "account", "login"
]

# main searching functionality
def find_sensitive_filenames(base_dir, keywords):
    print(f"Searching in: {base_dir}")
    for root, dirs, files in os.walk(base_dir):
        for name in files:
            lower_name = name.lower()
            for keyword in keywords:
                if keyword in lower_name:
                    full_path = os.path.join(root, name)
                    print(f"[!] Found potentially sensitive file: {full_path}")
                    break # Do not print the same file mutliple times


if __name__ == "__main__":
    target_dir = input("Enter path to directory: ").strip()
    if not os.path.isdir(target_dir):
        print("That path does not exist or is not a directory.")
    else:
        find_sensitive_filenames(target_dir, SENSITIVE_KEYWORDS)
