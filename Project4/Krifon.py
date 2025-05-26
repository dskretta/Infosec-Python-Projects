import os

# list of keywords that suggest sensitive files
SENSITIVE_KEYWORDS = [
    "username", "password", "passwd", "credentials", "creds", "secret",
    "web.config", "sitelist", "auth", "account", "login"
    "auth," "token", "apikey", "api", "login", "auth", 
]

def find_sensitive_content(base_dir, keywords):
    print(f"\nScanning file contents for sensitive strings...")
    for root, dirs, files in os.walk(base_dir):
        for name in files:
            path = os.path.join(root, name)
            lower_name = name.lower()

            # --- Filename match ---
            for keyword in keywords:
                if keyword in lower_name:
                    print(f"[FILENAME MATH] {path}")
                    break

            # --- Content match ---
            try:
                with open(path, "r", errors="ignore") as f:
                    for i, line in enumerate(f):
                        for keyword in keywords:
                            if keyword.lower() in line.lower():
                                print(f"[!] Keyword ' {keyword}' found in: {path} (line {i+1})")
                                break
            except Exception as e:
                # skip unreadable files
                continue
if __name__ == "__main__":
    target_dir = input("Enter path to directory: ").strip()
    if not os.path.isdir(target_dir):
        print("That path does not exist or is not a directory.")
    else:
        find_sensitive_content(target_dir, SENSITIVE_KEYWORDS)
