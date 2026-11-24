import json
import socket


def send_command(host: str, port: int, target_os: str, command: str, timeout: int = 65) -> dict:
    payload = {
        "os": target_os,
        "command": command,
        "timeout": timeout,
    }
    with socket.create_connection((host, port), timeout=timeout) as sock:
        sock.settimeout(timeout)
        sock.sendall((json.dumps(payload) + "\n").encode("utf-8"))

        buffer = b""
        while b"\n" not in buffer:
            chunk = sock.recv(4096)
            if not chunk:
                raise ConnectionError("Connection closed by receiver before response completed.")
            buffer += chunk

        line, _ = buffer.split(b"\n", 1)
        return json.loads(line.decode("utf-8"))


def print_result(result: dict) -> None:
    stdout = result.get("stdout", "")
    stderr = result.get("stderr", "")
    status = result.get("status", "Unknown status")

    print("\n--- Result ---")
    print(f"Status : {status}")
    if stdout.strip():
        print(f"Output :\n{stdout.rstrip()}")
    else:
        print("Output : <none>")

    if stderr.strip():
        print(f"Errors :\n{stderr.rstrip()}")
    print("--------------\n")


def main() -> None:
    host = input("Receiver IP/hostname [127.0.0.1]: ").strip() or "127.0.0.1"
    port_str = input("Receiver port [5055]: ").strip() or "5055"
    port = int(port_str)

    while True:
        target_os = input("Choose OS (linux / windows) or 'quit': ").strip().lower()
        if target_os in ("quit", "exit", "q"):
            break
        if target_os not in ("linux", "windows"):
            print("Please enter 'linux' or 'windows'.")
            continue

        command = input(f"Command ({target_os}): ").strip()
        if not command:
            print("Command cannot be empty.")
            continue

        try:
            res = send_command(host, port, target_os, command)
            print_result(res)
        except Exception as exc:
            print(f"[!] Failed to communicate with receiver: {exc}\n")


if __name__ == "__main__":
    main()