import argparse
import docker

HONEYPOTS = ["cowrie", "http_honeypot", "mosquitto", "cameraobscura", "riotpot", "sip_honeypot"]

def get_container(client, name):
    try:
        return client.containers.get(name)
    except docker.errors.NotFound:
        return None

def list_containers(client):
    print("\nAvailable Honeypots:")
    for idx, name in enumerate(HONEYPOTS, 1):
        container = get_container(client, name)
        status = container.status if container else "not found"
        print(f"{idx}. {name} [{status}]")
    print()

def control_container(client, name, action):
    container = get_container(client, name)
    if not container:
        print(f"Container '{name}' not found.")
        return
    try:
        if action == "start":
            container.start()
        elif action == "stop":
            container.stop()
        elif action == "restart":
            container.restart()
        print(f"{action.capitalize()}ed '{name}' successfully.")
    except Exception as e:
        print(f"Error: {e}")

def show_logs(client, name, tail=50):
    container = get_container(client, name)
    if not container:
        print(f"Container '{name}' not found.")
        return
    try:
        logs = container.logs(tail=tail).decode(errors="replace")
        print(f"\n--- Last {tail} log lines for '{name}' ---\n")
        print(logs)
    except Exception as e:
        print(f"Error: {e}")

def main():
    try:
        client = docker.from_env()
    except Exception as e:
        print(f"Could not connect to Docker: {e}")
        return

    while True:
        print("\nHoneypot CLI Control Panel")
        print("1. List honeypots")
        print("2. Start honeypot")
        print("3. Stop honeypot")
        print("4. Restart honeypot")
        print("5. Show logs")
        print("6. Exit")
        choice = input("Choose an option (1-6): ").strip()

        if choice == "1":
            list_containers(client)
        elif choice in ["2", "3", "4", "5"]:
            list_containers(client)
            idx = input("Select honeypot by number: ").strip()
            try:
                idx = int(idx) - 1
                name = HONEYPOTS[idx]
            except (ValueError, IndexError):
                print("Invalid selection.")
                continue
            if choice == "2":
                control_container(client, name, "start")
            elif choice == "3":
                control_container(client, name, "stop")
            elif choice == "4":
                control_container(client, name, "restart")
            elif choice == "5":
                tail = input("How many log lines? [default 50]: ").strip()
                tail = int(tail) if tail.isdigit() else 50
                show_logs(client, name, tail)
        elif choice == "6":
            print("Exiting.")
            break
        else:
            print("Invalid option.")

if __name__ == "__main__":
    main()