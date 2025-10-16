import argparse
import docker
import shutil
import subprocess
import os

HONEYPOTS = ["cowrie", "http_honeypot", "mosquitto", "cameraobscura", "riotpot", "sip_honeypot"]

def find_container_by_service(client, service_name):
    """Return a Container matching service_name (exact or partial/project-prefixed)."""
    try:
        containers = client.containers.list(all=True)
    except Exception:
        return None
    for c in containers:
        # container name like "smartcity-honeypot-http_honeypot-1"
        try:
            cname = c.name or ""
        except Exception:
            cname = ""
        if service_name == cname:
            return c
        if service_name in cname:
            return c
        # try matching suffix e.g. "..._http_honeypot-1"
        if cname.endswith(service_name) or cname.endswith(f"_{service_name}"):
            return c
    return None

def get_container(client, name):
    try:
        # first try direct get (fast)
        return client.containers.get(name)
    except docker.errors.NotFound:
        # try fuzzy search for project-prefixed container
        return find_container_by_service(client, name)
    except Exception:
        return None

def list_containers(client):
    print("\nAvailable Honeypots:")
    # gather running containers once for faster lookups
    for idx, name in enumerate(HONEYPOTS, 1):
        container = find_container_by_service(client, name)
        status = container.status if container else "not found"
        print(f"{idx}. {name} [{status}]")
    print()

def control_container(client, name, action):
    container = find_container_by_service(client, name)
    if not container:
        print(f"Container for '{name}' not found.")
        return
    try:
        if action == "start":
            if container.status == "running":
                print(f"'{name}' already running.")
            else:
                container.start()
                print(f"Started '{name}'.")
        elif action == "stop":
            if container.status != "running":
                print(f"'{name}' not running.")
            else:
                container.stop()
                print(f"Stopped '{name}'.")
        elif action == "restart":
            container.restart()
            print(f"Restarted '{name}'.")
    except Exception as e:
        print(f"Error controlling '{name}': {e}")

def show_logs(client, name, tail=50):
    container = find_container_by_service(client, name)
    if not container:
        print(f"Container for '{name}' not found.")
        return
    try:
        logs = container.logs(tail=tail).decode(errors="replace")
        print(f"\n--- Last {tail} log lines for '{container.name}' ---\n")
        print(logs)
    except Exception as e:
        print(f"Error: {e}")

def detect_compose_cmd():
    # prefer docker-compose binary if present, otherwise use 'docker compose'
    if shutil.which("docker-compose"):
        return ["docker-compose"]
    if shutil.which("docker"):
        return ["docker", "compose"]
    return None

def run_compose_command(args, cwd=None):
    compose = detect_compose_cmd()
    if not compose:
        print("docker / docker-compose not found in PATH; cannot run compose commands.")
        return False
    cmd = compose + args
    try:
        subprocess.run(cmd, cwd=cwd or os.getcwd(), check=True)
        return True
    except subprocess.CalledProcessError as e:
        print("Compose command failed:", e)
        return False

def start_all_honeypots(client):
    print("\nStarting all honeypots...")
    any_found = False
    for name in HONEYPOTS:
        c = find_container_by_service(client, name)
        if c:
            any_found = True
            try:
                if c.status == "running":
                    print(f"'{c.name}' already running.")
                else:
                    c.start()
                    print(f"Started '{c.name}'.")
            except Exception as e:
                print(f"Error starting '{c.name}': {e}")
        else:
            print(f"No container found for '{name}'.")
    if not any_found:
        print("No matching containers found locally — trying 'docker compose up -d' in project root.")
        if run_compose_command(["up", "-d"]):
            print("docker compose up -d executed.")
        else:
            print("Failed to start via docker compose.")
    print("Start-all operation complete.\n")

def stop_all_honeypots(client):
    print("\nStopping all honeypots...")
    any_found = False
    for name in HONEYPOTS:
        c = find_container_by_service(client, name)
        if c:
            any_found = True
            try:
                if c.status != "running":
                    print(f"'{c.name}' not running.")
                else:
                    c.stop()
                    print(f"Stopped '{c.name}'.")
            except Exception as e:
                print(f"Error stopping '{c.name}': {e}")
        else:
            print(f"No container found for '{name}'.")
    if not any_found:
        print("No matching containers found locally — trying 'docker compose down' in project root.")
        if run_compose_command(["down"]):
            print("docker compose down executed.")
        else:
            print("Failed to stop via docker compose.")
    print("Stop-all operation complete.\n")

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
        print("6. Start all honeypots")
        print("7. Stop all honeypots")
        print("8. Exit")
        choice = input("Choose an option (1-8): ").strip()

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
            start_all_honeypots(client)
        elif choice == "7":
            stop_all_honeypots(client)
        elif choice == "8":
            print("Exiting.")
            break
        else:
            print("Invalid option.")

if __name__ == "__main__":
    main()