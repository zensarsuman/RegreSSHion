import socket
import argparse
import ipaddress
import threading
from queue import Queue

def check_port(ip_address, port_number, timeout_duration):
    socket_instance = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    socket_instance.settimeout(timeout_duration)
    try:
        socket_instance.connect((ip_address, port_number))
        socket_instance.close()
        return True
    except:
        return False

def fetch_ssh_banner(ip_address, port_number, timeout_duration):
    try:
        socket_instance = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        socket_instance.settimeout(timeout_duration)
        socket_instance.connect((ip_address, port_number))
        banner_info = socket_instance.recv(1024).decode().strip()
        socket_instance.close()
        return banner_info
    except Exception as error:
        return str(error)

def assess_vulnerability(ip_address, port_number, timeout_duration, results_queue):
    if not check_port(ip_address, port_number, timeout_duration):
        results_queue.put((ip_address, port_number, 'closed', "Port closed"))
        return

    banner_info = fetch_ssh_banner(ip_address, port_number, timeout_duration)
    if "SSH-2.0-OpenSSH" not in banner_info:
        results_queue.put((ip_address, port_number, 'failed', f"Failed to retrieve SSH banner: {banner_info}"))
        return

    vulnerable_versions_list = [
        'SSH-2.0-OpenSSH_8.5p1',
        'SSH-2.0-OpenSSH_8.6p1',
        'SSH-2.0-OpenSSH_8.7p1',
        'SSH-2.0-OpenSSH_8.8p1',
        'SSH-2.0-OpenSSH_8.9p1',
        'SSH-2.0-OpenSSH_9.0p1',
        'SSH-2.0-OpenSSH_9.1p1',
        'SSH-2.0-OpenSSH_9.2p1',
        'SSH-2.0-OpenSSH_9.3p1',
        'SSH-2.0-OpenSSH_9.4p1',
        'SSH-2.0-OpenSSH_9.5p1',
        'SSH-2.0-OpenSSH_9.6p1',
        'SSH-2.0-OpenSSH_9.7p1'
    ]

    if any(version in banner_info for version in vulnerable_versions_list):
        results_queue.put((ip_address, port_number, 'vulnerable', f"(running {banner_info})"))
    else:
        results_queue.put((ip_address, port_number, 'not_vulnerable', f"(running {banner_info})"))

def main():
    argument_parser = argparse.ArgumentParser(description="Check if servers are running a vulnerable version of OpenSSH.")
    argument_parser.add_argument("targets", nargs='+', help="IP addresses, domain names, file paths containing IP addresses, or CIDR network ranges.")
    argument_parser.add_argument("--port", type=int, default=22, help="Port number to check (default: 22).")
    argument_parser.add_argument("-t", "--timeout", type=float, default=1.0, help="Connection timeout in seconds (default: 1 second).")

    arguments = argument_parser.parse_args()
    target_list = arguments.targets
    port_number = arguments.port
    timeout_duration = arguments.timeout

    ip_addresses = []
    for target in target_list:
        try:
            with open(target, 'r') as file:
                ip_addresses.extend(file.readlines())
        except IOError:
            if '/' in target:
                try:
                    network_range = ipaddress.ip_network(target, strict=False)
                    ip_addresses.extend([str(ip) for ip in network_range.hosts()])
                except ValueError:
                    print(f"❌ [-] Invalid CIDR notation: {target}")
            else:
                ip_addresses.append(target)

    results_queue = Queue()
    threads_list = []

    for ip_address in ip_addresses:
        ip_address = ip_address.strip()
        thread_instance = threading.Thread(target=assess_vulnerability, args=(ip_address, port_number, timeout_duration, results_queue))
        thread_instance.start()
        threads_list.append(thread_instance)

    for thread_instance in threads_list:
        thread_instance.join()

    total_scanned_targets = len(ip_addresses)
    closed_port_count = 0
    non_vulnerable_servers = []
    vulnerable_servers = []

    while not results_queue.empty():
        ip_address, port_number, status, message = results_queue.get()
        if status == 'closed':
            closed_port_count += 1
        elif status == 'vulnerable':
            vulnerable_servers.append((ip_address, message))
        elif status == 'not_vulnerable':
            non_vulnerable_servers.append((ip_address, message))
        else:
            print(f"⚠️ [!] Server at {ip_address}:{port_number} is {message}")

    print(f"\n🛡️ Servers not vulnerable: {len(non_vulnerable_servers)}\n")
    for ip_address, msg in non_vulnerable_servers:
        print(f"   [+] Server at {ip_address} {msg}")
    print(f"\n🚨 Servers likely vulnerable: {len(vulnerable_servers)}\n")
    for ip_address, msg in vulnerable_servers:
        print(f"   [+] Server at {ip_address} {msg}")
    print(f"\n🔒 Servers with port 22 closed: {closed_port_count}")
    print(f"\n📊 Total scanned targets: {total_scanned_targets}\n")

if __name__ == "__main__":
    main()
