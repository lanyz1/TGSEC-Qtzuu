import socket
import sys
import logging
from datetime import datetime
from pyfiglet import Figlet
from concurrent.futures import ThreadPoolExecutor, as_completed
from typing import Tuple, Optional, Union, List
from colorama import Fore, Style, init
from rich.console import Console
import json
import os

# Initialize colorama
init(autoreset=True)
console = Console()

# Security ports with importance levels
SECURITY_PORTS = {
    21: ('FTP', 'High'), 22: ('SSH', 'Critical'), 23: ('Telnet', 'High'),
    25: ('SMTP', 'Medium'), 53: ('DNS', 'Critical'), 80: ('HTTP', 'High'),
    443: ('HTTPS', 'Critical'), 3306: ('MySQL', 'High'), 3389: ('RDP', 'Critical'),
    8080: ('HTTP-Alt', 'Medium'), 8443: ('HTTPS-Alt', 'Medium')
}

# Banner_One
PURPLE = '\033[0;35m' 
END = "\033[0m"

banner = f"""
  {END}
    ███╗   ██╗ █████╗ ███████╗██╗██╗  ██╗███████╗███████╗       
    ████╗  ██║██╔══██╗╚══███╔╝██║╚██╗██╔╝██╔════╝██╔════╝       
    ██╔██╗ ██║███████║  ███╔╝ ██║ ╚███╔╝ ███████╗███████╗       
    ██║╚██╗██║██╔══██║ ███╔╝  ██║ ██╔██╗ ╚════██║╚════██║       
    ██║ ╚████║██║  ██║███████╗██║██╔╝ ██╗███████║███████║       
    ╚═╝  ╚═══╝╚═╝  ╚═╝╚══════╝╚═╝╚═╝  ╚═╝╚══════╝╚══════╝       
                                                                
    ██████╗  ██████╗ ██████╗ ████████╗                          
    ██╔══██╗██╔═══██╗██╔══██╗╚══██╔══╝                          
    ██████╔╝██║   ██║██████╔╝   ██║                             
    ██╔═══╝ ██║   ██║██╔══██╗   ██║                             
    ██║     ╚██████╔╝██║  ██║   ██║                             
    ╚═╝      ╚═════╝ ╚═╝  ╚═╝   ╚═╝                             
                                                                
    ███████╗ ██████╗ █████╗ ███╗   ██╗███╗   ██╗███████╗██████╗ 
    ██╔════╝██╔════╝██╔══██╗████╗  ██║████╗  ██║██╔════╝██╔══██╗
    ███████╗██║     ███████║██╔██╗ ██║██╔██╗ ██║█████╗  ██████╔╝
    ╚════██║██║     ██╔══██║██║╚██╗██║██║╚██╗██║██╔══╝  ██╔══██╗
    ███████║╚██████╗██║  ██║██║ ╚████║██║ ╚████║███████╗██║  ██║
    ╚══════╝ ╚═════╝╚═╝  ╚═╝╚═╝  ╚═══╝╚═╝  ╚═══╝╚══════╝╚═╝  ╚═╝
{Fore.YELLOW}
╔══════════════════════════════════════════════════════╗
║              Port Scanner v3.0               ║
╚══════════════════════════════════════════════════════╝
{Fore.RESET}"""

print(banner)

def setup_logging():
    """Initialize logging system."""
    logging.basicConfig(
        filename=f'scan_{datetime.now().strftime("%Y-%m-%d")}.log',
        level=logging.INFO,
        format='%(asctime)s - %(levelname)s - %(message)s'
    )

def ShowPortsTree(open_ports):
    """Display open ports in a formatted table."""
    print(Fore.CYAN + "\n" + "═"*65)
    print("╔" + " OPEN PORTS FOUND ".center(63, "═") + "╗")
    print("╠" + "═"*63 + "╣")
    print("║" + Fore.CYAN + f" {'No.':<4} {'Port':<8} {'Service':<20} {'Protocol':<12} {'Severity':<13} " + Fore.CYAN + "║")
    print("╠" + "═"*63 + "╣")
    
    for i, (port, service, proto, severity) in enumerate(open_ports, 1):
        color = Fore.RED if severity == 'Critical' else Fore.YELLOW if severity == 'High' else Fore.WHITE
        print(Fore.CYAN + "║ " + Fore.CYAN + f"{i:<4}" + Fore.WHITE + f"{port:<8} {service:<20} {proto:<12} " + color + f"{severity:<14}" + Fore.CYAN + " ║")
    
    print("╠" + "═"*63 + "╣")
    print("║" + Fore.MAGENTA + f" Total open ports: {len(open_ports)} ".center(63) + Fore.CYAN + "║")
    print("╚" + "═"*63 + "╝" + Style.RESET_ALL + "\n")

def save_to_json(open_ports: list, filename: str = "scan_results.json"):
    """Save scan results to JSON."""
    data = [{"port": p[0], "service": p[1], "protocol": p[2], "severity": p[3]} for p in open_ports]
    with open(filename, 'w') as f:
        json.dump(data, f, indent=4)

class PortScannerError(Exception):
    pass

class HostResolutionError(PortScannerError):
    pass

class PortScanError(PortScannerError):
    pass

class InvalidInputError(PortScannerError):
    pass

def ValidateIP(ip: str) -> bool:
    """Validate IP address."""
    try:
        socket.inet_aton(ip)
        return True
    except socket.error:
        return False

def ResolveHost(target: str) -> str:
    """Resolve hostname to IP."""
    if not target:
        raise InvalidInputError("Target cannot be empty")
    
    if ValidateIP(target):
        return target
    
    try:
        return socket.gethostbyname(target)
    except socket.gaierror:
        raise HostResolutionError(f"Could not resolve hostname: {target}")
    except Exception as e:
        raise HostResolutionError(f"Resolution error: {str(e)}")

def ParsePortInput(input_str: str) -> Union[int, range]:
    """Parse port input."""
    if not input_str.strip():
        raise InvalidInputError("Port input cannot be empty")
    
    try:
        if '-' in input_str:
            parts = input_str.split('-')
            if len(parts) != 2:
                raise InvalidInputError("Invalid port range format")
            
            start = int(parts[0].strip())
            end = int(parts[1].strip())
            
            if not (0 < start <= 65535) or not (0 < end <= 65535):
                raise InvalidInputError("Ports must be between 1-65535")
            if start > end:
                raise InvalidInputError("Start port must be <= end port")
                
            return range(start, end + 1)
        
        port = int(input_str)
        if not 0 < port <= 65535:
            raise InvalidInputError("Port must be between 1-65535")
        return port
        
    except ValueError:
        raise InvalidInputError("Port must be a valid number")

def ScanPort(ip: str, port: int, proto: str, timeout: float = 1.0) -> Optional[Tuple[int, str, str, str]]:
    """Scan a single port."""
    try:
        sock_type = socket.SOCK_STREAM if proto == 'tcp' else socket.SOCK_DGRAM
        with socket.socket(socket.AF_INET, sock_type) as sock:
            sock.settimeout(timeout)
            
            if proto == 'tcp':
                if sock.connect_ex((ip, port)) == 0:
                    service, severity = SECURITY_PORTS.get(port, ('Unknown', 'Low'))
                    return port, service, proto.upper(), severity
            else:
                sock.sendto(b'', (ip, port))
                try:
                    sock.recvfrom(1024)
                    service, severity = SECURITY_PORTS.get(port, ('Unknown', 'Low'))
                    return port, service, proto.upper(), severity
                except socket.timeout:
                    pass
                    
    except socket.timeout:
        pass
    except socket.error as e:
        raise PortScanError(f"Network error on port {port}: {str(e)}")
    except Exception as e:
        raise PortScanError(f"Unexpected error on port {port}: {str(e)}")
    
    return None

def RunScan(ip: str, ports: Union[int, range, List[int]], proto: str) -> List[Tuple[int, str, str, str]]:
    """Run the scan with multithreading."""
    if proto not in ('tcp', 'udp'):
        raise InvalidInputError("Invalid protocol")
    
    port_list = [ports] if isinstance(ports, int) else ports
    open_ports = []
    
    try:
        max_workers = min(100, len(port_list), os.cpu_count() * 4)
        with ThreadPoolExecutor(max_workers=max_workers) as executor:
            futures = {executor.submit(ScanPort, ip, port, proto): port for port in port_list}
            
            # First pass - just scan without progress bar
            for future in as_completed(futures):
                port = futures[future]
                try:
                    if result := future.result():
                        open_ports.append(result)
                        print(Fore.CYAN + f"[+] Found: {port}/{proto} - {result[1]} " + 
                              Fore.YELLOW + f"(Severity: {result[3]})" + Style.RESET_ALL)
                except PortScanError as e:
                    print(Fore.RED + f"[!] Warning: {str(e)}" + Style.RESET_ALL, file=sys.stderr)
        
        return sorted(open_ports, key=lambda x: x[0])
        
    except Exception as e:
        raise PortScanError(f"Scan failed: {str(e)}")

def main():
    """Main function."""
    setup_logging()
    print(Fore.RED + "\n[!] WARNING: Use this tool only on authorized networks. Unauthorized scanning is illegal!" + Style.RESET_ALL)
    print(Fore.YELLOW + "[i] By using this tool, you agree to use it ethically and legally.\n" + Style.RESET_ALL)
    
    try:
        target = input(Fore.CYAN + "[?] " + Fore.WHITE + "Enter target IP/hostname: " + Style.RESET_ALL).strip()
        proto = input(Fore.CYAN + "[?] " + Fore.WHITE + "Protocol (tcp/udp): " + Style.RESET_ALL).strip().lower()
        
        ip = ResolveHost(target)
        logging.info(f"Scan started for target: {target} -> {ip}")
        print(Fore.BLUE + f"\n[i] Target resolved: " + Fore.WHITE + f"{target}" + Fore.YELLOW + " → " + Fore.WHITE + f"{ip}" + Style.RESET_ALL)
        
        # Phase 1: Default security scan
        print(Fore.MAGENTA + "\n[+] Scanning security ports..." + Style.RESET_ALL)
        open_ports = RunScan(ip, SECURITY_PORTS.keys(), proto)
        ShowPortsTree(open_ports)
        save_to_json(open_ports)
        
        # Phase 2: Custom scan
        while True:
            try:
                custom = input(Fore.CYAN + "\n[?] " + Fore.WHITE + "Enter port/range or 'quit': " + Style.RESET_ALL).strip()
                if custom.lower() == 'quit':
                    break
                    
                ports = ParsePortInput(custom)
                print(Fore.MAGENTA + "\n[+] Scanning custom ports..." + Style.RESET_ALL)
                open_ports = RunScan(ip, ports, proto)
                ShowPortsTree(open_ports)
                save_to_json(open_ports)
                
            except InvalidInputError as e:
                logging.error(str(e))
                print(Fore.RED + f"[!] Error: {str(e)}" + Style.RESET_ALL, file=sys.stderr)
            except KeyboardInterrupt:
                print(Fore.YELLOW + "\n[!] Scan interrupted by user" + Style.RESET_ALL)
                break
            except Exception as e:
                logging.error(str(e))
                print(Fore.RED + f"[!] Error: {str(e)}" + Style.RESET_ALL, file=sys.stderr)
                
    except (HostResolutionError, InvalidInputError) as e:
        logging.critical(str(e))
        print(Fore.RED + f"\n[!] Fatal error: {str(e)}" + Style.RESET_ALL, file=sys.stderr)
        sys.exit(1)
    except KeyboardInterrupt:
        print(Fore.YELLOW + "\n[!] Operation cancelled by user" + Style.RESET_ALL)
        sys.exit(1)
    except Exception as e:
        logging.critical(str(e))
        print(Fore.RED + f"\n[!] Unexpected error: {str(e)}" + Style.RESET_ALL, file=sys.stderr)
        sys.exit(1)

if __name__ == "__main__":
    main()