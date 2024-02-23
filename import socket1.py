import tkinter as tk
from tkinter import messagebox, simpledialog, scrolledtext
import socket
import logging

# Setup logging
logging.basicConfig(filename='port_checker.log', level=logging.INFO,
                    format='%(asctime)s [%(levelname)s]: %(message)s', datefmt='%Y-%m-%d %H:%M:%S')

# Utility functions
def get_well_known_ports():
    """Returns a dictionary of well-known ports and their services."""
    return {
      1: "TCP Port Service Multiplexer (TCPMUX)",
        5: "Remote Job Entry (RJE)",
        7: "ECHO",
        18: "Message Send Protocol (MSP)",
        20: "FTP -- Data",
        21: "FTP -- Control",
        22: "SSH Remote Login Protocol",
        23: "Telnet",
        25: "Simple Mail Transfer Protocol (SMTP)",
        29: "MSG ICP",
        37: "Time",
        42: "Host Name Server (Nameserv)",
        43: "WhoIs",
        49: "Login Host Protocol (Login)",
        53: "Domain Name System (DNS)",
        69: "Trivial File Transfer Protocol (TFTP)",
        70: "Gopher Services",
        79: "Finger",
        80: "HTTP",
        103: "X.400 Standard",
        108: "SNA Gateway Access Server",
        109: "POP2",
        110: "POP3",
        115: "Simple File Transfer Protocol (SFTP)",
        118: "SQL Services",
        119: "Newsgroup (NNTP)",
        137: "NetBIOS Name Service",
        139: "NetBIOS Datagram Service",
        143: "Interim Mail Access Protocol (IMAP)",
        150: "NetBIOS Session Service",
        156: "SQL Server",
        161: "SNMP",
        179: "Border Gateway Protocol (BGP)",
        190: "Gateway Access Control Protocol (GACP)",
        194: "Internet Relay Chat (IRC)",
        197: "Directory Location Service (DLS)",
        389: "Lightweight Directory Access Protocol (LDAP)",
        396: "Novell Netware over IP",
        443: "HTTPS",
        444: "Simple Network Paging Protocol (SNPP)",
        445: "Microsoft-DS",
        458: "Apple QuickTime",
        465: "SMTP over TLS/SSL (SMTPS)",
        546: "DHCP Client",
        547: "DHCP Server",
        563: "SNEWS",
        # ... you can continue to add other ports as needed
    }

def parse_ports(input_str):
    """Parse a string of ports and ranges into a list of individual ports."""
    ports = set()
    parts = input_str.split(',')
    for part in parts:
        if '-' in part:
            start, end = map(int, part.split('-'))
            ports.update(range(start, end + 1))
        else:
            ports.add(int(part.strip()))
    return ports

def banner_grabbing(host, port):
    """Attempts to grab the banner for the specified host and port."""
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
            sock.settimeout(2)
            sock.connect((host, port))
            sock.send(b"GET / HTTP/1.1\r\nHost: " + host.encode() + b"\r\n\r\n")
            banner = sock.recv(1024).decode('utf-8', 'ignore')
            return banner
    except socket.error as e:
        logging.error(f"Error while grabbing banner for port {port}: {e}")
        return "Unable to grab banner"

def scan_port(ip, port):
    """Scan a single port on a given IP."""
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(1)
        result = sock.connect_ex((ip, port))
        if result == 0:
            return f"Port {port}: Open"
        else:
            return f"Port {port}: Closed"
    except socket.error as e:
        return f"Port {port}: Error {e}"
    finally:
        sock.close()

# GUI Application
class PortScannerApp:
    def __init__(self, root):
        self.root = root
        self.root.title("Port Scanner")
        self.create_widgets()

    def create_widgets(self):
        # Login button
        self.login_button = tk.Button(self.root, text="Login", command=self.login)
        self.login_button.pack(pady=10)

        # Scan button (initially disabled until user logs in)
        self.scan_button = tk.Button(self.root, text="Start Scan", command=self.start_scan, state=tk.DISABLED)
        self.scan_button.pack(pady=10)

        # Results area
        self.results_text = scrolledtext.ScrolledText(self.root, height=10, width=50)
        self.results_text.pack(pady=10)

    def login(self):
        password = simpledialog.askstring("Password", "Enter password:", show='*')
        if password == "admin":
            messagebox.showinfo("Login Success", "You are now logged in.")
            self.scan_button['state'] = tk.NORMAL
        else:
            messagebox.showerror("Login Failed", "Incorrect password.")

    def start_scan(self):
        self.results_text.delete(1.0, tk.END)
        ip = simpledialog.askstring("IP Address", "Enter IP address to scan:")
        ports_str = simpledialog.askstring("Ports", "Enter port numbers to scan (e.g., '21-25, 80, 443'):")
        if ip and ports_str:
            ports_to_scan = parse_ports(ports_str)
            for port in ports_to_scan:
                result = scan_port(ip, port)
                self.results_text.insert(tk.END, f"{result}\n")

if __name__ == "__main__":
    root = tk.Tk()
    app = PortScannerApp(root)
    root.mainloop()
