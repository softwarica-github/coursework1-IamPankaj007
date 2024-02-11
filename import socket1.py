import socket
import threading
from queue import Queue
from ipaddress import IPv4Network
import tkinter as tk
from tkinter import messagebox, simpledialog, scrolledtext

# Define COMMON_PORTS at the top level of the script
COMMON_PORTS = {
    21: 'FTP',
    22: 'SSH',
    23: 'TELNET',
    25: 'SMTP',
    53: 'DNS',
    80: 'HTTP',
    110: 'POP3',
    143: 'IMAP',
    443: 'HTTPS',
    445: 'SMB',
    3306: 'MySQL',
    3389: 'RDP',
    5800: 'VNC',
    5900: 'VNC'
}

# Function to create a queue with the ports to scan
def get_port_queue():
    port_queue = Queue()
    for port in COMMON_PORTS:
        port_queue.put(port)
    return port_queue

# AdvancedNetworkScanner class definition
# ... [include your AdvancedNetworkScanner class code here]

# GUI Application Class
class NetworkScannerApp(tk.Tk):
    def __init__(self):
        super().__init__()
        self.title("Network Scanner")
        self.geometry("800x600")

        # Text area for results
        self.result_area = scrolledtext.ScrolledText(self, state='disabled', height=30, width=90)
        self.result_area.pack(pady=10)

        # Menu options
        menu_bar = tk.Menu(self)
        self.config(menu=menu_bar)

        # File menu
        file_menu = tk.Menu(menu_bar, tearoff=0)
        file_menu.add_command(label="New Scan", command=self.prompt_new_scan)
        file_menu.add_separator()
        file_menu.add_command(label="Exit", command=self.exit_app)
        menu_bar.add_cascade(label="File", menu=file_menu)

        # Help menu
        help_menu = tk.Menu(menu_bar, tearoff=0)
        help_menu.add_command(label="About", command=self.show_about)
        menu_bar.add_cascade(label="Help", menu=help_menu)

    def prompt_new_scan(self):
        network = simpledialog.askstring("Input", "Enter the network to scan (e.g., 192.168.1.0/24):", parent=self)
        if network:
            self.run_new_scan(network)

    def run_new_scan(self, network):
        self.result_area.configure(state='normal')
        self.result_area.delete(1.0, tk.END)
        self.result_area.insert(tk.END, f"Scanning the network {network}...\n")
        self.result_area.configure(state='disabled')
        
        port_queue = get_port_queue()
        scanner = AdvancedNetworkScanner(network, port_queue)
        active_hosts = scanner.run_scan()
        self.display_results(active_hosts)

    def display_results(self, active_hosts):
        self.result_area.configure(state='normal')
        for host, ports in active_hosts.items():
            self.result_area.insert(tk.END, f"Host: {host}\n")
            for port, service in ports:
                self.result_area.insert(tk.END, f"  Port: {port} - Service: {service}\n")
        self.result_area.configure(state='disabled')

    def exit_app(self):
        if messagebox.askokcancel("Quit", "Do you want to exit the application?"):
            self.destroy()

    def show_about(self):
        messagebox.showinfo("About", "Network Scanner\nVersion 1.0")

# Function to start the GUI application
def start_gui_app():
    app = NetworkScannerApp()
    app.mainloop()

# Run the GUI app
if __name__ == "__main__":
    start_gui_app()
