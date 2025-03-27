# CyberSecurity_59 Mini Project Completed
# Code
import tkinter as tk
from tkinter import messagebox
import nmap
import os

# Set the correct path for Nmap
NMAP_PATH = "C:\\Program Files (x86)\\Nmap\\nmap.exe"  # Update this if needed

def scan_ports():
    target = entry_target.get().strip()
    if not target:
        messagebox.showerror("Error", "Please enter a target IP or hostname")
        return

    # Check if Nmap exists
    if not os.path.exists(NMAP_PATH):
        messagebox.showerror("Error", f"Nmap not found at {NMAP_PATH}. Please check the installation path.")
        return

    scanner = nmap.PortScanner(nmap_search_path=(NMAP_PATH,))  # Explicitly set Nmap path
    try:
        scanner.scan(hosts=target, arguments='-p 1-1024 -T4')
        result_text.delete("1.0", tk.END)
        
        if not scanner.all_hosts():
            result_text.insert(tk.END, "No hosts found or scan failed. Check target IP and permissions.\n")
            return
        
        for host in scanner.all_hosts():
            result_text.insert(tk.END, f"Scanning {host} ({scanner[host].hostname()})\n")
            for proto in scanner[host].all_protocols():
                result_text.insert(tk.END, f"Protocol: {proto}\n")
                ports = scanner[host][proto].keys()
                if not ports:
                    result_text.insert(tk.END, "No open ports found.\n")
                for port in sorted(ports):
                    state = scanner[host][proto][port]['state']
                    result_text.insert(tk.END, f"Port {port}: {state}\n")
    except Exception as e:
        messagebox.showerror("Error", f"Nmap scan failed: {str(e)}")

# GUI Setup
root = tk.Tk()
root.title("Nmap TCP Scanner")
root.geometry("500x400")

tk.Label(root, text="Enter Target IP/Hostname:").pack()
entry_target = tk.Entry(root, width=50)
entry_target.pack()

scan_button = tk.Button(root, text="Scan", command=scan_ports)
scan_button.pack()

result_text = tk.Text(root, height=15, width=60)
result_text.pack()

root.mainloop()
