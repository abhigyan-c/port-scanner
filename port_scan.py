import tkinter as tk
from tkinter import messagebox
from scapy.all import *
import threading

stop_scan_flag = threading.Event()

def SynScan(host, ports, update_callback):
    open_ports = []
    for port in ports:
        if stop_scan_flag.is_set():
            break
        ans, _ = sr(IP(dst=host)/TCP(sport=5555, dport=port, flags="S"), timeout=2, verbose=0)
        for (s, r) in ans:
            if s[TCP].dport == r[TCP].sport and r[TCP].flags == "SA":
                open_ports.append(s[TCP].dport)
        update_callback(port)
    return open_ports

def TcpConnectScan(host, ports, update_callback):
    open_ports = []
    for port in ports:
        if stop_scan_flag.is_set():
            break
        syn_ack = sr1(IP(dst=host)/TCP(dport=port, flags="S"), timeout=1, verbose=0)
        if syn_ack and syn_ack.getlayer(TCP).flags == 0x12:  # SYN+ACK
            send(IP(dst=host)/TCP(dport=port, flags="R"), verbose=0)  # RST to close the connection
            open_ports.append(port)
        update_callback(port)
    return open_ports

def UdpScan(host, ports, update_callback):
    open_ports = []
    for port in ports:
        if stop_scan_flag.is_set():
            break
        udp_packet = sr1(IP(dst=host)/UDP(dport=port), timeout=2, verbose=0)
        if udp_packet is None:
            open_ports.append(port)
        elif udp_packet.haslayer(UDP):
            open_ports.append(port)
        update_callback(port)
    return open_ports

def AckScan(host, ports, update_callback):
    filtered_ports = []
    for port in ports:
        if stop_scan_flag.is_set():
            break
        ack_resp = sr1(IP(dst=host)/TCP(dport=port, flags="A"), timeout=1, verbose=0)
        if ack_resp is None:
            filtered_ports.append(port)
        elif ack_resp.haslayer(TCP) and ack_resp.getlayer(TCP).flags == 0x4:  # RST flag
            pass  # Unfiltered, ignore for now
        update_callback(port)
    return filtered_ports

def start_scan():
    target = ip_entry.get()
    port_input = port_entry.get()
    scan_type = scan_type_var.get()

    try:
        if '-' in port_input:
            start_port, end_port = map(int, port_input.split('-'))
            ports = list(range(start_port, end_port + 1))
        else:
            ports = list(map(int, port_input.split(',')))
    except ValueError:
        messagebox.showerror("Error", "Invalid port range. Please enter single ports or comma-separated ports.")
        return

    stop_scan_flag.clear()

    def update_progress(port):
        progress_label.config(text=f"Scanning port: {port}")
        root.update_idletasks()

    def perform_scan():
        if scan_type == "SYN Scan":
            open_ports = SynScan(target, ports, update_progress)
        elif scan_type == "TCP Connect Scan":
            open_ports = TcpConnectScan(target, ports, update_progress)
        elif scan_type == "UDP Scan":
            open_ports = UdpScan(target, ports, update_progress)
        elif scan_type == "ACK Scan":
            filtered_ports = AckScan(target, ports, update_progress)
        else:
            messagebox.showerror("Error", "Invalid scan type.")
            return

        if scan_type == "ACK Scan":
            if filtered_ports:
                result_text = "Filtered ports in " + target + ":\n" + "\n".join(map(str, filtered_ports))
            else:
                result_text = "No filtered ports found in " + target
        else:
            if open_ports:
                result_text = "Open ports in " + target + ":\n" + "\n".join(map(str, open_ports))
            else:
                result_text = "No open ports found in " + target

        result_label.config(text=result_text)
        progress_label.config(text="Scan complete")

    scan_thread = threading.Thread(target=perform_scan)
    scan_thread.start()

def stop_scan():
    stop_scan_flag.set()
    progress_label.config(text="Scan stopped")

# Create the main window
root = tk.Tk()
root.title("Network Scanner")

# Create and place the widgets
tk.Label(root, text="Target IP:").grid(row=0, column=0, padx=10, pady=5)
ip_entry = tk.Entry(root)
ip_entry.grid(row=0, column=1, padx=10, pady=5)

tk.Label(root, text="Port Range (e.g., 0-1024 or 22,80,443):").grid(row=1, column=0, padx=10, pady=5)
port_entry = tk.Entry(root)
port_entry.grid(row=1, column=1, padx=10, pady=5)

tk.Label(root, text="Scan Type:").grid(row=2, column=0, padx=10, pady=5)
scan_type_var = tk.StringVar(value="SYN Scan")
tk.OptionMenu(root, scan_type_var, "SYN Scan", "TCP Connect Scan", "UDP Scan", "ACK Scan").grid(row=2, column=1, padx=10, pady=5)

tk.Button(root, text="Start Scan", command=start_scan).grid(row=3, column=0, padx=10, pady=5)
tk.Button(root, text="Stop Scan", command=stop_scan).grid(row=3, column=1, padx=10, pady=5)

progress_label = tk.Label(root, text="Scan progress will be shown here", justify=tk.LEFT)
progress_label.grid(row=4, columnspan=2, padx=10, pady=5)

result_label = tk.Label(root, text="", justify=tk.LEFT)
result_label.grid(row=5, columnspan=2, padx=10, pady=5)

# Start the Tkinter event loop
root.mainloop()
