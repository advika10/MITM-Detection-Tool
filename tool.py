import os  # Provides a way to interact with the operating system
import time  # Used for adding delays in detection loops
import threading  # Allows multi-threaded execution
from tkinter import *  # Provides GUI components for the tool
from plyer import notification  # Enables cross-platform desktop notifications
from collections import Counter  # Provides an easy way to count occurrences
from scapy.all import sniff, IP  # Scapy library for sniffing network packets

# Global variables
data = ""  # Stores the raw output of the `arp -a` command
ldata = []  # List of processed lines from the ARP table
logs = []  # Log entries for detected events
detected_ips = set()  # Tracks IPs involved in potential spoofing
addresses = {}  # Dictionary mapping IP addresses to MAC addresses
detection_running = False  # Tracks whether detection is running
packet_counts = Counter()  # Tracks the number of packets per IP

# Function to write a log entry to the file
def write_log_to_file(log_entry):
    with open("logs.txt", "a") as log_file:
        log_file.write(log_entry + "\n")

# Function to extract ARP table data
def extract():
    global data, ldata
    ldata.clear()  # Clear previous ARP table data
    with os.popen('arp -a') as f:  # Run the `arp -a` command
        data = f.read()  # Read the output of the command
    with os.popen('arp -a') as a_file:  # Run the command again for line-by-line processing
        for line in a_file:
            ldata.append(line.strip())  # Add each stripped line to the list
    del ldata[0:3]  # Remove the header lines

# Function to detect and handle duplicate MAC addresses
def dictMACdup():
    global logs
    logs.clear()  # Clear previous logs
    checkingDict = {}

    # Create a dictionary where MAC addresses map to sets of IP addresses
    for key, value in addresses.items():
        checkingDict.setdefault(value, set()).add(key)

    # Find MAC addresses with multiple associated IPs
    duplicate_mac = [key for key, values in checkingDict.items() if len(values) > 1]
    filtered_mac = [mac for mac in duplicate_mac if mac.lower() != "ff:ff:ff:ff:ff:ff"]

    # Notify user if duplicate MAC addresses are found
    if filtered_mac:
        notification.notify(
            title="MITM Attack Detected",
            message=f"Duplicate MACs: {', '.join(filtered_mac)}",
            app_name="MITM Attack Detection Tool",
        )

    # Log the details of duplicate MAC addresses
    for mac in filtered_mac:
        mac_str = str(mac)
        if mac_str in checkingDict.keys():
            mac_ips = checkingDict[mac_str]
            log_entry = f"{mac_str} was duplicated in these IPs: {mac_ips}"
            logs.append(log_entry)
            log_area.insert(END, log_entry + "\n")  # Display logs in the GUI
            write_log_to_file(log_entry)  # Write log to file

# Function to process the ARP table into a dictionary of IP-to-MAC mappings
def process_arp_table():
    global addresses
    # Remove interface lines from ARP table data
    res = [idx for idx in ldata if idx.lower().startswith('i')]
    for entry in res:
        ldata.remove(entry)

    # Prepare ARP data for dictionary creation
    ldata_str = " ".join(ldata).split()
    ldata_str = [word for word in ldata_str if word not in ["static", "dynamic"]]

    # Separate IPs and MACs into lists
    ip_list = []
    mac_list = []
    for i, entry in enumerate(ldata_str):
        if i % 2:
            mac_list.append(entry)
        else:
            ip_list.append(entry)

    # Map IPs to MACs
    addresses = dict(zip(ip_list, mac_list))

# Function to detect IP spoofing using network packets
def detect_ip_spoofing(packet):
    global detected_ips

    if packet.haslayer(IP):  # Check if the packet contains an IP layer
        ip_src = packet[IP].src  # Get the source IP
        ttl = packet[IP].ttl  # Get the Time-To-Live (TTL) value

        # Detect unusual TTL values
        expected_ttl_range = range(60, 130)
        if ttl not in expected_ttl_range:
            log_entry = f"Potential MITM Attack Detected: IP {ip_src} with unusual TTL {ttl}"
            if ip_src not in detected_ips:
                detected_ips.add(ip_src)
                notification.notify(
                    title="MITM Attack Detected",
                    message=f"Unusual TTL from IP {ip_src}: {ttl}",
                    app_name="MITM Attack Detection Tool",
                )
                log_area.insert(END, log_entry + "\n")
                write_log_to_file(log_entry)  # Write log to file

        # Detect packets from non-reachable IPs
        response = os.system(f"ping -c 1 -W 1 {ip_src} > /dev/null 2>&1")
        if response != 0:  # Non-zero response means the IP is unreachable
            log_entry = f"Potential MITM Attack: IP {ip_src} is not reachable."
            if ip_src not in detected_ips:
                detected_ips.add(ip_src)
                notification.notify(
                    title="MITM Attack Detected",
                    message=f"Unreachable IP: {ip_src}",
                    app_name="MITM Attack Detection Tool",
                )
                log_area.insert(END, log_entry + "\n")
                write_log_to_file(log_entry)  # Write log to file
        # Detect packet flooding
        flood_threshold = 100
        packet_counts[ip_src] += 1
        if packet_counts[ip_src] > flood_threshold:
            log_entry = f"MITM Attack Detected: IP {ip_src} exceeded threshold with {packet_counts[ip_src]} packets."
            if ip_src not in detected_ips:
                detected_ips.add(ip_src)
                notification.notify(
                    title="MITM Attack Detected",
                    message=f"Flooding detected from IP {ip_src}: {packet_counts[ip_src]} packets.",
                    app_name="MITM Attack Detection Tool",
                )
                log_area.insert(END, log_entry + "\n")
                write_log_to_file(log_entry)  # Write log to file

# Function to continuously monitor the network
def monitor_network():
    while detection_running:
        extract()  # Extract ARP table
        process_arp_table()  # Process ARP data into a dictionary
        dictMACdup()  # Detect duplicate MAC addresses
        sniff(prn=detect_ip_spoofing, filter="ip", store=False, count=50)  # Sniff packets for spoofing
        time.sleep(5)  # Wait before the next cycle

# Start detection in a separate thread
def start_detection():
    global detection_running
    detection_running = True
    status_label.set("Status: Running")
    detection_thread = threading.Thread(target=monitor_network, daemon=True)
    detection_thread.start()

# Stop detection
def stop_detection():
    global detection_running
    detection_running = False
    status_label.set("Status: Stopped")

# Setup GUI
root = Tk()
root.title("MITM Attack Detection Tool")
root.geometry("500x400")
root.resizable(False, False)

# Main frame for buttons and labels
frame = Frame(root)
frame.pack(pady=10)

# Status label
status_label = StringVar()
status_label.set("Status: Stopped")

# Title label
Label(frame, text="MITM Attack Detection Tool", font=("Arial", 16)).pack(pady=10)
Label(frame, textvariable=status_label, font=("Arial", 12), fg="blue").pack(pady=5)

# Buttons for control
Button(frame, text="Start Detection", font=("Arial", 12), command=start_detection, bg="green", fg="white", width=15).pack(pady=10)
Button(frame, text="Stop Detection", font=("Arial", 12), command=stop_detection, bg="red", fg="white", width=15).pack(pady=10)
Button(frame, text="Exit", font=("Arial", 12), command=root.destroy, bg="gray", fg="white", width=15).pack(pady=10)

# Log display area with a scrollbar
log_frame = Frame(root)
log_frame.pack(pady=10)
scrollbar = Scrollbar(log_frame, orient=VERTICAL)
scrollbar.pack(side=RIGHT, fill=Y)
log_area = Text(log_frame, height=10, width=50, wrap="word", yscrollcommand=scrollbar.set)
log_area.pack()
scrollbar.config(command=log_area.yview)

# Log footer
Label(root, text="Logs will appear here.", font=("Arial", 10), fg="gray").pack(pady=5)

# Start the GUI loop
root.mainloop()
