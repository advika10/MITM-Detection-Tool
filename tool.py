import os
import time
import threading
from tkinter import Tk, Label, Button, Frame, StringVar, Text, Scrollbar, VERTICAL, RIGHT, Y, END
from plyer import notification

# Initialize global variables
data = ""  # Holds the output of the `arp -a` command
ldata = []  # Processed lines from the ARP table
logs = []  # List to store log entries
duplicate_mac_check = []  # Tracks MAC addresses already reported as duplicates
addresses = {}  # Dictionary mapping IP addresses to MAC addresses
detection_running = False  # Tracks if detection is currently active

# Function to extract ARP table data using the `arp -a` command
def extract():
    global data, ldata
    ldata.clear()  # Clear the previous data
    # Execute `arp -a` and store the output
    with os.popen('arp -a') as f:
        data = f.read()
    # Process the output line by line
    with os.popen('arp -a') as a_file:
        for line in a_file:
            ldata.append(line.strip())
    # Remove the first three lines (header or irrelevant info)
    del ldata[0:3]

# Function to check for duplicate MAC addresses
def dictMACdup():
    global logs
    add_log = False  # Flag to determine if a new log entry should be created
    logs.clear()  # Clear previous logs
    checkingDict = {}  # Dictionary to group IPs by MAC address

    # Populate the dictionary with MACs as keys and sets of IPs as values
    for key, value in addresses.items():
        checkingDict.setdefault(value, set()).add(key)

    # Identify MACs associated with multiple IPs (potential spoofing)
    duplicate_mac = [key for key, values in checkingDict.items() if len(values) > 1]

    # Exclude broadcast MACs (ff:ff:ff:ff:ff:ff) from duplicates
    filtered_mac = [mac for mac in duplicate_mac if mac.lower() != "ff:ff:ff:ff:ff:ff"]

    # Notify only if valid duplicates exist
    if filtered_mac:
        notification.notify(
            title="Duplicate MAC Detected",
            message=f"Duplicate MACs: {', '.join(filtered_mac)}",
            app_name="ARP Spoofing Detector",
        )

    # Log valid duplicates to the GUI and log file
    for mac in filtered_mac:
        if mac not in duplicate_mac_check:  # Avoid re-reporting
            duplicate_mac_check.append(mac)
            add_log = True

    # Log valid duplicates to the GUI
    for mac in filtered_mac:
        mac_str = str(mac)
        if mac_str in checkingDict.keys():
            mac_ips = checkingDict[mac_str]  # Get associated IPs
            if add_log:
                log_entry = f"{mac_str} was duplicated in these IPs: {mac_ips}"
                logs.append(log_entry)
                log_area.insert(END, log_entry + "\n")  # Display log in GUI
                print("Log record added.")

# Function to write logs to a file
def logfunction():
    with open("logs.txt", "a") as f:
        for log in logs:
            logs_time = f"{time.strftime('%H:%M:%S')} {log}\n"
            f.write(logs_time)

# Function to start detection
def start_detection():
    global detection_running
    detection_running = True  # Mark detection as active
    status_label.set("Status: Running")  # Update GUI status
    detection_thread = threading.Thread(target=monitor_arp_table, daemon=True)
    detection_thread.start()  # Run detection in the background

# Function to stop detection
def stop_detection():
    global detection_running
    detection_running = False  # Stop detection
    status_label.set("Status: Stopped")  # Update GUI status

# Function to monitor the ARP table for spoofing
def monitor_arp_table():
    while detection_running:
        extract()  # Extract ARP table data
        process_arp_table()  # Process the extracted data
        dictMACdup()  # Check for duplicate MACs
        time.sleep(5)  # Pause for 5 seconds before the next check

# Function to process the ARP table into a dictionary of IP-MAC mappings
def process_arp_table():
    global addresses
    res = [idx for idx in ldata if idx.lower().startswith('i')]  # Ignore interface lines
    for entry in res:
        ldata.remove(entry)

    # Flatten and clean the data
    ldata_str = " ".join(ldata).split()
    ldata_str = [word for word in ldata_str if word not in ["static", "dynamic"]]

    # Separate IPs and MACs
    ip_list = []
    mac_list = []
    for i, entry in enumerate(ldata_str):
        if i % 2:
            mac_list.append(entry)
        else:
            ip_list.append(entry)

    addresses = dict(zip(ip_list, mac_list))  # Map IPs to MACs

# GUI Setup
root = Tk()
root.title("ARP Spoofing Detector")  # Set the window title
root.geometry("500x400")  # Set the window size
root.resizable(False, False)  # Disable resizing

frame = Frame(root)
frame.pack(pady=10)

# Status label
status_label = StringVar()
status_label.set("Status: Stopped")

Label(frame, text="ARP Spoofing Detector", font=("Arial", 16)).pack(pady=10)
Label(frame, textvariable=status_label, font=("Arial", 12), fg="blue").pack(pady=5)

# Buttons for starting, stopping, and exiting
Button(frame, text="Start Detection", font=("Arial", 12), command=start_detection, bg="green", fg="white", width=15).pack(pady=10)
Button(frame, text="Stop Detection", font=("Arial", 12), command=stop_detection, bg="red", fg="white", width=15).pack(pady=10)
Button(frame, text="Exit", font=("Arial", 12), command=root.destroy, bg="gray", fg="white", width=15).pack(pady=10)

# Log display area
log_frame = Frame(root)
log_frame.pack(pady=10)

scrollbar = Scrollbar(log_frame, orient=VERTICAL)
scrollbar.pack(side=RIGHT, fill=Y)

log_area = Text(log_frame, height=10, width=50, wrap="word", yscrollcommand=scrollbar.set)
log_area.pack()
scrollbar.config(command=log_area.yview)

Label(root, text="Logs will appear here and in 'logs.txt'.", font=("Arial", 10), fg="gray").pack(pady=5)

# Start the GUI loop
root.mainloop()
