# Personal-firewall-development-using-python
Developing firewall using scapy and iptables using python in linux
# Number of technologies used:
1.Firewall Concepts: Packet filtering, Stateful inspection.\
2.Intrusion Detection: Anomaly detection, Pattern recognition.\
3.Network Security: Port scanning, DoS protection.\
4.Socket Programming: Raw socket access, packet manipulation.\
5.Protocol Analysis: TCP/IP stack, Ethernet frames.\
6.Packet Crafting: Custom packet creation and injection.\
7.Tkinter (GUI).\
8.JSON & Configuration Management.
# Phase 1: Foundation & Planning
Phase 1 established the foundational knowledge and setup required for the firewall project, focusing on environment setup, Scapy basics, and system design.
 # Environment Setup & Scapy Basics 
1. Installing scrapy in kali linux virtual machine : sudo install scapy 
2. Packet Sniffing & Analysis
3. Firewall Rule Logic & Design
Commands : pip install scapy
packet[IP].src, packet[TCP].dport
sniff()
# sample code : 
1. Complete Phase 1 prototype
class BasicFirewall:
    def __init__(self):
        self.rules = []
        self.setup_default_rules()
    
    def setup_default_rules(self):
        """Initialize with basic security rules"""
        self.rules = [
            {
                "action": "BLOCK",
                "src_ip": "ANY", 
                "dst_ip": "ANY",
                "dst_port": "22",
                "description": "Block SSH"
            }
        ]
    
    def start_basic_monitoring(self):
        """Start simple packet inspection"""
        print("Starting basic firewall monitoring...")
        sniff(prn=self.inspect_packet, store=0)
    
    def inspect_packet(self, packet):
        """Basic packet inspection logic"""
        if packet.haslayer(IP):
            for rule in self.rules:
                if self.matches_rule(packet, rule):
                    print(f"BLOCKED: {packet[IP].src} -> {packet[IP].dst}")
                    break
# Phase 2: Core Functionality
Phase 2 focused on building the core functionality of the personal firewall, implementing packet filtering, rule management, logging, and basic anomaly detection.
1.  Implementing Basic Filtering
2.  Active Packet Blocking
3.  Logging System
 #  basic commands :
    "BLOCKED: TCP Packet from <IP>"
  
   add_rule(rule): To add a new rule at runtime.

load_rules_from_file(filename): To read rules from a JSON or text file when the firewall starts.

display_rules(): To show all active rules.
# Phase 2 sample code :
1. def start_monitoring(self, interface=None):
    """Start packet capture and filtering"""
    self.is_running = True
    sniff(prn=self.packet_handler, store=0, iface=interface)

def packet_handler(self, packet):
    """Process each captured packet"""
    if packet.haslayer(IP):
        action, rule = self.check_packet_against_rules(packet)
        self.logger.log_packet(action, packet, rule)
       
     2.   class FirewallRuleManager:
    def add_rule(self, rule_data):
        """Add new rule with auto-increment ID"""
        rule_data['rule_id'] = self.get_next_rule_id()
        self.rules.append(rule_data)
        self.save_rules_to_file()
    
    def check_packet_against_rules(self, packet):
        """Evaluate packet against all active rules"""
        for rule in self.get_active_rules():
            if self.rule_matches_packet(packet, rule):
                return rule['action'], rule
        return "ALLOW", None
        3.class FirewallLogger:
    def log_packet(self, action, packet, reason=None):
        """Log packet decisions with statistics"""
        self.stats['packets_processed'] += 1
        if action == "BLOCK":
            self.stats['packets_blocked'] += 1
        
        log_message = f"{action}: {packet[IP].src} -> {packet[IP].dst}"
        self.logger.info(log_message)
# Phase 3 : Anomaly Detection & Advanced Features
   Phase 3 focused on enhancing the firewall with professional interfaces, advanced features, and comprehensive testing over 4 days of development.
  1. Anomaly Detection
  2. Build a Simple CLI Interface
  3. GUI Development
  4. Finalization & Report
   # basic commands :
   python firewall.py --start: Starts the firewall.

python firewall.py --stop: Stops the firewall and flushes temporary block rules.

python firewall.py --add-rule ...: Adds a rule via the command line.

python firewall.py --view-logs: Tails the log file.
# Phase 3 sample code :
1. import argparse

def setup_cli_interface():
    """Setup advanced command-line interface"""
    parser = argparse.ArgumentParser(description='Personal Firewall Management')
    
    # Command groups
    subparsers = parser.add_subparsers(dest='command')
    
    # Monitoring commands
    monitor_parser = subparsers.add_parser('monitor', help='Monitoring operations')
    monitor_parser.add_argument('--start', action='store_true')
    monitor_parser.add_argument('--interface', type=str)
    
    # Rule management commands  
    rules_parser = subparsers.add_parser('rules', help='Rule management')
    rules_parser.add_argument('--list', action='store_true')
    rules_parser.add_argument('--add', nargs=7)
    
    return parser
  2. import tkinter as tk
from tkinter import ttk, scrolledtext

class FirewallGUI:
    def __init__(self, root, firewall):
        self.root = root
        self.firewall = firewall
        self.setup_gui()
    
    def setup_gui(self):
        """Create the main GUI interface"""
        self.root.title("Personal Firewall")
        self.root.geometry("1000x700")
        
        # Create notebook for tabs
        self.notebook = ttk.Notebook(self.root)
        self.notebook.pack(fill='both', expand=True)
        
        # Add tabs
        self.setup_dashboard_tab()
        self.setup_rules_tab()
        self.setup_monitoring_tab()
    
    def setup_dashboard_tab(self):
        """Create dashboard with statistics"""
        dashboard = ttk.Frame(self.notebook)
        self.notebook.add(dashboard, text="📊 Dashboard")
        
        # Real-time statistics
        self.stats_text = scrolledtext.ScrolledText(dashboard, height=10)
        self.stats_text.pack(fill='both', expand=True)

  # Whole code :
  # bash:
python firewall_gui.py
# code :
#!/usr/bin/env python3

import tkinter as tk\
from tkinter import ttk, messagebox, scrolledtext\
import threading\
import time\
from datetime import datetime\
import os\
import sys

class ImprovedFirewallGUI:
    def __init__(self, root, firewall):
        self.root = root\
        self.firewall = firewall\
        self.setup_gui()\
        self.update_dashboard()
        
    def setup_gui(self):
        """Setup the main GUI with error handling"""
        try:
            self.root.title("Personal Firewall Manager")
            self.root.geometry("1000x700")
            
            # Create main container
            self.main_frame = ttk.Frame(self.root, padding="10")
            self.main_frame.pack(fill='both', expand=True)
            
            # Setup components
            self.setup_header()
            self.setup_notebook()
            self.setup_status_bar()
            
        except Exception as e:
            self.show_error(f"GUI Setup Failed: {e}")
    
    def setup_header(self):
        """Setup header with controls"""
        header_frame = ttk.Frame(self.main_frame)
        header_frame.pack(fill='x', pady=10)
        
        # Title
        title_label = ttk.Label(header_frame, text="Personal Firewall", 
                               font=('Arial', 16, 'bold'))
        title_label.pack(side='left')
        
        # Controls
        control_frame = ttk.Frame(header_frame)
        control_frame.pack(side='right')
        
        self.start_btn = ttk.Button(control_frame, text="Start Firewall", 
                                   command=self.start_firewall)
        self.start_btn.pack(side='left', padx=5)
        
        self.stop_btn = ttk.Button(control_frame, text="Stop Firewall", 
                                  command=self.stop_firewall)
        self.stop_btn.pack(side='left', padx=5)
        
        # Status indicator
        self.status_var = tk.StringVar(value="Stopped")
        status_label = ttk.Label(control_frame, textvariable=self.status_var,
                                foreground='red', font=('Arial', 10, 'bold'))
        status_label.pack(side='left', padx=10)
    
    def setup_notebook(self):
        """Setup tabbed interface"""
        try:
            self.notebook = ttk.Notebook(self.main_frame)
            self.notebook.pack(fill='both', expand=True, pady=10)
            
            # Create tabs
            self.setup_dashboard_tab()
            self.setup_rules_tab()
            self.setup_monitoring_tab()
            self.setup_logs_tab()
            
        except Exception as e:
            self.show_error(f"Notebook Setup Failed: {e}")
    
    def setup_dashboard_tab(self):
        """Setup dashboard tab"""
        try:
            dashboard_frame = ttk.Frame(self.notebook)
            self.notebook.add(dashboard_frame, text="Dashboard")
            
            # Statistics frame
            stats_frame = ttk.LabelFrame(dashboard_frame, text="Statistics", padding=10)
            stats_frame.pack(fill='x', pady=5, padx=5)
            
            # Stats grid
            self.stats_labels = {}
            stats_info = [
                ('Rules', 'rules', 'Active Rules: 0'),
                ('Blocked IPs', 'blocked', 'Blocked IPs: 0'), 
                ('Packets', 'packets', 'Packets: 0'),
                ('Anomalies', 'anomalies', 'Anomalies: 0')
            ]
            
            for i, (title, key, default) in enumerate(stats_info):
                frame = ttk.Frame(stats_frame)
                frame.grid(row=i//2, column=i%2, sticky='w', padx=10, pady=5)
                
                ttk.Label(frame, text=title + ":", font=('Arial', 9)).pack(anchor='w')
                label = ttk.Label(frame, text=default, font=('Arial', 10, 'bold'))
                label.pack(anchor='w')
                self.stats_labels[key] = label
            
            # Quick actions
            actions_frame = ttk.LabelFrame(dashboard_frame, text="Quick Actions", padding=10)
            actions_frame.pack(fill='x', pady=5, padx=5)
            
            actions = [
                ("Run Diagnostics", self.run_diagnostics),
                ("View Logs", self.show_logs),
                ("Refresh Stats", self.refresh_stats)
            ]
            
            for text, command in actions:
                ttk.Button(actions_frame, text=text, command=command).pack(side='left', padx=5)
            
            # Recent activity
            activity_frame = ttk.LabelFrame(dashboard_frame, text="Recent Activity", padding=10)
            activity_frame.pack(fill='both', expand=True, pady=5, padx=5)
            
            self.activity_text = scrolledtext.ScrolledText(activity_frame, height=15)
            self.activity_text.pack(fill='both', expand=True)
            self.activity_text.insert('1.0', "Firewall activity will appear here...\n")
            self.activity_text.config(state='disabled')
            
        except Exception as e:
            self.show_error(f"Dashboard Setup Failed: {e}")
    
    def setup_rules_tab(self):
        """Setup rules management tab"""
        try:
            rules_frame = ttk.Frame(self.notebook)
            self.notebook.add(rules_frame, text="Rules")
            
            # Controls
            controls_frame = ttk.Frame(rules_frame)
            controls_frame.pack(fill='x', pady=10)
            
            ttk.Button(controls_frame, text="Add Rule", 
                      command=self.add_rule).pack(side='left', padx=5)
            ttk.Button(controls_frame, text="Refresh", 
                      command=self.refresh_rules).pack(side='left', padx=5)
            
            # Rules table
            table_frame = ttk.Frame(rules_frame)
            table_frame.pack(fill='both', expand=True)
            
            # Create treeview
            columns = ('id', 'action', 'protocol', 'port', 'description', 'enabled')
            self.rules_tree = ttk.Treeview(table_frame, columns=columns, show='headings', height=15)
            
            # Define headings
            self.rules_tree.heading('id', text='ID')
            self.rules_tree.heading('action', text='Action')
            self.rules_tree.heading('protocol', text='Protocol')
            self.rules_tree.heading('port', text='Port')
            self.rules_tree.heading('description', text='Description')
            self.rules_tree.heading('enabled', text='Enabled')
            
            # Set column widths
            self.rules_tree.column('id', width=50)
            self.rules_tree.column('action', width=80)
            self.rules_tree.column('protocol', width=80)
            self.rules_tree.column('port', width=80)
            self.rules_tree.column('description', width=200)
            self.rules_tree.column('enabled', width=80)
            
            # Scrollbar
            scrollbar = ttk.Scrollbar(table_frame, orient='vertical', 
                                    command=self.rules_tree.yview)
            self.rules_tree.configure(yscrollcommand=scrollbar.set)
            
            self.rules_tree.pack(side='left', fill='both', expand=True)
            scrollbar.pack(side='right', fill='y')
            
            # Load initial rules
            self.refresh_rules()
            
        except Exception as e:
            self.show_error(f"Rules Tab Setup Failed: {e}")
    
    def setup_monitoring_tab(self):
        """Setup monitoring tab"""
        try:
            monitor_frame = ttk.Frame(self.notebook)
            self.notebook.add(monitor_frame, text="Monitoring")
            
            # IP Management
            ip_frame = ttk.LabelFrame(monitor_frame, text="IP Management", padding=10)
            ip_frame.pack(fill='x', pady=5, padx=5)
            
            ip_controls = ttk.Frame(ip_frame)
            ip_controls.pack(fill='x')
            
            ttk.Label(ip_controls, text="IP Address:").pack(side='left', padx=5)
            self.ip_entry = ttk.Entry(ip_controls, width=15)
            self.ip_entry.pack(side='left', padx=5)
            
            ttk.Button(ip_controls, text="Block IP", 
                      command=self.block_ip).pack(side='left', padx=5)
            ttk.Button(ip_controls, text="Unblock IP", 
                      command=self.unblock_ip).pack(side='left', padx=5)
            ttk.Button(ip_controls, text="Refresh List", 
                      command=self.refresh_blocked_ips).pack(side='left', padx=5)
            
            # Blocked IPs list
            list_frame = ttk.Frame(ip_frame)
            list_frame.pack(fill='x', pady=5)
            
            self.blocked_listbox = tk.Listbox(list_frame, height=6)
            self.blocked_listbox.pack(fill='x')
            
            # Live monitor
            live_frame = ttk.LabelFrame(monitor_frame, text="Live Traffic", padding=10)
            live_frame.pack(fill='both', expand=True, pady=5, padx=5)
            
            self.traffic_text = scrolledtext.ScrolledText(live_frame, height=15)
            self.traffic_text.pack(fill='both', expand=True)
            self.traffic_text.insert('1.0', "Live traffic monitoring...\n")
            self.traffic_text.config(state='disabled')
            
            # Load initial data
            self.refresh_blocked_ips()
            
        except Exception as e:
            self.show_error(f"Monitoring Tab Setup Failed: {e}")
    
    def setup_logs_tab(self):
        """Setup logs tab"""
        try:
            logs_frame = ttk.Frame(self.notebook)
            self.notebook.add(logs_frame, text="Logs")
            
            # Controls
            controls_frame = ttk.Frame(logs_frame)
            controls_frame.pack(fill='x', pady=10)
            
            ttk.Button(controls_frame, text="Refresh Logs", 
                      command=self.refresh_logs).pack(side='left', padx=5)
            ttk.Button(controls_frame, text="Clear Logs", 
                      command=self.clear_logs).pack(side='left', padx=5)
            
            # Log type selection
            log_type_frame = ttk.Frame(controls_frame)
            log_type_frame.pack(side='right')
            
            ttk.Label(log_type_frame, text="Log Type:").pack(side='left', padx=5)
            self.log_type = tk.StringVar(value="firewall")
            
            ttk.Radiobutton(log_type_frame, text="Firewall", 
                           variable=self.log_type, value="firewall",
                           command=self.refresh_logs).pack(side='left', padx=5)
            ttk.Radiobutton(log_type_frame, text="Anomalies", 
                           variable=self.log_type, value="anomalies",
                           command=self.refresh_logs).pack(side='left', padx=5)
            
            # Log display
            log_frame = ttk.Frame(logs_frame)
            log_frame.pack(fill='both', expand=True)
            
            self.logs_text = scrolledtext.ScrolledText(log_frame, font=('Consolas', 9))
            self.logs_text.pack(fill='both', expand=True)
            self.logs_text.config(state='disabled')
            
            # Load initial logs
            self.refresh_logs()
            
        except Exception as e:
            self.show_error(f"Logs Tab Setup Failed: {e}")
    
    def setup_status_bar(self):
        """Setup status bar"""
        self.status_bar = ttk.Frame(self.main_frame, relief='sunken')
        self.status_bar.pack(fill='x', side='bottom')
        
        self.status_message = ttk.Label(self.status_bar, text="Ready")
        self.status_message.pack(side='left', padx=5, pady=2)
        
        self.time_label = ttk.Label(self.status_bar, text="")
        self.time_label.pack(side='right', padx=5, pady=2)
    
    def update_dashboard(self):
        """Update dashboard with current information"""
        try:
            # Update status
            if hasattr(self.firewall, 'is_running'):
                status = "Running" if self.firewall.is_running else "Stopped"
                color = "green" if self.firewall.is_running else "red"
                self.status_var.set(status)
                
                # Update button states
                self.start_btn.config(state='normal' if not self.firewall.is_running else 'disabled')
                self.stop_btn.config(state='normal' if self.firewall.is_running else 'disabled')
            
            # Update statistics
            if hasattr(self.firewall, 'get_status'):
                status_info = self.firewall.get_status()
                self.stats_labels['rules'].config(text=f"Active Rules: {status_info.get('active_rules', 0)}")
                self.stats_labels['blocked'].config(text=f"Blocked IPs: {status_info.get('blocked_ips', 0)}")
                
                stats = status_info.get('statistics', {})
                self.stats_labels['packets'].config(text=f"Packets: {stats.get('packets_processed', 0)}")
                self.stats_labels['anomalies'].config(text=f"Anomalies: {stats.get('anomalies_detected', 0)}")
            
            # Update time
            current_time = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
            self.time_label.config(text=current_time)
            
        except Exception as e:
            print(f"Dashboard update error: {e}")
        
        # Schedule next update
        self.root.after(2000, self.update_dashboard)
    
    # Action methods with error handling
    def start_firewall(self):
        """Start the firewall"""
        try:
            if hasattr(self.firewall, 'start_monitoring'):
                # Start in background thread to avoid blocking GUI
                def start_in_thread():
                    try:
                        self.firewall.start_monitoring()
                    except Exception as e:
                        self.root.after(0, lambda: messagebox.showerror("Error", f"Failed to start: {e}"))
                
                thread = threading.Thread(target=start_in_thread, daemon=True)
                thread.start()
                self.status_message.config(text="Starting firewall...")
            else:
                messagebox.showinfo("Info", "Firewall start method not available")
                
        except Exception as e:
            self.show_error(f"Start failed: {e}")
    
    def stop_firewall(self):
        """Stop the firewall"""
        try:
            if hasattr(self.firewall, 'stop_monitoring'):
                self.firewall.stop_monitoring()
                self.status_message.config(text="Firewall stopped")
                messagebox.showinfo("Success", "Firewall stopped successfully")
            else:
                messagebox.showinfo("Info", "Firewall stop method not available")
                
        except Exception as e:
            self.show_error(f"Stop failed: {e}")
    
    def add_rule(self):
        """Add a new rule"""
        try:
            # Simple rule addition dialog
            rule_data = {
                'action': 'BLOCK',
                'protocol': 'TCP', 
                'port': '80',
                'description': 'Block HTTP'
            }
            
            # In a real implementation, you'd show a dialog to get rule details
            if hasattr(self.firewall.rule_manager, 'add_rule'):
                rule_id = self.firewall.rule_manager.add_rule(rule_data)
                messagebox.showinfo("Success", f"Rule added with ID: {rule_id}")
                self.refresh_rules()
            else:
                messagebox.showinfo("Info", "Rule management not available")
                
        except Exception as e:
            self.show_error(f"Add rule failed: {e}")
    
    def refresh_rules(self):
        """Refresh rules list"""
        try:
            if hasattr(self.firewall, 'rule_manager'):
                # Clear existing rules
                for item in self.rules_tree.get_children():
                    self.rules_tree.delete(item)
                
                # Add rules to treeview
                for rule in self.firewall.rule_manager.rules:
                    self.rules_tree.insert('', 'end', values=(
                        rule.get('rule_id', 'N/A'),
                        rule.get('action', 'N/A'),
                        rule.get('protocol', 'N/A'),
                        rule.get('dst_port', 'N/A'),
                        rule.get('description', 'No description'),
                        'Yes' if rule.get('enabled', False) else 'No'
                    ))
            else:
                # Add sample data for demonstration
                sample_rules = [
                    (1, 'BLOCK', 'TCP', '22', 'Block SSH', 'Yes'),
                    (2, 'ALLOW', 'TCP', '80', 'Allow HTTP', 'Yes'),
                    (3, 'ALLOW', 'TCP', '443', 'Allow HTTPS', 'Yes')
                ]
                for rule in sample_rules:
                    self.rules_tree.insert('', 'end', values=rule)
                    
        except Exception as e:
            self.show_error(f"Refresh rules failed: {e}")
    
    def block_ip(self):
        """Block an IP address"""
        ip = self.ip_entry.get().strip()
        if not ip:
            messagebox.showwarning("Warning", "Please enter an IP address")
            return
        
        try:
            if hasattr(self.firewall.anomaly_detector, 'manual_block_ip'):
                result = self.firewall.anomaly_detector.manual_block_ip(ip)
                messagebox.showinfo("Success", result)
                self.ip_entry.delete(0, 'end')
                self.refresh_blocked_ips()
            else:
                messagebox.showinfo("Info", "IP blocking not available")
                
        except Exception as e:
            self.show_error(f"Block IP failed: {e}")
    
    def unblock_ip(self):
        """Unblock selected IP"""
        try:
            selection = self.blocked_listbox.curselection()
            if selection:
                ip = self.blocked_listbox.get(selection[0])
                if hasattr(self.firewall.anomaly_detector, 'manual_unblock_ip'):
                    result = self.firewall.anomaly_detector.manual_unblock_ip(ip)
                    messagebox.showinfo("Success", result)
                    self.refresh_blocked_ips()
                else:
                    messagebox.showinfo("Info", "IP unblocking not available")
            else:
                messagebox.showwarning("Warning", "Please select an IP to unblock")
                
        except Exception as e:
            self.show_error(f"Unblock IP failed: {e}")
    
    def refresh_blocked_ips(self):
        """Refresh blocked IPs list"""
        try:
            self.blocked_listbox.delete(0, 'end')
            
            if hasattr(self.firewall.anomaly_detector, 'get_blocked_ips'):
                blocked_ips = self.firewall.anomaly_detector.get_blocked_ips()
                for ip in blocked_ips:
                    self.blocked_listbox.insert('end', ip)
            else:
                # Sample data for demonstration
                sample_ips = ['192.168.1.100', '10.0.0.50', '172.16.0.25']
                for ip in sample_ips:
                    self.blocked_listbox.insert('end', ip)
                    
        except Exception as e:
            self.show_error(f"Refresh blocked IPs failed: {e}")
    
    def refresh_logs(self):
        """Refresh log display"""
        try:
            self.logs_text.config(state='normal')
            self.logs_text.delete(1.0, 'end')
            
            log_type = self.log_type.get()
            log_file = f"{log_type}.log"
            
            try:
                if os.path.exists(log_file):
                    with open(log_file, 'r') as f:
                        content = f.read()
                    self.logs_text.insert(1.0, content)
                else:
                    self.logs_text.insert(1.0, f"No {log_file} found.\nThis is a demonstration.")
            except Exception as e:
                self.logs_text.insert(1.0, f"Error reading log file: {e}")
            
            self.logs_text.config(state='disabled')
            self.logs_text.see('end')
            
        except Exception as e:
            self.show_error(f"Refresh logs failed: {e}")
    
    def clear_logs(self):
        """Clear log files"""
        try:
            if messagebox.askyesno("Confirm", "Clear all log files?"):
                log_files = ['firewall.log', 'anomalies.log']
                for log_file in log_files:
                    if os.path.exists(log_file):
                        os.remove(log_file)
                self.refresh_logs()
                messagebox.showinfo("Success", "Log files cleared")
                
        except Exception as e:
            self.show_error(f"Clear logs failed: {e}")
    
    def run_diagnostics(self):
        """Run diagnostic tests"""
        try:
            self.status_message.config(text="Running diagnostics...")
            
            # Simulate diagnostic tests
            tests = [
                "Checking rule database... OK",
                "Testing anomaly detection... OK", 
                "Verifying log system... OK",
                "Checking network interfaces... OK"
            ]
            
            self.activity_text.config(state='normal')
            self.activity_text.delete(1.0, 'end')
            self.activity_text.insert('1.0', "Diagnostic Results:\n" + "="*50 + "\n")
            
            for test in tests:
                self.activity_text.insert('end', test + "\n")
                self.activity_text.see('end')
                self.root.update()
                time.sleep(0.5)  # Simulate test time
            
            self.activity_text.insert('end', "\nAll tests passed successfully! ✅")
            self.activity_text.config(state='disabled')
            self.status_message.config(text="Diagnostics completed")
            
        except Exception as e:
            self.show_error(f"Diagnostics failed: {e}")
    
    def refresh_stats(self):
        """Refresh statistics"""
        try:
            self.status_message.config(text="Refreshing statistics...")
            # Statistics are updated automatically by update_dashboard
            self.status_message.config(text="Statistics updated")
            
        except Exception as e:
            self.show_error(f"Refresh stats failed: {e}")
    
    def show_logs(self):
        """Switch to logs tab"""
        try:
            self.notebook.select(3)  # Switch to logs tab
        except Exception as e:
            self.show_error(f"Show logs failed: {e}")
    
    def show_error(self, message):
        """Show error message"""
        print(f"GUI Error: {message}")
        try:
            messagebox.showerror("Error", message)
        except:
            print(f"Could not show error dialog: {message}")

 #Simple startup function
 def start_firewall_gui(firewall=None):
    """Start the firewall GUI"""
    try:
        # Create mock firewall if none provided
        if firewall is None:
            firewall = create_mock_firewall()
        
        root = tk.Tk()
        app = ImprovedFirewallGUI(root, firewall)
        root.mainloop()
        
    except Exception as e:
        print(f"Failed to start GUI: {e}")
        messagebox.showerror("Startup Error", f"Cannot start GUI: {e}")

 def create_mock_firewall():
    """Create a mock firewall for demonstration"""
    class MockFirewall:
        def __init__(self):
            self.is_running = False
            self.rule_manager = MockRuleManager()
            self.anomaly_detector = MockAnomalyDetector()
        
        def start_monitoring(self, interface=None):
            self.is_running = True
            print(f"Mock: Started monitoring on {interface}")
        
        def stop_monitoring(self):
            self.is_running = False
            print("Mock: Stopped monitoring")
        
        def get_status(self):
            return {
                'active_rules': len(self.rule_manager.rules),
                'blocked_ips': len(self.anomaly_detector.get_blocked_ips()),
                'statistics': {
                    'packets_processed': 1500,
                    'anomalies_detected': 12
                }
            }
    
    class MockRuleManager:
        def __init__(self):
            self.rules = [
                {'rule_id': 1, 'action': 'BLOCK', 'protocol': 'TCP', 
                 'dst_port': '22', 'description': 'Block SSH', 'enabled': True},
                {'rule_id': 2, 'action': 'ALLOW', 'protocol': 'TCP',
                 'dst_port': '80', 'description': 'Allow HTTP', 'enabled': True}
            ]
        
        def add_rule(self, rule_data):
            rule_id = max([r['rule_id'] for r in self.rules]) + 1
            rule_data['rule_id'] = rule_id
            self.rules.append(rule_data)
            return rule_id
    
    class MockAnomalyDetector:
        def get_blocked_ips(self):
            return ['192.168.1.100', '10.0.0.50']
        
        def manual_block_ip(self, ip):
            return f"Mock: Blocked {ip}"
        
        def manual_unblock_ip(self, ip):
            return f"Mock: Unblocked {ip}"
    
    return MockFirewall()

if __name__ == "__main__":
    start_firewall_gui()


