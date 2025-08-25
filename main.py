#!/usr/bin/env python3
import scapy.all as scapy
from scapy.layers.http import HTTPRequest
from scapy.layers.dns import DNS, DNSQR
import threading
import time
import json
import csv
from datetime import datetime
import os
import tkinter as tk
from tkinter import ttk, messagebox, filedialog
import matplotlib.pyplot as plt
from matplotlib.backends.backend_tkagg import FigureCanvasTkagg
import matplotlib
matplotlib.use('TkAgg')

class PacketSnifferGUI:
    def __init__(self, root):
        self.root = root
        self.root.title("Network Packet Sniffer/Analyzer")
        self.root.geometry("1200x800")
        self.root.minsize(1000, 700)
        
        self.sniffer_thread = None
        self.running = False
        self.interface = tk.StringVar(value="default")
        self.packet_count = tk.IntVar(value=0)
        self.max_packets = tk.IntVar(value=0)
        
        self.packets = []
        self.dns_queries = []
        self.http_requests = []
        self.anomalies = []
        self.stats = {
            'total_packets': 0,
            'tcp_packets': 0,
            'udp_packets': 0,
            'icmp_packets': 0,
            'http_requests': 0,
            'dns_queries': 0
        }
        
        self.setup_gui()
        self.update_interface_list()
        
    def setup_gui(self):
        self.create_control_panel()
        self.create_notebook_tabs()
        self.create_status_bar()
        
    def create_control_panel(self):
        control_frame = ttk.Frame(self.root, padding="10")
        control_frame.pack(fill=tk.X, padx=10, pady=5)
        
        ttk.Label(control_frame, text="Interface:").grid(row=0, column=0, sticky=tk.W, padx=(0, 5))
        self.interface_combo = ttk.Combobox(control_frame, textvariable=self.interface, width=15)
        self.interface_combo.grid(row=0, column=1, sticky=tk.W, padx=(0, 10))
        ttk.Button(control_frame, text="Refresh", command=self.update_interface_list).grid(row=0, column=2, padx=(0, 10))
        
        ttk.Label(control_frame, text="Max Packets (0=∞):").grid(row=0, column=3, sticky=tk.W, padx=(10, 5))
        ttk.Entry(control_frame, textvariable=self.max_packets, width=10).grid(row=0, column=4, padx=(0, 10))
        
        self.start_button = ttk.Button(control_frame, text="Start Sniffing", command=self.start_sniffing)
        self.start_button.grid(row=0, column=5, padx=(0, 5))
        self.stop_button = ttk.Button(control_frame, text="Stop Sniffing", command=self.stop_sniffing, state=tk.DISABLED)
        self.stop_button.grid(row=0, column=6, padx=(0, 5))
        ttk.Button(control_frame, text="Save Results", command=self.save_results).grid(row=0, column=7, padx=(0, 5))
        ttk.Button(control_frame, text="Clear Data", command=self.clear_data).grid(row=0, column=8)
        
        self.counter_label = ttk.Label(control_frame, text="Packets: 0")
        self.counter_label.grid(row=0, column=9, padx=(20, 0))
        
    def create_notebook_tabs(self):
        self.notebook = ttk.Notebook(self.root)
        self.notebook.pack(fill=tk.BOTH, expand=True, padx=10, pady=5)
        
        self.packets_frame = ttk.Frame(self.notebook)
        self.notebook.add(self.packets_frame, text="Packets")
        self.create_packets_tab()
        
        self.stats_frame = ttk.Frame(self.notebook)
        self.notebook.add(self.stats_frame, text="Statistics")
        self.create_stats_tab()
        
        self.dns_frame = ttk.Frame(self.notebook)
        self.notebook.add(self.dns_frame, text="DNS")
        self.create_dns_tab()
        
        self.http_frame = ttk.Frame(self.notebook)
        self.notebook.add(self.http_frame, text="HTTP")
        self.create_http_tab()
        
        self.anomalies_frame = ttk.Frame(self.notebook)
        self.notebook.add(self.anomalies_frame, text="Anomalies")
        self.create_anomalies_tab()
        
        self.viz_frame = ttk.Frame(self.notebook)
        self.notebook.add(self.viz_frame, text="Visualization")
        self.create_viz_tab()
        
    def create_packets_tab(self):
        columns = ("Time", "Protocol", "Source", "Destination", "Length")
        self.packets_tree = ttk.Treeview(self.packets_frame, columns=columns, show="headings", height=15)
        
        for col in columns:
            self.packets_tree.heading(col, text=col)
            self.packets_tree.column(col, width=150)
        
        v_scroll = ttk.Scrollbar(self.packets_frame, orient=tk.VERTICAL, command=self.packets_tree.yview)
        h_scroll = ttk.Scrollbar(self.packets_frame, orient=tk.HORIZONTAL, command=self.packets_tree.xview)
        self.packets_tree.configure(yscrollcommand=v_scroll.set, xscrollcommand=h_scroll.set)
        
        self.packets_tree.grid(row=0, column=0, sticky="nsew")
        v_scroll.grid(row=0, column=1, sticky="ns")
        h_scroll.grid(row=1, column=0, sticky="ew")
        
        self.packets_frame.grid_rowconfigure(0, weight=1)
        self.packets_frame.grid_columnconfigure(0, weight=1)
        
        details_frame = ttk.LabelFrame(self.packets_frame, text="Packet Details", padding="10")
        details_frame.grid(row=2, column=0, columnspan=2, sticky="ew", pady=(10, 0))
        
        self.packet_details_text = tk.Text(details_frame, height=8, wrap=tk.WORD)
        details_scroll = ttk.Scrollbar(details_frame, orient=tk.VERTICAL, command=self.packet_details_text.yview)
        self.packet_details_text.configure(yscrollcommand=details_scroll.set)
        
        self.packet_details_text.grid(row=0, column=0, sticky="nsew")
        details_scroll.grid(row=0, column=1, sticky="ns")
        
        details_frame.grid_rowconfigure(0, weight=1)
        details_frame.grid_columnconfigure(0, weight=1)
        
        self.packets_tree.bind("<<TreeviewSelect>>", self.on_packet_select)
        
    def create_stats_tab(self):
        protocol_frame = ttk.LabelFrame(self.stats_frame, text="Protocol Distribution", padding="10")
        protocol_frame.pack(fill=tk.BOTH, expand=True, padx=10, pady=10)
        
        self.protocol_text = tk.Text(protocol_frame, wrap=tk.WORD)
        protocol_scroll = ttk.Scrollbar(protocol_frame, orient=tk.VERTICAL, command=self.protocol_text.yview)
        self.protocol_text.configure(yscrollcommand=protocol_scroll.set)
        
        self.protocol_text.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
        protocol_scroll.pack(side=tk.RIGHT, fill=tk.Y)
        
        traffic_frame = ttk.LabelFrame(self.stats_frame, text="Traffic Statistics", padding="10")
        traffic_frame.pack(fill=tk.BOTH, expand=True, padx=10, pady=10)
        
        self.traffic_text = tk.Text(traffic_frame, wrap=tk.WORD)
        traffic_scroll = ttk.Scrollbar(traffic_frame, orient=tk.VERTICAL, command=self.traffic_text.yview)
        self.traffic_text.configure(yscrollcommand=traffic_scroll.set)
        
        self.traffic_text.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
        traffic_scroll.pack(side=tk.RIGHT, fill=tk.Y)
        
        ttk.Button(self.stats_frame, text="Refresh Statistics", command=self.update_stats_display).pack(pady=10)
        
    def create_dns_tab(self):
        columns = ("Time", "Source", "Query", "Type")
        self.dns_tree = ttk.Treeview(self.dns_frame, columns=columns, show="headings", height=15)
        
        for col in columns:
            self.dns_tree.heading(col, text=col)
            self.dns_tree.column(col, width=200)
        
        v_scroll = ttk.Scrollbar(self.dns_frame, orient=tk.VERTICAL, command=self.dns_tree.yview)
        h_scroll = ttk.Scrollbar(self.dns_frame, orient=tk.HORIZONTAL, command=self.dns_tree.xview)
        self.dns_tree.configure(yscrollcommand=v_scroll.set, xscrollcommand=h_scroll.set)
        
        self.dns_tree.grid(row=0, column=0, sticky="nsew")
        v_scroll.grid(row=0, column=1, sticky="ns")
        h_scroll.grid(row=1, column=0, sticky="ew")
        
        self.dns_frame.grid_rowconfigure(0, weight=1)
        self.dns_frame.grid_columnconfigure(0, weight=1)
        
    def create_http_tab(self):
        columns = ("Time", "Method", "Host", "Path", "User-Agent")
        self.http_tree = ttk.Treeview(self.http_frame, columns=columns, show="headings", height=15)
        
        for col in columns:
            self.http_tree.heading(col, text=col)
            self.http_tree.column(col, width=150)
        
        v_scroll = ttk.Scrollbar(self.http_frame, orient=tk.VERTICAL, command=self.http_tree.yview)
        h_scroll = ttk.Scrollbar(self.http_frame, orient=tk.HORIZONTAL, command=self.http_tree.xview)
        self.http_tree.configure(yscrollcommand=v_scroll.set, xscrollcommand=h_scroll.set)
        
        self.http_tree.grid(row=0, column=0, sticky="nsew")
        v_scroll.grid(row=0, column=1, sticky="ns")
        h_scroll.grid(row=1, column=0, sticky="ew")
        
        self.http_frame.grid_rowconfigure(0, weight=1)
        self.http_frame.grid_columnconfigure(0, weight=1)
        
    def create_anomalies_tab(self):
        columns = ("Time", "Source", "Destination", "Description")
        self.anomalies_tree = ttk.Treeview(self.anomalies_frame, columns=columns, show="headings", height=15)
        
        for col in columns:
            self.anomalies_tree.heading(col, text=col)
            self.anomalies_tree.column(col, width=200)
        
        v_scroll = ttk.Scrollbar(self.anomalies_frame, orient=tk.VERTICAL, command=self.anomalies_tree.yview)
        h_scroll = ttk.Scrollbar(self.anomalies_frame, orient=tk.HORIZONTAL, command=self.anomalies_tree.xview)
        self.anomalies_tree.configure(yscrollcommand=v_scroll.set, xscrollcommand=h_scroll.set)
        
        self.anomalies_tree.grid(row=0, column=0, sticky="nsew")
        v_scroll.grid(row=0, column=1, sticky="ns")
        h_scroll.grid(row=1, column=0, sticky="ew")
        
        self.anomalies_frame.grid_rowconfigure(0, weight=1)
        self.anomalies_frame.grid_columnconfigure(0, weight=1)
        
    def create_viz_tab(self):
        self.fig, self.ax = plt.subplots(figsize=(10, 6))
        self.fig.patch.set_facecolor('white')
        
        self.canvas = FigureCanvasTkagg(self.fig, self.viz_frame)
        self.canvas.get_tk_widget().pack(fill=tk.BOTH, expand=True, padx=10, pady=10)
        
        viz_control_frame = ttk.Frame(self.viz_frame)
        viz_control_frame.pack(fill=tk.X, padx=10, pady=5)
        
        ttk.Button(viz_control_frame, text="Refresh Chart", command=self.update_chart).pack(side=tk.LEFT)
        self.chart_type = tk.StringVar(value="protocol")
        ttk.Radiobutton(viz_control_frame, text="Protocol Distribution", variable=self.chart_type, 
                       value="protocol", command=self.update_chart).pack(side=tk.LEFT, padx=(20, 10))
        ttk.Radiobutton(viz_control_frame, text="Traffic Over Time", variable=self.chart_type, 
                       value="traffic", command=self.update_chart).pack(side=tk.LEFT, padx=(0, 10))
        
        self.update_chart()
        
    def create_status_bar(self):
        self.status_var = tk.StringVar(value="Ready")
        status_bar = ttk.Label(self.root, textvariable=self.status_var, relief=tk.SUNKEN, anchor=tk.W)
        status_bar.pack(side=tk.BOTTOM, fill=tk.X)
        
    def update_interface_list(self):
        try:
            interfaces = scapy.get_if_list()
            self.interface_combo['values'] = interfaces
            if interfaces:
                self.interface.set(interfaces[0])
        except Exception as e:
            messagebox.showerror("Error", f"Failed to get interfaces: {e}")
            
    def start_sniffing(self):
        if self.running:
            return
            
        self.running = True
        self.start_button.config(state=tk.DISABLED)
        self.stop_button.config(state=tk.NORMAL)
        self.status_var.set("Sniffing packets...")
        
        self.sniffer_thread = threading.Thread(target=self.sniff_packets, daemon=True)
        self.sniffer_thread.start()
        
    def stop_sniffing(self):
        self.running = False
        self.start_button.config(state=tk.NORMAL)
        self.stop_button.config(state=tk.DISABLED)
        self.status_var.set("Sniffing stopped")
        
    def sniff_packets(self):
        try:
            iface = self.interface.get() if self.interface.get() != "default" else None
            count = self.max_packets.get()
            
            scapy.sniff(
                iface=iface,
                prn=self.packet_handler,
                count=count if count > 0 else 0,
                stop_filter=self.should_stop
            )
        except Exception as e:
            self.root.after(0, lambda: messagebox.showerror("Error", f"Sniffing error: {e}"))
        finally:
            self.root.after(0, self.stop_sniffing)
            
    def should_stop(self, packet):
        return not self.running
        
    def packet_handler(self, packet):
        self.stats['total_packets'] += 1
        self.packet_count.set(self.stats['total_packets'])
        
        self.root.after(0, self.update_counter)
        
        if packet.haslayer(scapy.TCP):
            self.stats['tcp_packets'] += 1
        elif packet.haslayer(scapy.UDP):
            self.stats['udp_packets'] += 1
        elif packet.haslayer(scapy.ICMP):
            self.stats['icmp_packets'] += 1
        
        if packet.haslayer(HTTPRequest):
            self.process_http_request(packet)
        elif packet.haslayer(DNS):
            self.process_dns_packet(packet)
        
        self.detect_anomalies(packet)
        
        packet_info = self.extract_packet_info(packet)
        self.packets.append(packet_info)
        
        self.root.after(0, lambda: self.add_packet_to_display(packet_info))
        
    def process_http_request(self, packet):
        self.stats['http_requests'] += 1
        http_layer = packet[HTTPRequest]
        
        http_info = {
            'timestamp': datetime.now().strftime('%H:%M:%S'),
            'src_ip': packet[scapy.IP].src,
            'dst_ip': packet[scapy.IP].dst,
            'src_port': packet[scapy.TCP].sport,
            'dst_port': packet[scapy.TCP].dport,
            'method': http_layer.Method.decode() if http_layer.Method else 'UNKNOWN',
            'host': http_layer.Host.decode() if http_layer.Host else 'UNKNOWN',
            'path': http_layer.Path.decode() if http_layer.Path else '/',
            'user_agent': http_layer.User_Agent.decode() if http_layer.User_Agent else 'UNKNOWN'
        }
        
        self.http_requests.append(http_info)
        self.root.after(0, lambda: self.add_http_to_display(http_info))
        
    def process_dns_packet(self, packet):
        dns_layer = packet[DNS]
        
        if dns_layer.qr == 0:
            self.stats['dns_queries'] += 1
            if dns_layer.qd:
                dns_info = {
                    'timestamp': datetime.now().strftime('%H:%M:%S'),
                    'src_ip': packet[scapy.IP].src,
                    'dst_ip': packet[scapy.IP].dst,
                    'query': dns_layer.qd.qname.decode() if dns_layer.qd.qname else 'UNKNOWN',
                    'type': 'Query'
                }
                self.dns_queries.append(dns_info)
                self.root.after(0, lambda: self.add_dns_to_display(dns_info))
        
        elif dns_layer.qr == 1:
            if dns_layer.an:
                for i in range(dns_layer.ancount):
                    try:
                        answer = dns_layer.an[i]
                        if answer.type == 1:
                            dns_info = {
                                'timestamp': datetime.now().strftime('%H:%M:%S'),
                                'src_ip': packet[scapy.IP].src,
                                'dst_ip': packet[scapy.IP].dst,
                                'query': answer.rrname.decode() if answer.rrname else 'UNKNOWN',
                                'response': str(answer.rdata),
                                'type': 'Response'
                            }
                            self.dns_queries.append(dns_info)
                            self.root.after(0, lambda: self.add_dns_to_display(dns_info))
                    except Exception:
                        continue
                        
    def detect_anomalies(self, packet):
        anomalies = []
        
        if len(packet) > 1500:
            anomalies.append("Large packet detected")
        
        suspicious_ports = [22, 23, 445, 3389]
        if packet.haslayer(scapy.TCP):
            if packet[scapy.TCP].dport in suspicious_ports or packet[scapy.TCP].sport in suspicious_ports:
                anomalies.append(f"Suspicious port activity: {packet[scapy.TCP].dport}")
        
        if anomalies:
            anomaly_info = {
                'timestamp': datetime.now().strftime('%H:%M:%S'),
                'src_ip': packet[scapy.IP].src if packet.haslayer(scapy.IP) else 'UNKNOWN',
                'dst_ip': packet[scapy.IP].dst if packet.haslayer(scapy.IP) else 'UNKNOWN',
                'description': ', '.join(anomalies)
            }
            self.anomalies.append(anomaly_info)
            self.root.after(0, lambda: self.add_anomaly_to_display(anomaly_info))
            
    def extract_packet_info(self, packet):
        info = {
            'timestamp': datetime.now().strftime('%H:%M:%S'),
            'length': len(packet),
            'protocol': 'UNKNOWN'
        }
        
        if packet.haslayer(scapy.IP):
            info['src_ip'] = packet[scapy.IP].src
            info['dst_ip'] = packet[scapy.IP].dst
            info['protocol'] = packet[scapy.IP].proto
            
        if packet.haslayer(scapy.TCP):
            info['src_port'] = packet[scapy.TCP].sport
            info['dst_port'] = packet[scapy.TCP].dport
            info['protocol'] = 'TCP'
        elif packet.haslayer(scapy.UDP):
            info['src_port'] = packet[scapy.UDP].sport
            info['dst_port'] = packet[scapy.UDP].dport
            info['protocol'] = 'UDP'
        elif packet.haslayer(scapy.ICMP):
            info['protocol'] = 'ICMP'
            
        return info
        
    def add_packet_to_display(self, packet_info):
        src = f"{packet_info.get('src_ip', 'N/A')}:{packet_info.get('src_port', '')}"
        dst = f"{packet_info.get('dst_ip', 'N/A')}:{packet_info.get('dst_port', '')}"
        
        self.packets_tree.insert("", "end", values=(
            packet_info['timestamp'],
            packet_info['protocol'],
            src,
            dst,
            packet_info['length']
        ))
        
        self.packets_tree.yview_moveto(1)
        
    def add_dns_to_display(self, dns_info):
        self.dns_tree.insert("", "end", values=(
            dns_info['timestamp'],
            dns_info['src_ip'],
            dns_info['query'],
            dns_info['type']
        ))
        self.dns_tree.yview_moveto(1)
        
    def add_http_to_display(self, http_info):
        self.http_tree.insert("", "end", values=(
            http_info['timestamp'],
            http_info['method'],
            http_info['host'],
            http_info['path'],
            http_info['user_agent'][:50] + "..." if len(http_info['user_agent']) > 50 else http_info['user_agent']
        ))
        self.http_tree.yview_moveto(1)
        
    def add_anomaly_to_display(self, anomaly_info):
        self.anomalies_tree.insert("", "end", values=(
            anomaly_info['timestamp'],
            anomaly_info['src_ip'],
            anomaly_info['dst_ip'],
            anomaly_info['description']
        ))
        self.anomalies_tree.yview_moveto(1)
        
    def on_packet_select(self, event):
        selection = self.packets_tree.selection()
        if selection:
            item = self.packets_tree.item(selection[0])
            self.packet_details_text.delete(1.0, tk.END)
            self.packet_details_text.insert(tk.END, f"Selected packet: {item['values']}\n\n")
            self.packet_details_text.insert(tk.END, "Detailed packet analysis would appear here...")
            
    def update_counter(self):
        self.counter_label.config(text=f"Packets: {self.packet_count.get()}")
        
    def update_stats_display(self):
        # Protocol distribution
        protocol_stats = f"""Protocol Distribution:
            TCP Packets: {self.stats['tcp_packets']}
            UDP Packets: {self.stats['udp_packets']}
            ICMP Packets: {self.stats['icmp_packets']}
            HTTP Requests: {self.stats['http_requests']}
            DNS Queries: {self.stats['dns_queries']}
            Total Packets: {self.stats['total_packets']}"""
        
        self.protocol_text.delete(1.0, tk.END)
        self.protocol_text.insert(tk.END, protocol_stats)
        
        traffic_stats = f"""Traffic Statistics:
            Total Packets Captured: {self.stats['total_packets']}
            Average Packet Size: {sum(p['length'] for p in self.packets) / len(self.packets) if self.packets else 0:.2f} bytes
            Largest Packet: {max((p['length'] for p in self.packets), default=0)} bytes
            HTTP Requests: {self.stats['http_requests']}
            DNS Queries: {self.stats['dns_queries']}"""
        
        self.traffic_text.delete(1.0, tk.END)
        self.traffic_text.insert(tk.END, traffic_stats)
        
    def update_chart(self):
        self.ax.clear()
        
        if self.chart_type.get() == "protocol":
            labels = ['TCP', 'UDP', 'ICMP', 'Other']
            sizes = [
                self.stats['tcp_packets'],
                self.stats['udp_packets'],
                self.stats['icmp_packets'],
                max(0, self.stats['total_packets'] - self.stats['tcp_packets'] - 
                    self.stats['udp_packets'] - self.stats['icmp_packets'])
            ]
            
            if sum(sizes) > 0:
                self.ax.pie(sizes, labels=labels, autopct='%1.1f%%', startangle=90)
                self.ax.set_title("Protocol Distribution")
            else:
                self.ax.text(0.5, 0.5, "No data available", ha='center', va='center')
                
        else:
            if self.packets:
                time_counts = {}
                for packet in self.packets[-100:]:
                    minute = packet['timestamp'][:5]
                    time_counts[minute] = time_counts.get(minute, 0) + 1
                
                times = sorted(time_counts.keys())
                counts = [time_counts[t] for t in times]
                
                self.ax.plot(times, counts, marker='o')
                self.ax.set_title("Packets Over Time")
                self.ax.set_xlabel("Time (HH:MM)")
                self.ax.set_ylabel("Packet Count")
                self.ax.tick_params(axis='x', rotation=45)
            else:
                self.ax.text(0.5, 0.5, "No data available", ha='center', va='center')
                
        self.canvas.draw()
        
    def save_results(self):
        try:
            output_dir = filedialog.askdirectory(title="Select Output Directory")
            if not output_dir:
                return
                
            timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
            prefix = os.path.join(output_dir, f"packet_capture_{timestamp}")
            
            with open(f"{prefix}_stats.json", 'w') as f:
                json.dump(self.stats, f, indent=2)
            
            with open(f"{prefix}_packets.json", 'w') as f:
                json.dump(self.packets, f, indent=2)
            
            if self.dns_queries:
                with open(f"{prefix}_dns.csv", 'w', newline='') as f:
                    writer = csv.DictWriter(f, fieldnames=self.dns_queries[0].keys())
                    writer.writeheader()
                    writer.writerows(self.dns_queries)
            
            if self.http_requests:
                with open(f"{prefix}_http.csv", 'w', newline='') as f:
                    writer = csv.DictWriter(f, fieldnames=self.http_requests[0].keys())
                    writer.writeheader()
                    writer.writerows(self.http_requests)
            
            if self.anomalies:
                with open(f"{prefix}_anomalies.json", 'w') as f:
                    json.dump(self.anomalies, f, indent=2)
            
            messagebox.showinfo("Success", f"Results saved to {output_dir}")
        except Exception as e:
            messagebox.showerror("Error", f"Failed to save results: {e}")
            
    def clear_data(self):
        if messagebox.askyesno("Confirm", "Are you sure you want to clear all data?"):
            self.packets.clear()
            self.dns_queries.clear()
            self.http_requests.clear()
            self.anomalies.clear()
            
            for key in self.stats:
                self.stats[key] = 0
            self.packet_count.set(0)
            
            for tree in [self.packets_tree, self.dns_tree, self.http_tree, self.anomalies_tree]:
                for item in tree.get_children():
                    tree.delete(item)
                    
            self.protocol_text.delete(1.0, tk.END)
            self.traffic_text.delete(1.0, tk.END)
            self.packet_details_text.delete(1.0, tk.END)
            
            self.update_counter()
            self.update_stats_display()
            self.update_chart()
            
            self.status_var.set("Data cleared")

def main():
    root = tk.Tk()
    app = PacketSnifferGUI(root)
    
    def on_closing():
        if app.running:
            if messagebox.askokcancel("Quit", "Sniffing is in progress. Do you want to quit?"):
                app.running = False
                root.destroy()
        else:
            root.destroy()
            
    root.protocol("WM_DELETE_WINDOW", on_closing)
    root.mainloop()

if __name__ == "__main__":
    if os.geteuid() != 0:
        print("Warning: This application may require root/administrator privileges to capture packets.")
    
    main()