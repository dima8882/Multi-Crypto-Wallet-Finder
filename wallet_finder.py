## |/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\|
## |      PROGRAMMER = DIMA8882                 |
## |      GitGub = https://github.com/dima8882  |
## |/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\|
import tkinter as tk
from tkinter import ttk, scrolledtext, messagebox
import threading
import time
import os
import base58
import hashlib
import ecdsa
from datetime import datetime
from Crypto.Hash import keccak
import psutil
import matplotlib.pyplot as plt
from matplotlib.backends.backend_tkagg import FigureCanvasTkAgg
from matplotlib.figure import Figure
import random
import secrets
import bip32utils
from mnemonic import Mnemonic

class CryptoWalletFinder:
    def __init__(self, root):
        self.root = root
        self.root.title("Multi-Crypto Wallet Finder")
        self.root.geometry("1200x800")
        
        # Configure dark theme colors
        self.bg_color = '#1e1e2e'  # Dark blue-gray
        self.fg_color = '#cdd6f4'  # Light lavender
        self.accent_color = '#89b4fa'  # Light blue
        self.success_color = '#a6e3a1'  # Soft green
        self.warning_color = '#f9e2af'  # Soft yellow
        self.error_color = '#f38ba8'  # Soft red
        self.widget_bg = '#313244'  # Widget background
        self.border_color = '#45475a'  # Border color
        
        # Apply dark theme to root window
        self.root.configure(bg=self.bg_color)
        
        # Statistics variables
        self.start_time = time.time()
        self.total_wallets_checked = 0
        self.found_wallets = 0
        self.is_running = False
        self.threads = []
        self.speeds = []
        self.cpu_usages = []
        self.memory_usages = []
        self.last_update_time = time.time()
        self.last_wallet_count = 0
        self.mode = "private_key"  # or "mnemonic"
        
        # Create interface
        self.create_widgets()
        
        # Load addresses after creating widgets
        self.addresses = self.setup_address_sets()
        
        # Start updating statistics
        self.update_stats()
    
    def create_widgets(self):
        # Style configuration for dark theme
        style = ttk.Style()
        style.theme_use('clam')  # Use clam theme as base for customization
        
        # Configure styles
        style.configure('TFrame', background=self.bg_color)
        style.configure('TLabel', background=self.bg_color, foreground=self.fg_color)
        style.configure('TButton', 
                        background=self.widget_bg, 
                        foreground=self.fg_color,
                        borderwidth=1,
                        focusthickness=3,
                        focuscolor=self.accent_color)
        style.map('TButton',
                 background=[('active', self.accent_color), ('pressed', self.accent_color)],
                 foreground=[('active', self.bg_color), ('pressed', self.bg_color)])
        
        style.configure('TLabelframe', background=self.bg_color, foreground=self.accent_color)
        style.configure('TLabelframe.Label', background=self.bg_color, foreground=self.accent_color)
        style.configure('Header.TLabel', font=('Arial', 14, 'bold'), foreground=self.accent_color)
        style.configure('Stats.TLabel', font=('Arial', 12))
        
        # Main frame
        main_frame = ttk.Frame(self.root, padding="10")
        main_frame.grid(row=0, column=0, sticky=(tk.W, tk.E, tk.N, tk.S))
        
        # Header
        header_label = ttk.Label(main_frame, text="Multi-Crypto Wallet Finder", style='Header.TLabel')
        header_label.grid(row=0, column=0, columnspan=3, pady=10)
        
        # Mode selection
        mode_frame = ttk.LabelFrame(main_frame, text="Generation Mode", padding="10")
        mode_frame.grid(row=1, column=0, sticky=(tk.W, tk.E), padx=5, pady=5, columnspan=2)
        
        self.mode_var = tk.StringVar(value="private_key")
        ttk.Radiobutton(mode_frame, text="Private Key Generation", variable=self.mode_var, 
                       value="private_key", command=self.mode_changed).grid(row=0, column=0, padx=10)
        ttk.Radiobutton(mode_frame, text="Mnemonic Phrase (12 words)", variable=self.mode_var, 
                       value="mnemonic", command=self.mode_changed).grid(row=0, column=1, padx=10)
        
        # Statistics frame
        stats_frame = ttk.LabelFrame(main_frame, text="Statistics", padding="10")
        stats_frame.grid(row=2, column=0, sticky=(tk.W, tk.E, tk.N, tk.S), padx=5, pady=5, rowspan=2)
        
        # Statistics indicators
        self.total_label = ttk.Label(stats_frame, text="Wallets checked: 0", style='Stats.TLabel')
        self.total_label.grid(row=0, column=0, sticky=tk.W, pady=2)
        
        self.speed_label = ttk.Label(stats_frame, text="Speed: 0 wallets/sec", style='Stats.TLabel')
        self.speed_label.grid(row=1, column=0, sticky=tk.W, pady=2)
        
        self.found_label = ttk.Label(stats_frame, text="Wallets found: 0", style='Stats.TLabel')
        self.found_label.grid(row=2, column=0, sticky=tk.W, pady=2)
        
        self.time_label = ttk.Label(stats_frame, text="Running time: 00:00:00", style='Stats.TLabel')
        self.time_label.grid(row=3, column=0, sticky=tk.W, pady=2)
        
        # System stats
        self.cpu_label = ttk.Label(stats_frame, text="CPU Usage: 0%", style='Stats.TLabel')
        self.cpu_label.grid(row=4, column=0, sticky=tk.W, pady=2)
        
        self.memory_label = ttk.Label(stats_frame, text="Memory Usage: 0%", style='Stats.TLabel')
        self.memory_label.grid(row=5, column=0, sticky=tk.W, pady=2)
        
        self.threads_label = ttk.Label(stats_frame, text="Active Threads: 0", style='Stats.TLabel')
        self.threads_label.grid(row=6, column=0, sticky=tk.W, pady=2)
        
        # Mnemonic display (only visible in mnemonic mode)
        self.mnemonic_frame = ttk.LabelFrame(main_frame, text="Current Mnemonic", padding="5")
        self.mnemonic_label = ttk.Label(self.mnemonic_frame, text="Not generated yet", style='Stats.TLabel',  wraplength=600,)
        self.mnemonic_label.grid(row=0, column=0, sticky=tk.W, pady=2)
        
        # Control frame
        control_frame = ttk.LabelFrame(main_frame, text="Controls", padding="10")
        control_frame.grid(row=2, column=1, sticky=(tk.W, tk.E, tk.N, tk.S), padx=5, pady=5)
        
        # Control buttons
        self.start_button = ttk.Button(control_frame, text="Start", command=self.start_search)
        self.start_button.grid(row=0, column=0, padx=5, pady=5)
        
        self.stop_button = ttk.Button(control_frame, text="Stop", command=self.stop_search, state=tk.DISABLED)
        self.stop_button.grid(row=0, column=1, padx=5, pady=5)
        
        # Thread settings
        thread_frame = ttk.Frame(control_frame)
        thread_frame.grid(row=1, column=0, columnspan=2, pady=5)
        
        ttk.Label(thread_frame, text="Thread count:").grid(row=0, column=0)
        self.thread_var = tk.IntVar(value=os.cpu_count() or 4)
        thread_spinbox = ttk.Spinbox(thread_frame, from_=1, to=os.cpu_count() * 2 or 8, textvariable=self.thread_var, width=10)
        thread_spinbox.grid(row=0, column=1, padx=5)
        
        # Real-time generation frame
        generation_frame = ttk.LabelFrame(main_frame, text="Real-time Generation", padding="10")
        generation_frame.grid(row=3, column=1, sticky=(tk.W, tk.E, tk.N, tk.S), padx=5, pady=5)
        
        # Generation labels
        self.btc_label = ttk.Label(generation_frame, text="BTC: Not generated", style='Stats.TLabel')
        self.btc_label.grid(row=0, column=0, sticky=tk.W, pady=2)
        
        self.eth_label = ttk.Label(generation_frame, text="ETH: Not generated", style='Stats.TLabel')
        self.eth_label.grid(row=1, column=0, sticky=tk.W, pady=2)
        
        self.trx_label = ttk.Label(generation_frame, text="TRX: Not generated", style='Stats.TLabel')
        self.trx_label.grid(row=2, column=0, sticky=tk.W, pady=2)
        
        self.doge_label = ttk.Label(generation_frame, text="DOGE: Not generated", style='Stats.TLabel')
        self.doge_label.grid(row=3, column=0, sticky=tk.W, pady=2)
        
        # Log
        log_frame = ttk.LabelFrame(main_frame, text="Log", padding="10")
        log_frame.grid(row=4, column=0, columnspan=2, sticky=(tk.W, tk.E, tk.N, tk.S), padx=5, pady=5)
        
        self.log_text = scrolledtext.ScrolledText(log_frame, height=10, width=80, 
                                                 bg=self.widget_bg, fg=self.fg_color,
                                                 insertbackground=self.fg_color,  # Cursor color
                                                 selectbackground=self.accent_color)  # Selection color
        self.log_text.grid(row=0, column=0, sticky=(tk.W, tk.E, tk.N, tk.S))
        self.log_text.configure(state=tk.DISABLED)
        
        # Speed graph
        graph_frame = ttk.LabelFrame(main_frame, text="Performance Graphs", padding="10")
        graph_frame.grid(row=2, column=2, rowspan=3, sticky=(tk.W, tk.E, tk.N, tk.S), padx=5, pady=5)
        
        # Create graph with dark theme
        plt.style.use('dark_background')
        self.fig = Figure(figsize=(8, 10), dpi=100, facecolor=self.widget_bg)
        self.ax1 = self.fig.add_subplot(311)
        self.ax1.set_title('Wallet Check Speed', color=self.fg_color)
        self.ax1.set_ylabel('Wallets/sec', color=self.fg_color)
        self.ax1.tick_params(colors=self.fg_color)
        self.ax1.grid(True, color=self.border_color, linestyle='--')
        
        self.ax2 = self.fig.add_subplot(312)
        self.ax2.set_title('CPU Usage', color=self.fg_color)
        self.ax2.set_ylabel('Usage %', color=self.fg_color)
        self.ax2.tick_params(colors=self.fg_color)
        self.ax2.grid(True, color=self.border_color, linestyle='--')
        
        self.ax3 = self.fig.add_subplot(313)
        self.ax3.set_title('Memory Usage', color=self.fg_color)
        self.ax3.set_xlabel('Time (sec)', color=self.fg_color)
        self.ax3.set_ylabel('Usage %', color=self.fg_color)
        self.ax3.tick_params(colors=self.fg_color)
        self.ax3.grid(True, color=self.border_color, linestyle='--')
        
        self.speed_data = []
        self.cpu_data = []
        self.memory_data = []
        self.time_data = []
        
        self.canvas = FigureCanvasTkAgg(self.fig, master=graph_frame)
        self.canvas.draw()
        self.canvas.get_tk_widget().pack(fill=tk.BOTH, expand=True)
        
        # Configure expansion
        self.root.columnconfigure(0, weight=1)
        self.root.rowconfigure(0, weight=1)
        main_frame.columnconfigure(0, weight=1)
        main_frame.columnconfigure(1, weight=1)
        main_frame.columnconfigure(2, weight=2)
        main_frame.rowconfigure(4, weight=1)
        
        # Initially hide mnemonic frame
        self.mode_changed()
    
    def mode_changed(self):
        """Show/hide mnemonic frame based on selected mode"""
        if self.mode_var.get() == "mnemonic":
            self.mnemonic_frame.grid(row=1, column=2, sticky=(tk.W, tk.E, tk.N, tk.S), padx=5, pady=5)
        else:
            self.mnemonic_frame.grid_remove()
    
    def setup_address_sets(self):
        """Load all address sets once"""
        addresses = {}
        files = {
            'eth': "eth500.txt",
            'btc': "btc500.txt", 
            'trx': "trx500.txt",
            'doge': "doge500.txt"
        }
        
        for coin, filename in files.items():
            try:
                if os.path.exists(filename):
                    with open(filename, 'r') as f:
                        addresses[coin] = set(line.strip() for line in f if line.strip())
                    self.log_message(f"Loaded {len(addresses[coin])} addresses from {filename}")
                else:
                    addresses[coin] = set()
                    self.log_message(f"File {filename} not found, created empty list", "WARNING")
            except Exception as e:
                addresses[coin] = set()
                self.log_message(f"Error loading {filename}: {e}", "ERROR")
        
        return addresses
    
    def log_message(self, message, level="INFO"):
        """Adds a message to the log"""
        # Check if log_text has been created
        if not hasattr(self, 'log_text'):
            print(f"[{level}] {message}")  # Output to console if log not yet created
            return
            
        self.log_text.configure(state=tk.NORMAL)
        timestamp = datetime.now().strftime("%H:%M:%S")
        
        if level == "ERROR":
            tag = "error"
            color = self.error_color
        elif level == "WARNING":
            tag = "warning" 
            color = self.warning_color
        elif level == "SUCCESS":
            tag = "success"
            color = self.success_color
        else:
            tag = "info"
            color = self.fg_color
        
        self.log_text.insert(tk.END, f"[{timestamp}] {message}\n", tag)
        self.log_text.configure(state=tk.DISABLED)
        self.log_text.see(tk.END)
        
        # Add color tags
        self.log_text.tag_config("error", foreground=self.error_color)
        self.log_text.tag_config("warning", foreground=self.warning_color)
        self.log_text.tag_config("success", foreground=self.success_color)
        self.log_text.tag_config("info", foreground=self.fg_color)
    
    def generate_private_key(self):
        """Generates a cryptographically secure random private key"""
        return secrets.token_hex(32)
    
    def generate_mnemonic(self):
        """Generates a 12-word mnemonic phrase"""
        mnemo = Mnemonic("english")
        return mnemo.generate(strength=128)  # 128 bits for 12 words
    
    def mnemonic_to_private_key(self, mnemonic):
        """Converts mnemonic phrase to private key using BIP39 standard"""
        # Generate seed from mnemonic
        mnemo = Mnemonic("english")
        seed = mnemo.to_seed(mnemonic)
        
        # Create BIP32 root key from seed
        root_key = bip32utils.BIP32Key.fromEntropy(seed)
        
        # Derive private key for the first account: m/44'/0'/0'/0/0 (Bitcoin path)
        # We'll use this same private key for all currencies for simplicity
        derived_key = root_key.ChildKey(44 + bip32utils.BIP32_HARDEN).ChildKey(
            0 + bip32utils.BIP32_HARDEN).ChildKey(
            0 + bip32utils.BIP32_HARDEN).ChildKey(0).ChildKey(0)
        
        return derived_key.PrivateKey().hex()
    
    def private_key_to_public_key(self, private_key_hex):
        """Converts private key to public key"""
        private_key_bytes = bytes.fromhex(private_key_hex)
        sk = ecdsa.SigningKey.from_string(private_key_bytes, curve=ecdsa.SECP256k1)
        vk = sk.get_verifying_key()
        return b'\x04' + vk.to_string()
    
    def keccak256(self, data):
        """Keccak-256 hash implementation compatible with Ethereum"""
        keccak_hash = keccak.new(digest_bits=256)
        keccak_hash.update(data)
        return keccak_hash.digest()
    
    def public_key_to_eth_address(self, public_key):
        """Converts public key to Ethereum address"""
        hash_bytes = self.keccak256(public_key)
        return '0x' + hash_bytes[-20:].hex()
    
    def public_key_to_btc_address(self, public_key, version=0x00):
        """Converts public key to Bitcoin address"""
        sha256_hash = hashlib.sha256(public_key).digest()
        ripemd160_hash = hashlib.new('ripemd160', sha256_hash).digest()
        with_version = bytes([version]) + ripemd160_hash
        checksum = hashlib.sha256(hashlib.sha256(with_version).digest()).digest()[:4]
        return base58.b58encode(with_version + checksum).decode()
    
    def public_key_to_doge_address(self, public_key, version=0x1E):
        """Converts public key to Dogecoin address"""
        return self.public_key_to_btc_address(public_key, version)
    
    def public_key_to_trx_address(self, public_key):
        """Converts public key to Tron address"""
        hash_bytes = self.keccak256(public_key)
        trx_prefix = bytes.fromhex('41')
        trx_address = trx_prefix + hash_bytes[-20:]
        return base58.b58encode_check(trx_address).decode()
    
    def update_generation_labels(self, btc, eth, trx, doge, mnemonic=None):
        """Update the real-time generation labels"""
        self.btc_label.config(text=f"BTC: {btc}")
        self.eth_label.config(text=f"ETH: {eth}")
        self.trx_label.config(text=f"TRX: {trx}")
        self.doge_label.config(text=f"DOGE: {doge}")
        
        if mnemonic and self.mode_var.get() == "mnemonic":
            self.mnemonic_label.config(text=mnemonic)
    
    def save_result(self, filename, private_key, address, currency, mnemonic=None):
        """Saves results to a file"""
        try:
            with open(filename, 'a') as f:
                if mnemonic:
                    f.write(f"\nMnemonic: {mnemonic}")
                f.write(f"\n{currency} Private Key: {private_key}")
                f.write(f"\n{currency} Address: {address}")
                f.write(f"\nDiscovery Time: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
                f.write("\n" + "="*50 + "\n")
            
            self.found_wallets += 1
            self.log_message(f"Found {currency} wallet: {address}", "SUCCESS")
        except Exception as e:
            self.log_message(f"Error saving result: {e}", "ERROR")
    
    def wallet_search_thread(self, thread_id):
        """Thread for wallet searching"""
        local_count = 0
        last_update = time.time()
        
        while self.is_running:
            if self.mode_var.get() == "mnemonic":
                # Generate from mnemonic phrase
                mnemonic = self.generate_mnemonic()
                try:
                    private_key_hex = self.mnemonic_to_private_key(mnemonic)
                except Exception as e:
                    self.log_message(f"Error generating from mnemonic: {e}", "ERROR")
                    continue
            else:
                # Generate private key directly
                mnemonic = None
                private_key_hex = self.generate_private_key()
            
            # Generate public key and addresses
            public_key = self.private_key_to_public_key(private_key_hex)
            eth_address = self.public_key_to_eth_address(public_key)
            btc_address = self.public_key_to_btc_address(public_key)
            trx_address = self.public_key_to_trx_address(public_key)
            doge_address = self.public_key_to_doge_address(public_key)

            local_count += 1
            self.total_wallets_checked += 1
            
            # Update generation display occasionally
            current_time = time.time()
            if current_time - last_update > 0.5:  # Update twice per second
                self.root.after(0, self.update_generation_labels, 
                              btc_address[:12] + "...", 
                              eth_address[:12] + "...", 
                              trx_address[:12] + "...", 
                              doge_address[:12] + "...",
                              mnemonic)
                last_update = current_time
            
            # Check addresses
            if btc_address in self.addresses['btc']:
                self.save_result("BTCWinner.txt", private_key_hex, btc_address, "BTC", mnemonic)
                
            if eth_address in self.addresses['eth']:
                self.save_result("EthWinner.txt", private_key_hex, eth_address, "ETH", mnemonic)
                
            if trx_address in self.addresses['trx']:
                self.save_result("TRXWinner.txt", private_key_hex, trx_address, "TRX", mnemonic)
                
            if doge_address in self.addresses['doge']:
                self.save_result("DogeWinner.txt", private_key_hex, doge_address, "DOGE", mnemonic)
    
    def start_search(self):
        """Starts wallet search"""
        if self.is_running:
            return
        
        self.is_running = True
        self.start_time = time.time()
        self.total_wallets_checked = 0
        self.found_wallets = 0
        self.speed_data = []
        self.cpu_data = []
        self.memory_data = []
        self.time_data = []
        self.last_update_time = time.time()
        self.last_wallet_count = 0
        
        self.start_button.configure(state=tk.DISABLED)
        self.stop_button.configure(state=tk.NORMAL)
        
        # Start threads
        num_threads = self.thread_var.get()
        mode = "mnemonic" if self.mode_var.get() == "mnemonic" else "private key"
        self.log_message(f"Starting {num_threads} threads for {mode} wallet search")
        
        for i in range(num_threads):
            thread = threading.Thread(target=self.wallet_search_thread, args=(i,))
            thread.daemon = True
            thread.start()
            self.threads.append(thread)
    
    def stop_search(self):
        """Stops wallet search"""
        self.is_running = False
        self.start_button.configure(state=tk.NORMAL)
        self.stop_button.configure(state=tk.DISABLED)
        
        # Wait for all threads to finish
        for thread in self.threads:
            thread.join(timeout=1.0)
        
        self.threads = []
        self.log_message("Search stopped")
        
        # Final statistics
        elapsed_time = time.time() - self.start_time
        avg_speed = self.total_wallets_checked / elapsed_time if elapsed_time > 0 else 0
        
        self.log_message(f"Final statistics:")
        self.log_message(f"Total running time: {elapsed_time:.2f} seconds")
        self.log_message(f"Total wallets checked: {self.total_wallets_checked:,}")
        self.log_message(f"Average speed: {avg_speed:.2f} wallets/sec")
        self.log_message(f"Wallets found: {self.found_wallets}")
    
    def update_stats(self):
        """Updates statistics on the interface"""
        if self.is_running:
            current_time = time.time()
            elapsed_time = current_time - self.start_time
            
            # Calculate current speed (wallets per second)
            time_diff = current_time - self.last_update_time
            wallet_diff = self.total_wallets_checked - self.last_wallet_count
            current_speed = wallet_diff / time_diff if time_diff > 0 else 0
            
            # Update last values
            self.last_update_time = current_time
            self.last_wallet_count = self.total_wallets_checked
            
            # Get system stats
            cpu_percent = psutil.cpu_percent()
            memory_percent = psutil.virtual_memory().percent
            
            # Update labels
            self.total_label.config(text=f"Wallets checked: {self.total_wallets_checked:,}")
            self.speed_label.config(text=f"Speed: {current_speed:.2f} wallets/sec")
            self.found_label.config(text=f"Wallets found: {self.found_wallets}")
            self.cpu_label.config(text=f"CPU Usage: {cpu_percent}%")
            self.memory_label.config(text=f"Memory Usage: {memory_percent}%")
            self.threads_label.config(text=f"Active Threads: {threading.active_count()}")
            
            # Format time
            hours, remainder = divmod(int(elapsed_time), 3600)
            minutes, seconds = divmod(remainder, 60)
            self.time_label.config(text=f"Running time: {hours:02d}:{minutes:02d}:{seconds:02d}")
            
            # Update graph data
            if elapsed_time > 0:
                self.speed_data.append(current_speed)
                self.cpu_data.append(cpu_percent)
                self.memory_data.append(memory_percent)
                self.time_data.append(elapsed_time)
                
                # Limit graph data
                if len(self.speed_data) > 100:
                    self.speed_data = self.speed_data[-100:]
                    self.cpu_data = self.cpu_data[-100:]
                    self.memory_data = self.memory_data[-100:]
                    self.time_data = self.time_data[-100:]
                
                # Update graphs
                self.ax1.clear()
                self.ax1.plot(self.time_data, self.speed_data, color=self.accent_color)
                self.ax1.set_title('Wallet Check Speed', color=self.fg_color)
                self.ax1.set_ylabel('Wallets/sec', color=self.fg_color)
                self.ax1.tick_params(colors=self.fg_color)
                self.ax1.grid(True, color=self.border_color, linestyle='--')
                
                self.ax2.clear()
                self.ax2.plot(self.time_data, self.cpu_data, color=self.warning_color)
                self.ax2.set_title('CPU Usage', color=self.fg_color)
                self.ax2.set_ylabel('Usage %', color=self.fg_color)
                self.ax2.tick_params(colors=self.fg_color)
                self.ax2.grid(True, color=self.border_color, linestyle='--')
                
                self.ax3.clear()
                self.ax3.plot(self.time_data, self.memory_data, color=self.success_color)
                self.ax3.set_title('Memory Usage', color=self.fg_color)
                self.ax3.set_xlabel('Time (sec)', color=self.fg_color)
                self.ax3.set_ylabel('Usage %', color=self.fg_color)
                self.ax3.tick_params(colors=self.fg_color)
                self.ax3.grid(True, color=self.border_color, linestyle='--')
                
                self.fig.tight_layout()
                self.canvas.draw()
        
        # Schedule next update
        self.root.after(1000, self.update_stats)

def main():
    root = tk.Tk()
    app = CryptoWalletFinder(root)
    root.mainloop()

if __name__ == "__main__":
    main()