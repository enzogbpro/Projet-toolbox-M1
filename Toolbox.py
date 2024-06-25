import nmap
import re
import os
import webbrowser
import tkinter as tk
from tkinter import messagebox, scrolledtext, ttk, filedialog
import paramiko
import threading
import socket
import psutil
from scapy.all import sniff, IP
import subprocess
from fpdf import FPDF
import matplotlib.pyplot as plt
import time
import random
import string
from PIL import Image, ImageTk
import requests
import hashlib

API_KEY = '7d5154094fb8ce10f823137448fd39966e6136a69f26ffdad25552e755925da5'
API_URL_REPORT = 'https://www.virustotal.com/vtapi/v2/file/report'
API_URL_SCAN = 'https://www.virustotal.com/vtapi/v2/file/scan'

class Tooltip:
    def __init__(self, widget, text):
        self.widget = widget
        self.text = text
        self.tooltip_window = None
        widget.bind("<Enter>", self.show_tooltip)
        widget.bind("<Leave>", self.hide_tooltip)

    def show_tooltip(self, event=None):
        x, y, _, _ = self.widget.bbox("insert")
        x += self.widget.winfo_rootx() + 25
        y += self.widget.winfo_rooty() - 20  # Display above the widget
        self.tooltip_window = tw = tk.Toplevel(self.widget)
        tw.wm_overrideredirect(True)
        tw.wm_geometry("+%d+%d" % (x, y))
        label = tk.Label(tw, text=self.text, justify='left',
                         background="#ffffff", relief='solid', borderwidth=1,
                         font=("tahoma", "8", "normal"))
        label.pack(ipadx=1)

    def hide_tooltip(self, event=None):
        if self.tooltip_window:
            self.tooltip_window.destroy()
        self.tooltip_window = None

class App(tk.Tk):
    def __init__(self):
        super().__init__()
        self.title("Menu")
        self.geometry("1500x800")
        self.configure(bg="#2C3E50")

        # Maximiser la fenêtre au démarrage
        self.state('zoomed')

        self.current_frame = None
        self.shared_widgets = {}
        self.capture_thread = None
        self.stop_capture_event = threading.Event()
        self.stop_vuln_scan_event = threading.Event()  # New event for stopping vuln scan
        self.packets = []
        self.test_results = []
        self.brute_force_attempts = 0
        self.open_ports_count = 0
        self.packets_count = []
        self.capture_start_time = None
        self.language = 'fr'
        self.flag_buttons = {}
        self.container = None
        self.current_frame = None
        self.shared_widgets = {}
        self.test_results = []

        self.capture_in_progress = False
        self.thread_running = False

        self.create_flag_buttons()
        self.main_menu()

    def main_menu(self):
        self.clear_frame()

        self.container = tk.Frame(self, bg="#2C3E50")
        self.container.pack(expand=True, pady=(30, 0))

        label_title = tk.Label(self.container, text="MENU", bg="#2C3E50", fg="#ECF0F1", font=("Arial", 24))
        label_title.pack(pady=(0, 20))

        button_width = 30
        button_spacing = 15

        btn_brute_force = tk.Button(self.container, text=self.translate("Brute Force SSH"), bg="#3498DB", fg="#FFFFFF", font=("Arial", 16), relief=tk.FLAT, width=button_width, command=self.show_brute_force)
        btn_brute_force.pack(pady=(button_spacing, 10))

        btn_port_scan = tk.Button(self.container, text=self.translate("Scan de Ports"), bg="#3498DB", fg="#FFFFFF", font=("Arial", 16), relief=tk.FLAT, width=button_width, command=self.show_port_scan)
        btn_port_scan.pack(pady=(10, button_spacing))

        btn_network_scan = tk.Button(self.container, text=self.translate("Scan réseau"), bg="#3498DB", fg="#FFFFFF", font=("Arial", 16), relief=tk.FLAT, width=button_width, command=self.show_network_scan)
        btn_network_scan.pack(pady=(10, button_spacing))

        btn_vuln_scan = tk.Button(self.container, text=self.translate("Scan de Vulnérabilités"), bg="#3498DB", fg="#FFFFFF", font=("Arial", 16), relief=tk.FLAT, width=button_width, command=self.show_vuln_scan)
        btn_vuln_scan.pack(pady=(10, button_spacing))

        btn_file_scan = tk.Button(self.container, text=self.translate("Scan fichier"), bg="#3498DB", fg="#FFFFFF", font=("Arial", 16), relief=tk.FLAT, width=button_width, command=self.show_file_scan)
        btn_file_scan.pack(pady=(10, button_spacing))

        btn_generate_report = tk.Button(self.container, text=self.translate("Générer Rapport PDF"), bg="#2ECC71", fg="#FFFFFF", font=("Arial", 16), relief=tk.FLAT, width=button_width, command=self.generate_pdf_report)
        btn_generate_report.pack(pady=(10, button_spacing))

    def create_flag_buttons(self):
        self.flag_buttons['fr'] = tk.Button(self, command=lambda: self.show_second_flag('fr'), bg="#2C3E50", relief=tk.FLAT)
        flag_image_fr = self.load_image(r"C:\Users\enzo.gherbi\Desktop\enzo\Projet ToolBox\Script valide/France_flag.png", (30, 20))
        if flag_image_fr:
            self.flag_buttons['fr'].config(image=flag_image_fr)
            self.flag_buttons['fr'].image = flag_image_fr
            self.flag_buttons['fr'].place(relx=1.0, rely=0.0, anchor='ne', x=-10, y=10)

        self.flag_buttons['en'] = tk.Button(self, command=lambda: self.show_second_flag('en'), bg="#2C3E50", relief=tk.FLAT)
        flag_image_en = self.load_image(r"C:\Users\enzo.gherbi\Desktop\enzo\Projet ToolBox\Script valide/English_flag.png", (30, 20))
        if flag_image_en:
            self.flag_buttons['en'].config(image=flag_image_en)
            self.flag_buttons['en'].image = flag_image_en

    def update_flags(self):
        if self.language == 'fr':
            self.flag_buttons['fr'].place(relx=1.0, rely=0.0, anchor='ne', x=-10, y=10)
            self.flag_buttons['en'].place_forget()
        else:
            self.flag_buttons['en'].place(relx=1.0, rely=0.0, anchor='ne', x=-10, y=10)
            self.flag_buttons['fr'].place_forget()

    def show_second_flag(self, lang):
        if lang == 'fr':
            self.flag_buttons['en'].place(relx=1.0, rely=0.0, anchor='ne', x=-10, y=40)
            self.flag_buttons['en'].config(command=lambda: self.set_language('en'))
        else:
            self.flag_buttons['fr'].place(relx=1.0, rely=0.0, anchor='ne', x=-10, y=40)
            self.flag_buttons['fr'].config(command=lambda: self.set_language('fr'))

    def set_language(self, lang):
        self.language = lang
        self.update_flags()
        self.main_menu()
        self.show_second_flag(lang)

    def translate(self, text):
        translations = {
            'Brute Force SSH': {'en': 'Brute Force SSH', 'fr': 'Brute Force SSH'},
            'Scan de Ports': {'en': 'Port Scan', 'fr': 'Scan de Ports'},
            'Scan réseau': {'en': 'Network Scan', 'fr': 'Scan réseau'},
            'Scan de Vulnérabilités': {'en': 'Vulnerability Scan', 'fr': 'Scan de Vulnérabilités'},
            'Scan fichier': {'en': 'File Scan', 'fr': 'Scan fichier'},
            'Générer Rapport PDF': {'en': 'Generate PDF Report', 'fr': 'Générer Rapport PDF'}
        }
        return translations.get(text, {}).get(self.language, text)

    def clear_frame(self):
        if self.container:
            self.container.destroy()
        for widget in self.winfo_children():
            if widget not in self.flag_buttons.values():
                widget.destroy()
        self.current_frame = None    

    def show_vuln_scan(self):
        self.clear_frame()

        label_ip = tk.Label(self, text="Adresse IP de l'hôte à scanner :", bg="#2C3E50", fg="#ECF0F1", font=("Arial", 14))
        label_ip.pack(pady=(30, 10))

        entry_ip = tk.Entry(self, font=("Arial", 12))
        entry_ip.pack()

        btn_start = tk.Button(self, text="Démarrer le Scan de Vulnérabilités", command=lambda: self.start_vuln_scan(entry_ip.get()), bg="#3498DB", fg="#FFFFFF", font=("Arial", 12), relief=tk.FLAT)
        btn_start.pack(pady=10)

        btn_stop = tk.Button(self, text="Arrêter le Scan de Vulnérabilités", command=self.stop_vuln_scan, bg="#E74C3C", fg="#FFFFFF", font=("Arial", 12), relief=tk.FLAT, state=tk.DISABLED)
        btn_stop.pack(pady=10)

        text_results = tk.Text(self, height=20, width=120, font=("Arial", 12), bg="#34495E", fg="#ECF0F1", relief=tk.FLAT)
        text_results.pack(pady=20)

        self.shared_widgets["vuln_scan"] = (entry_ip, btn_start, btn_stop, text_results)

        btn_return = tk.Button(self, text="Retour au Menu Principal", command=self.main_menu, bg="#3498DB", fg="#FFFFFF", font=("Arial", 12), relief=tk.FLAT)
        btn_return.pack(side=tk.LEFT, padx=20, pady=10)

        info_icon = self.create_info_icon(self, r"C:\Users\enzo.gherbi\Downloads\icon_i.png", "Lancer un scan de vulnérabilités sur l'adresse IP spécifiée.", x=50, y=420)

    def start_vuln_scan(self, target):
        entry_ip, btn_start, btn_stop, text_results = self.shared_widgets["vuln_scan"]

        if not target:
            messagebox.showerror("Erreur", "Veuillez entrer l'adresse IP de l'hôte à scanner.")
            return

        text_results.config(state=tk.NORMAL)
        text_results.delete(1.0, tk.END)
        text_results.insert(tk.END, "Démarrage du scan de vulnérabilités...\n\n")
        text_results.config(state=tk.DISABLED)
        btn_start.config(state=tk.DISABLED)
        btn_stop.config(state=tk.NORMAL)

        threading.Thread(target=self.scan_vulnerabilities, args=(target, text_results, btn_start, btn_stop)).start()

    def stop_vuln_scan(self):
        self.stop_vuln_scan_event.set()
        entry_ip, btn_start, btn_stop, text_results = self.shared_widgets["vuln_scan"]
        btn_stop.config(state=tk.DISABLED)

    def scan_vulnerabilities(self, target, text_results, btn_start, btn_stop):
        NMAP_PATH = "C:/Program Files (x86)/Nmap/nmap.exe"

        if not os.path.exists(NMAP_PATH):
            text_results.config(state=tk.NORMAL)
            text_results.insert(tk.END, f"Nmap executable not found at {NMAP_PATH}. Please check the path and try again.\n")
            text_results.config(state=tk.DISABLED)
            btn_start.config(state=tk.NORMAL)
            btn_stop.config(state=tk.DISABLED)
            return

        nm = nmap.PortScanner(nmap_search_path=(NMAP_PATH,))
        
        text_results.config(state=tk.NORMAL)
        text_results.insert(tk.END, f"Scanning {target} for open ports and services...\n")
        text_results.config(state=tk.DISABLED)

        try:
            nm.scan(target, arguments='-sV --script=vulners,version')
            scan_data = nm.scanstats()
            text_results.config(state=tk.NORMAL)
            text_results.insert(tk.END, f"Scan completed in {scan_data['elapsed']} seconds\n")
            text_results.config(state=tk.DISABLED)

            vulnerabilities = []

            for host in nm.all_hosts():
                for proto in nm[host].all_protocols():
                    if self.stop_vuln_scan_event.is_set():  # Check for stop event
                        text_results.config(state=tk.NORMAL)
                        text_results.insert(tk.END, "Scan de vulnérabilités arrêté.\n")
                        text_results.config(state=tk.DISABLED)
                        btn_start.config(state=tk.NORMAL)
                        btn_stop.config(state=tk.DISABLED)
                        return

                    lport = nm[host][proto].keys()
                    for port in lport:
                        service = nm[host][proto][port]
                        product = service.get('product', '')
                        version = service.get('version', '')
                        cpe = service.get('cpe', '')
                        if 'script' in service:
                            for script_id, script_output in service['script'].items():
                                if 'vulners' in script_id:
                                    vulns = self.extract_vulns_from_output(script_output)
                                    for vuln in vulns:
                                        vulnerabilities.append({
                                            'host': host,
                                            'port': port,
                                            'service': service['name'],
                                            'product': product,
                                            'version': version,
                                            'cpe': cpe,
                                            'cve': vuln['cve'],
                                            'cvss': vuln['cvss'],
                                            'exploit_available': vuln['exploit'],
                                            'url': vuln['url']
                                        })

            self.display_vulnerabilities(vulnerabilities, text_results)
        except Exception as e:
            text_results.config(state=tk.NORMAL)
            text_results.insert(tk.END, f"Erreur lors du scan de vulnérabilités : {str(e)}\n")
            text_results.config(state=tk.DISABLED)
        finally:
            btn_start.config(state=tk.NORMAL)
            btn_stop.config(state=tk.DISABLED)

    def extract_vulns_from_output(self, output):
        vulns = []
        lines = output.split('\n')
        for line in lines:
            match = re.search(r'(\S+)\s+(\d+\.\d+)\s+(https://vulners.com/\S+)', line)
            if match:
                cve = match.group(1)
                cvss = match.group(2)
                url = match.group(3)
                exploit = "EXPLOIT" in line
                vulns.append({'cve': cve, 'cvss': cvss, 'exploit': exploit, 'url': url})
        return vulns

    def display_vulnerabilities(self, vulnerabilities, text_results):
        text_results.config(state=tk.NORMAL)
        if not vulnerabilities:
            text_results.insert(tk.END, "No vulnerabilities found.\n")
        else:
            vulnerabilities_with_exploits = [v for v in vulnerabilities if v['exploit_available']]
            if not vulnerabilities_with_exploits:
                text_results.insert(tk.END, "No vulnerabilities with available exploits found.\n")
            else:
                found_text = f"Trouvé {len(vulnerabilities_with_exploits)} vulnérabilités avec des exploits disponibles :\n"
                text_results.insert(tk.END, found_text, ('bold_red',))
                
                for vuln in vulnerabilities_with_exploits:
                    text_results.insert(tk.END, f"\nHost: {vuln['host']}\n")
                    text_results.insert(tk.END, f"Port: {vuln['port']}\n")
                    text_results.insert(tk.END, f"Service: {vuln['service']}\n")
                    text_results.insert(tk.END, f"Product: {vuln['product']}\n")
                    text_results.insert(tk.END, f"Version: {vuln['version']}\n")
                    text_results.insert(tk.END, f"CPE: {vuln['cpe']}\n")
                    text_results.insert(tk.END, f"CVE: {vuln['cve']} - ")
                    text_results.insert(tk.END, f"CVSS Score: {vuln['cvss']}\n")
                    text_results.insert(tk.END, f"Exploit Available: {vuln['exploit_available']}\n")

                    text_results.insert(tk.END, f"Description: ")
                    text_results.insert(tk.END, vuln['url'], ('link', vuln['url']))
                    text_results.insert(tk.END, "\n")

                self.display_recommendations(vulnerabilities_with_exploits, text_results)

        text_results.tag_config('link', foreground='white', underline=True)
        text_results.tag_config('bold', font=('Arial', 12, 'bold'))
        text_results.tag_config('bold_red', foreground='red', font=('Arial', 12, 'bold'))
        text_results.tag_config('bold_underline', font=('Arial', 12, 'bold', 'underline'))
        text_results.tag_config('underline', font=('Arial', 12, 'underline'))
        text_results.tag_bind('link', '<Button-1>', self.open_link)
        text_results.config(state=tk.DISABLED)

    def open_link(self, event):
        text_widget = event.widget
        index = text_widget.index("@%s,%s" % (event.x, event.y))
        start_index = text_widget.search("https://", index, backwards=True, stopindex="1.0")
        end_index = text_widget.search(" ", start_index, stopindex="%s lineend" % start_index)
        if not end_index:
            end_index = text_widget.index("%s lineend" % start_index)
        url = text_widget.get(start_index, end_index).strip()
        webbrowser.open(url)

    def display_recommendations(self, vulnerabilities, text_results):
        if not vulnerabilities:
            text_results.insert(tk.END, "\nNo critical vulnerabilities to address.\n")
            return

        products = set()
        for vuln in vulnerabilities:
            product_info = f"{vuln['product']} {vuln['version']}"
            products.add(product_info)

        text_results.insert(tk.END, "\nRECOMMANDATIONS:")
        text_results.insert(tk.END, "\n\nCorriger les vulnérabilités critiques en priorité :\n", 'bold_underline')
        text_results.insert(tk.END, "\nLes vulnérabilités avec un score CVSS élevé et des exploits disponibles doivent être corrigées immédiatement pour éviter tout risque de compromission.\n")
        text_results.insert(tk.END, "\n\nProduit affecté:\n", 'bold_underline')

        for product in products:
            text_results.insert(tk.END, f"\n{product}\n")

        text_results.insert(tk.END, "\n\nMettre à jour les logiciels :\n", 'bold_underline')
        for product in products:
            text_results.insert(tk.END, f"\nAssurez-vous de mettre à jour {product} et que toutes les mises à jour de sécurité sont appliquées.\n")

        text_results.insert(tk.END, "\n\nSurveiller les vulnérabilités restantes :\n", 'bold_underline')
        text_results.insert(tk.END, "\nMême si certaines vulnérabilités ont des scores CVSS faibles ou n'ont pas d'exploit disponible, elles doivent être surveillées et corrigées dès que possible.\n")

    def show_brute_force(self):
        self.clear_frame()

        label_ip = tk.Label(self, text="Adresse IP de l'hôte :", bg="#2C3E50", fg="#ECF0F1", font=("Arial", 14))
        label_ip.pack(pady=(30, 10))

        entry_ip = tk.Entry(self, font=("Arial", 12))
        entry_ip.pack()

        label_username = tk.Label(self, text="Nom d'utilisateur :", bg="#2C3E50", fg="#ECF0F1", font=("Arial", 14))
        label_username.pack(pady=(10, 10))

        entry_username = tk.Entry(self, font=("Arial", 12))
        entry_username.pack()

        btn_start = tk.Button(self, text="Démarrer le Brute Force", command=lambda: self.start_brute_force(entry_ip.get(), entry_username.get()), bg="#3498DB", fg="#FFFFFF", font=("Arial", 12), relief=tk.FLAT)
        btn_start.pack(pady=10)

        btn_stop = tk.Button(self, text="Arrêter le Brute Force", command=self.stop_brute_force, bg="#E74C3C", fg="#FFFFFF", font=("Arial", 12), relief=tk.FLAT, state=tk.DISABLED)
        btn_stop.pack(pady=10)

        text_results = tk.Text(self, height=13, width=95, font=("Arial", 12), bg="#34495E", fg="#ECF0F1", relief=tk.FLAT)
        text_results.pack(pady=20)

        text_results.config(state=tk.DISABLED)

        self.shared_widgets["brute_force"] = (entry_ip, entry_username, btn_start, btn_stop, text_results)

        btn_return = tk.Button(self, text="Retour au Menu Principal", command=self.main_menu, bg="#3498DB", fg="#FFFFFF", font=("Arial", 12), relief=tk.FLAT)
        btn_return.pack(side=tk.LEFT, padx=20, pady=10)

        info_icon = self.create_info_icon(self, r"C:\Users\enzo.gherbi\Downloads\icon_i.png", "Lancer une attaque brute force sur l'adresse IP et le nom d'utilisateur spécifiés.", x=50, y=420)

    def start_brute_force(self, ip, username):
        entry_ip, entry_username, btn_start, btn_stop, text_results = self.shared_widgets["brute_force"]

        if not ip or not username:
            messagebox.showerror("Erreur", "Veuillez entrer l'adresse IP et le nom d'utilisateur.")
            return

        text_results.config(state=tk.NORMAL)
        text_results.delete(1.0, tk.END)
        text_results.insert(tk.END, "Démarrage de l'attaque brute force...\n\n")
        text_results.config(state=tk.DISABLED)
        btn_start.config(state=tk.DISABLED)
        btn_stop.config(state=tk.NORMAL)

        self.brute_force_attempts = 0  # Reset counter
        self._stop_event = threading.Event()
        threading.Thread(target=self.brute_force_ssh, args=(ip, username, text_results, btn_start, btn_stop)).start()

    def stop_brute_force(self):
        self._stop_event.set()
        entry_ip, entry_username, btn_start, btn_stop, text_results = self.shared_widgets["brute_force"]
        btn_stop.config(state=tk.DISABLED)

    def brute_force_ssh(self, ip, username, text_results, btn_start, btn_stop):
        common_passwords = [
            'password', '123456', 'qwerty', 'root', 'letmein', 'welcome', '12345678',
            'monkey','Azerty-123','dragon', '123123', '1234', 'football', '12345', '123456789',
            'abc123', '111111', '1234567', 'sunshine', 'princess', 'password1',
            'shadow', 'password123', '12345678', 'iloveyou', 'admin123', 'admin@123',
            '1234567890', 'test', 'test123', 'adminadmin', 'admin1234', 'password1',
            'password1234', 'admin12345', 'qwerty123', '123456a', 'adminadmin123',
            'adminadmin1234', 'adminadmin12345', 'admin123456', 'admin1234567',
            'admin12345678', 'admin123456789', 'admin1234567890', 'adminadmin123456',
            'adminadmin1234567', 'adminadmin12345678', 'adminadmin123456789',
            'adminadmin1234567890', 'password123456', 'password1234567',
            'password12345678', 'password123456789', 'password1234567890',
            'passwordadmin', 'passwordadmin123', 'passwordadmin1234',
            'passwordadmin12345', 'passwordadmin123456', 'passwordadmin1234567',
            'passwordadmin12345678', 'passwordadmin123456789',
            'passwordadmin1234567890', '123456789a', 'password123456a',
            'password1234567a', 'password12345678a', 'password123456789a',
            'password1234567890a', 'admin123a', 'admin1234a', 'admin12345a',
            'admin123456a', 'admin1234567a', 'admin12345678a', 'admin123456789a',
            'admin1234567890a', 'password123a', 'password1234a', 'password12345a',
            'password123456a', 'password1234567a', 'password12345678a',
            'password123456789a', 'password1234567890a', 'adminadmin123a',
            'adminadmin1234a', 'adminadmin12345a', 'adminadmin123456a',
            'adminadmin1234567a', 'adminadmin12345678a', 'adminadmin123456789a',
            'adminadmin1234567890a', 'passwordadmin123a', 'passwordadmin1234a',
            'passwordadmin12345a', 'passwordadmin123456a', 'passwordadmin1234567a',
            'passwordadmin12345678a', 'passwordadmin123456789a',
            'passwordadmin1234567890a', '1234567890a', 'password1234567890a','admin',
            'admin1234567890a', 'adminadmin1234567890a', 'passwordadmin1234567890a',
            'Administrateur', 'Admin', 'Azerty', 'administrateur', 'admin', 'azerty',
            'Administrateur1', 'Admin1', 'Azerty1', 'Administrateur123', 'Admin123',
            'Azerty123', 'Administrateur!', 'Admin!', 'Azerty!', 'Administrateur1!',
            'Admin1!', 'Azerty1!', 'Administrateur123!', 'Admin123!', 'Azerty123!',
            'Azerty-123', 'Azerty-123', 'Azerty-123!','Azerty-123', 'Azerty-123',
            'Azerty-123!', 'qwerty','Qwerty1!', 'Qwerty123', 'Qwerty123!',
        ]

        def generate_passwords(username):
            passwords = []
            special_chars = string.punctuation.replace("!", "")
            passwords += [username]
            passwords += [username.capitalize()]
            passwords += [username.lower()]
            passwords += [username.upper()]
            passwords += [username + c for c in special_chars]
            passwords += [c + username for c in special_chars]
            passwords += [username + str(i) for i in range(100)]
            passwords += [str(i) + username for i in range(100)]
            return passwords

        def brute_force_ssh_with_passwords(ip, username, passwords):
            ssh = paramiko.SSHClient()
            ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
            for password in passwords:
                if self._stop_event.is_set():
                    break
                self.brute_force_attempts += 1
                try:
                    ssh.connect(ip, username=username, password=password)
                    text_results.config(state=tk.NORMAL)
                    text_results.insert(tk.END, f"Connexion réussie avec : {password}\n")
                    text_results.config(state=tk.DISABLED)
                    text_results.see(tk.END)
                    self.test_results.append(f"Brute Force SSH réussi avec {username}@{ip} et le mot de passe {password}")
                    return password
                except paramiko.AuthenticationException:
                    text_results.config(state=tk.NORMAL)
                    text_results.insert(tk.END, f"Échec avec : {password}\n")
                    text_results.config(state=tk.DISABLED)
                    text_results.see(tk.END)
                except paramiko.SSHException as e:
                    text_results.config(state=tk.NORMAL)
                    text_results.insert(tk.END, f"Erreur SSH : {e}\n")
                    text_results.config(state=tk.DISABLED)
                    text_results.see(tk.END)
                except Exception as e:
                    text_results.config(state=tk.NORMAL)
                    text_results.insert(tk.END, f"Erreur : {str(e)}\n")
                    text_results.config(state=tk.DISABLED)
                    text_results.see(tk.END)
                finally:
                    ssh.close()
            return None

        password_found = brute_force_ssh_with_passwords(ip, username, common_passwords)

        if not password_found:
            generated_passwords = generate_passwords(username)
            password_found = brute_force_ssh_with_passwords(ip, username, generated_passwords)

        if not password_found:
            for _ in range(500):  # Attempt with 8-character passwords
                if self._stop_event.is_set():
                    break
                password = self.generate_random_password(length=8)
                password_found = brute_force_ssh_with_passwords(ip, username, [password])
                if password_found:
                    break

        if not password_found:
            for _ in range(500):  # Attempt with 12-character passwords
                if self._stop_event.is_set():
                    break
                password = self.generate_random_password(length=12)
                password_found = brute_force_ssh_with_passwords(ip, username, [password])
                if password_found:
                    break

        text_results.config(state=tk.NORMAL)
        if password_found:
            text_results.insert(tk.END, f"Mot de passe trouvé : {password_found}\n")
        else:
            text_results.insert(tk.END, "Mot de passe non trouvé.\n")
            self.test_results.append(f"Brute Force SSH sur {username}@{ip}: Mot de passe non trouvé.")
        text_results.config(state=tk.DISABLED)
        text_results.see(tk.END)

        btn_start.config(state=tk.NORMAL)
        btn_stop.config(state=tk.DISABLED)

    def generate_random_password(self, length=8):
        chars = string.ascii_letters + string.digits + string.punctuation
        return ''.join(random.choice(chars) for _ in range(length))

    def show_port_scan(self):
        self.clear_frame()

        label_ip = tk.Label(self, text="Veuillez entrer l'hôte à scanner :", bg="#2C3E50", fg="#ECF0F1", font=("Arial", 14))
        label_ip.pack(pady=(30, 10))

        entry_ip = tk.Entry(self, font=("Arial", 12))
        entry_ip.pack()

        label_port_range = tk.Label(self, text="Veuillez entrer la plage de ports à scanner :", bg="#2C3E50", fg="#ECF0F1", font=("Arial", 14))
        label_port_range.pack(pady=(10, 10))

        frame_port_range = tk.Frame(self, bg="#2C3E50")
        frame_port_range.pack()

        entry_port_start = tk.Entry(frame_port_range, font=("Arial", 12), width=10)
        entry_port_start.pack(side=tk.LEFT, padx=(0, 10))

        label_to = tk.Label(frame_port_range, text="à", bg="#2C3E50", fg="#ECF0F1", font=("Arial", 14))
        label_to.pack(side=tk.LEFT)

        entry_port_end = tk.Entry(frame_port_range, font=("Arial", 12), width=10)
        entry_port_end.pack(side=tk.LEFT, padx=(10, 0))

        btn_start = tk.Button(self, text="Démarrer le Scan", command=lambda: self.start_scan(entry_ip.get(), entry_port_start.get(), entry_port_end.get()), bg="#3498DB", fg="#FFFFFF", font=("Arial", 12), relief=tk.FLAT)
        btn_start.pack(pady=10)

        btn_stop = tk.Button(self, text="Arrêter le Scan", command=self.stop_scan, bg="#E74C3C", fg="#FFFFFF", font=("Arial", 12), relief=tk.FLAT, state=tk.DISABLED)
        btn_stop.pack(pady=10)

        text_results = tk.Text(self, height=15, width=105, font=("Arial", 12), bg="#34495E", fg="#ECF0F1", relief=tk.FLAT)
        text_results.pack(pady=20)

        self.shared_widgets["port_scan"] = (entry_ip, entry_port_start, entry_port_end, btn_start, btn_stop, text_results)

        btn_return = tk.Button(self, text="Retour au Menu Principal", command=self.main_menu, bg="#3498DB", fg="#FFFFFF", font=("Arial", 12), relief=tk.FLAT)
        btn_return.pack(side=tk.LEFT, padx=20, pady=10)

        info_icon = self.create_info_icon(self, r"C:\Users\enzo.gherbi\Downloads\icon_i.png", "Lancer un scan de ports sur l'adresse IP spécifiée.", x=50, y=420)

    def start_scan(self, target_ip, port_start, port_end):
        entry_ip, entry_port_start, entry_port_end, btn_start, btn_stop, text_results = self.shared_widgets["port_scan"]

        if not target_ip:
            messagebox.showerror("Erreur", "Veuillez entrer l'adresse IP de l'hôte à scanner.")
            return

        try:
            port_start = int(port_start)
            port_end = int(port_end)
            if port_start < 0 or port_end > 65535 or port_start > port_end:
                raise ValueError
        except ValueError:
            messagebox.showerror("Erreur", "Plage de ports invalide. Veuillez entrer une plage valide (0-65535).")
            return

        text_results.config(state=tk.NORMAL)
        text_results.delete(1.0, tk.END)
        text_results.insert(tk.END, "Démarrage du scan de ports...\n\n")
        text_results.config(state=tk.DISABLED)
        btn_start.config(state=tk.DISABLED)
        btn_stop.config(state=tk.NORMAL)

        self.open_ports_count = 0  # Reset counter
        self._stop_event = threading.Event()
        threading.Thread(target=self.scan_ports, args=(target_ip, port_start, port_end, text_results, btn_start, btn_stop)).start()

    def stop_scan(self):
        self._stop_event.set()
        btn_start, btn_stop = self.shared_widgets["port_scan"][3:5]
        btn_start.config(state=tk.NORMAL)
        btn_stop.config(state=tk.DISABLED)

    def scan_ports(self, target_ip, port_start, port_end, text_results, btn_start, btn_stop):
        try:
            nm_path = "C:/Program Files (x86)/Nmap/nmap.exe"
            if not os.path.exists(nm_path):
                raise FileNotFoundError(f"Nmap executable not found at {nm_path}")

            nm = nmap.PortScanner(nmap_search_path=(nm_path,))
            nm.scan(target_ip, f'{port_start}-{port_end}', arguments='-A -O')

            for host in nm.all_hosts():
                text_results.config(state=tk.NORMAL)
                text_results.insert(tk.END, f"Host: {host} ({nm[host].hostname()})\n")
                text_results.insert(tk.END, f"State: {nm[host].state()}\n")
                for proto in nm[host].all_protocols():
                    text_results.insert(tk.END, f"Protocol: {proto}\n")
                    lport = nm[host][proto].keys()
                    for port in lport:
                        if self._stop_event.is_set():
                            break
                        state = nm[host][proto][port]['state']
                        name = nm[host][proto][port]['name']
                        version = nm[host][proto][port]['version']
                        product = nm[host][proto][port]['product']
                        extrainfo = nm[host][proto][port]['extrainfo']
                        text_results.insert(tk.END, f"Port: {port}, State: {state}, Service: {name}, Version: {version}, Product: {product}, Extra: {extrainfo}\n")
                        if state == 'open':
                            self.open_ports_count += 1

                if 'osclass' in nm[host]:
                    for osclass in nm[host]['osclass']:
                        text_results.insert(tk.END, f"OS Class: {osclass['osfamily']} ({osclass['osgen']})\n")
                if 'osmatch' in nm[host]:
                    for osmatch in nm[host]['osmatch']:
                        text_results.insert(tk.END, f"OS Match: {osmatch['name']} ({osmatch['accuracy']}%)\n")
                if 'fingerprint' in nm[host]:
                    text_results.insert(tk.END, f"OS Fingerprint: {nm[host]['fingerprint']}\n")

                if 'mac' in nm[host]:
                    text_results.insert(tk.END, f"MAC Address: {nm[host]['mac']}\n")
                if 'uptime' in nm[host]:
                    text_results.insert(tk.END, f"Uptime: {nm[host]['uptime']} seconds\n")
                if 'tcpsequence' in nm[host]:
                    text_results.insert(tk.END, f"TCP Sequence: {nm[host]['tcpsequence']}\n")
                if 'ipidsequence' in nm[host]:
                    text_results.insert(tk.END, f"IPID Sequence: {nm[host]['ipidsequence']}\n")
                if 'tcptssequence' in nm[host]:
                    text_results.insert(tk.END, f"TCP Timestamp Sequence: {nm[host]['tcptssequence']}\n")

            self.test_results.append(f"Scan de ports pour {target_ip} ({port_start}-{port_end}): {self.open_ports_count} ports ouverts trouvés.")
            text_results.config(state=tk.DISABLED)

        except Exception as e:
            text_results.config(state=tk.NORMAL)
            text_results.insert(tk.END, f"Erreur lors de l'exécution de la commande de scan : {e}\n")
            text_results.config(state=tk.DISABLED)
        finally:
            text_results.see(tk.END)
            btn_start.config(state=tk.NORMAL)
            btn_stop.config(state=tk.DISABLED)

    def filter_nmap_output(self, output):
        lines = output.split('\n')
        filtered_lines = []
        skip_phrases = [
            "Starting Nmap", "Nmap scan report", "Nmap done",
            "OS and Service detection performed", "Please report any incorrect results",
            "https://nmap.org", "Not shown: "
        ]
        for line in lines:
            if not any(phrase in line for phrase in skip_phrases):
                filtered_lines.append(line)
        return '\n'.join(filtered_lines)

    def show_network_scan(self):
        self.clear_frame()

        label_interface = tk.Label(self, text="Sélectionnez l'interface réseau :", bg="#2C3E50", fg="#ECF0F1", font=("Arial", 14))
        label_interface.pack(pady=(30, 10))

        self.interface_var = tk.StringVar(self)
        interfaces = self.get_interfaces()
        if not interfaces:
            messagebox.showerror("Erreur", "Aucune interface réseau trouvée.")
            return

        self.interface_var.set(interfaces[0])
        interface_menu = tk.OptionMenu(self, self.interface_var, *interfaces, command=self.on_interface_change)
        interface_menu.pack()

        self.start_button = tk.Button(self, text="Démarrer la capture", command=self.start_sniffing, bg="#3498DB", fg="#FFFFFF", font=("Arial", 12), relief=tk.FLAT)
        self.start_button.pack(pady=20)

        self.stop_button = tk.Button(self, text="Arrêter la capture", command=self.stop_sniffing, state=tk.DISABLED, bg="#E74C3C", fg="#FFFFFF", font=("Arial", 12), relief=tk.FLAT)
        self.stop_button.pack(pady=10)

        self.text_area = scrolledtext.ScrolledText(self, wrap=tk.WORD, width=140, height=7.5, font=("Arial", 12), bg="#34495E", fg="#ECF0F1", relief=tk.FLAT)
        self.text_area.pack(pady=8)

        self.tree = ttk.Treeview(self)
        self.tree['columns'] = ('value',)
        self.tree.column('#0', width=400, minwidth=200)
        self.tree.column('value', width=600, minwidth=200)
        self.tree.heading('#0', text='Field', anchor=tk.W)
        self.tree.heading('value', text='Value', anchor=tk.W)
        self.tree.pack(fill=tk.BOTH, expand=True)

        btn_return = tk.Button(self, text="Retour au Menu Principal", command=self.main_menu, bg="#3498DB", fg="#FFFFFF", font=("Arial", 12), relief=tk.FLAT)
        btn_return.pack(side=tk.LEFT, padx=20, pady=10)

        info_icon = self.create_info_icon(self, r"C:\Users\enzo.gherbi\Downloads\icon_i.png", "Sélectionnez une interface réseau et démarrez la capture de paquets.", x=50, y=420)

    def on_interface_change(self, event=None):
        if self.capture_in_progress:
            self.stop_sniffing()
        self.clear_text_area()
        self.clear_treeview()

        # Réinitialiser l'événement de capture pour être prêt pour une nouvelle capture
        self.stop_capture_event.clear()

        # Réinitialiser le thread de capture
        self.capture_thread = None

        self.capture_in_progress = False

    def get_interfaces(self):
        return [interface for interface, addrs in psutil.net_if_addrs().items() if any(":" not in addr.address for addr in addrs)]

    def start_sniffing(self):
        if self.capture_in_progress:
            messagebox.showinfo("Info", "La capture est déjà en cours.")
            return

        interface = self.interface_var.get()
        self.clear_text_area()
        self.clear_treeview()
        self.start_button.config(state=tk.DISABLED)
        self.stop_button.config(state=tk.NORMAL)
        self.stop_capture_event.clear()

        self.packets_count = []  # Reset packet count
        self.capture_start_time = time.time()  # Record start time

        self.capture_in_progress = True
        self.capture_thread = threading.Thread(target=self.start_capture, args=(interface,))
        self.capture_thread.start()
        self.thread_running = True

    def stop_sniffing(self):
        if not self.capture_in_progress:
            messagebox.showinfo("Info", "La capture est déjà arrêtée.")
            return

        self.stop_capture_event.set()
        self.wait_for_thread_to_finish()
        self.update_buttons_state()

        self.capture_in_progress = False

    def wait_for_thread_to_finish(self):
        if self.capture_thread.is_alive():
            self.after(100, self.wait_for_thread_to_finish)
        else:
            self.capture_in_progress = False
            self.thread_running = False

    def start_capture(self, interface):
        try:
            sniff(iface=interface, prn=self.packet_callback, stop_filter=lambda x: self.stop_capture_event.is_set(), store=0)
        except OSError:
            messagebox.showerror("Erreur", "Impossible d'ouvrir l'interface réseau. Assurez-vous d'avoir les permissions nécessaires.")
        finally:
            self.capture_in_progress = False
            self.thread_running = False

    def packet_callback(self, packet):
        if IP in packet:
            src, dst, proto, length, info = packet[IP].src, packet[IP].dst, packet.name, len(packet), packet.summary()
            line_index = len(self.packets) + 1
            self.packets.append(packet)
            tag = f"packet_{line_index}"
            self.text_area.insert(tk.END, f"{line_index}: Source: {src}, Destination: {dst}, Protocole: {proto}, Longueur: {length}, Info: {info}\n", tag)
            self.text_area.see(tk.END)
            self.text_area.tag_bind(tag, "<Button-1>", lambda e, p=packet: self.show_packet_details(p))
            self.test_results.append(f"Paquet capturé: Source: {src}, Destination: {dst}, Protocole: {proto}, Longueur: {length}, Info: {info}")
            elapsed_time = time.time() - self.capture_start_time
            self.packets_count.append((elapsed_time, len(self.packets)))

    def clear_text_area(self):
        self.text_area.delete("1.0", tk.END)
        for tag in self.text_area.tag_names():
            self.text_area.tag_unbind(tag, "<Button-1>")

    def clear_treeview(self):
        for item in self.tree.get_children():
            self.tree.delete(item)

    def update_buttons_state(self):
        self.start_button.config(state=tk.NORMAL)
        self.stop_button.config(state=tk.DISABLED)

    def show_packet_details(self, packet):
        self.clear_treeview()
        def add_tree_item(parent, key, value):
            node = self.tree.insert(parent, 'end', text=key, values=(value,))
            if isinstance(value, dict):
                for k, v in value.items():
                    add_tree_item(node, k, v)

        packet_details = packet.show(dump=True)
        details_dict = self.parse_packet_details(packet_details)
        for k, v in details_dict.items():
            add_tree_item('', k, v)

    def parse_packet_details(self, details_str):
        lines = details_str.split('\n')
        details = {}
        current_dict = details
        parents = []
        for line in lines:
            if line.startswith('###[ '):
                section_name = line[5:-4].strip()
                if parents:
                    current_dict = parents[-1]
                parents.append(current_dict)
                current_dict[section_name] = {}
                current_dict = current_dict[section_name]
            elif line.startswith(']###'):
                current_dict = parents.pop()
            elif line.startswith(' '):
                key, _, value = line.partition(' = ')
                current_dict[key.strip()] = value.strip()
        return details

    def generate_pdf_report(self):
        if not self.test_results:
            messagebox.showerror("Erreur", "Aucun test n'a été effectué pour générer le rapport.")
            return

        directory = filedialog.askdirectory()
        if not directory:
            return

        pdf = FPDF()
        pdf.add_page()
        pdf.set_font("Arial", size=12)

        pdf.set_font("Arial", size=16, style='B')
        pdf.cell(200, 10, txt="Rapport des Tests de la Toolbox", ln=True, align='C')

        for result in self.test_results:
            pdf.set_font("Arial", size=12)
            pdf.multi_cell(0, 10, result)

        pdf.add_page()
        pdf.set_font("Arial", size=14, style='B')
        pdf.cell(200, 10, txt="Nombre de Paquets Capturés", ln=True, align='L')
        pdf.set_font("Arial", size=12)

        self.plot_graphs()

        if os.path.exists('packets_count.png'):
            pdf.image('packets_count.png', x=10, y=None, w=100)

        # Scan de Vulnérabilités
        pdf.add_page()
        pdf.set_font("Arial", size=14, style='B')
        pdf.cell(200, 10, txt="Scan de Vulnérabilités", ln=True, align='L')
        pdf.set_font("Arial", size=12)

        text_results = self.shared_widgets.get("vuln_scan")
        if text_results:
            results_content = text_results[3].get("1.0", tk.END).strip()
            pdf.multi_cell(0, 10, results_content)

        pdf.output(f"{directory}/rapport_tests.pdf")

        messagebox.showinfo("Succès", "Le rapport PDF a été généré avec succès.")

    def plot_graphs(self):
        if self.packets_count:
            times, counts = zip(*self.packets_count)
            plt.figure(figsize=(10, 5))
            plt.plot(times, counts, color='red')
            plt.xlabel('Temps écoulé (s)')
            plt.ylabel('Nombre de paquets capturés')
            plt.title('Nombre de paquets capturés au fil du temps')
            plt.savefig('packets_count.png')

    def load_image(self, path, size):
        try:
            image = Image.open(path).resize(size, Image.LANCZOS)
            return ImageTk.PhotoImage(image)
        except Exception as e:
            messagebox.showerror("Erreur", f"Impossible de charger l'image '{path}': {e}")
            return None

    def create_info_icon(self, parent, path, tooltip_text, x, y):
        info_image = self.load_image(path, (20, 20))
        if info_image:
            info_icon = tk.Label(parent, image=info_image, bg="#2C3E50")
            info_icon.image = info_image
            info_icon.place(x=x, y=y)
            Tooltip(info_icon, tooltip_text)

    def show_file_scan(self):
        self.clear_frame()
        
        label_instruction = tk.Label(self, text="Sélectionner un fichier à scanner pour les virus :", bg="#2C3E50", fg="#ECF0F1", font=("Arial", 14))
        label_instruction.pack(pady=(30, 10))

        btn_select_file = tk.Button(self, text="Sélectionner un fichier", command=self.select_file, bg="#3498DB", fg="#FFFFFF", font=("Arial", 12), relief=tk.FLAT)
        btn_select_file.pack(pady=10)

        self.text_results = tk.Text(self, height=20, width=120, font=("Arial", 12), bg="#34495E", fg="#ECF0F1", relief=tk.FLAT)
        self.text_results.pack(pady=20)

        btn_return = tk.Button(self, text="Retour au Menu Principal", command=self.main_menu, bg="#3498DB", fg="#FFFFFF", font=("Arial", 12), relief=tk.FLAT)
        btn_return.pack(side=tk.LEFT, padx=20, pady=10)

        info_icon = self.create_info_icon(self, r"C:\Users\enzo.gherbi\Downloads\icon_i.png", "Sélectionner un fichier et scanner pour les virus.", x=50, y=420)x

    def get_file_hash(self, file_path):
        sha256_hash = hashlib.sha256()
        with open(file_path, "rb") as f:
            for byte_block in iter(lambda: f.read(4096), b""):
                sha256_hash.update(byte_block)
        return sha256_hash.hexdigest()

    def get_report(self, file_hash):
        params = {'apikey': API_KEY, 'resource': file_hash}
        response = requests.get(API_URL_REPORT, params=params)
        return response.json()

    def upload_file(self, file_path):
        with open(file_path, 'rb') as f:
            files = {'file': (file_path, f)}
            response = requests.post(API_URL_SCAN, files=files, params={'apikey': API_KEY})
        return response.json()

    def wait_for_scan(self, file_hash):
        while True:
            report = self.get_report(file_hash)
            if report['response_code'] == 1 and report.get('scan_date'):
                return report
            time.sleep(15)

    def scan_file(self, file_path):
        file_hash = self.get_file_hash(file_path)
        report = self.get_report(file_hash)
        
        if report['response_code'] != 1:
            upload_response = self.upload_file(file_path)
            scan_id = upload_response['scan_id']
            time.sleep(15)  # Attendre avant de vérifier le statut initialement
            report = self.wait_for_scan(scan_id)
        
        return report

    def format_basic_properties(self, report):
        basic_properties = report.get('additional_info', {})
        result_message = "\nPropriétés de base:\n"
        result_message += f"MD5: {report.get('md5', 'N/A')}\n"
        result_message += f"SHA-1: {report.get('sha1', 'N/A')}\n"
        result_message += f"SHA-256: {report.get('sha256', 'N/A')}\n"
        result_message += f"Vhash: {basic_properties.get('vhash', 'N/A')}\n"
        result_message += f"SSDEEP: {basic_properties.get('ssdeep', 'N/A')}\n"
        result_message += f"TLSH: {basic_properties.get('tlsh', 'N/A')}\n"
        result_message += f"Type de fichier: {basic_properties.get('file_type', 'N/A')}\n"
        result_message += f"Magic: {basic_properties.get('magic', 'N/A')}\n"
        result_message += f"TrID: {basic_properties.get('trid', 'N/A')}\n"
        result_message += f"Taille du fichier: {basic_properties.get('size', 'N/A')} octets\n"
        return result_message

    def format_history(self, report):
        basic_properties = report.get('additional_info', {})
        result_message = "\nHistorique:\n"
        result_message += f"Date de création: {basic_properties.get('creation_time', 'N/A')}\n"
        result_message += f"Première soumission: {basic_properties.get('first_submission', 'N/A')}\n"
        result_message += f"Dernière soumission: {basic_properties.get('last_submission', 'N/A')}\n"
        result_message += f"Dernière analyse: {basic_properties.get('last_analysis', 'N/A')}\n"
        return result_message

    def format_names(self, report):
        basic_properties = report.get('additional_info', {})
        result_message = "\nNoms:\n"
        result_message += f"Noms: {basic_properties.get('names', 'N/A')}\n"
        return result_message

    def format_bundle_info(self, report):
        basic_properties = report.get('additional_info', {})
        result_message = "\nInformations sur le bundle:\n"
        result_message += f"Nombre de fichiers contenus: {basic_properties.get('contained_files', 'N/A')}\n"
        result_message += f"Taille non compressée: {basic_properties.get('uncompressed_size', 'N/A')}\n"
        result_message += f"Modification la plus ancienne du contenu: {basic_properties.get('earliest_content_modification', 'N/A')}\n"
        result_message += f"Dernière modification du contenu: {basic_properties.get('latest_content_modification', 'N/A')}\n"
        return result_message

    def format_analysis_details(self, report):
        result_message = "\nDétails des analyses:\n"
        for engine, details in report['scans'].items():
            result_message += f"{engine}:\n"
            result_message += f"  - Résultat: {details['result']}\n"
            result_message += f"  - Moteur version: {details['version']}\n"
            result_message += f"  - Mise à jour: {details['update']}\n"
            result_message += f"  - Détecté: {'Oui' if details['detected'] else 'Non'}\n"
            result_message += "\n"
        return result_message

    def check_for_viruses(self, report):
        result_message = ""
        if report['positives'] > 0:
            result_message = f"Le fichier contient des virus ! ({report['positives']} détections positives)\n"
        else:
            result_message = "Le fichier est sain, aucun virus détecté.\n"
        
        result_message += self.format_basic_properties(report)
        result_message += self.format_history(report)
        result_message += self.format_names(report)
        result_message += self.format_bundle_info(report)
        result_message += self.format_analysis_details(report)

        return result_message

    def select_file(self):
        file_path = filedialog.askopenfilename()
        if file_path:
            self.text_results.config(state=tk.NORMAL)
            self.text_results.delete(1.0, tk.END)
            self.text_results.insert(tk.END, "Analyse en cours, veuillez patienter...")
            self.text_results.config(state=tk.DISABLED)
            threading.Thread(target=self.run_file_scan, args=(file_path,)).start()

    def run_file_scan(self, file_path):
        report = self.scan_file(file_path)
        result_message = self.check_for_viruses(report)
        self.text_results.config(state=tk.NORMAL)
        self.text_results.delete(1.0, tk.END)
        self.text_results.insert(tk.END, result_message)
        self.text_results.config(state=tk.DISABLED)

if __name__ == "__main__":
    app = App()
    app.mainloop()
