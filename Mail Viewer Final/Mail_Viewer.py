import imaplib
import poplib
import email
from email.header import decode_header
import configparser
import os
from typing import List, Dict, Optional, Tuple
import tkinter as tk
from tkinter import ttk, messagebox, filedialog
import threading
from datetime import datetime
import re
from html.parser import HTMLParser
import webbrowser
import json
import ssl
import time
import socket

# Fix IMAP response size limit
imaplib._MAXLINE = 10000000  # 10MB

class HTMLTextExtractor(HTMLParser):
    """Extract text from HTML and convert links"""
    def __init__(self):
        super().__init__()
        self.text = []
        self.in_script = False
        self.in_style = False
    
    def handle_starttag(self, tag, attrs):
        if tag == 'script':
            self.in_script = True
        elif tag == 'style':
            self.in_style = True
        elif tag == 'br':
            self.text.append('\n')
        elif tag == 'p':
            self.text.append('\n')
        elif tag == 'a':
            for attr, value in attrs:
                if attr == 'href':
                    self.text.append(f' [{value}] ')
    
    def handle_endtag(self, tag):
        if tag == 'script':
            self.in_script = False
        elif tag == 'style':
            self.in_style = False
        elif tag in ['p', 'div', 'br', 'tr']:
            self.text.append('\n')
    
    def handle_data(self, data):
        if not self.in_script and not self.in_style:
            cleaned = data.strip()
            if cleaned:
                self.text.append(cleaned + ' ')
    
    def get_text(self):
        return ''.join(self.text)


class SmartLoginHandler:
    """Advanced login handler with aggressive hybrid IMAP/POP3 connection and auto-cleaning DB"""
    
    # Safety delay between protocol attempts (seconds)
    PROTOCOL_SWITCH_DELAY = 3
    
    def __init__(self, db_path: str = "./email_config"):
        """Initialize SmartLoginHandler
        
        Args:
            db_path: Path to directory containing server configuration files
        """
        self.db_path = db_path
        self.imap_servers = {}
        self.pop_servers = {}
        self._ensure_config_exists()
        self._load_servers()
    
    def _ensure_config_exists(self):
        """Ensure config directory and files exist"""
        os.makedirs(self.db_path, exist_ok=True)
        
        imap_path = os.path.join(self.db_path, "imap_servers.txt")
        if not os.path.exists(imap_path):
            with open(imap_path, 'w', encoding='utf-8') as f:
                f.write("# IMAP Server Mappings - Auto-updated with working servers\n")
                f.write("# Format: domain=server (e.g., gmail.com=imap.gmail.com)\n")
        
        pop_path = os.path.join(self.db_path, "pop_servers.txt")
        if not os.path.exists(pop_path):
            with open(pop_path, 'w', encoding='utf-8') as f:
                f.write("# POP3 Server Mappings - Auto-updated with working servers\n")
                f.write("# Format: domain=server (e.g., gmail.com=pop.gmail.com)\n")
    
    def _load_servers(self):
        """Load server configurations from text files"""
        # Load IMAP servers
        imap_path = os.path.join(self.db_path, "imap_servers.txt")
        if os.path.exists(imap_path):
            with open(imap_path, 'r', encoding='utf-8') as f:
                for line in f:
                    line = line.strip()
                    if line and not line.startswith('#'):
                        if '=' in line:
                            parts = line.split('=', 1)
                            if len(parts) == 2:
                                domain = parts[0].strip().lower()
                                server = parts[1].strip()
                                self.imap_servers[domain] = server
        
        # Load POP3 servers
        pop_path = os.path.join(self.db_path, "pop_servers.txt")
        if os.path.exists(pop_path):
            with open(pop_path, 'r', encoding='utf-8') as f:
                for line in f:
                    line = line.strip()
                    if line and not line.startswith('#'):
                        if '=' in line:
                            parts = line.split('=', 1)
                            if len(parts) == 2:
                                domain = parts[0].strip().lower()
                                server = parts[1].strip()
                                self.pop_servers[domain] = server
    
    def _save_server(self, domain: str, server: str, protocol: str):
        """Save working server to config file (auto-cleaning)
        
        Args:
            domain: Email domain
            server: Server hostname
            protocol: 'imap' or 'pop3'
        """
        filename = "imap_servers.txt" if protocol == "imap" else "pop_servers.txt"
        filepath = os.path.join(self.db_path, filename)
        
        # Update in-memory cache
        if protocol == "imap":
            self.imap_servers[domain] = server
        else:
            self.pop_servers[domain] = server
        
        # Read existing entries
        entries = {}
        if os.path.exists(filepath):
            with open(filepath, 'r', encoding='utf-8') as f:
                for line in f:
                    line = line.strip()
                    if line and not line.startswith('#'):
                        if '=' in line:
                            parts = line.split('=', 1)
                            if len(parts) == 2:
                                d = parts[0].strip().lower()
                                s = parts[1].strip()
                                entries[d] = s
        
        # Update or add new entry
        entries[domain] = server
        
        # Write back to file
        with open(filepath, 'w', encoding='utf-8') as f:
            if protocol == "imap":
                f.write("# IMAP Server Mappings - Auto-updated with working servers\n")
                f.write("# Format: domain=server (e.g., gmail.com=imap.gmail.com)\n")
            else:
                f.write("# POP3 Server Mappings - Auto-updated with working servers\n")
                f.write("# Format: domain=server (e.g., gmail.com=pop.gmail.com)\n")
            
            for d, s in sorted(entries.items()):
                f.write(f"{d}={s}\n")
    
    def _try_imap_connection(self, server: str, port: int, email_addr: str, password: str, timeout: int, use_ssl: bool) -> Tuple[bool, Optional[object], str]:
        """Try IMAP connection
        
        Returns:
            (success, connection_object, error_type) where error_type is 'AUTH' or 'CONN'
        """
        try:
            if use_ssl:
                conn = imaplib.IMAP4_SSL(server, port, timeout=timeout)
            else:
                conn = imaplib.IMAP4(server, port, timeout=timeout)
                try:
                    conn.starttls()
                except (imaplib.IMAP4.error, ssl.SSLError):
                    pass  # StartTLS optional for port 143
            
            try:
                conn.login(email_addr, password)
                return True, conn, None
            except imaplib.IMAP4.error as e:
                # Authentication failed
                try:
                    conn.logout()
                except Exception:
                    pass
                return False, None, 'AUTH'
        except (socket.timeout, socket.error, OSError, ssl.SSLError) as e:
            # Connection failed
            return False, None, 'CONN'
        except Exception as e:
            return False, None, 'CONN'
    
    def _try_pop_connection(self, server: str, port: int, email_addr: str, password: str, timeout: int, use_ssl: bool) -> Tuple[bool, Optional[object], str]:
        """Try POP3 connection
        
        Returns:
            (success, connection_object, error_type) where error_type is 'AUTH' or 'CONN'
        """
        try:
            if use_ssl:
                conn = poplib.POP3_SSL(server, port, timeout=timeout)
            else:
                conn = poplib.POP3(server, port, timeout=timeout)
                try:
                    conn.stls()
                except (poplib.error_proto, ssl.SSLError):
                    pass  # STLS optional for port 110
            
            try:
                conn.user(email_addr)
                conn.pass_(password)
                return True, conn, None
            except poplib.error_proto as e:
                # Authentication failed
                try:
                    conn.quit()
                except Exception:
                    pass
                return False, None, 'AUTH'
        except (socket.timeout, socket.error, OSError, ssl.SSLError) as e:
            # Connection failed
            return False, None, 'CONN'
        except Exception as e:
            return False, None, 'CONN'
    
    def _guess_servers(self, domain: str) -> List[Tuple[str, str]]:
        """Guess common server names for domain
        
        Returns:
            List of (protocol, server) tuples
        """
        servers = []
        
        # Common IMAP patterns
        servers.append(('imap', f'imap.{domain}'))
        servers.append(('imap', f'mail.{domain}'))
        
        # Common POP3 patterns
        servers.append(('pop3', f'pop.{domain}'))
        servers.append(('pop3', f'pop3.{domain}'))
        servers.append(('pop3', f'mail.{domain}'))
        
        return servers
    
    def connect(self, email_addr: str, password: str) -> Tuple[str, Dict]:
        """Connect to mail server using aggressive hybrid approach
        
        Args:
            email_addr: Email address
            password: Password
            
        Returns:
            (result_code, details) where:
                result_code: 'SUCCESS', 'AUTH_FAILED', or 'CONN_ERROR'
                details: Dict with connection info (protocol, server, port, connection)
        """
        domain = email_addr.split('@')[-1].lower()
        
        # Track if we got any auth failures
        auth_failed = False
        
        # PHASE 1: IMAP
        # Try known IMAP server first
        imap_servers_to_try = []
        if domain in self.imap_servers:
            imap_servers_to_try.append(self.imap_servers[domain])
        
        # Add guessed servers
        for proto, server in self._guess_servers(domain):
            if proto == 'imap' and server not in imap_servers_to_try:
                imap_servers_to_try.append(server)
        
        for server in imap_servers_to_try:
            # Port 993 (SSL) - 6s timeout
            success, conn, error_type = self._try_imap_connection(
                server, 993, email_addr, password, 6, True
            )
            if success:
                self._save_server(domain, server, 'imap')
                return 'SUCCESS', {
                    'protocol': 'imap',
                    'server': server,
                    'port': 993,
                    'connection': conn,
                    'ssl': True
                }
            if error_type == 'AUTH':
                auth_failed = True
            
            # Port 143 (StartTLS) - 12s timeout
            success, conn, error_type = self._try_imap_connection(
                server, 143, email_addr, password, 12, False
            )
            if success:
                self._save_server(domain, server, 'imap')
                return 'SUCCESS', {
                    'protocol': 'imap',
                    'server': server,
                    'port': 143,
                    'connection': conn,
                    'ssl': False
                }
            if error_type == 'AUTH':
                auth_failed = True
        
        # Safety delay before trying POP3
        if auth_failed or len(imap_servers_to_try) > 0:
            time.sleep(self.PROTOCOL_SWITCH_DELAY)
        
        # PHASE 2: POP3 (Fallback)
        pop_servers_to_try = []
        if domain in self.pop_servers:
            pop_servers_to_try.append(self.pop_servers[domain])
        
        # Add guessed servers
        for proto, server in self._guess_servers(domain):
            if proto == 'pop3' and server not in pop_servers_to_try:
                pop_servers_to_try.append(server)
        
        for server in pop_servers_to_try:
            # Port 995 (SSL) - 4s timeout
            success, conn, error_type = self._try_pop_connection(
                server, 995, email_addr, password, 4, True
            )
            if success:
                self._save_server(domain, server, 'pop3')
                return 'SUCCESS', {
                    'protocol': 'pop3',
                    'server': server,
                    'port': 995,
                    'connection': conn,
                    'ssl': True
                }
            if error_type == 'AUTH':
                auth_failed = True
            
            # Port 110 (StartTLS) - 8s timeout
            success, conn, error_type = self._try_pop_connection(
                server, 110, email_addr, password, 8, False
            )
            if success:
                self._save_server(domain, server, 'pop3')
                return 'SUCCESS', {
                    'protocol': 'pop3',
                    'server': server,
                    'port': 110,
                    'connection': conn,
                    'ssl': False
                }
            if error_type == 'AUTH':
                auth_failed = True
        
        # Return final verdict
        if auth_failed:
            return 'AUTH_FAILED', {}
        else:
            return 'CONN_ERROR', {}


class MailViewerBackend:
    def __init__(self):
        """Initialize Mail Viewer Backend"""
        self.protocol = None
        self.connection = None
        self.email_address = None
        self.password = None
        self.host = None
        self.port = None
        self.timeout = 20
        self.current_folder = 'INBOX'
        
        self._search_cache = {}
        self._cached_emails = []
        
        self.servers = self.load_servers()
        self.config_servers = self.load_config_servers()
    
    def load_servers(self) -> Dict:
        """Load servers from text files"""
        servers = {'imap': {}, 'pop3': {}}
        
        if os.path.exists('imap.txt'):
            with open('imap.txt', 'r', encoding='utf-8') as f:
                for line in f:
                    line = line.strip()
                    if line and not line.startswith('#'):
                        if '|' in line:
                            parts = line.split('|', 1)
                            if len(parts) == 2:
                                domain = parts[0].strip().lower()
                                server = parts[1].strip()
                                servers['imap'][domain] = {'host': server, 'port': 993}
        
        if os.path.exists('pop.txt'):
            with open('pop.txt', 'r', encoding='utf-8') as f:
                for line in f:
                    line = line.strip()
                    if line and not line.startswith('#'):
                        if '|' in line:
                            parts = line.split('|', 1)
                            if len(parts) == 2:
                                domain = parts[0].strip().lower()
                                server = parts[1].strip()
                                servers['pop3'][domain] = {'host': server, 'port': 995}
        
        return servers
    
    def load_config_servers(self) -> Dict:
        """Load configuration from ini files"""
        configs = {'imap': {}, 'pop3': {}}
        
        if os.path.exists('imap.ini'):
            config = configparser.ConfigParser()
            config.read('imap.ini', encoding='utf-8')
            
            if 'DEFAULT' in config or config.defaults():
                configs['imap']['default'] = {
                    'host': config.get('DEFAULT', 'server', fallback=None),
                    'port': config.getint('DEFAULT', 'port', fallback=993)
                }
            
            for section in config.sections():
                if section.upper() != 'DEFAULT':
                    domain = section.lower()
                    configs['imap'][domain] = {
                        'host': config.get(section, 'server'),
                        'port': config.getint(section, 'port', fallback=993)
                    }
        
        if os.path.exists('pop3.ini'):
            config = configparser.ConfigParser()
            config.read('pop3.ini', encoding='utf-8')
            
            if 'DEFAULT' in config or config.defaults():
                configs['pop3']['default'] = {
                    'host': config.get('DEFAULT', 'server', fallback=None),
                    'port': config.getint('DEFAULT', 'port', fallback=995)
                }
            
            for section in config.sections():
                if section.upper() != 'DEFAULT':
                    domain = section.lower()
                    configs['pop3'][domain] = {
                        'host': config.get(section, 'server'),
                        'port': config.getint(section, 'port', fallback=995)
                    }
        
        return configs
    
    def auto_detect_server(self, email_address: str, protocol: str) -> Optional[Dict]:
        """Auto detect server"""
        domain = email_address.split('@')[-1].lower()
        
        if domain in self.servers[protocol]:
            return self.servers[protocol][domain]
        
        if domain in self.config_servers[protocol]:
            return self.config_servers[protocol][domain]
        
        if 'default' in self.config_servers[protocol]:
            default_info = self.config_servers[protocol]['default']
            if default_info['host']:
                host = default_info['host']
                if '{domain}' in host:
                    host = host.replace('{domain}', domain)
                return {'host': host, 'port': default_info['port']}
        
        return None
    
    def try_connect(self, email_address: str, password: str, protocol: str) -> tuple:
        """Try to connect with multiple ports (SSL and non-SSL)"""
        try:
            server_info = self.auto_detect_server(email_address, protocol)
            if not server_info:
                return False, f"No {protocol.upper()} server configured"
            
            self.host = server_info['host']
            
            if protocol == 'imap':
                # Try Port 993 (SSL) first, then 143 (non-SSL)
                ports_to_try = [
                    (993, True),   # SSL
                    (143, False)   # Non-SSL
                ]
                
                for port, use_ssl in ports_to_try:
                    try:
                        if use_ssl:
                            self.connection = imaplib.IMAP4_SSL(self.host, port)
                            self.connection.sock.settimeout(self.timeout)
                        else:
                            self.connection = imaplib.IMAP4(self.host, port)
                            self.connection.sock.settimeout(self.timeout)
                        
                        self.connection.login(email_address, password)
                        self.protocol = protocol
                        self.email_address = email_address
                        self.password = password
                        self.port = port
                        
                        ssl_info = "SSL" if use_ssl else "Non-SSL"
                        return True, f"Connected via {protocol.upper()} port {port} ({ssl_info})"
                        
                    except Exception as e:
                        continue
                
                return False, f"IMAP: Could not connect on ports 993 or 143"
            
            else:  # POP3
                # Try Port 995 (SSL) first, then 110 (non-SSL)
                ports_to_try = [
                    (995, True),   # SSL
                    (110, False)   # Non-SSL
                ]
                
                for port, use_ssl in ports_to_try:
                    try:
                        if use_ssl:
                            self.connection = poplib.POP3_SSL(self.host, port, timeout=self.timeout)
                        else:
                            self.connection = poplib.POP3(self.host, port, timeout=self.timeout)
                        
                        self.connection.user(email_address)
                        self.connection.pass_(password)
                        self.protocol = protocol
                        self.email_address = email_address
                        self.password = password
                        self.port = port
                        
                        ssl_info = "SSL" if use_ssl else "Non-SSL"
                        return True, f"Connected via {protocol.upper()} port {port} ({ssl_info})"
                        
                    except Exception as e:
                        continue
                
                return False, f"POP3: Could not connect on ports 995 or 110"
                
        except Exception as e:
            return False, f"{protocol.upper()}: {str(e)[:80]}"
    
    def connect(self, email_address: str, password: str) -> tuple:
        """Connect to server"""
        success, message = self.try_connect(email_address, password, 'imap')
        if success:
            return True, message
        
        imap_error = message
        
        success, message = self.try_connect(email_address, password, 'pop3')
        if success:
            return True, message
        
        pop3_error = message
        
        return False, f"Connection failed:\nIMAP: {imap_error}\nPOP3: {pop3_error}"
    
    def get_folders(self) -> List[str]:
        """Get folders"""
        if self.protocol != 'imap':
            return ['INBOX']
        
        try:
            status, folders = self.connection.list()
            if status == 'OK':
                folder_list = []
                for folder in folders:
                    decoded = folder.decode()
                    parts = decoded.split('"')
                    if len(parts) >= 3:
                        folder_name = parts[-2]
                        folder_list.append(folder_name)
                return folder_list
        except:
            pass
        
        return ['INBOX']
    
    def search_emails(self, search_term: str, search_field: str = 'ALL', folder: str = None, progress_callback=None) -> List[Dict]:
        """Search emails"""
        if folder:
            self.current_folder = folder
            
        try:
            if self.protocol != 'imap':
                return []
            
            status, response = self.connection.select(self.current_folder, readonly=True)
            if status != 'OK':
                return []
            
            if search_field == 'Subject':
                criteria = f'(SUBJECT "{search_term}")'
            elif search_field == 'From' or search_field == 'Sender':
                criteria = f'(FROM "{search_term}")'
            elif search_field == 'Body':
                criteria = f'(BODY "{search_term}")'
            else:
                criteria = f'(OR (OR SUBJECT "{search_term}" FROM "{search_term}") BODY "{search_term}")'
            
            status, messages = self.connection.search(None, criteria)
            
            if status != 'OK':
                return []
            
            email_ids = messages[0].split()[-100:]
            return self._batch_fetch_emails(email_ids, progress_callback)
            
        except:
            return []
    
    def fetch_page(self, page: int, per_page: int = 100, folder: str = None, progress_callback=None) -> tuple:
        """Fetch emails"""
        if folder:
            self.current_folder = folder
        
        try:
            if self.protocol == 'imap':
                return self._fetch_page_imap(page, per_page, progress_callback)
            else:
                return self._fetch_page_pop3(page, per_page, progress_callback)
        except:
            return [], 0
    
    def _batch_fetch_emails(self, email_ids: list, progress_callback=None) -> List[Dict]:
        """Batch fetch emails"""
        if not email_ids:
            return []
        
        emails = []
        batch_size = 20
        total = len(email_ids)
        
        for i in range(0, len(email_ids), batch_size):
            batch = email_ids[i:i+batch_size]
            try:
                id_string = b','.join(batch)
                status, msg_data = self.connection.fetch(id_string, '(BODY.PEEK[])')
                
                if status != 'OK':
                    continue
                
                for j in range(0, len(msg_data), 2):
                    try:
                        if msg_data[j] and len(msg_data[j]) > 1:
                            msg = email.message_from_bytes(msg_data[j][1])
                            email_id = batch[j//2].decode() if j//2 < len(batch) else str(i+j//2)
                            emails.append(self._parse_email(msg, email_id))
                    except:
                        continue
                
                if progress_callback:
                    progress_callback(len(emails), total)
                    
            except:
                for email_id in batch:
                    try:
                        status, msg_data = self.connection.fetch(email_id, '(BODY.PEEK[])')
                        if status == 'OK' and msg_data and msg_data[0]:
                            msg = email.message_from_bytes(msg_data[0][1])
                            emails.append(self._parse_email(msg, email_id.decode()))
                            
                            if progress_callback:
                                progress_callback(len(emails), total)
                    except:
                        continue
        
        return emails[::-1]
    
    def _fetch_page_imap(self, page: int, per_page: int, progress_callback=None) -> tuple:
        """Fetch IMAP page"""
        try:
            status, response = self.connection.select(self.current_folder, readonly=True)
            if status != 'OK':
                return [], 0
            
            status, messages = self.connection.search(None, 'ALL')
            
            if status != 'OK':
                return [], 0
            
            email_ids = messages[0].split()
            total = len(email_ids)
            
            email_ids = email_ids[::-1]
            
            start = page * per_page
            end = start + per_page
            
            selected_ids = email_ids[start:end]
            
            emails = self._batch_fetch_emails(selected_ids, progress_callback)
            
            return emails, total
        except:
            return [], 0
    
    def _fetch_page_pop3(self, page: int, per_page: int, progress_callback=None) -> tuple:
        """Fetch POP3 page"""
        try:
            num_messages = len(self.connection.list()[1])
            emails = []
            
            start = page * per_page
            end = start + per_page
            
            actual_start = max(1, num_messages - end)
            actual_end = max(1, num_messages - start)
            
            total = actual_end - actual_start + 1
            
            for i in range(actual_start, actual_end + 1):
                try:
                    response, lines, octets = self.connection.retr(i)
                    msg_content = b'\r\n'.join(lines)
                    msg = email.message_from_bytes(msg_content)
                    emails.append(self._parse_email(msg, str(i)))
                    
                    if progress_callback:
                        progress_callback(len(emails), total)
                except:
                    continue
            
            return emails[::-1], num_messages
        except:
            return [], 0
    
    def _parse_email(self, msg, email_id) -> Dict:
        """Parse email"""
        subject = self._decode_header(msg.get('Subject'))
        from_ = self._decode_header(msg.get('From'))
        to = self._decode_header(msg.get('To'))
        date = msg.get('Date', '')
        
        body, links = self._get_email_body_smart(msg)
        
        attachments = []
        if msg.is_multipart():
            for part in msg.walk():
                if part.get_content_maintype() == 'multipart':
                    continue
                if part.get('Content-Disposition') is None:
                    continue
                
                filename = part.get_filename()
                if filename:
                    attachments.append({
                        'filename': self._decode_header(filename),
                        'size': len(part.get_payload(decode=True) or b''),
                        'part': part
                    })
        
        return {
            'id': email_id,
            'subject': subject or "(No Subject)",
            'from': from_ or "(Unknown Sender)",
            'to': to or "",
            'date': date,
            'date_formatted': self._format_date(date),
            'body': body or "(Empty Message)",
            'links': links,
            'attachments': attachments,
            'msg': msg
        }
    
    def _format_date(self, date_str: str) -> str:
        """Format date with 12-hour format"""
        try:
            from email.utils import parsedate_to_datetime
            dt = parsedate_to_datetime(date_str)
            now = datetime.now(dt.tzinfo)
            
            diff = now - dt
            
            # 12-hour format with AM/PM
            if diff.days == 0:
                return f"Today {dt.strftime('%I:%M %p')}"
            elif diff.days == 1:
                return f"Yesterday {dt.strftime('%I:%M %p')}"
            elif diff.days < 7:
                return dt.strftime('%A %I:%M %p')
            elif diff.days < 365:
                return dt.strftime('%d %b %I:%M %p')
            else:
                return dt.strftime('%d %b %Y')
        except:
            return date_str[:16] if date_str else "N/A"
    
    def _get_email_body_smart(self, msg) -> tuple:
        """Get email body"""
        text_body = ""
        html_body = ""
        
        if msg.is_multipart():
            for part in msg.walk():
                content_type = part.get_content_type()
                
                if content_type not in ["text/plain", "text/html"]:
                    continue
                
                try:
                    payload = part.get_payload(decode=True)
                    if not payload:
                        continue
                    
                    charset = part.get_content_charset() or 'utf-8'
                    
                    decoded = None
                    for enc in [charset, 'utf-8', 'latin-1', 'cp1252']:
                        try:
                            decoded = payload.decode(enc, errors='ignore')
                            break
                        except:
                            continue
                    
                    if not decoded:
                        continue
                    
                    if content_type == "text/plain":
                        text_body += decoded + "\n"
                    elif content_type == "text/html":
                        html_body += decoded + "\n"
                        
                except:
                    continue
        else:
            try:
                payload = msg.get_payload(decode=True)
                if payload:
                    charset = msg.get_content_charset() or 'utf-8'
                    
                    decoded = None
                    for enc in [charset, 'utf-8', 'latin-1', 'cp1252']:
                        try:
                            decoded = payload.decode(enc, errors='ignore')
                            break
                        except:
                            continue
                    
                    if decoded:
                        if msg.get_content_type() == "text/html":
                            html_body = decoded
                        else:
                            text_body = decoded
            except:
                pass
        
        final_body = ""
        
        if text_body.strip():
            final_body = text_body.strip()
        elif html_body.strip():
            try:
                parser = HTMLTextExtractor()
                parser.feed(html_body)
                final_body = parser.get_text().strip()
            except:
                final_body = re.sub('<[^<]+?>', '', html_body).strip()
        
        links = self._extract_links(final_body[:3000])
        
        if len(final_body) > 1500:
            final_body = final_body[:1500] + "..."
        
        return final_body, links
    
    def get_full_email_body(self, email_data: Dict) -> str:
        """Get full body"""
        if 'msg' not in email_data:
            return email_data.get('body', '')
        
        body, _ = self._get_full_email_body(email_data['msg'])
        return body
    
    def _get_full_email_body(self, msg) -> tuple:
        """Get full body without truncation"""
        text_body = ""
        html_body = ""
        
        if msg.is_multipart():
            for part in msg.walk():
                content_type = part.get_content_type()
                
                if content_type not in ["text/plain", "text/html"]:
                    continue
                
                try:
                    payload = part.get_payload(decode=True)
                    if not payload:
                        continue
                    
                    charset = part.get_content_charset() or 'utf-8'
                    
                    decoded = None
                    for enc in [charset, 'utf-8', 'latin-1', 'cp1252']:
                        try:
                            decoded = payload.decode(enc, errors='ignore')
                            break
                        except:
                            continue
                    
                    if not decoded:
                        continue
                    
                    if content_type == "text/plain":
                        text_body += decoded + "\n"
                    elif content_type == "text/html":
                        html_body += decoded + "\n"
                        
                except:
                    continue
        else:
            try:
                payload = msg.get_payload(decode=True)
                if payload:
                    charset = msg.get_content_charset() or 'utf-8'
                    
                    decoded = None
                    for enc in [charset, 'utf-8', 'latin-1', 'cp1252']:
                        try:
                            decoded = payload.decode(enc, errors='ignore')
                            break
                        except:
                            continue
                    
                    if decoded:
                        if msg.get_content_type() == "text/html":
                            html_body = decoded
                        else:
                            text_body = decoded
            except:
                pass
        
        final_body = ""
        
        if text_body.strip():
            final_body = text_body.strip()
        elif html_body.strip():
            try:
                parser = HTMLTextExtractor()
                parser.feed(html_body)
                final_body = parser.get_text().strip()
            except:
                final_body = re.sub('<[^<]+?>', '', html_body).strip()
        
        links = self._extract_links(final_body)
        
        return final_body, links
    
    def _decode_header(self, header) -> str:
        """Decode header"""
        if header is None:
            return ""
        
        decoded = decode_header(header)
        header_parts = []
        
        for content, encoding in decoded:
            if isinstance(content, bytes):
                if encoding:
                    try:
                        header_parts.append(content.decode(encoding))
                    except:
                        header_parts.append(content.decode('utf-8', errors='ignore'))
                else:
                    header_parts.append(content.decode('utf-8', errors='ignore'))
            else:
                header_parts.append(str(content))
        
        return ''.join(header_parts)
    
    def _extract_links(self, text: str) -> List[str]:
        """Extract URLs"""
        url_pattern = r'https?://[^\s<>"{}|\\^`\[\]]+[^\s.,;:)\]}<>"\']'
        links = re.findall(url_pattern, text)
        return list(set(links))[:15]
    
    def save_attachment(self, attachment: Dict, filepath: str) -> bool:
        """Save attachment"""
        try:
            with open(filepath, 'wb') as f:
                f.write(attachment['part'].get_payload(decode=True))
            return True
        except:
            return False
    
    def delete_email(self, email_id: str) -> bool:
        """Delete email"""
        try:
            if self.protocol == 'imap':
                self.connection.select(self.current_folder)
                self.connection.store(email_id, '+FLAGS', '\\Deleted')
                self.connection.expunge()
                return True
            else:
                try:
                    self.connection.dele(int(email_id))
                    return True
                except:
                    return False
        except:
            return False
    
    def disconnect(self):
        """Disconnect"""
        try:
            if self.connection:
                if self.protocol == 'imap':
                    try:
                        self.connection.close()
                    except:
                        pass
                    try:
                        self.connection.logout()
                    except:
                        pass
                else:
                    try:
                        self.connection.quit()
                    except:
                        pass
        except:
            pass
        finally:
            self.connection = None
            self.protocol = None
            self.email_address = None
            self.password = None
            self.host = None
            self.port = None
            self.current_folder = 'INBOX'


class MailViewerGUI:
    def __init__(self, root):
        self.root = root
        self.root.title("Mail Viewer Turbo")
        
        self.settings = self.load_settings()
        
        self.root.geometry('450x280')
        self.root.resizable(False, False)
        
        self.colors = {
            'bg': '#1a1a1a',
            'header': '#0d47a1',
            'sidebar': '#252525',
            'panel': '#2d2d2d',
            'text': '#e0e0e0',
            'text_dim': '#999999',
            'border': '#404040',
            'selected': '#1976d2',
            'button': '#1565c0',
            'button_hover': '#0d47a1',
            'input': '#1e1e1e',
            'input_border': '#555555'
        }
        
        self.root.configure(bg=self.colors['bg'])
        
        self.backend = MailViewerBackend()
        self.current_emails = []
        self.per_page = 100
        self.is_searching = False
        self.loading = False
        
        self.root.protocol("WM_DELETE_WINDOW", self.on_closing)
        
        self.create_login_widgets()
        
        self.root.bind('<Control-r>', lambda e: self.refresh_inbox() if hasattr(self, 'mail_frame') and self.mail_frame.winfo_ismapped() else None)
        self.root.bind('<Control-f>', lambda e: self.focus_search() if hasattr(self, 'mail_frame') and self.mail_frame.winfo_ismapped() else None)
        self.root.bind('<F5>', lambda e: self.refresh_inbox() if hasattr(self, 'mail_frame') and self.mail_frame.winfo_ismapped() else None)
    
    def load_settings(self) -> dict:
        try:
            if os.path.exists('mail_viewer_settings.json'):
                with open('mail_viewer_settings.json', 'r') as f:
                    return json.load(f)
        except:
            pass
        return {}
    
    def save_settings(self):
        try:
            settings = {
                'last_folder': self.folder_var.get() if hasattr(self, 'folder_var') else 'INBOX',
                'num_messages': self.num_var.get() if hasattr(self, 'num_var') else '100'
            }
            with open('mail_viewer_settings.json', 'w') as f:
                json.dump(settings, f)
        except:
            pass
    
    def on_closing(self):
        self.save_settings()
        self.backend.disconnect()
        self.root.destroy()
    
    def focus_search(self):
        if hasattr(self, 'search_entry'):
            self.search_entry.focus()
    
    def create_login_widgets(self):
        """Login widgets"""
        
        self.login_frame = tk.Frame(self.root, bg=self.colors['bg'])
        self.login_frame.pack(fill=tk.BOTH, expand=True, padx=40, pady=40)
        
        tk.Label(self.login_frame, text="Mail Log-in", font=('Segoe UI', 16, 'bold'), bg=self.colors['bg'], fg=self.colors['text']).pack(pady=(0, 30))
        
        tk.Label(self.login_frame, text="Login", font=('Segoe UI', 10, 'bold'), bg=self.colors['bg'], fg=self.colors['text'], anchor='w').pack(anchor='w', pady=(0, 5))
        
        tk.Label(self.login_frame, text="Email:Pass", font=('Segoe UI', 9), bg=self.colors['bg'], fg=self.colors['text_dim'], anchor='w').pack(anchor='w', pady=(0, 5))
        
        entry_container = tk.Frame(self.login_frame, bg=self.colors['input'], highlightbackground=self.colors['input_border'], highlightthickness=1)
        entry_container.pack(fill=tk.X, pady=(0, 5))
        
        self.credentials_entry = tk.Entry(entry_container, font=('Segoe UI', 11), relief=tk.FLAT, bg=self.colors['input'], fg=self.colors['text'], insertbackground=self.colors['text'], bd=0)
        self.credentials_entry.pack(padx=5, pady=8, fill=tk.X)
        self.credentials_entry.focus()
        
        self.credentials_entry.bind('<Control-v>', self.on_paste)
        self.credentials_entry.bind('<Return>', lambda e: self.login())
        
        self.status_label = tk.Label(self.login_frame, text="", font=('Segoe UI', 9), bg=self.colors['bg'], fg='#ff5252')
        self.status_label.pack(pady=5)
        
        self.login_button = tk.Button(self.login_frame, text="Login", font=('Segoe UI', 10, 'bold'), bg=self.colors['button'], fg=self.colors['text'], activebackground=self.colors['button_hover'], activeforeground=self.colors['text'], relief=tk.FLAT, cursor='hand2', command=self.login, padx=60, pady=10)
        self.login_button.pack(pady=(10, 15))
        
        self.progress = ttk.Progressbar(self.login_frame, mode='indeterminate', length=350)
        
        self.mail_frame_created = False
    
    def on_paste(self, event):
        self.root.after(100, self.auto_login_after_paste)
        return None
    
    def auto_login_after_paste(self):
        credentials = self.credentials_entry.get().strip()
        if credentials and ':' in credentials:
            self.login()
    
    def parse_credentials(self, input_str):
        input_str = input_str.strip()
        if ':' in input_str:
            parts = input_str.split(':', 1)
            return parts[0].strip(), parts[1].strip()
        return input_str, None
    
    def login(self):
        if self.loading:
            return
            
        credentials = self.credentials_entry.get().strip()
        
        if not credentials:
            self.status_label.config(text="Please enter credentials")
            return
        
        email_address, password = self.parse_credentials(credentials)
        
        if not email_address or '@' not in email_address:
            self.status_label.config(text="Invalid email")
            return
        
        if not password:
            self.status_label.config(text="Please enter password")
            return
        
        self.loading = True
        self.login_button.config(state=tk.DISABLED)
        self.credentials_entry.config(state=tk.DISABLED)
        self.status_label.config(text="Connecting...", fg='#4caf50')
        self.progress.pack(pady=10)
        self.progress.start(10)
        
        threading.Thread(target=self._login_thread, args=(email_address, password), daemon=True).start()
    
    def _login_thread(self, email_address, password):
        """Background thread for login using SmartLoginHandler"""
        handler = SmartLoginHandler(db_path="./email_config")
        result_code, details = handler.connect(email_address, password)
        self.root.after(0, self._login_callback, result_code, details, email_address, password)
    
    def _login_callback(self, result_code, details, email_address, password):
        """Callback after login attempt"""
        self.progress.stop()
        self.progress.pack_forget()
        self.login_button.config(state=tk.NORMAL)
        self.credentials_entry.config(state=tk.NORMAL)
        self.loading = False
        
        if result_code == "SUCCESS":
            # Extract connection details
            protocol = details['protocol']
            server = details['server']
            port = details['port']
            connection = details['connection']
            
            # Set up backend with the working connection
            self.backend.protocol = protocol
            self.backend.connection = connection
            self.backend.email_address = email_address
            self.backend.password = password
            self.backend.host = server
            self.backend.port = port
            
            self.status_label.config(text="Connected successfully", fg='#4caf50')
            self.stored_credentials = f"{email_address}:{password}"
            self.root.after(500, self.show_mail_frame)
            
        elif result_code == "AUTH_FAILED":
            self.status_label.config(text="Authentication failed", fg='#ff5252')
            messagebox.showerror(
                "Invalid Password",
                "Authentication failed. Your credentials were rejected by all mail servers.\n\n"
                "Both IMAP and POP3 protocols were tried with a safety delay between attempts.\n\n"
                "Please verify your email and password are correct."
            )
            
        elif result_code == "CONN_ERROR":
            self.status_label.config(text="Connection failed", fg='#ff5252')
            messagebox.showerror(
                "Connection Failed",
                "Server not responding. Could not connect to any mail servers.\n\n"
                "Please check your internet connection and try again."
            )
    
    def show_mail_frame(self):
        """Show mail interface"""
        if not self.mail_frame_created:
            self.create_mail_frame()
        
        self.login_frame.pack_forget()
        self.mail_frame.pack(fill=tk.BOTH, expand=True)
        
        self.root.geometry('950x650')
        self.root.resizable(True, True)
        
        self.email_display.config(state='normal')
        self.email_display.delete(0, tk.END)
        self.email_display.insert(0, self.stored_credentials)
        self.email_display.config(state='readonly')
        
        if self.backend.protocol == 'imap':
            folders = self.backend.get_folders()
            self.folder_combo['values'] = folders
            if self.folder_var.get() not in folders:
                self.folder_combo.set('INBOX')
        else:
            self.folder_combo['values'] = ['INBOX']
            self.folder_combo.config(state=tk.DISABLED)
        
        self.load_emails()
    
    def create_mail_frame(self):
        """Create mail interface"""
        self.mail_frame = tk.Frame(self.root, bg=self.colors['bg'])
        
        header = tk.Frame(self.mail_frame, bg=self.colors['header'], height=45)
        header.pack(fill=tk.X)
        header.pack_propagate(False)
        
        tk.Label(header, text="MAIL VIEWER TURBO", font=('Segoe UI', 11, 'bold'), bg=self.colors['header'], fg=self.colors['text']).pack(side=tk.LEFT, padx=15, pady=10)
        
        tk.Label(header, text="Ctrl+R:Refresh | Ctrl+F:Search | F5:Reload | Del:Delete", font=('Segoe UI', 8), bg=self.colors['header'], fg=self.colors['text_dim']).pack(side=tk.RIGHT, padx=15, pady=10)
        
        control_bar = tk.Frame(self.mail_frame, bg=self.colors['sidebar'], height=40)
        control_bar.pack(fill=tk.X)
        control_bar.pack_propagate(False)
        
        tk.Label(control_bar, text="Email:", font=('Segoe UI', 9), bg=self.colors['sidebar'], fg=self.colors['text']).pack(side=tk.LEFT, padx=(10, 2))
        
        self.email_display = tk.Entry(control_bar, font=('Segoe UI', 9), relief=tk.FLAT, bg=self.colors['input'], fg=self.colors['text'], state='readonly', width=35, readonlybackground=self.colors['input'])
        self.email_display.pack(side=tk.LEFT, padx=3)
        
        tk.Label(control_bar, text="Folder:", font=('Segoe UI', 9), bg=self.colors['sidebar'], fg=self.colors['text']).pack(side=tk.LEFT, padx=(10, 2))
        
        self.folder_var = tk.StringVar(value=self.settings.get('last_folder', 'INBOX'))
        self.folder_combo = ttk.Combobox(control_bar, textvariable=self.folder_var, font=('Segoe UI', 9), width=12, state='readonly')
        self.folder_combo.pack(side=tk.LEFT, padx=3)
        self.folder_combo.bind('<<ComboboxSelected>>', self.on_folder_change)
        
        tk.Label(control_bar, text="Count:", font=('Segoe UI', 9), bg=self.colors['sidebar'], fg=self.colors['text']).pack(side=tk.LEFT, padx=(10, 2))
        
        self.num_var = tk.StringVar(value=self.settings.get('num_messages', '100'))
        num_spinbox = tk.Spinbox(control_bar, from_=10, to=500, increment=10, textvariable=self.num_var, font=('Segoe UI', 9), width=5, bg=self.colors['input'], fg=self.colors['text'], buttonbackground=self.colors['button'], relief=tk.FLAT)
        num_spinbox.pack(side=tk.LEFT, padx=3)
        
        tk.Button(control_bar, text="INBOX", font=('Segoe UI', 8, 'bold'), bg=self.colors['button'], fg=self.colors['text'], relief=tk.FLAT, cursor='hand2', command=self.refresh_inbox, width=7).pack(side=tk.RIGHT, padx=(3, 10), pady=5, ipady=3)
        
        tk.Button(control_bar, text="Refresh", font=('Segoe UI', 8), bg=self.colors['button'], fg=self.colors['text'], relief=tk.FLAT, cursor='hand2', command=self.refresh_inbox, width=7).pack(side=tk.RIGHT, padx=2, pady=5, ipady=3)
        
        tk.Button(control_bar, text="Logout", font=('Segoe UI', 8), bg='#d32f2f', fg=self.colors['text'], relief=tk.FLAT, cursor='hand2', command=self.logout, width=7).pack(side=tk.RIGHT, padx=3, pady=5, ipady=3)
        
        search_bar = tk.Frame(self.mail_frame, bg=self.colors['sidebar'], height=35)
        search_bar.pack(fill=tk.X)
        search_bar.pack_propagate(False)
        
        tk.Label(search_bar, text="Search:", font=('Segoe UI', 9), bg=self.colors['sidebar'], fg=self.colors['text']).pack(side=tk.LEFT, padx=(10, 5))
        
        self.search_option = tk.StringVar(value="ALL")
        search_opt = ttk.Combobox(search_bar, textvariable=self.search_option, values=["ALL", "Subject", "From", "Sender", "Body"], font=('Segoe UI', 9), width=8, state='readonly')
        search_opt.pack(side=tk.LEFT, padx=3)
        
        self.search_var = tk.StringVar()
        self.search_entry = tk.Entry(search_bar, textvariable=self.search_var, font=('Segoe UI', 9), relief=tk.FLAT, bg=self.colors['input'], fg=self.colors['text'], insertbackground=self.colors['text'], width=35)
        self.search_entry.pack(side=tk.LEFT, padx=5, ipady=3)
        self.search_entry.bind('<Return>', lambda e: self.perform_search())
        
        tk.Button(search_bar, text="Search", font=('Segoe UI', 9), bg=self.colors['button'], fg=self.colors['text'], relief=tk.FLAT, cursor='hand2', command=self.perform_search, width=10).pack(side=tk.LEFT, padx=5, ipady=2)
        
        tk.Button(search_bar, text="Clear", font=('Segoe UI', 9), bg=self.colors['sidebar'], fg=self.colors['text_dim'], relief=tk.FLAT, cursor='hand2', command=self.clear_search, width=6).pack(side=tk.LEFT, padx=2, ipady=2)
        
        self.search_progress = ttk.Progressbar(search_bar, mode='determinate', length=100)
        
        content = tk.Frame(self.mail_frame, bg=self.colors['bg'])
        content.pack(fill=tk.BOTH, expand=True, padx=5, pady=5)
        
        headers_frame = tk.Frame(content, bg=self.colors['sidebar'], height=30)
        headers_frame.pack(fill=tk.X)
        headers_frame.pack_propagate(False)
        
        tk.Label(headers_frame, text="#", font=('Segoe UI', 9, 'bold'), bg=self.colors['sidebar'], fg=self.colors['text'], width=6, anchor='w').pack(side=tk.LEFT, padx=5)
        tk.Label(headers_frame, text="FROM", font=('Segoe UI', 9, 'bold'), bg=self.colors['sidebar'], fg=self.colors['text'], width=25, anchor='w').pack(side=tk.LEFT)
        tk.Label(headers_frame, text="SUBJECT", font=('Segoe UI', 9, 'bold'), bg=self.colors['sidebar'], fg=self.colors['text'], anchor='w').pack(side=tk.LEFT, fill=tk.X, expand=True, padx=5)
        tk.Label(headers_frame, text="DATE", font=('Segoe UI', 9, 'bold'), bg=self.colors['sidebar'], fg=self.colors['text'], width=15, anchor='w').pack(side=tk.LEFT, padx=5)
        
        list_frame = tk.Frame(content, bg=self.colors['bg'])
        list_frame.pack(fill=tk.BOTH, expand=True)
        
        scrollbar = ttk.Scrollbar(list_frame)
        scrollbar.pack(side=tk.RIGHT, fill=tk.Y)
        
        self.emails_listbox = tk.Listbox(list_frame, font=('Consolas', 9), yscrollcommand=scrollbar.set, selectmode=tk.SINGLE, relief=tk.FLAT, bg=self.colors['bg'], fg=self.colors['text'], selectbackground=self.colors['selected'], selectforeground=self.colors['text'], bd=0, highlightthickness=0)
        self.emails_listbox.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
        scrollbar.config(command=self.emails_listbox.yview)
        
        self.emails_listbox.bind('<<ListboxSelect>>', self.on_email_select)
        self.emails_listbox.bind('<Double-Button-1>', self.show_email_detail)
        
        self.context_menu = tk.Menu(self.emails_listbox, tearoff=0, bg=self.colors['panel'], fg=self.colors['text'])
        self.context_menu.add_command(label="Open", command=lambda: self.show_email_detail(None))
        self.context_menu.add_separator()
        self.context_menu.add_command(label="Copy Subject", command=self.copy_subject)
        self.context_menu.add_command(label="Copy From", command=self.copy_from)
        self.context_menu.add_separator()
        self.context_menu.add_command(label="Delete Email", command=self.delete_selected_email)
        
        self.emails_listbox.bind('<Button-3>', self.show_context_menu)
        self.emails_listbox.bind('<Delete>', lambda e: self.delete_selected_email())
        
        status_bar = tk.Frame(self.mail_frame, bg=self.colors['sidebar'], height=25)
        status_bar.pack(fill=tk.X)
        status_bar.pack_propagate(False)
        
        self.status_text = tk.Label(status_bar, text="Ready", font=('Segoe UI', 9), bg=self.colors['sidebar'], fg=self.colors['text_dim'], anchor='w')
        self.status_text.pack(side=tk.LEFT, padx=10, fill=tk.X, expand=True)
        
        self.status_progress = ttk.Progressbar(status_bar, mode='determinate', length=150)
        
        self.mail_frame_created = True
    
    def show_context_menu(self, event):
        try:
            self.emails_listbox.selection_clear(0, tk.END)
            self.emails_listbox.selection_set(self.emails_listbox.nearest(event.y))
            self.context_menu.tk_popup(event.x_root, event.y_root)
        finally:
            self.context_menu.grab_release()
    
    def copy_subject(self):
        selection = self.emails_listbox.curselection()
        if selection and selection[0] < len(self.current_emails):
            subject = self.current_emails[selection[0]]['subject']
            self.root.clipboard_clear()
            self.root.clipboard_append(subject)
            self.status_text.config(text="Subject copied")
            self.root.after(2000, lambda: self.status_text.config(text="Ready"))
    
    def copy_from(self):
        selection = self.emails_listbox.curselection()
        if selection and selection[0] < len(self.current_emails):
            from_ = self.current_emails[selection[0]]['from']
            self.root.clipboard_clear()
            self.root.clipboard_append(from_)
            self.status_text.config(text="From copied")
            self.root.after(2000, lambda: self.status_text.config(text="Ready"))
    
    def delete_selected_email(self):
        selection = self.emails_listbox.curselection()
        if not selection:
            messagebox.showwarning("No Selection", "Please select an email")
            return
        
        idx = selection[0]
        if idx >= len(self.current_emails):
            return
        
        email_data = self.current_emails[idx]
        
        subject = email_data['subject'][:60]
        from_ = email_data['from'][:60]
        
        result = messagebox.askyesno("Delete Email", f"Delete this email?\n\nSubject: {subject}\nFrom: {from_}\n\nWarning: This action cannot be undone!", icon='warning')
        
        if not result:
            return
        
        self.status_text.config(text="Deleting...")
        
        threading.Thread(target=self._delete_email_thread, args=(email_data['id'], idx), daemon=True).start()
    
    def _delete_email_thread(self, email_id, idx):
        success = self.backend.delete_email(email_id)
        self.root.after(0, self._delete_email_callback, success, idx)
    
    def _delete_email_callback(self, success, idx):
        if success:
            try:
                self.current_emails.pop(idx)
                
                self.emails_listbox.delete(0, tk.END)
                for i, email_data in enumerate(self.current_emails, 1):
                    from_name = email_data['from'].split('<')[0].strip()
                    if len(from_name) > 20:
                        from_name = from_name[:20] + "..."
                    
                    subject = email_data['subject']
                    if email_data.get('attachments'):
                        subject = f"[+] {subject}"
                    
                    if len(subject) > 58:
                        subject = subject[:58] + "..."
                    
                    date_str = email_data.get('date_formatted', email_data['date'][:16] if email_data['date'] else "N/A")
                    
                    item = f"{i:<6} {from_name:<25} {subject:<60} {date_str}"
                    self.emails_listbox.insert(tk.END, item)
                
                self.status_text.config(text=f"Deleted ({len(self.current_emails)} remaining)")
                self.root.after(3000, lambda: self.status_text.config(text="Ready"))
            except:
                pass
        else:
            self.status_text.config(text="Delete failed")
            messagebox.showerror("Delete Failed", "Could not delete email from server.")
            self.root.after(3000, lambda: self.status_text.config(text="Ready"))
    
    def update_progress(self, current, total):
        try:
            self.root.after(0, self._update_progress_ui, current, total)
        except:
            pass
    
    def _update_progress_ui(self, current, total):
        try:
            if total > 0:
                percent = (current / total) * 100
                
                if self.is_searching and hasattr(self, 'search_progress'):
                    self.search_progress['value'] = percent
                    if not self.search_progress.winfo_ismapped():
                        self.search_progress.pack(side=tk.RIGHT, padx=5)
                elif hasattr(self, 'status_progress'):
                    self.status_progress['value'] = percent
                    if not self.status_progress.winfo_ismapped():
                        self.status_progress.pack(side=tk.RIGHT, padx=10)
                
                self.status_text.config(text=f"Loading {current}/{total} ({percent:.0f}%)...")
        except:
            pass
    
    def hide_progress(self):
        try:
            if hasattr(self, 'status_progress'):
                self.status_progress.pack_forget()
                self.status_progress['value'] = 0
            if hasattr(self, 'search_progress'):
                self.search_progress.pack_forget()
                self.search_progress['value'] = 0
        except:
            pass
    
    def on_folder_change(self, event):
        self.is_searching = False
        self.search_var.set("")
        self.load_emails()
    
    def load_emails(self):
        if self.loading:
            return
            
        try:
            num = int(self.num_var.get())
        except:
            num = 100
        
        self.loading = True
        self.status_text.config(text="Loading...")
        
        threading.Thread(target=self._load_emails_thread, args=(num,), daemon=True).start()
    
    def _load_emails_thread(self, num):
        folder = self.folder_var.get()
        emails, total = self.backend.fetch_page(0, num, folder, self.update_progress)
        self.current_emails = emails
        self.root.after(0, self._update_display, total)
    
    def _update_display(self, total):
        self.emails_listbox.delete(0, tk.END)
        
        for i, email_data in enumerate(self.current_emails, 1):
            from_name = email_data['from'].split('<')[0].strip()
            if len(from_name) > 20:
                from_name = from_name[:20] + "..."
            
            subject = email_data['subject']
            
            if email_data.get('attachments'):
                subject = f"[+] {subject}"
            
            if len(subject) > 58:
                subject = subject[:58] + "..."
            
            date_str = email_data.get('date_formatted', email_data['date'][:16] if email_data['date'] else "N/A")
            
            item = f"{i:<6} {from_name:<25} {subject:<60} {date_str}"
            self.emails_listbox.insert(tk.END, item)
        
        self.hide_progress()
        self.status_text.config(text=f"Loaded {len(self.current_emails)}/{total} emails")
        self.loading = False
    
    def refresh_inbox(self):
        self.folder_var.set('INBOX')
        self.is_searching = False
        self.search_var.set("")
        self.load_emails()
    
    def perform_search(self):
        if self.loading:
            return
            
        term = self.search_var.get().strip()
        if not term:
            self.refresh_inbox()
            return
        
        self.loading = True
        self.is_searching = True
        self.status_text.config(text="Searching...")
        
        threading.Thread(target=self._search_thread, args=(term,), daemon=True).start()
    
    def _search_thread(self, term):
        field = self.search_option.get()
        folder = self.folder_var.get()
        
        if field == 'Sender':
            field = 'From'
        
        results = self.backend.search_emails(term, field, folder, self.update_progress)
        self.current_emails = results
        self.root.after(0, self._update_search_display)
    
    def _update_search_display(self):
        self.emails_listbox.delete(0, tk.END)
        
        for i, email_data in enumerate(self.current_emails, 1):
            from_name = email_data['from'].split('<')[0].strip()
            if len(from_name) > 20:
                from_name = from_name[:20] + "..."
            
            subject = email_data['subject']
            
            if email_data.get('attachments'):
                subject = f"[+] {subject}"
            
            if len(subject) > 58:
                subject = subject[:58] + "..."
            
            date_str = email_data.get('date_formatted', email_data['date'][:16] if email_data['date'] else "N/A")
            
            item = f"{i:<6} {from_name:<25} {subject:<60} {date_str}"
            self.emails_listbox.insert(tk.END, item)
        
        self.hide_progress()
        self.is_searching = False
        self.status_text.config(text=f"Found {len(self.current_emails)} results")
        self.loading = False
    
    def clear_search(self):
        self.search_var.set("")
        self.is_searching = False
        self.load_emails()
    
    def on_email_select(self, event):
        pass
    
    def show_email_detail(self, event):
        selection = self.emails_listbox.curselection()
        if not selection:
            return
        
        idx = selection[0]
        if idx >= len(self.current_emails):
            return
        
        email_data = self.current_emails[idx]
        
        detail_win = tk.Toplevel(self.root)
        detail_win.title(f"Email: {email_data['subject'][:50]}")
        detail_win.geometry("800x700")
        detail_win.configure(bg=self.colors['bg'])
        
        detail_win.bind('<Escape>', lambda e: detail_win.destroy())
        
        header_frame = tk.Frame(detail_win, bg=self.colors['sidebar'])
        header_frame.pack(fill=tk.X, padx=10, pady=10)
        
        tk.Label(header_frame, text="Subject:", font=('Segoe UI', 9, 'bold'), bg=self.colors['sidebar'], fg=self.colors['text']).grid(row=0, column=0, sticky='w', pady=2)
        tk.Label(header_frame, text=email_data['subject'], font=('Segoe UI', 9), bg=self.colors['sidebar'], fg=self.colors['text'], wraplength=700, justify='left').grid(row=0, column=1, sticky='w', pady=2, padx=5)
        
        tk.Label(header_frame, text="From:", font=('Segoe UI', 9, 'bold'), bg=self.colors['sidebar'], fg=self.colors['text']).grid(row=1, column=0, sticky='w', pady=2)
        tk.Label(header_frame, text=email_data['from'], font=('Segoe UI', 9), bg=self.colors['sidebar'], fg=self.colors['text'], wraplength=700).grid(row=1, column=1, sticky='w', pady=2, padx=5)
        
        tk.Label(header_frame, text="Date:", font=('Segoe UI', 9, 'bold'), bg=self.colors['sidebar'], fg=self.colors['text']).grid(row=2, column=0, sticky='w', pady=2)
        tk.Label(header_frame, text=email_data['date'], font=('Segoe UI', 9), bg=self.colors['sidebar'], fg=self.colors['text']).grid(row=2, column=1, sticky='w', pady=2, padx=5)
        
        if email_data.get('attachments'):
            att_frame = tk.Frame(detail_win, bg=self.colors['sidebar'])
            att_frame.pack(fill=tk.X, padx=10, pady=(0, 10))
            
            tk.Label(att_frame, text=f"Attachments ({len(email_data['attachments'])}):", font=('Segoe UI', 9, 'bold'), bg=self.colors['sidebar'], fg=self.colors['text']).pack(anchor='w', pady=5, padx=5)
            
            for att in email_data['attachments'][:5]:
                size_kb = att['size'] / 1024
                att_info = f"{att['filename']} ({size_kb:.1f} KB)"
                if len(att_info) > 80:
                    att_info = att_info[:80] + "..."
                
                att_btn = tk.Button(att_frame, text=att_info, font=('Segoe UI', 8), bg=self.colors['button'], fg=self.colors['text'], relief=tk.FLAT, cursor='hand2', anchor='w', command=lambda a=att: self.save_attachment_dialog(a))
                att_btn.pack(fill=tk.X, padx=5, pady=2, ipady=3)
        
        if email_data.get('links'):
            links_frame = tk.Frame(detail_win, bg=self.colors['sidebar'])
            links_frame.pack(fill=tk.X, padx=10, pady=(0, 10))
            
            tk.Label(links_frame, text=f"Links ({len(email_data['links'])}):", font=('Segoe UI', 9, 'bold'), bg=self.colors['sidebar'], fg=self.colors['text']).pack(anchor='w', pady=5, padx=5)
            
            for link in email_data['links'][:5]:
                link_display = link[:90] + "..." if len(link) > 90 else link
                link_btn = tk.Button(links_frame, text=link_display, font=('Segoe UI', 8), bg=self.colors['button'], fg=self.colors['text'], relief=tk.FLAT, cursor='hand2', anchor='w', command=lambda url=link: webbrowser.open(url))
                link_btn.pack(fill=tk.X, padx=5, pady=2, ipady=3)
        
        body_frame = tk.Frame(detail_win, bg=self.colors['bg'])
        body_frame.pack(fill=tk.BOTH, expand=True, padx=10, pady=(0, 10))
        
        scrollbar = ttk.Scrollbar(body_frame)
        scrollbar.pack(side=tk.RIGHT, fill=tk.Y)
        
        body_text = tk.Text(body_frame, font=('Consolas', 9), wrap=tk.WORD, bg=self.colors['sidebar'], fg=self.colors['text'], yscrollcommand=scrollbar.set, relief=tk.FLAT, padx=10, pady=10)
        body_text.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
        scrollbar.config(command=body_text.yview)
        
        body_text.insert('1.0', email_data['body'])
        body_text.config(state='disabled')
        
        if email_data['body'].endswith('...'):
            threading.Thread(target=self._load_full_body, args=(email_data, body_text), daemon=True).start()
        
        btn_frame = tk.Frame(detail_win, bg=self.colors['bg'])
        btn_frame.pack(fill=tk.X, padx=10, pady=(0, 10))
        
        tk.Button(btn_frame, text="Export as .txt", font=('Segoe UI', 9), bg=self.colors['button'], fg=self.colors['text'], relief=tk.FLAT, cursor='hand2', command=lambda: self.export_email(email_data), width=15).pack(side=tk.LEFT, padx=5)
        
        tk.Button(btn_frame, text="Close (Esc)", font=('Segoe UI', 9), bg=self.colors['sidebar'], fg=self.colors['text'], relief=tk.FLAT, cursor='hand2', command=detail_win.destroy, width=15).pack(side=tk.RIGHT, padx=5)
    
    def save_attachment_dialog(self, attachment):
        filepath = filedialog.asksaveasfilename(defaultextension="", initialfile=attachment['filename'], title="Save Attachment")
        
        if filepath:
            if self.backend.save_attachment(attachment, filepath):
                messagebox.showinfo("Success", f"Attachment saved to:\n{filepath}")
            else:
                messagebox.showerror("Error", "Failed to save attachment")
    
    def export_email(self, email_data):
        filepath = filedialog.asksaveasfilename(defaultextension=".txt", initialfile=f"{email_data['subject'][:30]}.txt", filetypes=[("Text files", "*.txt"), ("All files", "*.*")], title="Export Email")
        
        if filepath:
            try:
                full_body = self.backend.get_full_email_body(email_data)
                
                content = f"""Subject: {email_data['subject']}
From: {email_data['from']}
To: {email_data['to']}
Date: {email_data['date']}

{'='*80}

{full_body}

{'='*80}

"""
                if email_data.get('links'):
                    content += "\nLinks:\n"
                    for link in email_data['links']:
                        content += f"- {link}\n"
                
                if email_data.get('attachments'):
                    content += f"\nAttachments ({len(email_data['attachments'])}):\n"
                    for att in email_data['attachments']:
                        content += f"- {att['filename']} ({att['size']} bytes)\n"
                
                with open(filepath, 'w', encoding='utf-8') as f:
                    f.write(content)
                
                messagebox.showinfo("Success", f"Email exported to:\n{filepath}")
            except Exception as e:
                messagebox.showerror("Error", f"Failed to export email:\n{str(e)}")
    
    def _load_full_body(self, email_data, text_widget):
        try:
            full_body = self.backend.get_full_email_body(email_data)
            self.root.after(0, self._update_body_text, text_widget, full_body)
        except:
            pass
    
    def _update_body_text(self, text_widget, body):
        try:
            text_widget.config(state='normal')
            text_widget.delete('1.0', tk.END)
            text_widget.insert('1.0', body)
            text_widget.config(state='disabled')
        except:
            pass
    
    def logout(self):
        self.backend.disconnect()
        
        self.current_emails = []
        self.emails_listbox.delete(0, tk.END)
        self.is_searching = False
        self.loading = False
        self.search_var.set("")
        self.search_option.set("ALL")
        self.folder_var.set('INBOX')
        self.folder_combo['values'] = ['INBOX']
        self.folder_combo.config(state='readonly')
        self.num_var.set("100")
        self.status_text.config(text="Ready")
        self.hide_progress()
        
        self.email_display.config(state='normal')
        self.email_display.delete(0, tk.END)
        self.email_display.config(state='readonly')
        
        if hasattr(self, 'stored_credentials'):
            delattr(self, 'stored_credentials')
        
        self.mail_frame.pack_forget()
        self.login_frame.pack(fill=tk.BOTH, expand=True, padx=40, pady=40)
        
        self.root.geometry('450x280')
        self.root.resizable(False, False)
        
        self.credentials_entry.delete(0, tk.END)
        self.credentials_entry.focus()
        self.status_label.config(text="Logged out successfully", fg='#4caf50')
        
        self.root.after(2000, lambda: self.status_label.config(text=""))


def main():
    root = tk.Tk()
    app = MailViewerGUI(root)
    root.mainloop()


if __name__ == "__main__":
    main()