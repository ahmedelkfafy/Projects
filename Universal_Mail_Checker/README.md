# Universal Mail Checker

A powerful email verification tool that supports both IMAP and POP3 protocols with intelligent auto-discovery and hybrid checking logic.

## Features

- **Hybrid Protocol Support**: Automatically checks POP3 first, then falls back to IMAP
- **Smart Search Mode**: Toggle to use IMAP-only checking with intelligence search
- **Auto-Discovery**: Automatically detects mail servers for common providers
- **Proxy Support**: HTTP/HTTPS, SOCKS4, and SOCKS5 proxy support with auto-reload
- **Real-time Updates**: Live status updates with safety delays
- **Timestamped Results**: Organized results in timestamped session folders
- **Export Functionality**: Right-click export menu for all result tables
- **Dark Theme**: Beautiful Fusion dark theme interface

## Installation

### Prerequisites

- Python 3.8 or higher
- pip package manager

### Steps

1. Clone or download this repository

2. Install dependencies:
```bash
pip install -r requirements.txt
```

## Usage

### Basic Usage

1. Run the application:
```bash
python Universal_Mail_Checker.py
```

2. Load your combo list (format: `email:password`)
3. Configure settings (optional):
   - Thread count (default: 200)
   - Timeout (default: 10 seconds)
   - Smart Search (ON = IMAP only, OFF = POP3→IMAP fallback)
4. Click **START** to begin verification

### Smart Search Mode

- **Smart Search ON**: Uses IMAP protocol only (ports 993→143) for faster checking
  - Enables Intelligence Search feature
  - Creates `intelligence_results/` subfolder when keywords/senders are found
- **Smart Search OFF**: Tries POP3 first (ports 995→110), then IMAP as fallback with 2-second safety delay
  - No Intelligence Search capability
  - Faster for POP3-only accounts

## File Format Rules

### CRITICAL: Live.txt Format

**Live.txt is ALWAYS saved with ONLY `email:pass` format:**
```
test@gmail.com:password123
user@yahoo.com:mypass456
admin@outlook.com:secret789
```

**NO protocol, NO port, NO extra information is saved to Live.txt**

### Results Folder Structure

#### Smart Search OFF:
```
Results/
  └── 2025-12-23_14-30-45/
      ├── Live.txt          (email:pass only)
      ├── Banned.txt        (email:pass only)
      ├── Unknown.txt       (email:pass only)
      └── invalids.txt      (email:pass only)
```

#### Smart Search ON:
```
Results/
  └── 2025-12-23_14-30-45/
      ├── Live.txt          (email:pass only - SAME as OFF mode)
      ├── Banned.txt
      ├── Unknown.txt
      ├── invalids.txt
      └── intelligence_results/
          ├── epicgames.com.txt       (email:pass | X messages)
          ├── password.txt            (email:pass | X messages)
          ├── invoice.txt             (email:pass | X messages)
          └── microsoft.com.txt       (email:pass | X messages)
```

### Intelligence Results Files

When Smart Search is ON and keywords/senders are found, separate files are created in the `intelligence_results/` subfolder:

**Format**: `email:pass | X messages`

**Example** (`epicgames.com.txt`):
```
test@gmail.com:pass123 | 5 messages
gamer@yahoo.com:pass456 | 12 messages
```

**Example** (`password.txt`):
```
admin@gmail.com:admin123 | 8 messages
support@hotmail.com:pass999 | 15 messages
```

## Proxy Configuration

### Auto-Reload Proxies

1. Go to **Tools** → **Settings** → **Proxy** tab
2. Enable "Auto-Reload Proxies"
3. Enter proxy URL (returns proxies in `IP:PORT` format)
4. When active proxies drop below 10, the checker automatically:
   - Loads new proxies from the URL
   - Clears blocked proxy list
   - Shows proxy count updates in log

### Manual Proxy Loading

1. Enable proxies and select type (HTTP/HTTPS, SOCKS4, SOCKS5)
2. Load proxies from file or URL
3. Optional: Set username/password for authenticated proxies

## Intelligence Search

### Configuration (Smart Search ON only)

1. Go to **Tools** → **Settings** → **Intelligence Search** tab
2. Add senders (one per line):
   ```
   epicgames.com
   account@microsoft.com
   ```
3. Add keywords (one per line):
   ```
   password
   invoice
   ```
4. Select where to search: Subject, Body, or both
5. Configure mailboxes to search (default: `INBOX,Spam`)
6. Set fetch count (how many recent emails to check per account)

### How It Works

When a valid account is found (Smart Search ON):
1. Logs into IMAP
2. Searches specified mailboxes for keywords/senders
3. Creates one file per keyword/sender in `intelligence_results/`
4. Saves as: `email:pass | X messages`

## Configuration Files

- **imap_servers.txt**: Pre-configured IMAP servers for common providers
- **pop_servers.txt**: Pre-configured POP3 servers for common providers

Format: `domain.com,server.domain.com`

You can add custom servers manually.

## Troubleshooting

### "No valid accounts found"
- Verify your combo list format is correct (`email:password`)
- Check if the delimiter is set correctly in settings

### "Connection timeout"
- Increase timeout value in settings
- Check your internet connection
- Verify proxy settings if enabled

### "Import errors"
- Ensure all dependencies are installed: `pip install -r requirements.txt`

## Credits

**Title**: UNIVERSAL MAIL CHECKER  
**Author**: MOATTYA

## License

This tool is for educational purposes only. Use responsibly and only on accounts you own or have permission to test.

