# Universal Mail Checker

A powerful email verification tool that supports both IMAP and POP3 protocols with intelligent auto-discovery and hybrid checking logic.

## Features

- **Hybrid Protocol Support**: Automatically checks POP3 first, then falls back to IMAP
- **Smart Search Mode**: Toggle to use IMAP-only checking
- **Auto-Discovery**: Automatically detects mail servers for common providers
- **Proxy Support**: HTTP/HTTPS, SOCKS4, and SOCKS5 proxy support
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

- **Smart Search ON**: Uses IMAP protocol only for faster checking
- **Smart Search OFF**: Tries POP3 first, then IMAP as fallback with 2-second safety delay

### Proxy Configuration

1. Go to **Tools** → **Settings** → **Proxy** tab
2. Enable proxies and select type (HTTP/HTTPS, SOCKS4, SOCKS5)
3. Optionally load proxies from file or URL

### Results

Results are automatically saved to timestamped folders in `Results/`:
- **Live.txt**: Valid credentials (format: `email:pass | Protocol | Capture`)
- **Banned.txt**: Invalid credentials
- **Unknown.txt**: Connection errors or unknown issues

## Configuration Files

- **imap_servers.txt**: Pre-configured IMAP servers for common providers
- **pop_servers.txt**: Pre-configured POP3 servers for common providers

You can add custom servers in the format: `domain.com,server.domain.com`

## Keyboard Shortcuts

- **F5**: Reload combo list
- **Ctrl+S**: Open settings
- **Ctrl+Q**: Quit application

## Advanced Features

### Thread Count

Adjust the number of concurrent threads (10-5000) for optimal performance based on your system.

### Timeout Configuration

Set connection timeout (1-120 seconds) to balance speed and accuracy.

### Safety Delays

When Smart Search is OFF, the checker waits 2 seconds between POP3 and IMAP attempts to avoid rate limiting.

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

Developed by MOATTYA

## License

This tool is for educational purposes only. Use responsibly and only on accounts you own or have permission to test.
