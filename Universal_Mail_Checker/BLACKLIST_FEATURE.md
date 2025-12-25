# Blacklist Feature Documentation

## Overview
The Universal Mail Checker now includes a blacklist feature that allows you to skip checking emails from specific domains. This feature is similar to the implementation in POP CHECKER and IMAP CHECKER.

## Features

### 1. Automatic Blacklist File Creation
On first run, the application automatically creates a `blacklist.txt` file with example format:
```
# Add domains to blacklist (one per line)
# Example:
# example.com
# spam-domain.com
```

### 2. Domain Blacklisting
- Add domains to `blacklist.txt` (one per line)
- Lines starting with `#` are treated as comments
- Domains are case-insensitive (e.g., `SPAM.COM` and `spam.com` are treated the same)
- Blacklisted emails are skipped **before** any server connection attempt

### 3. UI Integration

#### Stats Display
- **BLACKLISTED** stat card (red color: #ff6b6b) shows the count of blacklisted emails
- Blacklist counter label shows the number of loaded blacklisted domains

#### Menu Options
- **File > Reload Blacklist**: Reload the blacklist from file
- **Domains > View Blacklist...**: View all blacklisted domains in a dialog
- **Domains > Edit Blacklist...**: Open blacklist.txt in the system's default text editor

### 4. Workflow

1. **On Startup**: 
   - Creates `blacklist.txt` if it doesn't exist
   - Auto-loads blacklisted domains
   - Displays count in UI

2. **During Checking**:
   - Each email is checked against the blacklist **before** server connection
   - If blacklisted: logged and counted, no server check performed
   - If not blacklisted: proceeds with normal POP3/IMAP checking

3. **Manual Management**:
   - Edit `blacklist.txt` using the menu or manually
   - Reload blacklist without restarting the application

## Usage Example

### Adding Domains to Blacklist

1. Click **Domains > Edit Blacklist...**
2. Add domains (one per line):
   ```
   spam.com
   malware.org
   phishing.net
   ```
3. Save the file
4. Click **File > Reload Blacklist** to apply changes

### Viewing Blacklist

Click **Domains > View Blacklist...** to see all blacklisted domains in a formatted dialog.

## Technical Details

### Implementation
- **Blacklist Storage**: `set()` for O(1) lookup performance
- **Domain Matching**: Case-insensitive domain extraction from email
- **Stats Tracking**: Separate counter for blacklisted emails
- **Signal/Slot**: PyQt6 signal `blacklisted` emitted when domain is blacklisted

### Files Modified
- `Universal_Mail_Checker.py`: Main application file with all blacklist functionality

### Key Functions
- `create_default_blacklist()`: Creates default blacklist.txt
- `load_blacklist_from_file()`: Loads domains from file
- `is_blacklisted()`: Checks if email domain is blacklisted
- `reload_blacklist()`: Reloads blacklist from file
- `view_blacklist()`: Shows blacklist dialog
- `edit_blacklist()`: Opens blacklist file in editor

## Benefits

1. **Performance**: Skip server connections for known spam/invalid domains
2. **Efficiency**: Reduce unnecessary network traffic and delays
3. **Control**: User-managed list of domains to ignore
4. **Consistency**: Same implementation across all mail checkers (POP, IMAP, Universal)

## Notes

- Blacklisted emails are counted in the "CHECKED" total but not in hits, invalids, or errors
- The blacklist is loaded once on startup and when manually reloaded
- Changes to `blacklist.txt` require a reload to take effect
- The blacklist is copied to the worker thread when checking starts
