# Blacklist Feature - Quick Start Guide

## What is it?
The blacklist feature allows you to skip checking emails from specific domains, saving time and network resources.

## Quick Start

### 1. First Run
When you start the Universal Mail Checker, it automatically creates `blacklist.txt` with this format:
```
# Add domains to blacklist (one per line)
# Example:
# example.com
# spam-domain.com
```

### 2. Add Domains
**Option A: Using the Menu**
1. Click **Domains** → **Edit Blacklist...**
2. Add domains (one per line)
3. Save and close the file
4. Click **File** → **Reload Blacklist**

**Option B: Manually**
1. Open `blacklist.txt` in any text editor
2. Add domains:
   ```
   spam.com
   malware.org
   phishing.net
   ```
3. Save the file
4. In the app: **File** → **Reload Blacklist**

### 3. View Blacklist
Click **Domains** → **View Blacklist...** to see all blacklisted domains.

## How it Works

```
┌─────────────────────────────────────────────────┐
│  Email Check Flow with Blacklist                │
├─────────────────────────────────────────────────┤
│                                                  │
│  1. Load combo: user@spam.com:password123       │
│           ↓                                      │
│  2. Check blacklist (BEFORE server connection)  │
│           ↓                                      │
│     Is "spam.com" blacklisted?                   │
│           ↓                                      │
│        YES → Skip server check                   │
│              Log as BLACKLISTED                  │
│              Increment counter                   │
│                                                  │
│        NO  → Continue to POP3/IMAP check        │
│              Normal checking process             │
│                                                  │
└─────────────────────────────────────────────────┘
```

## UI Elements

### Stats Display
- **BLACKLISTED** counter (red) - Shows how many emails were skipped
- **Blacklist: X** label - Shows how many domains are loaded

### Menu Options
- **File** → **Reload Blacklist** - Refresh after editing
- **Domains** → **View Blacklist...** - See all domains
- **Domains** → **Edit Blacklist...** - Edit the file

## Example

### Before Adding to Blacklist
```
Checking: user@spam.com:pass123
  ↓ Connect to mail.spam.com...
  ↓ Try authentication...
  ↓ Result: Invalid
  Time: 10 seconds
```

### After Adding to Blacklist
```
Checking: user@spam.com:pass123
  ↓ Domain "spam.com" is blacklisted
  ↓ Result: BLACKLISTED
  Time: 0.001 seconds (10,000x faster!)
```

## Tips

1. **Add Known Spam Domains**: If you know certain domains are always invalid, add them
2. **Temporary Domains**: Services like guerrillamail.com, 10minutemail.com
3. **Case Doesn't Matter**: "SPAM.COM" and "spam.com" are treated the same
4. **Comments**: Use # for notes in blacklist.txt
5. **Reload**: Always reload after editing the blacklist file

## Benefits

| Feature | Benefit |
|---------|---------|
| Pre-Check | Skip network calls for known bad domains |
| Fast | O(1) lookup time |
| Flexible | Edit anytime, reload on demand |
| Visible | Clear UI feedback |
| Safe | No server connection for blacklisted emails |

## Troubleshooting

**Q: I added a domain but it's still being checked**
- Make sure you clicked "Reload Blacklist" after editing

**Q: My blacklist file disappeared**
- The app creates it automatically on next run

**Q: Can I use wildcards like *.spam.com?**
- Not currently - add each subdomain separately

**Q: Where is blacklist.txt located?**
- In the same folder as Universal_Mail_Checker.py

## Examples of Good Blacklist Entries

```
# Temporary email services
guerrillamail.com
10minutemail.com
temp-mail.org

# Known spam domains
spam-domain.com
fake-mail.net

# Typo domains (if checking real databases)
gmial.com
yahooo.com
```

---

For detailed technical documentation, see [BLACKLIST_FEATURE.md](BLACKLIST_FEATURE.md)
