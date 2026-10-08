"""IT support matching vocabulary: plain-words issue -> service category. Used by the centre, which never loads the
edge-side connector or the simulator."""
CATEGORY_WORDS = {
    "it.accounts": ["sign in", "signin", "log in", "login", "locked", "password", "account", "new starter", "starter",
                    "leaves", "leaver", "offboard", "mfa", "approval prompt", "authenticator"],
    "it.email": ["email", "mailbox", "outlook", "inbox", "bounc", "forward", "shared mailbox"],
    "it.printing": ["print", "printer", "queue", "scan"],
    "it.network": ["wi-fi", "wifi", "network", "internet", "vpn", "ip address", "dhcp"],
    "it.endpoint": ["slow", "disk", "full", "update", "restart", "crash", "teams", "microphone", "hear", "pc ", "laptop"],
    "it.files": ["onedrive", "share", "access denied", "folder", "files", "sync"],
    "it.web": ["website", "web site", "certificate", "not private", "dns", "domain"],
    "it.security": ["virus", "threat", "malware", "hacked", "pop-up", "popup", "homepage", "admin access", "contractor"],
    "it.backup": ["backup", "back up", "restore"],
}
DEFAULT_CATEGORY = "it.endpoint"
