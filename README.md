
The window updates **every second**. Nothing to refresh manually.

The same idea exists for **single ports**: in the Ports tab, click `[inspect]` next to a port to open a per-port live view.

---

## SNMP: reading the router

CubScanner tries to read your router's DHCP/ARP table using SNMP. This is
**automatic and passive** — no credentials, no brute-force.

What SNMP gives you:

- **Router model and firmware** shown in the Overview of every device
- **Devices that are currently offline** (from the router's memory)
- **Full list of MACs** the router knows about

**When it works**: routers with SNMP enabled (many business and prosumer models).
**When it doesn't**: most consumer routers ship with SNMP disabled by default.
CubScanner skips it silently if the router doesn't respond.

To check if your router has SNMP: open its admin panel and look for "SNMP" in
the settings. The default community string is usually `public`.

---

## Client isolation warning

If CubScanner only sees 2-3 devices (you + gateway), you may see this message
in the status bar:

> ⚠ Possible client isolation — few devices visible.

**This is not a CubScanner bug.** It means the network is blocking direct
device-to-device communication. Common on:

- Guest WiFi networks
- Public WiFi (cafés, hotels, airports)
- Networks with a restrictive firewall

**Wireshark, Nmap and Fing see the same thing.** There's nothing a scanner can
do from your PC alone.

**To fix**: connect to the main (non-guest) network, or disable client
isolation in your router's admin panel (often under "Wireless" or "Advanced").

---

## Requirements

| | Minimum | Recommended |
|---|---|---|
| Windows | 10 or 11 (64-bit) | 10 or 11 (64-bit) |
| RAM | 4 GB | 8 GB |
| Disk | 150 MB | 250 MB |
| Network | Wi-Fi or Ethernet | Either |
| Permissions | Admin (for capture) | Admin |

**Nothing else to install.** The `.exe` contains Python, Scapy, PySNMP, and
the Npcap installer helper. Npcap itself is installed automatically on the
first run (or bundled with the installer version).

---

## Troubleshooting

### "Windows protected your PC"

Normal for unsigned `.exe`. Click **More info → Run anyway**.
Happens once per file version.

### Nothing appears in the device list

- **Not running as admin?** Right-click → **Run as administrator**.
- **Wi-Fi on a guest network?** Client isolation is likely blocking you.
- **Npcap not installed?** Restart CubScanner. It will prompt you to install.

### Few devices show up

- Try clicking **🔍 Deep Scan** — it wakes sleeping devices (TVs, cameras)
- Try the **▶ Capture** button and keep it on. Any device that sends traffic
  will appear in the list.
- If still nothing: check for client isolation (see above)

### Ports all show as "closed"

- Firewall on the target device is probably filtering the scan. This is
  normal for modern phones and computers.
- The router may block port scan packets. Try from a different network.

### "Npcap not found" error

- The auto-installer should have handled it. If it didn't, install Npcap
  manually from **https://npcap.com/#download**
- During Npcap install, **check the box** "Install Npcap in WinPcap API-compatible Mode"

### The app freezes on first launch

- The first scan can take 30-60 seconds on a large network
- If it's stuck past 60 seconds, a **Skip loading** button appears — click it
- After that, the app runs smoothly

### Antivirus complains

Normal for unsigned PyInstaller `.exe`. Add an exclusion for
`CubScannerFree.exe` in your antivirus settings, or build from source.

### The Npcap installer didn't open

- Check your internet connection
- Download Npcap manually from **https://npcap.com/#download** and install it
- Then restart CubScanner

---

## Legal

Use this software **only on networks you own or have explicit written
authorization to monitor**.

Monitoring a network without authorization is illegal in most countries,
including:

- **Brazil**: Lei 12.737/2012 (Lei Carolina Dieckmann)
- **United States**: Computer Fraud and Abuse Act (CFAA)
- **European Union**: Directive 2013/40/EU

You are solely responsible for ensuring your use complies with local laws.

---

## Support

- **Issues, suggestions, PRO upgrade**: https://ko-fi.com/pietro67
- **Npcap driver**: https://npcap.com

---

## What's next?

**CubScanner PRO** adds:

- 🤖 AI-driven vulnerability scan (local LLM, no cloud)
- 🔐 Real CVE matching from the NIST database
- 🎥 Video stream decoding (RTSP/RTP) with AI
- 📅 7-day history and behavioral baseline
- 🔔 Native Windows notifications for anomalies
- 🔌 REST API and CSV export

Get it at **https://ko-fi.com/pietro67**

---

*CubScanner Free v11.1 — MIT-style license for personal use.*