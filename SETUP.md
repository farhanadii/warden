# Warden: Setup & Usage Guide

> **Important:** Warden only works on **macOS**. It does not run on Windows or Linux.

---

## What is Warden?

Warden is a network management tool that lets you see every device connected to your Wi-Fi and temporarily cut off their internet access whenever you want. It works completely on your own Mac — no accounts, no subscriptions, no internet service required after setup.

**Practical uses:**
- See what unknown devices are on your home network
- Temporarily pause internet for a specific device (e.g. a child's tablet)
- Check who is connected to a personal hotspot

**Important:** Only use Warden on networks you own or have explicit permission to manage. Using it on public Wi-Fi, university networks, or workplace networks without authorisation is against the law.

---

## What You Need Before Starting

- A **Mac** running macOS (Warden will not run on Windows or Linux)
- Your Mac must be connected to the **same Wi-Fi** as the devices you want to manage
- An internet connection for the one-time setup steps below
- Your Mac's **login password** (you will be asked for it each time you run Warden)

---

## Step 1: Check That Python Is Installed

Python is the programming language Warden is written in. Most Macs already have it.

1. Open **Terminal**
   - Press `Command + Space`, type **Terminal**, then press Enter
2. Type the following line exactly and press Enter:
   ```
   python3 --version
   ```
3. You should see something like `Python 3.11.4`. Any version beginning with `3` is fine.

**If you see `command not found`:**
Download Python from **python.org/downloads** and run the installer. Choose the latest stable release for macOS. After installing, restart Terminal and try Step 1 again.

---

## Step 2: Install the Required Libraries

Warden needs two extra components that do not come with Python by default:

| Library | What it does |
|---------|-------------|
| **PyQt5** | Draws the window, buttons, and table you see on screen |
| **scapy** | Sends and receives the network packets used to scan and block devices |

In Terminal, copy and paste this line exactly, then press Enter:

```
pip3 install PyQt5 scapy
```

You will see a lot of text scroll past — this is normal. Wait until it stops and your cursor reappears. This may take a minute or two depending on your internet speed.

**If you see "Permission denied"**, try:
```
pip3 install --user PyQt5 scapy
```

**If you see "pip3: command not found"**, try:
```
python3 -m pip install PyQt5 scapy
```

---

## Step 3: Get the Warden Files

Warden is made up of five files. All five must stay in the **same folder** — do not move individual files out of it.

| File | What it does |
|------|-------------|
| `warden.py` | The file you run to start the app |
| `app.py` | The main window and all interface logic |
| `network.py` | Handles scanning and blocking |
| `theme.py` | Colours and visual design |
| `oui.py` | Device brand name lookup database |

Save the entire Warden folder somewhere easy to find, for example your **Desktop** or **Documents** folder.

---

## Step 4: Run Warden

Warden needs administrator permission to send raw network packets (this is a macOS security requirement — the same kind of permission used by professional network tools like Wireshark). You grant this by running it with `sudo`.

**What is `sudo`?** It stands for "superuser do" — it temporarily elevates Warden to administrator level for that one session only. It does not make any permanent changes to your system and the elevated permission ends the moment you close the app.

### Steps to run:

1. Open **Terminal**
2. Type `sudo python3 ` (include the space at the end — do not press Enter yet)
3. Open **Finder** and navigate to the Warden folder
4. **Drag the file `warden.py`** from Finder into the Terminal window — it will automatically fill in the correct file path
5. Press **Enter**
6. You will be asked: `Password:` — type your **Mac login password**. Nothing will appear as you type; this is normal. Press Enter when done.

The Warden window will open.

**Example of what the full command looks like:**
```
sudo python3 /Users/yourname/Desktop/Warden/warden.py
```

---

## Step 5: Find Your Gateway IP

Before you can scan, Warden needs to know the address of your router.

### What is a router and what is an IP address?

Your **router** (also called a gateway) is the physical box that connects your home Wi-Fi to the internet — usually the device provided by your internet service provider, or a separate box you bought. Every device on your network, including your router, has a unique **IP address**: a set of four numbers separated by dots (for example, `192.168.1.1`). Think of it like a house number — it tells the network exactly where to deliver data.

### How to find your gateway IP:

1. Open a **second Terminal window** (press `Command + N` while Terminal is active)
2. Type the following and press Enter:
   ```
   netstat -nr | grep default | head -1
   ```
3. Look at the number in the **second column** — that is your gateway IP.

   Example output:
   ```
   default   192.168.1.1   UGScg   en0
   ```
   In this example, the gateway IP is **192.168.1.1**

**Common gateway IPs:**
- Home routers (most common): `192.168.0.1` or `192.168.1.1`
- iPhone Personal Hotspot: `172.20.10.1`
- Some routers: `10.0.0.1`

---

## Using Warden

### The Main Window

When Warden first opens, you will see a welcome screen. Here is a map of all the sections:

```
┌─────────────────────────────────────────────────────────────────┐
│ ⬡ Warden │ Network Control        Active   en0  IP  ···  show  │ ← Top bar
├─────────────────────┬─────────────────────┬─────────────────────┤
│          5          │          2          │          3          │ ← Stats row
│       DEVICES       │       BLOCKED       │       ONLINE        │
├─────────────────────┴─────────────────────┴─────────────────────┤
│  Gateway IP  [192.168.1.1]           Gateway MAC:  ···  show    │ ← Toolbar
├─────────────────────────────────────────────────────────────────┤
│                                                                 │
│              ⬡  Welcome to Warden                               │
│                  [ Scan Network ]                               │ ← Main area
│                                                                 │
├─────────────────────────────────────────────────────────────────┤
│ SELECTION [Block] [Unblock]  │  ALL  [Block All] [Unblock All]  │ ← Controls
│                                                      ↺   Reset  │
├─────────────────────────────────────────────────────────────────┤
│ ● Ready — click Scan Network to begin              v1.0.0       │ ← Status bar
└─────────────────────────────────────────────────────────────────┘
```

**Top bar** — Shows the Warden name and, after a scan, your network interface (e.g. `en0`) and your Mac's IP address. Both are hidden by default — click **show** to reveal them.

**Stats row** — A quick summary: total devices found, how many are blocked, and how many are online.

**Toolbar** — Where you enter the gateway IP. After the first scan, the gateway's MAC address also appears here (hidden by default).

**Main area** — Shows a welcome screen with a **Scan Network** button on first launch and after resetting. Changes to a "Scanning…" screen while the scan runs, then to the device table once devices are found.

**Control bar** — Block and Unblock buttons for ticked devices; Block All / Unblock All for bulk actions. Buttons only appear coloured when they have something to do — if they look invisible, it means no action is available right now. The reload icon (↺) on the right rescans the network; the **Reset** button clears the list.

**Status bar** — A one-line message showing the most recent action (e.g. "3 devices blocked", "Scan complete — 5 devices found"). The app version is shown on the right.

---

### Scanning the Network

1. Type your **Gateway IP** into the box in the toolbar (see Step 5 above)
2. Click **Scan Network** (the button in the centre of the welcome screen)
3. The screen changes to **"Scanning network..."** — Warden is sending ARP requests to every possible address on your network
4. Devices appear in the list as they respond. This typically takes 3–8 seconds.
5. When the scan finishes, the status bar shows how many devices were found

**What is ARP?**
ARP stands for Address Resolution Protocol. It is a standard mechanism built into every network device. Warden broadcasts an ARP question to every address on your network, and connected devices automatically reply to identify themselves. It is a passive, read-only discovery process — nothing is modified or disrupted during a scan.

**Scanning again:** After the first scan, the reload icon (↺) appears in the bottom-right corner of the controls bar. Click it at any time to refresh. Devices already in the list stay visible; new devices are added. Any active blocking is not interrupted.

**The first scan may not find every device.** Some devices take a moment to respond to ARP requests, especially if they have just woken from sleep or have not sent any network traffic recently. If you expect more devices than the list shows, click the reload icon (↺) one or two more times. Each additional scan adds any newly responding devices to the list without removing the ones already found.

---

### Understanding the Device Table

Each row in the table represents one device found on your network.

---

#### ☐ Checkbox (first column)

Tick this to **select** a device. You can tick multiple rows at once. The Block and Unblock buttons act only on the rows that are ticked.

---

#### IP Address

The device's current address on the network (e.g. `192.168.1.42`). Your router assigns this automatically and it can change if the device reconnects to Wi-Fi. If a device seems to have vanished after rescanning, it may have been given a new IP.

---

#### MAC Address

A unique identifier permanently built into the physical network hardware of every device — like a serial number. Unlike an IP address, a MAC address belongs to the device itself and never changes.

You may see a normal MAC address such as `a8:5c:2c:d3:f1:09`, or you may see one that triggers a **[Private MAC]** label in the Device column (explained below).

---

#### Device

The name or brand of the device. Warden tries three methods in order:

1. **Network name (mDNS / Bonjour)** — Devices often broadcast their own name (e.g. `Muhammads-iPhone`, `DESKTOP-ABC123`). macOS reads these automatically at no extra cost.
2. **Brand lookup from MAC address** — The first six characters of a MAC address identify the manufacturer. Warden checks a built-in database and shows the brand if it is found.
3. **Fallback** — If neither method works, a dash `—` is shown.

**What you might see:**

| Display | What it means |
|---------|---------------|
| `Muhammads-iPhone` | Device's own name resolved from the network |
| `Muhammads-iPhone  [Apple]` | Network name found, and MAC confirms Apple hardware |
| `[Apple]` | No network name available, but MAC identifies the maker |
| `[Samsung]`, `[Google]`, etc. | Brand identified from MAC address |
| `[Private MAC]` | Device is using a randomised MAC — see explanation below |
| `—` | No name found and MAC not in the database |

---

**What is [Private MAC] and why does it appear?**

Starting with iOS 14 (iPhone, iPad), Android 10, and Windows 10, most modern phones and laptops generate a **random, temporary MAC address** each time they join a Wi-Fi network. This is a deliberate privacy feature designed to prevent tracking: without a consistent MAC address, shops, advertisers, and other parties cannot follow your device as it moves between different Wi-Fi networks.

When a device uses a random MAC:
- Warden cannot look it up in the manufacturer database, so no brand name appears
- You cannot tell from the MAC address alone whether it is a phone, laptop, or tablet
- The device still works perfectly and **can still be blocked**

Seeing `[Private MAC]` in the Device column is completely normal and expected for any modern smartphone or laptop. It does not indicate a problem with Warden or with the device — it simply means the device is using its operating system's built-in privacy protection.

---

#### Latency

How quickly the device responded to a test ping sent by Warden, measured in **milliseconds** (ms). One millisecond is one thousandth of a second — so `12 ms` means the device replied in 0.012 seconds.

| Display | What it means |
|---------|---------------|
| `8 ms` | Very fast — device is nearby and responding quickly |
| `80 ms` | Normal — slightly more delay, possibly further from the router |
| `400 ms` | Slow — could indicate a congested or distant device |
| `timeout` | Device did not reply to the ping. This is completely normal for many devices (smart TVs, game consoles, some phones). They are still on the network; they just ignore pings. |
| `—` | Ping measurement has not run yet |
| `ARP x14` | Device is **currently blocked**. The number counts how many blocking packets have been sent. As long as the number keeps increasing, blocking is actively working. |

---

#### Status

- **● Online** — Device has full internet access
- **● Blocked** — Internet access has been cut off. The entire row also turns dark red so blocked devices are easy to spot at a glance.

---

### Blocking a Device

Blocking temporarily cuts off a device's internet connection while it stays connected to your Wi-Fi. The device will show full Wi-Fi signal bars — it has no way to know it is blocked — but websites will fail to load, apps will stop updating, and video calls will drop.

**How blocking works (simplified):**

Your router and every device on the network constantly exchange small messages saying "my hardware address is X, please send traffic here." This exchange uses ARP.

When you block a device, Warden continuously sends fake ARP messages to both the device and the router. It tells the device "I am the router" and tells the router "I am the target device." Both sides start sending traffic to your Mac. Since your Mac does not forward that traffic, the connection is cut. This technique is called **ARP spoofing**.

The moment you click Unblock or close Warden, it sends several corrective ARP messages to both sides. Normal traffic resumes within a few seconds.

**To block one or more devices:**
1. Tick the checkbox next to each device you want to block
2. Click **Block** (it appears in red when blocking is available)
3. The Status column changes to **● Blocked** and the Latency column starts counting `ARP x1`, `ARP x2`, etc. — this confirms the block is active

**To block all devices at once:** Click **Block All**

---

### Unblocking a Device

1. Tick the checkbox next to the blocked device
2. Click **Unblock** (it appears in green when unblocking is available)
3. Internet access returns within a few seconds

**To unblock all devices at once:** Click **Unblock All**

---

### Resetting the List

Click **Reset** to remove all devices from the table. Any blocked devices are automatically unblocked first, then the entire list is cleared and the welcome screen returns.

---

### Hidden Sensitive Information (show / hide)

After scanning, two pieces of network information appear in the interface:

- **Gateway MAC** (in the toolbar) — the MAC address of your router
- **IP** (in the top bar) — your Mac's current IP address on the network

Both are hidden by default and replaced with placeholder text (`xx:xx:xx:xx:xx:xx` and `xxx.xxx.xxx.xxx`). This protects your network details if someone can see your screen or if you take a screenshot for support.

Click **show** next to either value to reveal it, and **hide** to conceal it again.

---

## Important Notes

- **Stay connected.** Your Mac must remain on the same Wi-Fi network during blocking. If your Mac disconnects from Wi-Fi, blocking stops automatically.
- **Blocking is temporary.** Closing Warden unblocks all devices automatically. No settings are permanently changed on any device.
- **Not all traffic can be blocked.** Some apps (notably YouTube on newer Android) use a protocol called **QUIC** that bypasses ARP-based blocking. To confirm blocking is working, test with a web browser opening a brand-new page rather than a streaming app.
- **iPhone Personal Hotspot will not work.** Apple prevents devices connected to an iPhone hotspot from sending ARP messages to each other. Use a regular Wi-Fi router instead.
- **Only use on networks you own.** Using Warden on public Wi-Fi, university networks, or any network you do not control is illegal.

---

## Troubleshooting

**No devices found after scanning**
- Check that you entered the correct Gateway IP (Step 5). An incorrect IP means Warden scans the wrong address range entirely.
- Confirm your Mac and the target devices are all on the same Wi-Fi network.
- Some routers have a setting called **AP Isolation** or **Client Isolation** that prevents devices from seeing each other. Log in to your router's admin page and disable it.
- Disconnect from Wi-Fi, reconnect, and try scanning again.

**"Permission denied" when running the app**
- You must use `sudo python3 warden.py`. Without `sudo`, macOS will not allow Warden to send the raw network packets it needs.

**"ModuleNotFoundError: No module named 'PyQt5'" or similar**
- Go back to Step 2 and run the install command again.
- If you have multiple Python versions, try: `python3 -m pip install PyQt5 scapy`

**The app window is blank or does not appear**
- PyQt5 may not have installed correctly. Try reinstalling:
  ```
  pip3 uninstall PyQt5 && pip3 install PyQt5
  ```

**Blocking does not seem to work**
- Check that the Latency column shows `ARP x1`, `ARP x2`, etc. — if not, the block may not have started.
- Test with a web browser, not a video streaming app. Streaming apps often use QUIC which bypasses this type of blocking.
- Keep your Mac connected to Wi-Fi — if it drops, blocking stops.

**Device shows [Private MAC] — I cannot identify it**
- This is expected behaviour. Most modern smartphones and laptops (iOS 14+, Android 10+, Windows 10+) generate a random MAC address each time they join a network, so no brand name is available. The device is still on the network and can still be blocked. You will not be able to determine the device type from the MAC address alone.

**Device name shows "resolving..." for a long time**
- Warden runs a second name lookup 4 seconds after scanning. If nothing appears after that, the device is not broadcasting its name on the network.

**The Block or Unblock button looks invisible (no colour, no border)**
- This is intentional design. The Block button only becomes visible and red when you have ticked at least one device that is currently online. The Unblock button only becomes visible and green when you have ticked at least one device that is currently blocked. If both look invisible, tick a row in the table first.
