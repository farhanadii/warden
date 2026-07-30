# Warden: Setup & Usage Guide

> **Important:** Warden only works on **macOS**. It does not run on Windows or Linux.

---

## What You Need Before Starting

- A Mac (running macOS)
- An internet connection (just for the one-time setup below)
- About 5 minutes

---

## Step 1: Check That Python Is Installed

1. Open **Terminal**
   - Press `Command + Space`, type **Terminal**, press Enter
2. Type the following and press Enter:
   ```
   python3 --version
   ```
3. You should see something like `Python 3.11.4` (any version starting with 3 is fine)

If you see `command not found`, download Python from **https://www.python.org/downloads/** and install it, then come back here.

---

## Step 2: Install the Required Libraries

In Terminal, copy and paste this line exactly, then press Enter:

```
pip3 install PyQt5 scapy
```

This downloads two packages that Warden needs. You will see a lot of text scroll by. That is normal. Wait until it finishes and you see your cursor again.

> If you get a "permission denied" error, try:
> ```
> pip3 install --user PyQt5 scapy
> ```

---

## Step 3: Download Warden

If you received the file directly, skip to Step 4.

Otherwise, save the file `warden.py` somewhere easy to find, for example your **Desktop** or **Downloads** folder.

---

## Step 4: Run Warden

Warden needs special permission to see network traffic, so you must run it with `sudo`.

1. Open **Terminal**
2. Type `sudo python3 ` (note the space at the end), then **drag and drop** the `warden.py` file from Finder into the Terminal window; it will fill in the file path for you automatically
3. Press **Enter**
4. Type your **Mac login password** when asked (nothing will appear as you type, that is normal), then press Enter

The Warden window should open.

> **Example of what you type:**
> ```
> sudo python3 /Users/yourname/Desktop/warden.py
> ```

---

## Step 5: Find Your Gateway IP

The Gateway IP is the address of your Wi-Fi router or hotspot. You need this to scan the network.

1. Open **Terminal** (you can have two Terminal windows open at the same time)
2. Type the following and press Enter:
   ```
   netstat -nr | grep default | head -1
   ```
3. The number in the second column is your gateway IP

   Example output:
   ```
   default   192.168.1.1   ...
   ```
   In this example, the gateway IP is `192.168.1.1`

Common gateway IPs:
- Home routers: `192.168.0.1` or `192.168.1.1`
- iPhone hotspot: `172.20.10.1`

---

## How to Use Warden

### Scanning the Network

1. Type your **Gateway IP** into the box at the top (see Step 5 above)
2. Click **Scan**
3. Wait a few seconds; all devices connected to the same network will appear in the list

Each row shows:
| Column | What it means |
|--------|--------------|
| IP Address | The device's address on the network |
| MAC Address | The device's unique hardware ID |
| Device | Device name or brand (e.g. Apple, Samsung) |
| Latency | How fast the device responds (lower = better). `—` means no response |
| Status | Whether the device is currently blocked or online |

### Blocking a Device

Blocking a device cuts off its internet access while it stays connected to the Wi-Fi.

1. Click on a device row to select it (it will be highlighted)
2. Click **Block**
3. The status will change to **Blocked** and the Latency column will show `ARP x1`, `ARP x2`, etc. counting up; this means blocking is active

To block all devices at once, click **Block All**.

### Unblocking a Device

1. Click on the blocked device row to select it
2. Click **Unblock**

To unblock everyone at once, click **Unblock All**.

### Clearing the List

Click **Clear List** to remove all devices from the table. Any blocked devices will be automatically unblocked first.

---

## Important Notes

- **You must be on the same Wi-Fi network** as the devices you want to scan. Warden cannot see devices on a different network.
- **iPhone Personal Hotspot will not work.** Apple prevents devices connected to an iPhone hotspot from seeing each other. Use a regular Wi-Fi router instead.
- **Blocking is temporary.** If you close Warden or click Unblock, the affected device's internet access returns to normal within a few seconds.
- **Do not use this on networks you do not own.** Only use Warden on your own home network or your own hotspot. Using it on public or university Wi-Fi is against the law.

---

## Troubleshooting

**"No devices found after scanning"**
- Make sure you entered the correct Gateway IP (Step 5)
- Make sure your Mac and the target device are on the same Wi-Fi network
- Try disconnecting and reconnecting to the Wi-Fi, then scan again

**"Permission denied" when running the app**
- Make sure you used `sudo python3 warden.py` (not just `python3 warden.py`)

**"ModuleNotFoundError: No module named 'PyQt5'" or similar**
- Go back to Step 2 and run the install command again

**The app opens but the window is blank**
- This can happen if PyQt5 did not install correctly. Try:
  ```
  pip3 uninstall PyQt5 && pip3 install PyQt5
  ```

**Blocking does not seem to work**
- Some apps (like YouTube) use a protocol called QUIC that is harder to block. Try a different app like a web browser loading a new page
- Make sure you clicked Block and the status column shows "Blocked"
