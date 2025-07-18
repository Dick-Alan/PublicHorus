# PublicHorus: Network Packet Analyzer and Minimap Tool

Horus is a Python-based tool designed to sniff network packets from a specific game, extract relevant information like player coordinates, health, and entity details (realm, class, level), and display them on a real-time minimap. It uses Scapy for packet sniffing and Pygame for the graphical user interface.

## Features

* **Real-time Minimap:** Visualizes your character and other detected entities on a dynamic map.
* **Entity Tracking:** Displays the position, realm, class, and health of other players/NPCs.
* **Target Information:** Automatically tracks your in-game target and shows its details and distance.
* **Realm Coloring:** Differentiates entities by their realm (Albion, Hibernia, Midgard) on the minimap.
* **Interactive Map:** Click on entities on the map to set them as your tracked target.
* **Zoom Functionality:** Adjust the minimap's zoom level using the mouse wheel.
* **Packet Parsing:** Decodes custom game packets to extract crucial gameplay data.

## Requirements

Before you can run PublicHorus, you'll need to install the following:

* **Python 3.x:** Make sure you have a recent version of Python 3 installed. You can download it from [python.org](https://www.python.org/downloads/).
* **Scapy:** A powerful interactive packet manipulation program.
* **Npcap (for Windows):** The recommended packet capture library for Windows, required by Scapy.
* **Pygame:** A set of Python modules designed for writing video games.
* **Pywin32 (for Windows):** Python extensions for Microsoft Windows.

## Installation

You have two main ways to get the code:

### Option 1: Clone the Repository (Recommended)

This is the easiest way to get the entire project.

1.  **Install Git:** If you don't have Git installed, download it from [git-scm.com](https://git-scm.com/downloads/).
2.  **Open your terminal or command prompt.**
3.  **Navigate to where you want to save the project** (e.g., your Documents folder):
    ```bash
    cd C:\Users\YourUser\Documents
    ```
    (Replace `C:\Users\YourUser\Documents` with your desired path.)
4.  **Clone the repository:**
    ```bash
    git clone [https://github.com/Dick-Alan/PublicHorus.git](https://github.com/Dick-Alan/PublicHorus.git)
    ```
    (Replace `Dick-Alan/PublicHorus.git` with the actual path to this repository.)
5.  **Move into the newly created `PublicHorus` directory:**
    ```bash
    cd PublicHorus
    ```

### Option 2: Copy and Paste into an IDE (e.g., VS Code)

If you're new to Git or prefer using an IDE directly:

1.  **Create a new file:** Open your IDE (like VS Code) and create a new file. Save it immediately as `horus.py` (it's crucial to end it with `.py` so Python knows it's a script).
2.  **Copy the entire code:** Select all the code from the `horus.py` file in the GitHub repository and paste it into your newly created `horus.py` file in the IDE.

### Install Python Dependencies

Regardless of how you got the code, you need to install the required Python libraries.

1.  **Open your terminal or command prompt.**
2.  **Navigate to the `PublicHorus` directory** (if you cloned, you should already be there; if you copied the file, navigate to where you saved `horus.py`):
    ```bash
    cd C:\path\to\PublicHorus
    ```
3.  **Install the libraries:**
    ```bash
    pip install scapy pygame pywin32
    ```

### Install Npcap (Windows only)

This step is **essential** for Windows users as Scapy needs it to capture network packets.

1.  Download and install Npcap from the official website: [https://nmap.org/npcap/](https://nmap.org/npcap/)
2.  During the installation process, make sure to **check the "Install Npcap in WinPcap API-compatible Mode" option.** This is crucial for Scapy to function correctly with older applications and is often required.

## Configuration

Before running the script, you **must** configure some variables within the `horus.py` file to match your network setup and preferences.

1.  **Open `horus.py` in a text editor or your IDE.**

2.  **Locate the `--- Configuration ---` section.**

3.  **Identify your `NETWORK_DEVICE_NAME`:**
    * This tells Scapy which network adapter to listen on.
    * **How to find it:** Open a Python interpreter (or create a new temporary Python file, run it, and then close it) and type:
        ```python
        from scapy.all import show_interfaces
        show_interfaces()
        ```
    * You'll see a list of network interfaces. Look for one that corresponds to your active internet connection (e.g., "Ethernet", "Wi-Fi"). It will have a name like `\Device\NPF_{YOUR-GUID-HERE}`.
    * **Copy the exact string, including the curly braces `{}`**, and paste it into the `NETWORK_DEVICE_NAME` variable. Remember the `r` before the string!
        ```python
        NETWORK_DEVICE_NAME = r'\Device\NPF_{XXXXXXXX-XXXX-XXXX-XXXX-XXXXXXXXXXXX}' # <<< PASTE EXACT NAME HERE >>>
        ```
        *Example (your GUID will be different):*
        `NETWORK_DEVICE_NAME = r'\Device\NPF_{A1B2C3D4-E5F6-7890-1234-567890ABCDEF}'`

4.  **Set `SERVER_IP` and `SELF_IP`:**
    * `SERVER_IP`: This is the IP address of the game server you are connecting to.
    * `SELF_IP`: This is your computer's local IP address.
    * **How to find them:**
        * While you are playing the game, open your Command Prompt (Windows) or Terminal (Linux/macOS).
        * Type `netstat -an | findstr 10300` (for Windows) or `netstat -an | grep 10300` (for Linux/macOS) and press Enter. (The port `10300` comes from `SERVER_PORT` in the script.)
        * Look for a line that shows an `ESTABLISHED` connection. The foreign address (the one not belonging to your computer) will likely be the `SERVER_IP`, and your local address will be `SELF_IP`.
        * Alternatively, you can use a tool like Wireshark to inspect your network traffic and identify these IPs.
    * Replace the placeholder values with your actual IPs:
        ```python
        SERVER_IP = "XXX.XXX.X.XXX" # e.g., "203.0.113.45" (Game Server IP)
        SELF_IP = "XXX.XXX.X.XXX"   # e.g., "192.168.1.10" (Your Computer's IP)
        ```

5.  **Optional: Set `SELF_PLAYER_ID`:**
    * If you know your character's unique 2-byte ID in the game, you can set this. It helps the minimap identify and highlight your own character. If you don't know it, you can leave it as `None`.
        ```python
        SELF_PLAYER_ID = None # Set YOUR 2-byte ID here if known (S2C ID Offset 22)
        ```

### Customization Variables

You can adjust these variables in the `--- Pygame Fonts & Constants ---` section to change the appearance of the minimap:

* **`SCREEN_WIDTH` and `SCREEN_HEIGHT`:**
    * Controls the size of the minimap window in pixels.
    * `SCREEN_WIDTH = 1400`
    * `SCREEN_HEIGHT = 900`
* **`MAP_CENTER_X` and `MAP_CENTER_Y`:**
    * Determines the initial center point of the minimap within the window. Usually set to `(SCREEN_WIDTH // 2)` and `(SCREEN_HEIGHT // 2)` for a centered map.
    * `MAP_CENTER_X = (SCREEN_WIDTH // 2) - 300`
    * `MAP_CENTER_Y = SCREEN_HEIGHT // 2`
* **`PLAYER_DOT_RADIUS`:**
    * Size of the dots representing players/entities on the map.
    * `PLAYER_DOT_RADIUS = 4`
* **`FONT_SIZE_TRACKER`:**
    * Font size for the information displayed in the top-left tracking panel.
    * `FONT_SIZE_TRACKER = 24`
* **`FONT_SIZE_MAP`:**
    * Font size for the labels (class/ID) next to entities on the map.
    * `FONT_SIZE_MAP = 16`
* **`STALE_TIMEOUT_SEC`:**
    * How long an entity's dot will remain on the map after no updates are received, before it disappears.
    * `STALE_TIMEOUT_SEC = 10` (in seconds)

## Running the Script

To run PublicHorus, you **must** execute it with administrator/root privileges because Scapy requires elevated permissions to sniff network traffic.

### Windows

1.  **Open Command Prompt** or **PowerShell** as an **Administrator**.
    * Search for "cmd" or "powershell", right-click on the result, and select "Run as administrator".
2.  **Navigate to the directory** where you saved `horus.py` (the `PublicHorus` folder if you cloned):
    ```bash
    cd C:\path\to\PublicHorus
    ```
3.  **Run the script:**
    ```bash
    python horus.py
    ```

### Linux / macOS (Important Note)

This script uses specific Windows API calls (`win32api`, `win32con`, `win32gui`) to create a transparent, topmost window. These modules are Windows-specific. Therefore, **this script will not run directly on Linux or macOS without significant modifications** to the Pygame window setup and transparency handling.

If you were to adapt it for Linux/macOS (e.g., replacing `pywin32` with equivalent display management methods, if available for Pygame), you would typically run it with `sudo`:

1.  Open a terminal.
2.  Navigate to the repository directory:
    ```bash
    cd /path/to/PublicHorus
    ```
3.  Run the script:
    ```bash
    sudo python3 horus.py
    ```
    (You might need to use `python` instead of `python3` depending on your system's Python setup.)

## Usage

Once PublicHorus is running:

* A transparent Pygame window will appear on your screen. You can usually click through it to interact with your game.
* **Your Character:** A **green dot** at the center of the map.
* **Other Entities:**
    * **Red dots:** Entities from Albion realm.
    * **Green dots:** Entities from Hibernia realm.
    * **Blue dots:** Entities from Midgard realm.
    * **Yellow dots:** Entities with an unknown realm.
    * **Dull Grey dots:** Entities that are no longer alive (e.g., dead players/NPCs).
* **Labels:** Each entity dot will have a short label showing its class/role (e.g., "Guardian", "Celt") or its hexadecimal ID if the class is not detected.
* **Range Circles:** Circles around your character indicate specific distances (e.g., common spell ranges in game).
* **Target Line:** If you have an in-game target, a **red line** will connect your character to that target on the minimap, and its details will be shown in the top-left panel.
* **Zooming:** Use your **mouse scroll wheel** to zoom in and out on the minimap.
* **Manual Tracking:** **Left-click** on any entity's dot on the minimap. This will make PublicHorus track that entity and display its detailed information in the top-left panel, overriding your in-game target if you have one.
* **Clear Manual Target:** **Left-click** on an empty part of the minimap to clear any manually selected target.

## Troubleshooting

* **"ERROR: Scapy not found."**: This means the `scapy` library isn't installed. Go back to the "Install Python Dependencies" step and run `pip install scapy`.
* **"ERROR: Npcap/Scapy load failed."**:
    * On Windows, ensure you have Npcap installed and that you specifically checked the "Install Npcap in WinPcap API-compatible Mode" option during its installation.
    * **Crucially, make sure you are running the `horus.py` script with administrator privileges.** Scapy needs these permissions to access network interfaces.
* **"*** ERROR: Set NETWORK\_DEVICE\_NAME!"**: You missed or incorrectly configured the `NETWORK_DEVICE_NAME` variable in the `horus.py` script. Review the "Configuration" section carefully.
* **No entities appearing / Map is empty**:
    * **Double-check all configuration variables:** `NETWORK_DEVICE_NAME`, `SERVER_IP`, and `SELF_IP`. Even a small typo will prevent it from working.
    * **Are you actually playing the game?** The script only works when the game client is actively sending and receiving data on the network.
    * **Are you running as Administrator/Root?** This is the most common reason for no traffic being captured.
    * The `BPF_FILTER` (also in the configuration section) might be too specific if the game uses different ports or hosts. For testing, you could temporarily simplify it to `BPF_FILTER = "tcp"` to capture all TCP traffic, but be aware this will show a lot more unrelated data.
* **`win32api` / `win32con` / `win32gui` errors**: If you see errors related to these modules, it means you're trying to run the script on a non-Windows operating system. As mentioned above, this script's GUI is Windows-specific and requires significant re-coding for other platforms.
* **Antivirus/Firewall Blocking**: Your antivirus or firewall might be blocking Scapy's ability to capture packets. You may need to temporarily disable them or add an exception for Python/Npcap.

---
