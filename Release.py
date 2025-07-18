# Horus USER EDITED. FULL FEATURED

import sys, os, socket, struct, threading, time, math, pygame, win32api, win32con, win32gui

# --- Scapy Import ---
try:
    from scapy.layers.inet import IP, TCP; from scapy.packet import Raw; from scapy.sendrecv import sniff
    import logging; logging.getLogger("scapy.runtime").setLevel(logging.ERROR)
except ImportError: print("ERROR: Scapy not found. pip install scapy"); sys.exit(1)
except OSError as e: print(f"ERROR: Npcap/Scapy load failed: {e}"); sys.exit(1)

# --- Configuration ---
NETWORK_DEVICE_NAME = r'\Device\NPF_{XXXXXXX-XXXX-XXXX-XXXX-XXXXXXXXXXXX}' # *** PASTE EXACT NAME HERE ***
SERVER_IP = "XXX.XXX.X.XXX"; SELF_IP = "XXX.XXX.X.XXX"; SERVER_PORT = 10300
BPF_FILTER = f"tcp and host {SERVER_IP} and port {SERVER_PORT}"
SELF_PLAYER_ID = None # Set YOUR 2-byte ID here if known (S2C ID Offset 22)

# --- C2S Constants --- (User Offsets)
C2S_POS_IP_LEN = 106
C2S_X_OFFSET_PAYLOAD = 11; C2S_Y_OFFSET_PAYLOAD = 15; C2S_Z_OFFSET_PAYLOAD = 20 # <h
C2S_TARGET_ID_OFFSET = 32 # <H, size 2
C2S_HEADING_BYTE_OFFSET = 36
# --- S2C Constants ---
# Update Packet
S2C_UPDATE_MARKER = b'\x00\x28\xa9'; S2C_UPDATE_ID_OFFSET = 22   # <H, Size 2
S2C_UPDATE_X_OFFSET = 1; S2C_UPDATE_Y_OFFSET_32b = 3; S2C_UPDATE_Z_OFFSET_32b = 8 # Coords
S2C_UPDATE_HEALTH_OFFSET = 35 # <BBB, Size 3
S2C_UPDATE_REQUIRED_LEN = 39 
S2C_UPDATE_ALIVE_STATUS_OFFSET = 26 # <B, Size 1 (00=Alive, 14=Dead?)


# Info Packets (XX 4B type and 04 A2 type)
S2C_INFO_ID_MARKER = b'\x08\xde' # Sequence preceding ID (<H>) in info packets
S2C_INFO_PACKET_OPCODE_BYTE = 0x4b # Common byte for Race/ascii info packets?
S2C_INFO_BLOCK_LEVEL_OFFSET = 22
S2C_INFO_BLOCK_REALM_OFFSET = 23# Offset for realm in info block (after ID)


# --- Realm Definitions ---
ALBION_RACES = ["Briton", "Avalonian", "Highlander", "Saracen", "Inconnu", "Half Ogre"]
HIBERNIA_RACES = ["Celt", "Firbolg", "Lurikeen", "Elf", "Shar", "Sylvan"]
MIDGARD_RACES = ["Norseman", "Troll", "Dwarf", "Kobold", "Valkyn", "Svartalf"]
ALBION_asciiS = ["Guardian", "Warder","Myrmidon","Gryphon Knight", "Eagle Knight", "Phoenix Knight", "Alerion Knight", "Unicorn Knight", "Lion Knight", "Dragon Knight"]
HIBERNIA_asciiS = ["Savant", "Brehon", "Cosantoir", "Grove Protector", "Raven Ardent", "Silver Hand", "Thunderer", "Gilded Spear"]
MIDGARD_asciiS = ["Skiltvakten", "Isen Vakten", "Flammen Vakten", "Elding Vakten", "Stormur Vakten", "Isen Herra","Isen Fru", "Flammen Herra","Flammen Fru","Elding Herra","Elding Fru", "Stormur Herra", "Stormur Fru"]
# --- Global Data Storage ---
self_pos = {"x": 0.0, "y": 0.0, "z": 0.0, "last_update": 0 }
# Store more info: type, race, ascii, name, realm etc.
detected_entities = {} # Key= ID(<H>), Value includes various fields
data_lock = threading.Lock(); sniffer_active = True
current_target_id = None
manual_tracked_id = None # <<< ID selected manually via Map Click
persistent_entity_info = {} # Key= ID(<H>), Holds static info (Race, ascii, Name, Realm, Type)

# --- Map State ---
REL_MAP_SCALE = 1.0

# --- Pygame Colors ---
COLOR_BACKGROUND=(0,0,0); COLOR_GRID=(40,40,40)
COLOR_SELF = (0, 255, 0) # White for self
COLOR_ALBION = (255, 75, 75)   # Red
COLOR_HIBERNIA = (75, 255, 75) # Green
COLOR_MIDGARD = (75, 75, 255)# Blue
COLOR_UNKNOWN = (255, 255, 0)# Grey for entities with unknown realm
COLOR_FRIENDLY = (0, 255, 255)# Light Blue for known friendlies (from 04a2)
COLOR_TARGET = (128,0,128) # Magenta for current target override
COLOR_TEXT=(255,255,255); COLOR_TEXT_STALE=(76,51,51); COLOR_TEXT_HEX=(200, 200, 100)
COORD_WRAP_VALUE = 65536.0 # Value for 16-bit coordinate wrapping
COLOR_TARGET_LINE = (255, 0, 0) # Same as COLOR_TARGET (or choose another)
GREEN = (0, 255,0)
TEXT_BG = (1,1,1)

# --- Helper Functions ---
def float_to_hex_int(float_val): # (Unchanged)
    if not isinstance(float_val, float) or math.isnan(float_val): return None
    try: return struct.unpack('<I', struct.pack('<f', float_val))[0]
    except: return None
def format_hexdump(data, bytes_per_line=16, label="data"): # (Unchanged)
    lines = []; ascii_str = ""
    if not data: return [f"(No {label} received yet)"]
    for i in range(0, len(data), bytes_per_line):
        chunk = data[i:i + bytes_per_line]; hex_parts = []; ascii_parts = []
        for byte in chunk: hex_parts.append(f"{byte:02X}"); ascii_parts.append(chr(byte) if 32 <= byte <= 126 else '.')
        hex_str = " ".join(hex_parts); ascii_str = "".join(ascii_parts); lines.append(f"{i:04X}   {hex_str:<{bytes_per_line*3}}  |{ascii_str}|")
    return lines

INFO_BLOCK_LEN = 29 # Expected length of the block


def extract_ascii_block_backward(payload, id_marker_location,entity_id, max_search=160):
    separator = entity_id.to_bytes(2, byteorder='little') # Convert entity ID to bytes for search
    ascii_block_end_offset = id_marker_location # Start search right before the marker

    # Find the actual end of ASCII data by skipping trailing nulls before the marker
    while ascii_block_end_offset > 0 and payload[ascii_block_end_offset - 1] == 0:
        ascii_block_end_offset -= 1
    if ascii_block_end_offset == 0 : return "" # Only nulls found

    # Search backwards for the separator before the actual ASCII end
    search_start_for_sep = max(0, ascii_block_end_offset - max_search)
    separator_loc = payload.rfind(separator, search_start_for_sep, ascii_block_end_offset)

    if separator_loc == -1: return "" # Separator not found

    ascii_block_start = separator_loc + len(separator) + 13
    ascii_block_raw = payload[ascii_block_start : ascii_block_end_offset] # Slice includes actual end now
    info_block_raw = payload[ascii_block_start -31 : ascii_block_start + 1] # Slice includes actual end now

    if not ascii_block_raw: return ""

    # Decode and clean
    result_chars = []
    try:
        for byte_value in ascii_block_raw:
            if 32 <= byte_value <= 126: result_chars.append(chr(byte_value))
            else: result_chars.append(' ') # Replace others with newline
        return ["".join(result_chars).strip(), info_block_raw] # Strip leading/trailing whitespace/newlines
    except Exception as e:
        print(f"[ERROR] ASCII Conversion failed: {e}")
        return "[ASCII Error]"
# --- Packet Handling Logic ---
def parse_s2c_update_packet(payload):
    """Parses S2C Update packets (marker 00 28 a9) for ID, Coords, Health."""
    global detected_entities
    current_search_offset = 0
    while current_search_offset < len(payload):
        marker_offset=payload.find(S2C_UPDATE_MARKER, current_search_offset)
        if marker_offset == -1: break
        struct_data_start_index=marker_offset + len(S2C_UPDATE_MARKER) 
        slice_len = S2C_UPDATE_REQUIRED_LEN # Need at least up to health
        if struct_data_start_index+slice_len <= len(payload):
            struct_data_slice=payload[struct_data_start_index : struct_data_start_index + slice_len]
            try:
                entity_id=struct.unpack('<H',struct_data_slice[S2C_UPDATE_ID_OFFSET:S2C_UPDATE_ID_OFFSET+2])[0] # ID @ 22
                packet_x_int=struct.unpack('<H',struct_data_slice[S2C_UPDATE_X_OFFSET:S2C_UPDATE_X_OFFSET+2])[0] # X @ 1
                packet_y_full_int=struct.unpack('<I',struct_data_slice[S2C_UPDATE_Y_OFFSET_32b:S2C_UPDATE_Y_OFFSET_32b+4])[0]; packet_y_int = packet_y_full_int >> 16 # Y @ 3
                hc,hm,hi=struct.unpack('BBB',struct_data_slice[S2C_UPDATE_HEALTH_OFFSET:S2C_UPDATE_HEALTH_OFFSET+3])
                alive_byte = struct.unpack('<B', struct_data_slice[S2C_UPDATE_ALIVE_STATUS_OFFSET:S2C_UPDATE_ALIVE_STATUS_OFFSET+1])[0]
                is_currently_alive = (alive_byte != 0x14) # True if byte is 0, False otherwise
                

                with data_lock:
                    timestamp = time.time()
                    entity_data = detected_entities.get(entity_id, {})
                    # Update existing entry or create a placeholder
                    cached_info = persistent_entity_info.get(entity_id)
                    if cached_info:
                    # Copy cached static info if available

    
                        entity_data["ascii"] = cached_info.get("ascii", entity_data.get("ascii"))
       
                        entity_data["realm"] = cached_info.get("realm", entity_data.get("realm", "Unknown"))

                    
                # --- End Merge ---
                # Update dynamic fields
                entity_data["x"] = float(packet_x_int)
                entity_data["y"] = float(packet_y_int)
                entity_data["health"] = (hc, hm,hi)
                entity_data["is_alive"] = is_currently_alive
                entity_data["raw_struct_slice"] = struct_data_slice
                entity_data["last_update"] = timestamp

                # Store the merged data back
                detected_entities[entity_id] = entity_data

            except(struct.error, IndexError) as e_parse:
             # --- MODIFIED: Make errors visible ---
             err_id = "Unknown"
             try: # Try to get ID for context
                 err_id = struct.unpack('<H',struct_data_slice[S2C_UPDATE_ID_OFFSET:S2C_UPDATE_ID_OFFSET+2])[0]
             except: pass
             print(f"[{time.strftime('%H:%M:%S')}] S2C Update Parse Error (ID Attempt@22: {hex(err_id)}): {e_parse}")
             # --- END MODIFICATION ---
            except Exception as e_generic: print(f"[{time.strftime('%H:%M:%S')}] Unexpected S2C Update Parse Error: {e_generic}")
        current_search_offset = marker_offset + len(S2C_UPDATE_MARKER)

def parse_enemy_info_packet(payload):
    """Parses S2C Info packets (XX 4B type) for ID, Race, ascii."""
    global detected_entities
    current_search_offset = 0
    while True:
        id_marker_offset = payload.find(S2C_INFO_ID_MARKER, current_search_offset)
        if id_marker_offset == -1: break
        id_start_offset = id_marker_offset + len(S2C_INFO_ID_MARKER)
        if id_start_offset + 2 > len(payload): current_search_offset = id_marker_offset + 1; continue

        try:
            entity_id = struct.unpack('<H', payload[id_start_offset : id_start_offset+2])[0]
            # Try to parse ascii then Race backwards from ID marker
            ascii_str = extract_ascii_block_backward(payload, id_marker_offset, entity_id)[0]
            info_block = extract_ascii_block_backward(payload, id_marker_offset, entity_id)[1]
            realm_op = None
            if info_block:
       
                realm_op = struct.unpack('<B', info_block[S2C_INFO_BLOCK_REALM_OFFSET : S2C_INFO_BLOCK_REALM_OFFSET + 1])[0]
                lvl_op = struct.unpack('<B', info_block[S2C_INFO_BLOCK_LEVEL_OFFSET : S2C_INFO_BLOCK_LEVEL_OFFSET + 1])[0]

            realm = "Unknown"
            if realm_op:
                if realm_op == 0x04: realm = "Albion"
                elif realm_op == 0x08: realm = "Midgard"
                elif realm_op >= 0x0c: realm = "Hibernia"
                # if ascii_str in ALBION_RACES: realm = "Albion"
                # elif ascii_str in HIBERNIA_asciiS: realm = "Hibernia"
                # elif ascii_str in MIDGARD_asciiS: realm = "Midgard"

            with data_lock:
                timestamp = time.time()
                if entity_id not in persistent_entity_info:
                    persistent_entity_info[entity_id] = {} # Create persistent entry if new
                # Update persistent info with newly parsed static data (if found)

                if ascii_str: persistent_entity_info[entity_id]["ascii"] = ascii_str 
                if info_block: persistent_entity_info[entity_id]["info_block"] = info_block # Store raw block for later use          
                if realm != "Unknown": persistent_entity_info[entity_id]["realm"] = realm
                # --- End Persistent Update ---
                if entity_id in detected_entities:
                    detected_entities[entity_id]["last_update"] = timestamp
                if entity_id not in detected_entities: # Create new if not seen before
                    detected_entities[entity_id] = {"x":0.0, "y":0.0, "z":0.0, "health":(0,0,0), "raw_struct_slice": payload[max(0,id_marker_offset-20):id_start_offset+10]} # Store slice around ID
                # Update with found info

                detected_entities[entity_id]["ascii"] = ascii_str if ascii_str else detected_entities[entity_id].get("ascii")
                detected_entities[entity_id]["info_block"] = info_block
                detected_entities[entity_id]["realm"] = realm
                detected_entities[entity_id]["last_update"] = timestamp
                detected_entities[entity_id]['level'] = lvl_op
  

        except (struct.error, IndexError) as e: pass # 
        current_search_offset = id_marker_offset + 1 # Move past current marker



def packet_analyzer(pkt):
    """Callback. Parses C2S Pos(106). Routes S2C packets to specific parsers."""
    
    global self_pos, current_target_id
    try:
        if not pkt.haslayer(IP) or not pkt.haslayer(TCP): return
        src_ip=pkt[IP].src; dst_ip=pkt[IP].dst; payload=b''
        if pkt.haslayer(TCP) and isinstance(pkt[TCP].payload,(bytes,Raw)): payload=bytes(pkt[TCP].payload)
        elif pkt.haslayer(Raw): payload=bytes(pkt[Raw].load)
        if not payload: return
        timestamp = time.time(); ip_len = len(pkt); payload_len = len(payload)

        # --- C2S Packet Parsing ---
        if src_ip==SELF_IP and dst_ip==SERVER_IP:
             min_len_c2s_pos = max(C2S_X_OFFSET_PAYLOAD+2, C2S_Y_OFFSET_PAYLOAD+2, C2S_Z_OFFSET_PAYLOAD+2, C2S_TARGET_ID_OFFSET+2)
             if payload.find(b'\x00\0e') and len(pkt) == 80:
                # print('Found 00 0e')
                try:
                    p_rot4 = struct.unpack('>b',payload[14:15])[0]
                    # print(payload[14])
                  
                    # print(p_rot4)
                    with data_lock:
                        
                        self_pos['r']=float(p_rot4)
                except: pass
             if payload_len >= min_len_c2s_pos:
                 try:
                     px_short=struct.unpack('<h',payload[C2S_X_OFFSET_PAYLOAD:C2S_X_OFFSET_PAYLOAD+2])[0];
                     py_short=struct.unpack('<h',payload[C2S_Y_OFFSET_PAYLOAD:C2S_Y_OFFSET_PAYLOAD+2])[0];
                     pz_short=struct.unpack('<h',payload[C2S_Z_OFFSET_PAYLOAD:C2S_Z_OFFSET_PAYLOAD+2])[0];
                    
                     p_rot4 = struct.unpack('>b',payload[40:41])[0] 
                    #  print(p_rot4)
                     target_id=struct.unpack('<H', payload[C2S_TARGET_ID_OFFSET:C2S_TARGET_ID_OFFSET+2])[0]
                     with data_lock:
                         self_pos["x"]=float(px_short);
                         self_pos["y"]=float(py_short);
                         self_pos["z"]=float(pz_short);
                         
                         self_pos["r"]=float(p_rot4)
                         
                         self_pos["last_update"]=timestamp;    
                     if target_id: current_target_id=target_id
                 except (struct.error, IndexError) as e_pos: print(f"[{time.strftime('%H:%M:%S')}] C2S Parse Error: {e_pos}")
       
        # --- S2C Packet Parsing ---
        elif src_ip == SERVER_IP and dst_ip == SELF_IP:
            # Dispatch based on packet type indicators
   

            # Check for XX 4B type packets (more robust check might be needed)
            if len(payload) > 3 and payload.find(S2C_INFO_ID_MARKER) != -1:
                parse_enemy_info_packet(payload)
            # Check for standard update packets (contains marker)
            if payload.find(S2C_UPDATE_MARKER) != -1:
                parse_s2c_update_packet(payload)


    except Exception as e_handler: print(f"\nError in packet handler: {e_handler}")

# --- Packet Sniffing Thread --- (Unchanged)
# --- Packet Sniffing Thread --- (Unchanged)
def scapy_sniffer_thread(): # (Remains same as V42)
    global sniffer_active; print(f"Attempting to sniff on device: {NETWORK_DEVICE_NAME}");
    if not NETWORK_DEVICE_NAME or '{' not in NETWORK_DEVICE_NAME: print("\n*** ERROR: Set NETWORK_DEVICE_NAME!"); sniffer_active=False; return
    print(f"Using filter: {BPF_FILTER}"); print("Starting Scapy sniff()... (Requires Admin privileges)")
    try: sniff(iface=NETWORK_DEVICE_NAME, filter=BPF_FILTER, prn=packet_analyzer, store=0, stop_filter=lambda pkt: not sniffer_active)
    except OSError as e: print(f"\nFatal Scapy/Npcap OSError: {e}"); sniffer_active=False
    except Exception as e: print(f"\nFatal Error starting sniff: {e}"); sniffer_active=False
    print("Scapy sniffer thread finished.")

# --- Pygame Fonts & Constants ---
SCREEN_WIDTH=1400; SCREEN_HEIGHT=900; MAP_CENTER_X=(SCREEN_WIDTH//2)-300; MAP_CENTER_Y=SCREEN_HEIGHT//2
PLAYER_DOT_RADIUS = 4; CLICK_RADIUS = 10
TRACKER_X = 10; TRACKER_Y = 100; FONT_SIZE_TRACKER=24; HEX_LINE_HEIGHT = 18
FONT_SIZE_MAP=16; STALE_TIMEOUT_SEC=10; FONT_SIZE_DEBUG=24 # Increased stale timeout slightly
MONO_FONTS='consolas, courier new, courier, monospace'
ZOOM_FACTOR = 1.1; MIN_SCALE = 0.001; MAX_SCALE = 5.0

def run_gui():
    """Minimap with auto-tracker, realm colors, race/ascii/name display."""
     # Reset tracked ID on GUI start
    
    COORD_WRAP_VALUE = 65535.0 # <<< NEED TO DEFINE COORD_WRAP_VALUE
    global SCREEN_WIDTH, SCREEN_HEIGHT, MAP_CENTER_X, MAP_CENTER_Y
    global sniffer_active, REL_MAP_SCALE, current_target_id
    if current_target_id:   tracked_entity_id = current_target_id
    try: pygame.init()
    except Exception as e: print(f"ERROR initializing Pygame: {e}"); sniffer_active = False; return
    screen = pygame.display.set_mode((SCREEN_WIDTH, SCREEN_HEIGHT), pygame.NOFRAME)
    hwnd = pygame.display.get_wm_info()["window"]
    win32gui.SetWindowLong(hwnd, win32con.GWL_EXSTYLE,
        win32gui.GetWindowLong(hwnd, win32con.GWL_EXSTYLE) | win32con.WS_EX_LAYERED),
    win32gui.SetWindowPos(hwnd, win32con.HWND_TOPMOST, 0, 0, 0, 0, win32con.SWP_NOMOVE | win32con.SWP_NOSIZE)
    # Set window transparency color
    win32gui.SetLayeredWindowAttributes(hwnd, win32api.RGB(*COLOR_BACKGROUND), 0, win32con.LWA_COLORKEY)
    

        
    pygame.display.set_caption("Horus") # Title

    # Fonts
    try: map_font=pygame.font.SysFont(MONO_FONTS,FONT_SIZE_MAP); debug_font=pygame.font.SysFont(MONO_FONTS,FONT_SIZE_DEBUG); tracker_font=pygame.font.SysFont(MONO_FONTS,FONT_SIZE_TRACKER); hex_font=pygame.font.SysFont(MONO_FONTS, FONT_SIZE_TRACKER); print(f"Using font: {map_font.name}")
    except: print("Warning: Font error. Using default."); map_font=pygame.font.Font(None,FONT_SIZE_MAP); debug_font=pygame.font.Font(None,FONT_SIZE_DEBUG); tracker_font=pygame.font.Font(None, FONT_SIZE_TRACKER); hex_font = tracker_font

    clock = pygame.time.Clock(); running = True
    
    
    last_frame_positions = {}

    while running and sniffer_active:
        
            
        current_frame_positions = {}
        target_screen_pos = None # Reset target screen position each frame
        mouse_pos = pygame.mouse.get_pos()
        # Event Handling (Zoom only)
        for event in pygame.event.get():
            
            if event.type == pygame.MOUSEBUTTONDOWN and event.button == 1: # Left Click
                click_pos = event.pos
                clicked_id = None
                clicked_on_dot = False
                for entity_id_loop, screen_pos in list(last_frame_positions.items()): # Use different variable name in loop
                    if screen_pos:  
                        dist_sq=(click_pos[0]-screen_pos[0])**2 + (click_pos[1]-screen_pos[1])**2
                        if dist_sq < (CLICK_RADIUS**2): # Use click radius

                            clicked_id = entity_id_loop; clicked_on_dot = True; break
                if clicked_id is not None:
                    # --- MODIFIED: Update the single target_id global ---
                    with data_lock: # Lock potentially needed if sniffer thread modifies target_id often
                        current_target_id = clicked_id # Set the global target ID to the clicked one
                    print(f"Map Click - Set Target ID: {hex(current_target_id)}")
                    # --- End Modification ---
                elif not clicked_on_dot: # Optional: Clear target if background clicked
                    with data_lock:
                        print('No ID')
                        current_target_id = None # Clear the global target ID
                    print("Map Click - Target Cleared.")
            if event.type == pygame.QUIT: running = False
            if event.type == pygame.MOUSEWHEEL:
                if event.y > 0: REL_MAP_SCALE *= ZOOM_FACTOR; 
                elif event.y < 0: REL_MAP_SCALE /= ZOOM_FACTOR
                REL_MAP_SCALE = max(MIN_SCALE, min(REL_MAP_SCALE, MAX_SCALE))
            if event.type == pygame.VIDEORESIZE:
                WIDTH, HEIGHT = event.size
                screen = pygame.display.set_mode((WIDTH, HEIGHT), pygame.RESIZABLE)
       
                MAP_CENTER_X=WIDTH//2; MAP_CENTER_Y=HEIGHT//2

        # Read Data & Cleanup Stale
        with data_lock: 
            s_x=self_pos.get("x",0.0); 
            s_y=self_pos.get("y",0.0);
            s_r=self_pos.get("r",0);
            target_id = current_target_id; 
            current_entities=dict(detected_entities)
        heading_deg_cw_from_north = ((s_r * 22.5) + 180.0) % 360.0
    # Map needs to rotate opposite to player heading
        map_rotation_angle_deg = -heading_deg_cw_from_north
        map_rotation_angle_rad = math.radians(map_rotation_angle_deg)
        # Pre-calculate sin/cos for efficiency
        cos_angle = math.cos(map_rotation_angle_rad)
        sin_angle = math.sin(map_rotation_angle_rad)
        current_time=time.time(); entities_to_remove=[pid for pid, data in current_entities.items() if current_time-data.get("last_update",0)>STALE_TIMEOUT_SEC]
        if entities_to_remove: 
            with data_lock: [detected_entities.pop(pid,None) for pid in entities_to_remove]; current_entities={k:v for k,v in current_entities.items() if k not in entities_to_remove}
        
        # Count Midgard
        mid_count = sum(1 for entity_data in current_entities.values() if entity_data.get("realm") == "Midgard" and entity_data.get("is_alive")==True)
        # Count Albion
        alb_count = sum(1 for entity_data in current_entities.values() if entity_data.get("realm") == "Albion" and entity_data.get("is_alive")==True)
        # Count Hibernia
        hib_count = sum(1 for entity_data in current_entities.values() if entity_data.get("realm") == "Hibernia" and entity_data.get("is_alive")==True)
        entity_count = mid_count + alb_count + hib_count

        if current_target_id:
            tracked_entity_id = current_target_id # Auto-track
        else:
            tracked_entity_id = target_id
        tracked_data = current_entities.get(tracked_entity_id) if tracked_entity_id is not None else None
        # --- Calculate Target Distance ---
        target_distance = None
        if tracked_data: # Ensure we have data for the target
            t_x = tracked_data.get("x", 0.0)
            t_y = tracked_data.get("y", 0.0)
            # Ensure coords are valid floats before calculating
            if not(isinstance(t_x,float) and isinstance(t_y,float) and isinstance(s_x,float) and isinstance(s_y,float)): pass # Skip if types are wrong
            elif math.isnan(t_x) or math.isnan(t_y) or math.isnan(s_x) or math.isnan(s_y): pass # Skip if NaN
            else:
                # Calculate relative distance with wrap correction
                dist_x = t_x - s_x
                dist_y = t_y - s_y
                wrap_threshold = COORD_WRAP_VALUE / 2.0
                if dist_x > wrap_threshold: dist_x -= COORD_WRAP_VALUE
                elif dist_x < -wrap_threshold: dist_x += COORD_WRAP_VALUE
                if dist_y > wrap_threshold: dist_y -= COORD_WRAP_VALUE
                elif dist_y < -wrap_threshold: dist_y += COORD_WRAP_VALUE
                # Calculate Euclidean distance
                target_distance = math.sqrt(dist_x**2 + dist_y**2) * 15.625
        # --- End Distance Calculation ---

        # --- Drawing ---
        screen.fill(COLOR_BACKGROUND)
        # Grid & Self dot
       
        # pygame.draw.circle(screen,COLOR_SELF,(MAP_CENTER_X,MAP_CENTER_Y),PLAYER_DOT_RADIUS+1);
        pygame.draw.circle(screen,(255,75,75,100),(MAP_CENTER_X,MAP_CENTER_Y),PLAYER_DOT_RADIUS+128 * REL_MAP_SCALE,1);
        pygame.draw.circle(screen,(100,100,100,100),(MAP_CENTER_X,MAP_CENTER_Y),PLAYER_DOT_RADIUS+386 * REL_MAP_SCALE,1);
        
        
        # --- Draw Other Entities ---
        sorted_entity_ids = sorted(current_entities.keys())
        for entity_id in sorted_entity_ids:
           
            
            if SELF_PLAYER_ID is not None and entity_id == SELF_PLAYER_ID: continue
            data=current_entities.get(entity_id) # Get potentially updated data
            if not data: continue # Skip if data somehow missing after cleanup check
            p_x=data.get("x",0.0); p_y=data.get("y",0.0); 
           
            realm = data.get("realm")

            ascii = data.get("ascii")


            # NaN/Type checks
            if not(isinstance(p_x,float) and isinstance(p_y,float) and isinstance(s_x,float) and isinstance(s_y,float)): continue
            if math.isnan(p_x): continue
            if math.isnan(p_y): continue
            if math.isnan(s_x): continue
            if math.isnan(s_y): continue
            # Map calculation
            rel_x = p_x - s_x; rel_y = p_y - s_y
            # Wrap Correction

            wrap_threshold = COORD_WRAP_VALUE / 2.0 # <<< NEED TO DEFINE COORD_WRAP_VALUE
            if rel_x > wrap_threshold: rel_x -= COORD_WRAP_VALUE
            elif rel_x < -wrap_threshold: rel_x += COORD_WRAP_VALUE
            if rel_y > wrap_threshold: rel_y -= COORD_WRAP_VALUE
            elif rel_y < -wrap_threshold: rel_y += COORD_WRAP_VALUE
            # Screen calculation
            rotated_rel_x = rel_x * cos_angle - rel_y * sin_angle
            rotated_rel_y = rel_x * sin_angle + rel_y * cos_angle
            screen_x = int(MAP_CENTER_X + (rotated_rel_x * REL_MAP_SCALE))
            screen_y = int(MAP_CENTER_Y + (rotated_rel_y * REL_MAP_SCALE))
               # ---> Assign to the now-defined dictionary <---
            current_frame_positions[entity_id] = (screen_x, screen_y)
            if not (0 <= screen_x < SCREEN_WIDTH and 0 <= screen_y < SCREEN_HEIGHT): continue
            # --- Determine Dot Color & Label ---
            is_target = (current_target_id is not None and entity_id == current_target_id)
            if is_target: dot_color = COLOR_TARGET
            elif realm == "Albion": dot_color = COLOR_ALBION
            elif realm == "Hibernia": dot_color = COLOR_HIBERNIA
            elif realm == "Midgard": dot_color = COLOR_MIDGARD
            else: dot_color = COLOR_UNKNOWN # Grey for unknown realm/type
            id_color = (255,255,255)
            is_alive = data.get("is_alive", True) # Default to alive if status unknown
            if not is_alive:
                dot_color = COLOR_TEXT_STALE # Override dot color to grey
                id_color = COLOR_TEXT_STALE  # Override label color to grey
            if is_target:
                target_screen_pos = (screen_x, screen_y)
            # Determine Label

            if ascii: label_string = f"{ascii.strip().split(' ')[0]}"
      
    
            else: label_string = str(hex(entity_id)) # Fallback to hex ID
            # --- End Color/Label ---
            # Draw
            dot_pos=(screen_x,screen_y); 
            pygame.draw.circle(screen,(1,1,1),dot_pos, PLAYER_DOT_RADIUS+2)
            pygame.draw.circle(screen,dot_color,dot_pos,PLAYER_DOT_RADIUS)
            id_surf=map_font.render(label_string,True,id_color, TEXT_BG)
            id_rect=id_surf.get_rect(center=(screen_x,screen_y-PLAYER_DOT_RADIUS-FONT_SIZE_MAP//2)); screen.blit(id_surf,id_rect)
            if target_screen_pos: # Draw line only if target exists and was calculated this frame
                pygame.draw.line(screen, COLOR_TARGET_LINE, (MAP_CENTER_X, MAP_CENTER_Y), target_screen_pos, 1)
        # --- Draw Top-Left Debug Info ---
        debug_y = 50
        # mouse_text = f"Mouse: ({mouse_pos[0]}, {mouse_pos[1]})"; mouse_surf = debug_font.render(mouse_text, True, COLOR_TEXT_STALE); screen.blit(mouse_surf, (10, debug_y)); debug_y += FONT_SIZE_DEBUG + 2
        self_coord_text = f"Self Coords(X,Y, R): ({s_x}, {s_y}, {s_r})" # Simple XY
        # self_coord_surf = debug_font.render(self_coord_text, True, COLOR_SELF); screen.blit(self_coord_surf, (10, debug_y)); debug_y += FONT_SIZE_DEBUG + 2
        
        alb_count_text = f"Alb: {alb_count}"; alb_count_surf = debug_font.render(alb_count_text, True, COLOR_ALBION, TEXT_BG); screen.blit(alb_count_surf, (10, debug_y)); 
        mid_count_text = f"Mid: {mid_count}"; mid_count_surf = debug_font.render(mid_count_text, True, COLOR_MIDGARD, TEXT_BG); screen.blit(mid_count_surf, (10 + 80, debug_y))
        hib_count_text = f"Hib: {hib_count}"; hib_count_surf = debug_font.render(hib_count_text, True, COLOR_HIBERNIA, TEXT_BG); screen.blit(hib_count_surf, (10 + 160, debug_y)); debug_y += FONT_SIZE_DEBUG + 2
        # entity_count_text = f"Total: {entity_count}";
        # entity_count_surf = debug_font.render(entity_count_text, True, COLOR_TEXT, TEXT_BG); screen.blit(entity_count_surf, (10, debug_y)); debug_y += FONT_SIZE_DEBUG + 2
        # scale_text = f"Map Scale: {REL_MAP_SCALE:.4f}"; scale_surf = debug_font.render(scale_text, True, COLOR_TEXT_STALE); screen.blit(scale_surf, (10, debug_y));
        tracker_y_start = debug_y
        # --- Draw Tracker Info Panel (Auto-tracks C2S target) ---
        RED = (255,0,0)
        tracker_x = 10; tracker_y = tracker_y_start
        header_text = f"{hex(target_id) if tracked_entity_id is not None else 'None'}"
        # if tracked_entity_id is not None and not tracked_data: header_text += " (Data N/A)"
        # track_header_surf = debug_font.render(header_text, True, COLOR_TEXT, TEXT_BG); screen.blit(track_header_surf, (tracker_x, tracker_y)); tracker_y += FONT_SIZE_DEBUG + 4
        if tracked_data:
            t_level  = tracked_data.get("level", 0)
            t_info_block = tracked_data.get("info_block")
            t_x = int(tracked_data.get("x", 0)); t_y = int(tracked_data.get("y", 0));
            t_ascii = tracked_data.get("ascii", "N/A"); t_realm = tracked_data.get("realm", "N/A"); t_health = tracked_data.get("health", (0,0,0))
            t_alive = tracked_data.get("is_alive", True) # Get alive status
            info_text_1 = f"{t_realm}"
            info_text_2 = f"{t_ascii}"
            info_text_3 = f"{t_info_block}"
            level_text = f" Level: {t_level}"

            coord_text = f"X:{t_x} | Y:{t_y}"
            
            status_text = f" {'Alive' if t_alive else 'Dead'}"
            health_text = f" {t_health[0]} :: {t_health[1]} :: {t_health[2]}"
            WHITE = (255,255,255)
            dist_text = f" {target_distance:.0f}" if target_distance is not None else "N/A"
            info_surf_1 = tracker_font.render(info_text_1  + level_text, True, WHITE,TEXT_BG ); screen.blit(info_surf_1, (tracker_x, tracker_y)); tracker_y += FONT_SIZE_TRACKER + 2
            info_surf_2 = tracker_font.render(info_text_2, True, WHITE, TEXT_BG); screen.blit(info_surf_2, (tracker_x, tracker_y)); tracker_y += FONT_SIZE_TRACKER + 2
            # coord_surf = tracker_font.render(coord_text, True, COLOR_TARGET); screen.blit(coord_surf, (tracker_x, tracker_y)); tracker_y += FONT_SIZE_TRACKER + 4
            # level_surf = tracker_font.render(level_text, True, COLOR_TARGET); screen.blit(level_surf, (tracker_x, tracker_y)); tracker_y += FONT_SIZE_TRACKER + 2
            status_surf = tracker_font.render(status_text, True, (0,255,0) if t_alive else COLOR_TEXT_STALE, TEXT_BG); screen.blit(status_surf, (tracker_x, tracker_y)); tracker_y += FONT_SIZE_TRACKER + 2
            if t_alive: health_surf = tracker_font.render(health_text, True, (0,255,0), TEXT_BG); screen.blit(health_surf, (tracker_x, tracker_y)); tracker_y += FONT_SIZE_TRACKER + 2
            dist_surf = tracker_font.render(dist_text, True, RED, TEXT_BG); screen.blit(dist_surf, (tracker_x, tracker_y)); tracker_y += FONT_SIZE_TRACKER + 10
            # raw_slice = tracked_data.get("raw_struct_slice");
            # info_surf_3 = tracker_font.render(info_text_3, True, COLOR_TARGET); screen.blit(info_surf_3, (tracker_x, tracker_y)); tracker_y += FONT_SIZE_TRACKER + 2
            # hex_dump_lines = format_hexdump(raw_slice, bytes_per_line=16, label="tracked data")
           
        #     hex_dump_lines = format_hexdump(t_info_block, bytes_per_line=16, label="tracked data")
        #     hex_header_surf = tracker_font.render("INFO BLOCK:", True, COLOR_TEXT); screen.blit(hex_header_surf, (tracker_x, tracker_y)); tracker_y += FONT_SIZE_TRACKER + 2
        #     for line_idx, line in enumerate(hex_dump_lines):
        #         if tracker_y > SCREEN_HEIGHT - HEX_LINE_HEIGHT: break
        #         line_surf = hex_font.render(line, True, RED); screen.blit(line_surf, (tracker_x + 5, tracker_y)); tracker_y += HEX_LINE_HEIGHT
        #         if len(hex_dump_lines) > 3 and line_idx >= 2: trunc_surf = hex_font.render("...", True, COLOR_TEXT_HEX); screen.blit(trunc_surf, (tracker_x + 5, tracker_y)); break
        # else:
        #      if target_id is not None: no_track_text = f"(Waiting for data for Target {hex(target_id)})"
        #      else: no_track_text = "(No target selected in game)"
        #      no_track_surf = tracker_font.render(no_track_text, True, COLOR_TEXT_STALE); screen.blit(no_track_surf, (tracker_x, tracker_y))
            
        last_frame_positions = current_frame_positions
        pygame.display.flip(); clock.tick(30)   


    sniffer_active = False; pygame.quit(); print("GUI closed.")

# --- Main Execution ---
if __name__ == "__main__":
    print("Horus)...") # Title
    # (Startup unchanged)
    if '{' not in NETWORK_DEVICE_NAME or '}' not in NETWORK_DEVICE_NAME: print("\n--- FATAL ERROR --- Set NETWORK_DEVICE_NAME!"); sys.exit(1)
    try: import pygame
    except ImportError: print("\n--- FATAL ERROR --- Pygame not found. pip install pygame"); sys.exit(1)
    print(f"Using Server IP: {SERVER_IP}:{SERVER_PORT}, Self IP: {SELF_IP}"); print(f"Using Network Device: {NETWORK_DEVICE_NAME}")
    print("IMPORTANT: Set SELF_PLAYER_ID if known!"); print("IMPORTANT: Ensure script is run with Administrator privileges!")
    sniffer_thread = threading.Thread(target=scapy_sniffer_thread, daemon=True); sniffer_thread.start()
    print("Waiting for sniffer to initialize..."); time.sleep(3)
    if sniffer_active: print("Starting GUI..."); run_gui()
    else: print("Sniffer thread failed. GUI not started. Exiting.")
    print("Waiting for sniffer thread..."); sniffer_thread.join(timeout=2); print("Program finished.")
