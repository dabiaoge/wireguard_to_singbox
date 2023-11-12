import json

def wireguard_to_singbox(wg_conf):
    """
    Convert WireGuard configuration to SingBox JSON format.
    
    Parameters:
    wg_conf (str): WireGuard configuration as a string.
    
    Returns:
    str: JSON string in SingBox format.
    """
    def split_conf_line(line):
        """Split a configuration line into a key and value, handling potential issues."""
        try:
            key, value = line.split("=", 1)
            return key.strip(), value.strip()
        except ValueError:
            raise ValueError(f"Line '{line}' is not a valid key-value pair.")
    
    sb_json = {
        "tag": "wg-out",
        "type": "wireguard",
        "interface_name": "wg0",
        "mtu": 1420,
        "system_interface": False
    }

    # Loop through each line and extract values
    for line in wg_conf.strip().split("\n"):
        if "=" in line:
            key, value = split_conf_line(line)
            if key == "PrivateKey":
                sb_json["private_key"] = value
            elif key == "Address":
                # Append "/32" subnet mask if it's not present
                sb_json["local_address"] = [value if '/' in value else f"{value}/32"]
            elif key == "DNS":
                continue  # Skip DNS as it's not used in the JSON template
            elif key == "PublicKey":
                sb_json["peer_public_key"] = value
            elif key == "Endpoint":
                server, server_port = value.split(":")
                sb_json["server"] = server
                sb_json["server_port"] = int(server_port)
    
    return json.dumps(sb_json, indent=4)
