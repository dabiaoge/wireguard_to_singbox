# wireguard_to_singbox
Convert WireGuard configuration to SingBox JSON format.


# Example usage:
wg_config_content = """
[Interface]
PrivateKey = ...
Address = ...
DNS = ...

[Peer]
PublicKey = ...
AllowedIPs = ...
Endpoint = ...
PersistentKeepalive = ...
"""
print(wireguard_to_singbox(wg_config_content))
