"""
DarkTunnel (.dark / darktunnel://) decoder
"""

from __future__ import annotations

import base64
import json
import re
from typing import Any
from urllib.parse import quote

from Crypto.Cipher import AES
import msgpack


KEY_256 = b"$B&E)H@McQfThWmZq4t7w!z%C*F-JaNd"
KEY_192 = b"F)J@NcRfUjXn2r4u7x!A%D*G"
IV = bytes.fromhex("232e39185523184a5723586242200e05")


def _aes_cfb_decrypt(data: bytes, key: bytes, iv: bytes) -> bytes:
    return AES.new(key, AES.MODE_CFB, iv=iv, segment_size=128).decrypt(data)


def _b64_decode_safe(s: str | bytes) -> bytes:
    if isinstance(s, bytes):
        return s

    s = s.strip()
    s = s.replace("-", "+").replace("_", "/")
    s = re.sub(r"[^A-Za-z0-9+/=]", "", s)

    missing = len(s) % 4
    if missing:
        s += "=" * (4 - missing)

    return base64.b64decode(s)


def _try_decrypt_field(value: Any, key: bytes = KEY_192) -> Any:
    if value is None or value == "":
        return value

    raw = None
    if isinstance(value, bytes):
        raw = value
    elif isinstance(value, str):
        try:
            raw = bytes.fromhex(value)
        except Exception:
            try:
                raw = _b64_decode_safe(value)
            except Exception:
                return value

    if not raw:
        return value

    try:
        dec = _aes_cfb_decrypt(raw, key, IV)
        try:
            return dec.decode("utf-8")
        except Exception:
            return dec.hex()
    except Exception:
        return value


def _recursive_clean(obj: Any, key: bytes = KEY_192) -> Any:
    if isinstance(obj, dict):
        result = {}
        for k, v in obj.items():
            if k.startswith("Encrypted") and v:
                result[k] = _try_decrypt_field(v, key)
            else:
                result[k] = _recursive_clean(v, key)
        return result
    if isinstance(obj, list):
        return [_recursive_clean(i, key) for i in obj]
    if isinstance(obj, bytes):
        try:
            return obj.decode("utf-8")
        except Exception:
            return obj.hex()
    return obj


def decode_darktunnel(content: str) -> dict:
    content = content.strip().lstrip("\ufeff").strip()

    if content.startswith("darktunnel://"):
        content = content[len("darktunnel://"):]

    content = re.sub(r"\s+", "", content)

    try:
        outer_bytes = _b64_decode_safe(content)
        outer = json.loads(outer_bytes.decode("utf-8"))
    except Exception as e:
        raise ValueError(f"Impossible de lire le contenu base64/JSON : {e}")

    if "encryptedLockedConfig" not in outer:
        raise ValueError("Champ encryptedLockedConfig manquant")

    encrypted_bytes = _b64_decode_safe(outer["encryptedLockedConfig"])
    decrypted_outer = _aes_cfb_decrypt(encrypted_bytes, KEY_256, IV)
    unpacked = msgpack.unpackb(decrypted_outer, raw=False, strict_map_key=False)

    locked = _recursive_clean(unpacked.get("LockedAppConfig", {}))
    if "Password" in locked and isinstance(locked["Password"], str):
        locked["Password"] = locked["Password"][:64]
    if "HardwareIdList" in locked:
        locked["HardwareIdList"] = [
            h[:64] if isinstance(h, str) and len(h) > 64 else h
            for h in locked["HardwareIdList"]
        ]

    inner_enc = unpacked.get("EncryptedLockedConfig")
    if not isinstance(inner_enc, bytes):
        raise ValueError("EncryptedLockedConfig interne invalide")

    decrypted_inner = _aes_cfb_decrypt(inner_enc, KEY_192, IV)
    inner = msgpack.unpackb(decrypted_inner, raw=False, strict_map_key=False)
    cleaned_inner = _recursive_clean(inner)

    v2ray_str = cleaned_inner.get("V2RayConfig", {}).get("EncryptedConfig", "")
    if not v2ray_str:
        raise ValueError("Aucune configuration V2Ray trouvée dans le fichier")

    v2ray_str_clean = (
        v2ray_str
        .replace('"$SOCKS5_LISTEN_HOST"', '"127.0.0.1"')
        .replace("$SOCKS5_LISTEN_PORT", "10808")
        .replace('"$HTTP_LISTEN_HOST"', '"127.0.0.1"')
        .replace("$HTTP_LISTEN_PORT", "10809")
        .replace("$MUX_ENABLED", "true")
    )
    v2ray_json = json.loads(v2ray_str_clean)

    outbound = v2ray_json["outbounds"][0]
    vnext = outbound["settings"]["vnext"][0]
    user = vnext["users"][0]
    stream = outbound["streamSettings"]
    ws = stream.get("wsSettings", {})
    tls = stream.get("tlsSettings", {})

    path = ws.get("path", "/")
    host = ws.get("headers", {}).get("Host", "")
    sni = tls.get("serverName", "")

    vless_link = (
        f"vless://{user['id']}@{vnext['address']}:{vnext['port']}"
        f"?encryption={user.get('encryption', 'none')}"
        f"&security={stream.get('security', 'tls')}"
        f"&type={stream.get('network', 'ws')}"
        f"&host={quote(host)}"
        f"&path={quote(path)}"
        f"&sni={quote(sni)}"
        f"&allowInsecure=1"
        f"#{quote(outer.get('name', 'DarkTunnel'))}"
    )

    return {
        "name": outer.get("name"),
        "type": outer.get("type"),
        "LockedAppConfig": locked,
        "InjectConfig": {
            "Mode": cleaned_inner["InjectConfig"]["EncryptedMode"],
            "ProxyHost": cleaned_inner["InjectConfig"]["EncryptedProxyHost"],
            "ProxyPort": cleaned_inner["InjectConfig"]["EncryptedProxyPort"],
            "SNI": cleaned_inner["InjectConfig"]["EncryptedServerNameIndication"] or None,
            "Payload": cleaned_inner["InjectConfig"]["EncryptedPayload"],
            "DnsttDnsHost": cleaned_inner["InjectConfig"]["EncryptedDnsttDnsHost"],
            "DnsttDnsPort": cleaned_inner["InjectConfig"]["EncryptedDnsttDnsPort"],
        },
        "SshConfig": {
            "IsLocked": cleaned_inner["SshConfig"]["IsLocked"],
            "Host": cleaned_inner["SshConfig"]["EncryptedHost"] or None,
            "Port": cleaned_inner["SshConfig"]["EncryptedPort"],
            "Username": cleaned_inner["SshConfig"]["EncryptedUsername"] or None,
            "Password": cleaned_inner["SshConfig"]["EncryptedPassword"] or None,
        },
        "V2RayConfig": v2ray_json,
        "VLESS_Share_Link": vless_link,
}
