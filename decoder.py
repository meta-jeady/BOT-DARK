"""
DarkTunnel (.dark / darktunnel://) decoder - version robuste
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
    s = s.strip().replace("-", "+").replace("_", "/")
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


def _build_vless_link(v2ray_json: dict, name: str) -> str:
    """Essaie d'extraire un lien VLESS. Retourne une chaîne vide si impossible."""
    try:
        outbounds = v2ray_json.get("outbounds") or []
        if not outbounds:
            return ""

        outbound = outbounds[0]
        settings = outbound.get("settings") or {}

        # Structure classique VLESS
        vnext = settings.get("vnext")
        if vnext and isinstance(vnext, list) and len(vnext) > 0:
            server = vnext[0]
            address = server.get("address", "")
            port = server.get("port", 443)
            users = server.get("users") or [{}]
            user = users[0] if users else {}
            uuid = user.get("id", "")
            encryption = user.get("encryption", "none")
        else:
            # Autre structure possible
            address = settings.get("address") or settings.get("server") or ""
            port = settings.get("port") or 443
            uuid = settings.get("id") or settings.get("uuid") or ""
            encryption = settings.get("encryption", "none")

        if not address or not uuid:
            return ""

        stream = outbound.get("streamSettings") or {}
        network = stream.get("network", "tcp")
        security = stream.get("security", "none")

        ws = stream.get("wsSettings") or {}
        path = ws.get("path", "/")
        host = (ws.get("headers") or {}).get("Host", "")

        tls = stream.get("tlsSettings") or {}
        sni = tls.get("serverName", "")

        link = (
            f"vless://{uuid}@{address}:{port}"
            f"?encryption={encryption}"
            f"&security={security}"
            f"&type={network}"
        )
        if host:
            link += f"&host={quote(str(host))}"
        if path:
            link += f"&path={quote(str(path))}"
        if sni:
            link += f"&sni={quote(str(sni))}"
        link += f"&allowInsecure=1#{quote(name or 'DarkTunnel')}"
        return link
    except Exception:
        return ""


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

    # V2RayConfig
    v2ray_str = cleaned_inner.get("V2RayConfig", {}).get("EncryptedConfig", "")
    v2ray_json = {}
    if v2ray_str:
        try:
            v2ray_str_clean = (
                v2ray_str
                .replace('"$SOCKS5_LISTEN_HOST"', '"127.0.0.1"')
                .replace("$SOCKS5_LISTEN_PORT", "10808")
                .replace('"$HTTP_LISTEN_HOST"', '"127.0.0.1"')
                .replace("$HTTP_LISTEN_PORT", "10809")
                .replace("$MUX_ENABLED", "true")
            )
            v2ray_json = json.loads(v2ray_str_clean)
        except Exception:
            v2ray_json = {"raw": v2ray_str}

    name = outer.get("name") or "DarkTunnel"
    vless_link = _build_vless_link(v2ray_json, name) if v2ray_json else ""

    return {
        "name": name,
        "type": outer.get("type"),
        "LockedAppConfig": locked,
        "InjectConfig": {
            "Mode": cleaned_inner.get("InjectConfig", {}).get("EncryptedMode"),
            "ProxyHost": cleaned_inner.get("InjectConfig", {}).get("EncryptedProxyHost"),
            "ProxyPort": cleaned_inner.get("InjectConfig", {}).get("EncryptedProxyPort"),
            "SNI": cleaned_inner.get("InjectConfig", {}).get("EncryptedServerNameIndication") or None,
            "Payload": cleaned_inner.get("InjectConfig", {}).get("EncryptedPayload"),
            "DnsttDnsHost": cleaned_inner.get("InjectConfig", {}).get("EncryptedDnsttDnsHost"),
            "DnsttDnsPort": cleaned_inner.get("InjectConfig", {}).get("EncryptedDnsttDnsPort"),
        },
        "SshConfig": {
            "IsLocked": cleaned_inner.get("SshConfig", {}).get("IsLocked"),
            "Host": cleaned_inner.get("SshConfig", {}).get("EncryptedHost") or None,
            "Port": cleaned_inner.get("SshConfig", {}).get("EncryptedPort"),
            "Username": cleaned_inner.get("SshConfig", {}).get("EncryptedUsername") or None,
            "Password": cleaned_inner.get("SshConfig", {}).get("EncryptedPassword") or None,
        },
        "V2RayConfig": v2ray_json,
        "VLESS_Share_Link": vless_link,
                     }
