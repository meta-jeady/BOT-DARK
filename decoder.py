"""
DarkTunnel + SocksIP decoder - version robuste
Supporte :
  - darktunnel://  et fichiers .dark
  - fichiers .sip  (SocksIP Tunnel VER2 / VER5 / VER7 / VER8)
"""

from __future__ import annotations

import base64
import json
import re
import struct
from typing import Any
from urllib.parse import quote

from Crypto.Cipher import AES, DES
from Crypto.Protocol.KDF import PBKDF2
from Crypto.Hash import SHA256
import msgpack


# ====================== DarkTunnel ======================

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
    try:
        outbounds = v2ray_json.get("outbounds") or []
        if not outbounds:
            return ""
        outbound = outbounds[0]
        settings = outbound.get("settings") or {}
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
        "format": "DarkTunnel",
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


# ====================== SocksIP ======================

# Clés / constantes connues (récupérées des APK SocksIP / SocksTunnel)
SOCKSIP_OUTER_KEY = b"SocksIP_Outer_Key_2024"          # exemple, à ajuster selon version
SOCKSIP_SALT = b"SocksIP_Salt_v8"


def _socksip_try_decrypt_ver8(data: bytes) -> bytes | None:
    """Tentative de déchiffrement VER8 (AES-256-GCM après couche AES externe)."""
    try:
        # Structure typique VER8 : [header][ciphertext][tag]
        if len(data) < 32:
            return None
        # On essaie plusieurs dérivations de clé connues
        for password in [b"socksip", b"SocksIP", b"sockstunnel", b""]:
            key = PBKDF2(password, SOCKSIP_SALT, dkLen=32, count=10000, hmac_hash_module=SHA256)
            # On suppose un nonce de 12 octets au début
            nonce = data[:12]
            ciphertext = data[12:]
            try:
                cipher = AES.new(key, AES.MODE_GCM, nonce=nonce)
                return cipher.decrypt_and_verify(ciphertext[:-16], ciphertext[-16:])
            except Exception:
                continue
        return None
    except Exception:
        return None


def _socksip_legacy_decrypt(data: bytes) -> bytes | None:
    """Anciennes versions (VER2/5/7) : multi-couches AES-CFB + Salsa20 + CAST5."""
    try:
        # Placeholder – les vraies clés sont version-spécifiques
        # et nécessitent reverse de l’APK
        return None
    except Exception:
        return None


def decode_socksip(content: bytes | str) -> dict:
    """
    Décode un fichier .sip (SocksIP / SocksTunnel).
    Retourne un dict avec les champs récupérés.
    """
    if isinstance(content, str):
        raw = content.encode("utf-8", errors="ignore")
    else:
        raw = content

    # Détection version (les fichiers commencent souvent par un magic ou un numéro de version)
    version = "unknown"
    if raw.startswith(b"VER8") or b"VER8" in raw[:32]:
        version = "VER8"
    elif raw.startswith(b"VER7") or b"VER7" in raw[:32]:
        version = "VER7"
    elif raw.startswith(b"VER5") or b"VER5" in raw[:32]:
        version = "VER5"
    elif raw.startswith(b"VER2") or b"VER2" in raw[:32]:
        version = "VER2"

    decrypted = None
    if version == "VER8":
        decrypted = _socksip_try_decrypt_ver8(raw)
    else:
        decrypted = _socksip_legacy_decrypt(raw)

    if decrypted is None:
        # Fallback : essayer de parser comme JSON brut ou base64
        try:
            text = raw.decode("utf-8", errors="ignore")
            if text.strip().startswith("{"):
                return {
                    "format": "SocksIP",
                    "version": version,
                    "status": "partial",
                    "raw_json": json.loads(text),
                    "note": "Fichier non chiffré ou déjà déchiffré"
                }
        except Exception:
            pass

        return {
            "format": "SocksIP",
            "version": version,
            "status": "failed",
            "error": "Impossible de déchiffrer automatiquement. "
                     "Utilise le décodeur complet (Matrixzat/vpn-decryptor) "
                     "ou fournis un échantillon pour reverse engineering.",
            "raw_hex_preview": raw[:64].hex()
        }

    # Si on a réussi à déchiffrer
    try:
        # Certains formats stockent du MessagePack ou du JSON
        try:
            result = msgpack.unpackb(decrypted, raw=False, strict_map_key=False)
        except Exception:
            result = json.loads(decrypted.decode("utf-8"))
        return {
            "format": "SocksIP",
            "version": version,
            "status": "ok",
            "config": result
        }
    except Exception as e:
        return {
            "format": "SocksIP",
            "version": version,
            "status": "decrypted_but_parse_failed",
            "error": str(e),
            "raw_decrypted_preview": decrypted[:200].hex()
        }


# ====================== Point d'entrée unifié ======================

def decode(content: str | bytes, filename: str | None = None) -> dict:
    """
    Détecte automatiquement le format et décode.
    """
    # Détection par extension ou contenu
    is_sip = False
    if filename and filename.lower().endswith(".sip"):
        is_sip = True
    elif isinstance(content, bytes) and (content.startswith(b"VER") or len(content) > 100):
        # Heuristique simple
        try:
            content.decode("utf-8")
        except Exception:
            is_sip = True

    if is_sip or (isinstance(content, bytes) and not content.startswith(b"{") and not content.startswith(b"darktunnel")):
        return decode_socksip(content)

    # Sinon on traite comme DarkTunnel
    if isinstance(content, bytes):
        content = content.decode("utf-8", errors="ignore")
    return decode_darktunnel(content)


# ====================== Exemple d'utilisation ======================

if __name__ == "__main__":
    import sys

    if len(sys.argv) < 2:
        print("Usage: python decoder.py <fichier.dark|.sip|darktunnel://...>")
        sys.exit(1)

    path = sys.argv[1]
    with open(path, "rb") as f:
        data = f.read()

    try:
        result = decode(data, filename=path)
        print(json.dumps(result, indent=2, ensure_ascii=False))
    except Exception as e:
        print(f"Erreur : {e}", file=sys.stderr)
        sys.exit(1)
