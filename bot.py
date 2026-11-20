"""
Bot Telegram – DarkTunnel + SocksIP Decoder
KCORP TECH
"""

from __future__ import annotations

import json
import logging
import os
import re
import tempfile
from pathlib import Path
from threading import Thread

from dotenv import load_dotenv
from flask import Flask
from telegram import Update, Document
from telegram.constants import ParseMode
from telegram.ext import (
    Application,
    CommandHandler,
    MessageHandler,
    ContextTypes,
    filters,
)

from decoder import decode   # ← fonction unifiée (DarkTunnel + SocksIP)

load_dotenv()

logging.basicConfig(
    format="%(asctime)s - %(name)s - %(levelname)s - %(message)s",
    level=logging.INFO,
)
logger = logging.getLogger(__name__)

BOT_TOKEN = os.getenv("BOT_TOKEN")
if not BOT_TOKEN:
    raise RuntimeError("Variable d'environnement BOT_TOKEN manquante")

ADMIN_ID = 8464953107
USERS_FILE = "users.json"

# --- Serveur Web pour Render ---
web_app = Flask(__name__)

@web_app.route('/')
def home():
    return "Bot is alive! - KCORP TECH", 200

def run_web():
    port = int(os.environ.get("PORT", 10000))
    web_app.run(host="0.0.0.0", port=port)

# --- SAUVEGARDE UTILISATEURS POUR BROADCAST ---
def load_users():
    if os.path.exists(USERS_FILE):
        try:
            with open(USERS_FILE, "r", encoding="utf-8") as f:
                return json.load(f)
        except:
            return []
    return []

def save_user(user_id, username):
    users = load_users()
    for u in users:
        if u["id"] == user_id:
            return
    users.append({"id": user_id, "username": username or ""})
    try:
        with open(USERS_FILE, "w", encoding="utf-8") as f:
            json.dump(users, f)
    except Exception as e:
        logger.warning(f"Impossible de sauver user: {e}")

def is_supported_file(filename: str | None) -> bool:
    """Accepte .dark et .sip (même avec numéro, emoji, etc.)"""
    if not filename:
        return False
    name = filename.lower()
    return ".dark" in name or ".sip" in name

async def start(update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
    if update.effective_user:
        save_user(update.effective_user.id, update.effective_user.username)

    text = (
        "🔓 *DARKTUNNEL + SOCKSIP DECODER — KCORP TECH*\n"
        "━━━━━━━━━━━━━━━━━━\n\n"
        "👋 Bienvenue !\n"
        "Décryptez vos fichiers **DarkTunnel** et **SocksIP** en quelques secondes.\n\n"
        "📂 *COMMENT UTILISER LE BOT ?*\n"
        "1️⃣ Envoyez votre fichier `.dark` ou `.sip`\n"
        "2️⃣ Ou collez votre lien `darktunnel://...`\n"
        "3️⃣ Recevez instantanément votre configuration déchiffrée en `.txt`\n\n"
        "⚡ *FONCTIONNALITÉS*\n"
        "• ✅ Décodage instantané\n"
        "• ✅ Support fichiers renommés / avec numéros / emoji\n"
        "• ✅ Support DarkTunnel + SocksIP\n"
        "• ✅ Fichier propre + prêt à l'emploi\n"
        "• ✅ Disponible 24h/24 - 7j/7\n\n"
        "━━━━━━━━━━━━━━━━━━\n"
        "👇 *Envoyez votre fichier .dark ou .sip maintenant*"
    )
    await update.message.reply_text(text, parse_mode=ParseMode.MARKDOWN)

async def broadcast(update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
    if update.effective_user.id != ADMIN_ID:
        await update.message.reply_text("⛔ Tu n'as pas le droit d'utiliser cette commande.")
        return

    if not context.args:
        await update.message.reply_text(
            "Utilise : /broadcast ton message\n\nExemple :\n/broadcast Salut, nouvelle mise à jour du bot !"
        )
        return

    message = " ".join(context.args)
    users = load_users()

    if not users:
        await update.message.reply_text("Aucun utilisateur enregistré pour l'instant. Les gens doivent d'abord faire /start.")
        return

    await update.message.reply_text(f"📤 Envoi en cours à {len(users)} utilisateurs...")

    count = 0
    failed = 0
    for u in users:
        try:
            await context.bot.send_message(
                chat_id=u["id"],
                text=f"📢 *MESSAGE DE KCORP TECH :*\n\n{message}",
                parse_mode=ParseMode.MARKDOWN
            )
            count += 1
        except Exception as e:
            logger.warning(f"Echec envoi à {u['id']}: {e}")
            failed += 1

    await update.message.reply_text(f"✅ Terminé !\nEnvoyé à : {count}\nÉchec : {failed}")

async def handle_document(update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
    doc: Document = update.message.document
    if not doc:
        return

    if not is_supported_file(doc.file_name):
        await update.message.reply_text(
            "⚠️ Envoie uniquement un fichier `.dark` ou `.sip`\n"
            "(même s'il a un numéro ou un emoji)."
        )
        return

    await update.message.reply_text("⏳ Décodage en cours…")

    try:
        tg_file = await doc.get_file()
        content = await tg_file.download_as_bytearray()

        # On passe le nom du fichier pour que le decoder sache si c'est .sip ou .dark
        result = decode(content, filename=doc.file_name)
        await _send_result(update, result)

    except Exception as e:
        logger.exception("Erreur décodage fichier")
        await update.message.reply_text(
            f"❌ Erreur de décodage :\n`{e}`",
            parse_mode=ParseMode.MARKDOWN
        )

async def handle_text(update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
    text = (update.message.text or "").strip()

    if "darktunnel://" not in text.lower():
        await update.message.reply_text(
            "Envoie un fichier `.dark` / `.sip` ou colle un lien qui commence par `darktunnel://`"
        )
        return

    start_idx = text.lower().find("darktunnel://")
    content = text[start_idx:].split()[0]

    await update.message.reply_text("⏳ Décodage en cours…")

    try:
        result = decode(content)
        await _send_result(update, result)
    except Exception as e:
        logger.exception("Erreur décodage texte")
        await update.message.reply_text(
            f"❌ Erreur de décodage :\n`{e}`",
            parse_mode=ParseMode.MARKDOWN
        )

async def _send_result(update: Update, result: dict) -> None:
    name = result.get("name") or result.get("format") or "config"
    safe_name = re.sub(r'[\\/*?:"<>|]', "_", str(name))[:40]

    user = update.effective_user
    if user:
        requested_by = user.full_name
        if user.username:
            requested_by += f" (@{user.username})"
    else:
        requested_by = "Unknown"

    json_text = json.dumps(result, indent=2, ensure_ascii=False)
    json_text += "\n\nDECODE BY : KCORP TECH"

    with tempfile.NamedTemporaryFile(
        delete=False, suffix=".txt", prefix=f"{safe_name}_", mode="w", encoding="utf-8"
    ) as tmp:
        tmp.write(json_text)
        tmp_path = tmp.name

    caption = (
        f"✅ <b>Decrypted Successfully</b>\n\n"
        f"👤 <b>Requested by:</b> {requested_by}\n"
        f"DECODE BY : KCORP TECH"
    )

    with open(tmp_path, "rb") as f:
        await update.message.reply_document(
            document=f,
            filename=f"{safe_name}_decoded.txt",
            caption=caption,
            parse_mode=ParseMode.HTML,
        )
    Path(tmp_path).unlink(missing_ok=True)

def main() -> None:
    Thread(target=run_web, daemon=True).start()

    app = Application.builder().token(BOT_TOKEN).build()

    app.add_handler(CommandHandler("start", start))
    app.add_handler(CommandHandler("broadcast", broadcast))
    app.add_handler(MessageHandler(filters.Document.ALL, handle_document))
    app.add_handler(MessageHandler(filters.TEXT & ~filters.COMMAND, handle_text))

    logger.info("Bot démarré…")
    app.run_polling(allowed_updates=Update.ALL_TYPES)

if __name__ == "__main__":
    main()
