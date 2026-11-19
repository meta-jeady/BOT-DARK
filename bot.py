"""
Bot Telegram – DarkTunnel Decoder
"""

from __future__ import annotations

import json
import logging
import os
import re
import tempfile
from pathlib import Path

from dotenv import load_dotenv
from telegram import Update, Document
from telegram.constants import ParseMode
from telegram.ext import (
    Application,
    CommandHandler,
    MessageHandler,
    ContextTypes,
    filters,
)

from decoder import decode_darktunnel

load_dotenv()

logging.basicConfig(
    format="%(asctime)s - %(name)s - %(levelname)s - %(message)s",
    level=logging.INFO,
)
logger = logging.getLogger(__name__)

BOT_TOKEN = os.getenv("BOT_TOKEN")
if not BOT_TOKEN:
    raise RuntimeError("Variable d'environnement BOT_TOKEN manquante")

def is_dark_file(filename: str | None) -> bool:
    if not filename:
        return False
    return ".dark" in filename.lower()

async def start(update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
    text = (
        "🔓 *DarkTunnel Decoder Bot*\n\n"
        "Envoie-moi :\n"
        "• un fichier `.dark`\n"
        "• ou un lien `darktunnel://...`\n\n"
        "Je te renverrai la configuration déchiffrée en fichier `.txt`.\n\n"
        "DECODE BY : KCORP TECH"
    )
    await update.message.reply_text(text, parse_mode=ParseMode.MARKDOWN)

async def handle_document(update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
    doc: Document = update.message.document
    if not doc:
        return

    if not is_dark_file(doc.file_name):
        await update.message.reply_text(
            "⚠️ Envoie uniquement un fichier `.dark` (même s'il a un numéro ou un emoji)."
        )
        return

    await update.message.reply_text("⏳ Décodage en cours…")

    try:
        tg_file = await doc.get_file()
        with tempfile.NamedTemporaryFile(delete=False, suffix=".dark") as tmp:
            await tg_file.download_to_drive(tmp.name)
            content = Path(tmp.name).read_text(encoding="utf-8", errors="ignore")
            Path(tmp.name).unlink(missing_ok=True)

        result = decode_darktunnel(content)
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
            "Envoie un fichier `.dark` ou colle un lien qui commence par `darktunnel://`"
        )
        return

    start_idx = text.lower().find("darktunnel://")
    content = text[start_idx:].split()[0]

    await update.message.reply_text("⏳ Décodage en cours…")

    try:
        result = decode_darktunnel(content)
        await _send_result(update, result)
    except Exception as e:
        logger.exception("Erreur décodage texte")
        await update.message.reply_text(
            f"❌ Erreur de décodage :\n`{e}`",
            parse_mode=ParseMode.MARKDOWN
        )

async def _send_result(update: Update, result: dict) -> None:
    name = result.get("name", "config")
    safe_name = re.sub(r'[\\/*?:"<>|]', "_", str(name))[:40]

    json_text = json.dumps(result, indent=2, ensure_ascii=False)
    json_text += "\n\nDECODE BY : KCORP TECH"

    with tempfile.NamedTemporaryFile(
        delete=False, suffix=".txt", prefix=f"{safe_name}_", mode="w", encoding="utf-8"
    ) as tmp:
        tmp.write(json_text)
        tmp_path = tmp.name

    with open(tmp_path, "rb") as f:
        await update.message.reply_document(
            document=f,
            filename=f"{safe_name}_decoded.txt",
            caption="📄 Configuration décodée\nDECODE BY : KCORP TECH",
        )
    Path(tmp_path).unlink(missing_ok=True)

def main() -> None:
    app = Application.builder().token(BOT_TOKEN).build()

    app.add_handler(CommandHandler("start", start))
    app.add_handler(MessageHandler(filters.Document.ALL, handle_document))
    app.add_handler(MessageHandler(filters.TEXT & ~filters.COMMAND, handle_text))

    logger.info("Bot démarré…")
    app.run_polling(allowed_updates=Update.ALL_TYPES)

if __name__ == "__main__":
    main()
