import asyncio
import logging
import os
import sys
from telegram import Update
from telegram.ext import ApplicationBuilder, CommandHandler, ContextTypes

# ==========================================
# 🔑 ВСТАВЬТЕ СЮДА ВАШ ТОКЕН ОТ @BotFather:
# ==========================================
BOT_TOKEN = "9091785595:AAE-NiLQSM6uM8uNjKAd9gZKxJNWXaaiI_A"

# Настройка логирования
logging.basicConfig(
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    level=logging.INFO
)

async def start(update: Update, context: ContextTypes.DEFAULT_TYPE):
    welcome_text = (
        "👋 **Привет! Я генератор красивых адресов TON (WalletTg)**\n\n"
        "Чтобы запустить поиск кошелька с нужным окончанием, отправьте команду:\n"
        "`/search СИМВОЛЫ`\n\n"
        "Пример:\n"
        "`/search PEPE`\n"
        "`/search 7777`"
    )
    await update.message.reply_text(welcome_text, parse_mode="Markdown")

async def search(update: Update, context: ContextTypes.DEFAULT_TYPE):
    if not context.args:
        await update.message.reply_text("❌ Укажите окончание адреса!\nПример: `/search PEPE`", parse_mode="Markdown")
        return

    suffix = context.args[0].strip()
    if len(suffix) > 6:
        await update.message.reply_text("⚠️ Длина окончания не должна превышать 6 символов.")
        return

    msg = await update.message.reply_text(f"⏳ Запускаем поиск адреса с окончанием **UQ...{suffix}**...\nПожалуйста, подождите.", parse_mode="Markdown")

    try:
        # Получаем абсолютный путь к папке, где лежит сам bot.py
        script_dir = os.path.dirname(os.path.abspath(__file__))
        vanity_path = os.path.join(script_dir, 'vanity.py')

        # Запуск vanity.py через стандартный python с привязкой к рабочей папке
        process = await asyncio.create_subprocess_exec(
            sys.executable, vanity_path, 'search', suffix,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
            cwd=script_dir  # <-- Устанавливаем рабочую директорию скрипта
        )
        stdout, stderr = await process.communicate()

        stdout_str = stdout.decode('utf-8', errors='ignore')
        stderr_str = stderr.decode('utf-8', errors='ignore')

        if process.returncode == 0:
            await msg.edit_text(f"✅ **Адрес успешно найден!**\n\n```text\n{stdout_str}\n```", parse_mode="Markdown")
        else:
            err_details = stderr_str if stderr_str else stdout_str
            if len(err_details) > 300:
                err_details = err_details[-300:]
            await msg.edit_text(f"❌ Ошибка в скрипте `vanity.py` (код {process.returncode}):\n```text\n{err_details}\n```", parse_mode="Markdown")
    except Exception as e:
        await msg.edit_text(f"⚠️ Ошибка запуска процесса: {str(e)}")

def main():
    if not BOT_TOKEN or "ВАШ_ТОКЕН" in BOT_TOKEN:
        print("ОШИБКА: Замените токен на ваш реальный API token в файле bot.py!")
        return

    app = ApplicationBuilder().token(BOT_TOKEN).build()

    app.add_handler(CommandHandler("start", start))
    app.add_handler(CommandHandler("search", search))

    print("🚀 Бот запущен и готов к работе!")
    app.run_polling()

if __name__ == '__main__':
    main()