# -*- coding: utf-8 -*-
"""
Скрипт для запуска консультанта по кибербезопасности
"""

import sys
import os

# Добавляем директорию проекта в sys.path
sys.path.append(os.path.dirname(os.path.abspath(__file__)))

# Импортируем консультанта
from cybersec_consultant import create_consultant

def main():
    """Основная функция для запуска консультанта"""
    print("=== Консультант по кибербезопасности ===")
    print("Инициализация...")
    
    # Создаем экземпляр консультанта
    consultant = create_consultant()
    
    # Загружаем индекс или создаем новый
    index_loaded = consultant.load_index()
    if not index_loaded:
        print("Индекс не найден. Загружаем базу знаний...")
        consultant.load_knowledge_base()
    
    # Запускаем интерактивный режим
    consultant.run_interactive_mode()

if __name__ == "__main__":
    main()
