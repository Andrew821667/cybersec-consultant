#!/usr/bin/env python
# -*- coding: utf-8 -*-
"""
Скрипт для запуска консультанта по кибербезопасности
"""

import os
import sys
import time
import argparse
from cybersec_consultant import create_consultant
from cybersec_consultant.state_management import STATE

def main():
    """Основная функция запуска консультанта"""
    # Парсинг аргументов командной строки
    parser = argparse.ArgumentParser(description='Консультант по кибербезопасности')
    parser.add_argument('--knowledge', '-k', help='Путь к файлу с базой знаний')
    parser.add_argument('--model', '-m', help='Модель для генерации ответов')
    parser.add_argument('--profile', '-p', help='Профиль для ответов (standard, expert, beginner, educational, incident_response)')
    parser.add_argument('--documents', '-d', type=int, help='Количество документов для поиска (1-5)')
    parser.add_argument('--api-key', help='API ключ OpenAI (если не указан, будет запрошен)')
    parser.add_argument('--no-cache', action='store_true', help='Выключить использование кэша')
    
    args = parser.parse_args()
    
    # Получаем API ключ
    api_key = args.api_key
    if not api_key:
        api_key = os.environ.get("OPENAI_API_KEY")
    
    if not api_key:
        api_key = input("Введите ваш API ключ OpenAI: ")
    
    # Инициализируем глобальное состояние
    STATE.api_key = api_key
    if args.model:
        STATE.model_name = args.model
    if args.profile:
        STATE.profile = args.profile
    if args.documents and 1 <= args.documents <= 5:
        STATE.k_docs = args.documents
    if args.no_cache:
        STATE.use_cache = False
    
    # Создаем и запускаем консультанта
    consultant = create_consultant()
    
    # Загружаем базу знаний, если указан путь
    if args.knowledge:
        consultant.load_knowledge_base(args.knowledge)
    
    # Запускаем интерактивный режим
    consultant.run_interactive_mode()

if __name__ == "__main__":
    main()
