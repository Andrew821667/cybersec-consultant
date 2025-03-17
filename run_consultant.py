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
from cybersec_consultant.user_profiles import get_profile_manager

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
    
    # Новые опции для персонализации
    parser.add_argument('--list-profiles', action='store_true', help='Показать доступные профили пользователей')
    
    # Новые опции для обогащения базы знаний
    parser.add_argument('--enrich', action='store_true', help='Обогатить базу знаний данными из внешних источников при запуске')
    parser.add_argument('--auto-enrich', action='store_true', help='Включить автоматическое обогащение базы знаний')
    parser.add_argument('--enrich-interval', type=int, default=24, help='Интервал автоматического обогащения в часах (по умолчанию: 24)')
    
    # Новые опции для внешних сервисов
    parser.add_argument('--vt-api-key', help='API ключ VirusTotal для анализа угроз')
    parser.add_argument('--abuseipdb-api-key', help='API ключ AbuseIPDB для анализа IP-адресов')
    parser.add_argument('--safebrowsing-api-key', help='API ключ Google SafeBrowsing для анализа URL')
    
    args = parser.parse_args()

    # Получаем API ключ
    api_key = args.api_key
    if not api_key:
        api_key = os.environ.get("OPENAI_API_KEY")
        if not api_key:
            api_key = input("Введите ваш API ключ OpenAI: ")

    # Сохраняем API ключи внешних сервисов в переменные окружения
    if args.vt_api_key:
        os.environ["VIRUSTOTAL_API_KEY"] = args.vt_api_key
    if args.abuseipdb_api_key:
        os.environ["ABUSEIPDB_API_KEY"] = args.abuseipdb_api_key
    if args.safebrowsing_api_key:
        os.environ["SAFEBROWSING_API_KEY"] = args.safebrowsing_api_key

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

    # Если нужно только показать список профилей
    if args.list_profiles:
        profile_manager = get_profile_manager()
        profiles = profile_manager.profiles
        print("\n📋 ДОСТУПНЫЕ ПРОФИЛИ ПОЛЬЗОВАТЕЛЕЙ:")
        print("-" * 50)
        for profile_id, profile in profiles.items():
            print(f"🔹 {profile_id}: {profile.get('name')}")
            print(f"   {profile.get('description')}")
            print(f"   Уровень: {profile.get('technical_level')}, Стиль: {profile.get('style')}")
            print("-" * 50)
        return

    # Создаем и запускаем консультанта
    consultant = create_consultant()

    # Загружаем базу знаний, если указан путь
    if args.knowledge:
        consultant.load_knowledge_base(args.knowledge)

    # Обогащаем базу знаний, если запрошено
    if args.enrich:
        print("\n🔄 Обогащение базы знаний из внешних источников...")
        success, message = consultant.enrich_knowledge_base(force_update=True)
        status = "✅ Успешно" if success else "❌ Ошибка"
        print(f"{status}: {message}")

    # Запускаем автоматическое обогащение, если запрошено
    if args.auto_enrich:
        print(f"\n🔄 Включение автоматического обогащения базы знаний (интервал: {args.enrich_interval} часов)...")
        success = consultant.start_auto_enrichment(args.enrich_interval)
        status = "✅ Успешно" if success else "❌ Ошибка"
        print(f"{status} включения автоматического обогащения")

    # Запускаем интерактивный режим
    consultant.run_interactive()

if __name__ == "__main__":
    main()
