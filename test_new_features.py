#!/usr/bin/env python
# -*- coding: utf-8 -*-
"""
Тестовый скрипт для проверки новых функциональных возможностей
консультанта по кибербезопасности без использования API OpenAI
"""

import os
import sys
import json
from pprint import pprint

# Добавляем путь к проекту, если запускаем скрипт напрямую
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

# Импортируем модули для тестирования
from cybersec_consultant.user_profiles import get_profile_manager
from cybersec_consultant.external_services import ExternalServicesManager

def test_user_profiles():
    """Тестирование модуля профилей пользователей"""
    print("\n" + "=" * 50)
    print("ТЕСТИРОВАНИЕ ПРОФИЛЕЙ ПОЛЬЗОВАТЕЛЕЙ")
    print("=" * 50)
    
    # Получаем менеджер профилей
    profile_manager = get_profile_manager()
    
    # Выводим список доступных профилей
    print("\nДоступные профили:")
    for profile_id, profile in profile_manager.profiles.items():
        print(f"- {profile_id}: {profile.get('name')} ({profile.get('description')})")
    
    # Тестируем получение профиля
    print("\nТест получения профиля 'expert':")
    expert_profile = profile_manager.get_profile("expert")
    print(f"Имя: {expert_profile.get('name')}")
    print(f"Описание: {expert_profile.get('description')}")
    print(f"Технический уровень: {expert_profile.get('technical_level')}")
    
    # Тестируем генерацию модификации промпта
    print("\nТест генерации модификации промпта:")
    prompt_mod = profile_manager.generate_profile_prompt_modification("beginner")
    print(prompt_mod)
    
    return True

def test_external_services():
    """Тестирование модуля внешних сервисов"""
    print("\n" + "=" * 50)
    print("ТЕСТИРОВАНИЕ ВНЕШНИХ СЕРВИСОВ")
    print("=" * 50)
    
    # Создаем менеджер внешних сервисов
    services = ExternalServicesManager()
    
    # Тестируем запрос к MITRE ATT&CK
    print("\nТест MITRE ATT&CK:")
    try:
        mitre_results = services.query_mitre_att_ck("ransomware")
        print(f"Найдено {len(mitre_results.get('techniques', []))} техник, {len(mitre_results.get('groups', []))} групп")
        
        if mitre_results.get('techniques'):
            print("\nПример техники:")
            technique = mitre_results.get('techniques')[0]
            print(f"- ID: {technique.get('id')}")
            print(f"- Название: {technique.get('name')}")
            print(f"- Описание: {technique.get('description')[:100]}...")
    except Exception as e:
        print(f"Ошибка при запросе к MITRE ATT&CK: {str(e)}")
    
    # Тестируем запрос к базе CVE
    print("\nТест CVE:")
    try:
        cve_info = services.get_cve_info("CVE-2021-44228")
        print(f"- CVE ID: {cve_info.get('id')}")
        print(f"- Описание: {cve_info.get('description')[:100]}...")
        print(f"- Оценка CVSS: {cve_info.get('score')} ({cve_info.get('severity')})")
    except Exception as e:
        print(f"Ошибка при запросе к базе CVE: {str(e)}")
    
    # Тестируем анализ угроз
    print("\nТест анализа угроз (IP):")
    try:
        threat_info = services.get_threat_intelligence("8.8.8.8")
        print(f"- Тип запроса: {threat_info.get('query_type')}")
        print(f"- Найдено информации: {threat_info.get('found')}")
        if threat_info.get('data') and threat_info.get('data').get('geolocation'):
            geo = threat_info.get('data').get('geolocation')
            print(f"- Страна: {geo.get('country')}")
            print(f"- Организация: {geo.get('org')}")
    except Exception as e:
        print(f"Ошибка при анализе угроз: {str(e)}")
    
    return True

if __name__ == "__main__":
    print("Тестирование новых функциональных возможностей консультанта по кибербезопасности")
    
    # Тестируем профили пользователей
    test_user_profiles()
    
    # Тестируем внешние сервисы
    test_external_services()
    
    print("\nТестирование завершено!")
