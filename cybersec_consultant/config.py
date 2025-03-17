# -*- coding: utf-8 -*-
"""
Модуль конфигурации консультанта по кибербезопасности
"""

import os
import json
import getpass
from pathlib import Path

# Определение путей для хранения данных
BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
DATA_DIR = os.path.join(BASE_DIR, "data")
PROMPTS_DIR = os.path.join(BASE_DIR, "prompts")
INDICES_DIR = os.path.join(BASE_DIR, "indices")
CONFIG_FILE = os.path.join(BASE_DIR, "config", "config.json")

# Создание директорий, если они не существуют
os.makedirs(DATA_DIR, exist_ok=True)
os.makedirs(os.path.join(DATA_DIR, "knowledge_base"), exist_ok=True)
os.makedirs(os.path.join(DATA_DIR, "cache"), exist_ok=True)
os.makedirs(PROMPTS_DIR, exist_ok=True)
os.makedirs(INDICES_DIR, exist_ok=True)
os.makedirs(os.path.dirname(CONFIG_FILE), exist_ok=True)

def get_api_key():
    """
    Получает API ключ OpenAI от пользователя
    
    Returns:
        str: API ключ
    """
    api_key = getpass.getpass("Введите ваш API ключ OpenAI: ")
    return api_key

class ConfigManager:
    """Класс для управления настройками консультанта"""
    
    def __init__(self):
        """Инициализация менеджера конфигурации"""
        self.config = {
            "api": {
                "openai_api_key": None
            },
            "settings": {
                "chunk_size": 1024,
                "chunk_overlap": 200,
                "temperature": 0.7,
                "max_tokens": 2000,
                "cache_size": 100,
                "use_hybrid_search": True,
                "hybrid_weight": 0.5
            }
        }
        
        # Загружаем конфигурацию, если она существует
        self.load_config()
        
    def load_config(self):
        """Загружает конфигурацию из файла"""
        if os.path.exists(CONFIG_FILE):
            try:
                with open(CONFIG_FILE, 'r', encoding='utf-8') as f:
                    loaded_config = json.load(f)
                    
                    # Обновляем конфигурацию
                    for section in loaded_config:
                        if section in self.config:
                            for key, value in loaded_config[section].items():
                                self.config[section][key] = value
            except Exception as e:
                print(f"Ошибка при загрузке конфигурации: {str(e)}")
    
    def save_config(self):
        """Сохраняет текущую конфигурацию в файл"""
        try:
            with open(CONFIG_FILE, 'w', encoding='utf-8') as f:
                json.dump(self.config, f, ensure_ascii=False, indent=4)
        except Exception as e:
            print(f"Ошибка при сохранении конфигурации: {str(e)}")
    
    def get_setting(self, section, key, default=None):
        """
        Получает значение настройки
        
        Args:
            section (str): Раздел настроек
            key (str): Ключ настройки
            default: Значение по умолчанию, если настройка не найдена
            
        Returns:
            Значение настройки или значение по умолчанию
        """
        if section in self.config and key in self.config[section]:
            return self.config[section][key]
        return default
        
    def set_setting(self, section, key, value):
        """
        Устанавливает значение настройки
        
        Args:
            section (str): Раздел настроек
            key (str): Ключ настройки
            value: Новое значение
            
        Returns:
            bool: Успешность операции
        """
        if section not in self.config:
            self.config[section] = {}
        
        self.config[section][key] = value
        self.save_config()
        return True
