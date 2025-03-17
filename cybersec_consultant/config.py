# -*- coding: utf-8 -*-
"""
Модуль конфигурации для консультанта по кибербезопасности
"""

import os
import json
from datetime import datetime

# Базовые директории
BASE_DIR = os.path.dirname(os.path.abspath(__file__))
PROJECT_ROOT = os.path.dirname(BASE_DIR)
DATA_DIR = os.path.join(PROJECT_ROOT, "data")
INDICES_DIR = os.path.join(PROJECT_ROOT, "indices")
CACHE_DIR = os.path.join(PROJECT_ROOT, "cache")
RESPONSES_DIR = os.path.join(PROJECT_ROOT, "responses")
DIALOGS_DIR = os.path.join(PROJECT_ROOT, "dialogs")
STATS_DIR = os.path.join(PROJECT_ROOT, "stats")
PROMPTS_DIR = os.path.join(PROJECT_ROOT, "prompts")

# Создаем все необходимые директории
for directory in [DATA_DIR, INDICES_DIR, CACHE_DIR, RESPONSES_DIR, DIALOGS_DIR, STATS_DIR, PROMPTS_DIR]:
    os.makedirs(directory, exist_ok=True)

# Настройки моделей
AVAILABLE_MODELS = {
    "gpt-4o-mini": {"name": "GPT-4o Mini", "description": "Быстрая модель с хорошим балансом скорости и качества", "default_temperature": 0},
    "gpt-4": {"name": "GPT-4", "description": "Мощная модель для сложных вопросов", "default_temperature": 0},
    "gpt-3.5-turbo": {"name": "GPT-3.5 Turbo", "description": "Экономичная модель для простых запросов", "default_temperature": 0},
    "gpt-4o": {"name": "GPT-4o", "description": "Универсальная модель с широким контекстом", "default_temperature": 0}
}

# Настройки по умолчанию
DEFAULT_MODEL = "gpt-4o-mini"
DEFAULT_TEMPERATURE = 0.0
DEFAULT_MAX_TOKENS = 4000
DEFAULT_CHUNK_SIZE = 1024
DEFAULT_CHUNK_OVERLAP = 200
DEFAULT_SEARCH_K = 3

class ConfigManager:
    """Класс для управления конфигурацией приложения"""

    def __init__(self, config_file=None):
        """Инициализация менеджера конфигурации"""
        if config_file is None:
            self.config_file = os.path.join(PROJECT_ROOT, "config", "settings.json")
        else:
            self.config_file = config_file

        self.config = self.load_config()

    def load_config(self):
        """Загружает конфигурацию из JSON файла"""
        try:
            if os.path.exists(self.config_file):
                with open(self.config_file, "r", encoding="utf-8") as f:
                    return json.load(f)
            else:
                # Создаем конфигурацию по умолчанию
                default_config = {
                    "models": {
                        "default": DEFAULT_MODEL,
                        "available": [
                            {"id": model_id, "name": info["name"], "description": info["description"]}
                            for model_id, info in AVAILABLE_MODELS.items()
                        ]
                    },
                    "settings": {
                        "temperature": DEFAULT_TEMPERATURE,
                        "max_tokens": DEFAULT_MAX_TOKENS,
                        "chunk_size": DEFAULT_CHUNK_SIZE,
                        "chunk_overlap": DEFAULT_CHUNK_OVERLAP,
                        "search_k": DEFAULT_SEARCH_K
                    }
                }

                # Создаем директорию, если она не существует
                os.makedirs(os.path.dirname(self.config_file), exist_ok=True)

                # Сохраняем дефолтную конфигурацию
                with open(self.config_file, "w", encoding="utf-8") as f:
                    json.dump(default_config, f, ensure_ascii=False, indent=2)

                return default_config
        except Exception as e:
            print(f"Ошибка при загрузке конфигурации: {str(e)}")
            return {
                "models": {"default": DEFAULT_MODEL},
                "settings": {
                    "temperature": DEFAULT_TEMPERATURE,
                    "max_tokens": DEFAULT_MAX_TOKENS,
                    "chunk_size": DEFAULT_CHUNK_SIZE,
                    "chunk_overlap": DEFAULT_CHUNK_OVERLAP,
                    "search_k": DEFAULT_SEARCH_K
                }
            }

    def save_config(self):
        """Сохраняет конфигурацию в JSON файл"""
        try:
            # Создаем директорию, если она не существует
            os.makedirs(os.path.dirname(self.config_file), exist_ok=True)

            with open(self.config_file, "w", encoding="utf-8") as f:
                json.dump(self.config, f, ensure_ascii=False, indent=2)
            return True
        except Exception as e:
            print(f"Ошибка при сохранении конфигурации: {str(e)}")
            return False

    def get_setting(self, section, key, default=None):
        """Получает значение настройки"""
        try:
            return self.config[section][key]
        except KeyError:
            return default

    def update_setting(self, section, key, value):
        """Обновляет значение настройки"""
        if section not in self.config:
            self.config[section] = {}

        self.config[section][key] = value
        self.save_config()
        return True

# Функция для получения и установки API ключа
def get_api_key():
    """Получает API ключ OpenAI"""
    api_key = os.getenv('OPENAI_API_KEY')
    if not api_key:
        api_key = input("Введите ваш API ключ OpenAI: ")
        os.environ['OPENAI_API_KEY'] = api_key
    return api_key
