# -*- coding: utf-8 -*-
"""
Модуль для централизованного управления состоянием консультанта по кибербезопасности.
Заменяет глобальные переменные структурированным хранилищем состояния.
"""

import os
import time
import json
import hashlib
from datetime import datetime
from typing import Dict, List, Any, Set, Optional

class ConsultantState:
    """
    Класс для управления состоянием консультанта.
    Используется для хранения всех переменных состояния в одном месте,
    избегая глобальных переменных и улучшая тестируемость и поддерживаемость.
    """
    
    _instance = None  # Singleton-экземпляр
    
    def __new__(cls):
        """Реализация паттерна Singleton"""
        if cls._instance is None:
            cls._instance = super(ConsultantState, cls).__new__(cls)
            cls._instance._initialized = False
        return cls._instance
    
    def __init__(self):
        """Инициализация состояния консультанта"""
        # Избегаем повторной инициализации для Singleton
        if getattr(self, '_initialized', False):
            return
            
        # Основные настройки
        self.api_key = None  # API ключ OpenAI
        self.model_name = "gpt-4o-mini"  # Модель LLM по умолчанию
        self.embedding_model = "text-embedding-3-small"  # Модель эмбеддингов
        self.temperature = 0.2  # Температура генерации
        
        # Настройки базы знаний
        self.knowledge_base_path = None  # Путь к файлу с базой знаний
        self.knowledge_base_text = None  # Текст базы знаний
        self.document_chunks = []  # Чанки документов
        
        # Настройки индексирования и поиска
        self.chunk_size = 1024  # Размер чанка для разбиения текста
        self.chunk_overlap = 200  # Перекрытие чанков
        self.vector_db = None  # Векторная база данных
        
        # Настройки профилей
        self.profile = "standard"  # Текущий выбранный профиль
        self.k_docs = 3  # Количество документов для поиска
        
        # Кэширование и производительность
        self.use_cache = True  # Флаг использования кэша
        self.response_cache = {}  # Кэш ответов LLM
        self.search_cache = {}  # Кэш результатов поиска
        
        # Метрики и статистика
        self.session_stats = {
            "start_time": datetime.now().isoformat(),
            "queries": [],
            "models_used": set(),
            "profiles_used": set(),
            "total_tokens": 0,
            "total_cost": 0,
            "total_time": 0
        }
        
        # Идентификаторы сессии
        self.session_id = datetime.now().strftime("%Y%m%d_%H%M%S")
        self.session_dir = None  # Директория для сохранения диалогов
        self.stats_file = None  # Файл для сохранения статистики
        
        # Состояние инициализации
        self.is_initialized = False  # Флаг инициализации
        self.verbose_mode = False  # Режим подробного вывода
        
        # Помечаем как инициализированный
        self._initialized = True
    
    def reset(self):
        """Сбрасывает состояние до значений по умолчанию"""
        self._initialized = False
        self.__init__()
    
    def update_session_stats(self, query: str, response_data: Dict[str, Any]):
        """
        Обновляет статистику сессии

        Args:
            query (str): Запрос пользователя
            response_data (dict): Данные ответа
        """
        model = response_data.get("model", self.model_name)
        profile = response_data.get("profile", self.profile)
        tokens = response_data.get("tokens", 0)
        cost = response_data.get("cost", 0)
        execution_time = response_data.get("total_time", 0)
        is_cached = response_data.get("cached", False)
        
        # Добавляем информацию о запросе
        self.session_stats["queries"].append({
            "query": query,
            "model": model,
            "profile": profile,
            "time": execution_time,
            "tokens": tokens,
            "cost": cost,
            "cached": is_cached
        })
        
        # Обновляем общую статистику
        self.session_stats["models_used"].add(model)
        self.session_stats["profiles_used"].add(profile)
        self.session_stats["total_tokens"] += 0 if is_cached else tokens
        self.session_stats["total_cost"] += 0 if is_cached else cost
        self.session_stats["total_time"] += execution_time
    
    def get_response_from_cache(self, system_prompt: str, user_prompt: str, model: str, temperature: float) -> Optional[Dict[str, Any]]:
        """
        Получает ответ из кэша, если он существует

        Args:
            system_prompt (str): Системный промпт
            user_prompt (str): Запрос пользователя
            model (str): Название модели
            temperature (float): Температура генерации

        Returns:
            dict or None: Данные кэшированного ответа или None
        """
        if not self.use_cache:
            return None
            
        # Создаем ключ кэша
        cache_key = hashlib.md5(f"{system_prompt}_{user_prompt}_{model}_{temperature}".encode()).hexdigest()
        
        # Проверяем наличие в кэше
        if cache_key in self.response_cache:
            cached_response = self.response_cache[cache_key].copy()
            cached_response["cached"] = True
            return cached_response
            
        return None
    
    def add_response_to_cache(self, system_prompt: str, user_prompt: str, model: str, temperature: float, response_data: Dict[str, Any]):
        """
        Добавляет ответ в кэш

        Args:
            system_prompt (str): Системный промпт
            user_prompt (str): Запрос пользователя
            model (str): Название модели
            temperature (float): Температура генерации
            response_data (dict): Данные ответа
        """
        # Создаем ключ кэша
        cache_key = hashlib.md5(f"{system_prompt}_{user_prompt}_{model}_{temperature}".encode()).hexdigest()
        
        # Сохраняем в кэш
        self.response_cache[cache_key] = response_data.copy()
    
    def get_search_from_cache(self, query: str, k: int) -> Optional[List[Any]]:
        """
        Получает результаты поиска из кэша, если они существуют

        Args:
            query (str): Поисковый запрос
            k (int): Количество результатов

        Returns:
            list or None: Кэшированные результаты поиска или None
        """
        if not self.use_cache:
            return None
            
        # Создаем ключ кэша
        cache_key = f"{query}_{k}"
        
        # Проверяем наличие в кэше
        if cache_key in self.search_cache:
            return self.search_cache[cache_key]
            
        return None
    
    def add_search_to_cache(self, query: str, k: int, results: List[Any]):
        """
        Добавляет результаты поиска в кэш

        Args:
            query (str): Поисковый запрос
            k (int): Количество результатов
            results (list): Результаты поиска
        """
        # Создаем ключ кэша
        cache_key = f"{query}_{k}"
        
        # Сохраняем в кэш
        self.search_cache[cache_key] = results

# Глобальная точка доступа к состоянию (Singleton)
STATE = ConsultantState()
