# -*- coding: utf-8 -*-
"""
Модуль для эффективного управления кэшированием в консультанте по кибербезопасности.
Реализует структуры данных и алгоритмы для оптимизации кэширования.
"""

import time
import json
import hashlib
import os
from typing import Dict, Any, Optional, List, Tuple, Callable, TypeVar, Union
from collections import OrderedDict
from functools import wraps
import threading

# Импортируем логгер из модуля обработки ошибок
from cybersec_consultant.error_handling import logger

# Типовая переменная для аннотаций
T = TypeVar('T')
KT = TypeVar('KT')  # Тип ключа
VT = TypeVar('VT')  # Тип значения


class LRUCache(OrderedDict):
    """
    LRU (Least Recently Used) кэш на основе OrderedDict.
    Автоматически удаляет наименее недавно использованные элементы
    при достижении максимального размера.
    """
    
    def __init__(self, maxsize: int = 128, *args, **kwargs):
        """
        Инициализация LRU кэша.
        
        Args:
            maxsize: Максимальный размер кэша
            *args, **kwargs: Аргументы для передачи OrderedDict
        """
        self.maxsize = maxsize
        super().__init__(*args, **kwargs)
        
        # Добавляем блокировку для потокобезопасности
        self._lock = threading.RLock()
    
    def __getitem__(self, key):
        """
        Получение элемента из кэша с обновлением его позиции.
        
        Args:
            key: Ключ для поиска
            
        Returns:
            Значение из кэша
        """
        with self._lock:
            value = super().__getitem__(key)
            self.move_to_end(key)
            return value
    
    def __setitem__(self, key, value):
        """
        Добавление элемента в кэш с проверкой максимального размера.
        
        Args:
            key: Ключ
            value: Значение
        """
        with self._lock:
            if key in self:
                self.move_to_end(key)
            super().__setitem__(key, value)
            if len(self) > self.maxsize:
                oldest = next(iter(self))
                del self[oldest]
    
    def get(self, key, default=None):
        """
        Получение элемента с обновлением его позиции или возвратом значения по умолчанию.
        
        Args:
            key: Ключ для поиска
            default: Значение по умолчанию
            
        Returns:
            Значение из кэша или default
        """
        with self._lock:
            if key in self:
                return self[key]
            return default


class TimedCache(LRUCache):
    """
    Расширение LRU кэша с поддержкой временного TTL (Time-To-Live).
    Элементы автоматически устаревают после определенного времени.
    """
    
    def __init__(self, maxsize: int = 128, ttl: int = 3600, *args, **kwargs):
        """
        Инициализация кэша с временем жизни.
        
        Args:
            maxsize: Максимальный размер кэша
            ttl: Время жизни элементов (в секундах)
            *args, **kwargs: Аргументы для передачи LRUCache
        """
        super().__init__(maxsize, *args, **kwargs)
        self.ttl = ttl
        # Словарь для хранения времени создания элементов
        self._timestamps = {}
    
    def __getitem__(self, key):
        """
        Получение элемента с проверкой его срока действия.
        
        Args:
            key: Ключ для поиска
            
        Returns:
            Значение из кэша
        
        Raises:
            KeyError: Если элемент истек или не найден
        """
        with self._lock:
            # Проверяем истек ли срок
            current_time = time.time()
            timestamp = self._timestamps.get(key, 0)
            
            if current_time - timestamp > self.ttl:
                # Удаляем устаревший элемент
                del self[key]
                del self._timestamps[key]
                raise KeyError(key)
            
            # Возвращаем значение
            return super().__getitem__(key)
    
    def __setitem__(self, key, value):
        """
        Добавление элемента с указанием времени создания.
        
        Args:
            key: Ключ
            value: Значение
        """
        with self._lock:
            super().__setitem__(key, value)
            self._timestamps[key] = time.time()
    
    def __delitem__(self, key):
        """
        Удаление элемента и его временной метки.
        
        Args:
            key: Ключ для удаления
        """
        with self._lock:
            super().__delitem__(key)
            if key in self._timestamps:
                del self._timestamps[key]
    
    def get(self, key, default=None):
        """
        Получение элемента с проверкой его срока действия.
        
        Args:
            key: Ключ для поиска
            default: Значение по умолчанию
            
        Returns:
            Значение из кэша или default
        """
        with self._lock:
            try:
                return self[key]
            except KeyError:
                return default
    
    def clear_expired(self):
        """Очистка истекших элементов из кэша"""
        with self._lock:
            current_time = time.time()
            expired_keys = [
                key for key, timestamp in self._timestamps.items()
                if current_time - timestamp > self.ttl
            ]
            
            for key in expired_keys:
                if key in self:
                    del self[key]
                del self._timestamps[key]
            
            return len(expired_keys)


class CacheManager:
    """
    Менеджер кэшей для различных типов данных консультанта.
    Предоставляет единый интерфейс для работы с разными кэшами.
    """
    
    def __init__(self):
        """Инициализация менеджера кэшей"""
        # Кэш для ответов LLM
        self.response_cache = TimedCache(maxsize=200, ttl=86400)  # 24 часа
        
        # Кэш для векторных эмбеддингов (долгоживущий)
        self.embedding_cache = TimedCache(maxsize=1000, ttl=604800)  # 7 дней
        
        # Кэш для результатов поиска по базе знаний
        self.search_cache = TimedCache(maxsize=200, ttl=3600)  # 1 час
        
        # Флаг использования кэша
        self.use_cache = True
        
        # Путь для персистентного хранения
        self.cache_dir = os.path.join(os.path.expanduser("~"), ".cybersec_consultant_cache")
        os.makedirs(self.cache_dir, exist_ok=True)
    
    def clear_all_caches(self):
        """Очистка всех кэшей"""
        self.response_cache.clear()
        self.embedding_cache.clear()
        self.search_cache.clear()
    
    def clear_expired(self):
        """Очистка истекших элементов во всех кэшах"""
        total_cleared = 0
        total_cleared += self.response_cache.clear_expired()
        total_cleared += self.embedding_cache.clear_expired()
        total_cleared += self.search_cache.clear_expired()
        return total_cleared
    
    def get_cache_stats(self) -> Dict[str, Dict[str, int]]:
        """
        Получение статистики по всем кэшам.
        
        Returns:
            Словарь со статистикой кэшей
        """
        return {
            "response_cache": {
                "size": len(self.response_cache),
                "maxsize": self.response_cache.maxsize
            },
            "embedding_cache": {
                "size": len(self.embedding_cache),
                "maxsize": self.embedding_cache.maxsize
            },
            "search_cache": {
                "size": len(self.search_cache),
                "maxsize": self.search_cache.maxsize
            }
        }
    
    def save_to_disk(self, cache_name: str = "all"):
        """
        Сохранение кэша на диск для персистентности.
        
        Args:
            cache_name: Имя кэша для сохранения ("response", "embedding", "search" или "all")
        """
        try:
            if cache_name in ["response", "all"]:
                self._save_cache(self.response_cache, "response_cache.json")
            
            if cache_name in ["embedding", "all"]:
                self._save_cache(self.embedding_cache, "embedding_cache.json")
            
            if cache_name in ["search", "all"]:
                self._save_cache(self.search_cache, "search_cache.json")
                
            logger.info(f"Cache '{cache_name}' successfully saved to disk")
        except Exception as e:
            logger.error(f"Error saving cache to disk: {str(e)}")
    
    def load_from_disk(self, cache_name: str = "all"):
        """
        Загрузка кэша с диска.
        
        Args:
            cache_name: Имя кэша для загрузки ("response", "embedding", "search" или "all")
        """
        try:
            if cache_name in ["response", "all"]:
                self._load_cache(self.response_cache, "response_cache.json")
            
            if cache_name in ["embedding", "all"]:
                self._load_cache(self.embedding_cache, "embedding_cache.json")
            
            if cache_name in ["search", "all"]:
                self._load_cache(self.search_cache, "search_cache.json")
                
            logger.info(f"Cache '{cache_name}' successfully loaded from disk")
        except Exception as e:
            logger.error(f"Error loading cache from disk: {str(e)}")
    
    def _save_cache(self, cache: TimedCache, filename: str):
        """
        Сохранение конкретного кэша в файл.
        
        Args:
            cache: Кэш для сохранения
            filename: Имя файла
        """
        cache_file = os.path.join(self.cache_dir, filename)
        
        # Преобразуем кэш и метки времени в сериализуемый формат
        cache_data = {
            "items": dict(cache),
            "timestamps": cache._timestamps.copy()
        }
        
        with open(cache_file, 'w', encoding='utf-8') as f:
            json.dump(cache_data, f, ensure_ascii=False, indent=2)
    
    def _load_cache(self, cache: TimedCache, filename: str):
        """
        Загрузка конкретного кэша из файла.
        
        Args:
            cache: Кэш для заполнения
            filename: Имя файла
        """
        cache_file = os.path.join(self.cache_dir, filename)
        
        if not os.path.exists(cache_file):
            logger.warning(f"Cache file {filename} not found")
            return
        
        with open(cache_file, 'r', encoding='utf-8') as f:
            cache_data = json.load(f)
        
        # Очищаем текущий кэш
        cache.clear()
        
        # Загружаем элементы и метки времени
        items = cache_data.get("items", {})
        timestamps = cache_data.get("timestamps", {})
        
        # Фильтруем истекшие элементы при загрузке
        current_time = time.time()
        for key, value in items.items():
            timestamp = float(timestamps.get(key, 0))
            if current_time - timestamp <= cache.ttl:
                cache[key] = value
                cache._timestamps[key] = timestamp


# Создаем глобальный экземпляр для использования в других модулях
cache_manager = CacheManager()


def cached(cache_type: str = "response", key_func: Optional[Callable] = None):
    """
    Декоратор для кэширования результатов функций.
    
    Args:
        cache_type: Тип кэша ("response", "embedding", "search")
        key_func: Функция для генерации ключа кэша (если None, используется хеш аргументов)
    """
    def decorator(func: Callable[..., T]) -> Callable[..., T]:
        @wraps(func)
        def wrapper(*args, **kwargs):
            if not cache_manager.use_cache:
                return func(*args, **kwargs)
            
            # Выбираем кэш в зависимости от типа
            if cache_type == "response":
                cache = cache_manager.response_cache
            elif cache_type == "embedding":
                cache = cache_manager.embedding_cache
            elif cache_type == "search":
                cache = cache_manager.search_cache
            else:
                raise ValueError(f"Unknown cache type: {cache_type}")
            
            # Генерируем ключ кэша
            if key_func is not None:
                cache_key = key_func(*args, **kwargs)
            else:
                # Создаем ключ на основе аргументов
                key_parts = [func.__name__]
                key_parts.extend([str(arg) for arg in args])
                key_parts.extend([f"{k}={v}" for k, v in sorted(kwargs.items())])
                cache_key = hashlib.md5("_".join(key_parts).encode()).hexdigest()
            
            # Проверяем наличие в кэше
            cached_result = cache.get(cache_key)
            if cached_result is not None:
                return cached_result
            
            # Вычисляем результат и сохраняем в кэш
            result = func(*args, **kwargs)
            cache[cache_key] = result
            return result
        
        return wrapper
    
    return decorator
