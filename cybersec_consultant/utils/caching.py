# -*- coding: utf-8 -*-
"""
Утилиты для кэширования данных
"""

import os
import json
import hashlib
import time
from datetime import datetime, timedelta

from cybersec_consultant.config import CACHE_DIR

class CacheManager:
    """Класс для управления кэшем"""

    def __init__(self, cache_dir=None, max_size=1000, ttl=24*60*60):
        """
        Инициализация менеджера кэша

        Args:
            cache_dir (str): Директория для хранения кэша
            max_size (int): Максимальное количество элементов в кэше
            ttl (int): Время жизни кэша в секундах (по умолчанию 24 часа)
        """
        self.cache_dir = cache_dir or os.path.join(CACHE_DIR, "general")
        self.max_size = max_size
        self.ttl = ttl
        
        # Создаем директорию для кэша, если она не существует
        os.makedirs(self.cache_dir, exist_ok=True)
        
        # Путь к файлу кэша
        self.cache_file = os.path.join(self.cache_dir, "cache.json")
        
        # Загружаем кэш
        self.cache = self._load_cache()
    
    def _load_cache(self):
        """
        Загружает кэш из файла

        Returns:
            dict: Загруженный кэш или пустой словарь
        """
        if os.path.exists(self.cache_file):
            try:
                with open(self.cache_file, 'r', encoding='utf-8') as f:
                    cache = json.load(f)
                
                # Очищаем старые записи
                current_time = time.time()
                cache = {k: v for k, v in cache.items() 
                         if 'timestamp' not in v or current_time - v['timestamp'] < self.ttl}
                
                return cache
            except Exception as e:
                print(f"Ошибка при загрузке кэша: {str(e)}")
        
        return {}
    
    def _save_cache(self):
        """Сохраняет кэш в файл"""
        try:
            with open(self.cache_file, 'w', encoding='utf-8') as f:
                json.dump(self.cache, f, ensure_ascii=False, indent=2)
            return True
        except Exception as e:
            print(f"Ошибка при сохранении кэша: {str(e)}")
            return False
    
    def _clean_cache_if_needed(self):
        """Очищает кэш, если он превышает максимальный размер"""
        if len(self.cache) > self.max_size:
            # Сортируем по времени последнего использования и удаляем самые старые
            sorted_items = sorted(self.cache.items(), 
                                 key=lambda x: x[1].get('last_accessed', 0))
            
            # Удаляем старые записи, оставляя 80% от максимального размера
            items_to_keep = int(self.max_size * 0.8)
            self.cache = dict(sorted_items[-items_to_keep:])
            
            # Сохраняем обновленный кэш
            self._save_cache()
    
    def get(self, key, default=None):
        """
        Получает значение из кэша по ключу

        Args:
            key (str): Ключ
            default (any): Значение по умолчанию

        Returns:
            any: Значение из кэша или default
        """
        if key in self.cache:
            item = self.cache[key]
            
            # Проверяем срок действия
            if 'timestamp' in item and time.time() - item['timestamp'] > self.ttl:
                # Запись устарела
                del self.cache[key]
                self._save_cache()
                return default
            
            # Обновляем время последнего доступа
            item['last_accessed'] = time.time()
            self.cache[key] = item
            
            return item.get('value', default)
        
        return default
    
    def set(self, key, value, metadata=None):
        """
        Устанавливает значение в кэш

        Args:
            key (str): Ключ
            value (any): Значение
            metadata (dict): Дополнительные метаданные

        Returns:
            bool: True если операция успешна, иначе False
        """
        try:
            # Очищаем кэш, если он слишком большой
            self._clean_cache_if_needed()
            
            # Создаем запись в кэше
            cache_item = {
                'value': value,
                'timestamp': time.time(),
                'last_accessed': time.time()
            }
            
            # Добавляем метаданные, если они есть
            if metadata:
                cache_item.update(metadata)
            
            self.cache[key] = cache_item
            
            # Сохраняем кэш
            self._save_cache()
            
            return True
        except Exception as e:
            print(f"Ошибка при сохранении в кэш: {str(e)}")
            return False
    
    def delete(self, key):
        """
        Удаляет значение из кэша по ключу

        Args:
            key (str): Ключ

        Returns:
            bool: True если ключ найден и удален, иначе False
        """
        if key in self.cache:
            del self.cache[key]
            self._save_cache()
            return True
        
        return False
    
    def clear(self):
        """
        Очищает весь кэш

        Returns:
            bool: True если операция успешна, иначе False
        """
        try:
            self.cache = {}
            self._save_cache()
            return True
        except Exception as e:
            print(f"Ошибка при очистке кэша: {str(e)}")
            return False
    
    def get_stats(self):
        """
        Возвращает статистику кэша

        Returns:
            dict: Статистика кэша
        """
        current_time = time.time()
        active_items = {k: v for k, v in self.cache.items() 
                       if 'timestamp' not in v or current_time - v['timestamp'] < self.ttl}
        
        # Группируем по возрасту
        age_groups = {
            "0-1 часа": 0,
            "1-6 часов": 0,
            "6-24 часа": 0,
            "> 24 часа": 0
        }
        
        for item in active_items.values():
            if 'timestamp' in item:
                age = current_time - item['timestamp']
                if age < 3600:  # 1 час
                    age_groups["0-1 часа"] += 1
                elif age < 21600:  # 6 часов
                    age_groups["1-6 часов"] += 1
                elif age < 86400:  # 24 часа
                    age_groups["6-24 часа"] += 1
                else:
                    age_groups["> 24 часа"] += 1
        
        # Оцениваем размер кэша
        cache_size = len(json.dumps(self.cache))
        
        return {
            "total_items": len(self.cache),
            "active_items": len(active_items),
            "expired_items": len(self.cache) - len(active_items),
            "age_groups": age_groups,
            "estimated_size_bytes": cache_size,
            "last_update": datetime.now().isoformat()
        }

# Вспомогательная функция для создания хэш-ключа
def generate_cache_key(content, prefix=None):
    """
    Генерирует ключ кэша на основе содержимого

    Args:
        content (str): Содержимое для хэширования
        prefix (str): Префикс для ключа

    Returns:
        str: Ключ кэша
    """
    if isinstance(content, dict) or isinstance(content, list):
        content = json.dumps(content, sort_keys=True)
    
    content_hash = hashlib.md5(content.encode()).hexdigest()
    return f"{prefix}_{content_hash}" if prefix else content_hash
