# -*- coding: utf-8 -*-
"""
Модуль для оптимизации использования памяти в консультанте по кибербезопасности.
Реализует потоковую обработку для снижения использования памяти при работе с большими базами знаний.
"""

import os
import gc
import psutil
import threading
import time
from typing import List, Dict, Any, Callable, Generator, Optional, Iterator, Union, TypeVar
from contextlib import contextmanager

# Импортируем логгер из модуля обработки ошибок
from cybersec_consultant.error_handling import logger

# Типовая переменная для аннотаций
T = TypeVar('T')


class MemoryMonitor:
    """
    Класс для мониторинга и отслеживания использования памяти.
    Позволяет контролировать потребление памяти и получать уведомления при превышении порогов.
    """
    
    def __init__(self, threshold_percentage: float = 80.0, check_interval: float = 5.0):
        """
        Инициализация монитора памяти.
        
        Args:
            threshold_percentage: Пороговый процент использования памяти для уведомлений
            check_interval: Интервал проверки использования памяти в секундах
        """
        self.threshold_percentage = threshold_percentage
        self.check_interval = check_interval
        self._monitor_thread = None
        self._stop_event = threading.Event()
        self._process = psutil.Process(os.getpid())
        self._peak_memory = 0
        self._callbacks = []
    
    def start_monitoring(self):
        """Запускает фоновый мониторинг использования памяти"""
        if self._monitor_thread is not None and self._monitor_thread.is_alive():
            logger.warning("Memory monitoring is already running")
            return
        
        self._stop_event.clear()
        self._monitor_thread = threading.Thread(
            target=self._monitor_memory,
            daemon=True,
            name="MemoryMonitorThread"
        )
        self._monitor_thread.start()
        logger.info("Memory monitoring started")
    
    def stop_monitoring(self):
        """Останавливает фоновый мониторинг использования памяти"""
        if self._monitor_thread is None or not self._monitor_thread.is_alive():
            logger.warning("Memory monitoring is not running")
            return
        
        self._stop_event.set()
        self._monitor_thread.join(timeout=2.0)
        logger.info("Memory monitoring stopped")
    
    def register_callback(self, callback: Callable[[float, float], None]):
        """
        Регистрирует функцию обратного вызова для уведомлений о памяти.
        
        Args:
            callback: Функция, принимающая два аргумента: текущий и пороговый процент памяти
        """
        self._callbacks.append(callback)
    
    def _monitor_memory(self):
        """Фоновая функция для мониторинга использования памяти"""
        while not self._stop_event.is_set():
            try:
                # Получаем текущее использование памяти
                memory_info = self._process.memory_info()
                memory_percent = self._process.memory_percent()
                
                # Обновляем пиковое использование памяти
                memory_usage_mb = memory_info.rss / (1024 * 1024)
                if memory_usage_mb > self._peak_memory:
                    self._peak_memory = memory_usage_mb
                
                # Проверяем превышение порога
                if memory_percent > self.threshold_percentage:
                    logger.warning(
                        f"Memory usage exceeds threshold: {memory_percent:.1f}% "
                        f"(threshold: {self.threshold_percentage:.1f}%)"
                    )
                    
                    # Вызываем все зарегистрированные обратные вызовы
                    for callback in self._callbacks:
                        try:
                            callback(memory_percent, self.threshold_percentage)
                        except Exception as e:
                            logger.error(f"Error in memory callback: {str(e)}")
            
            except Exception as e:
                logger.error(f"Error monitoring memory: {str(e)}")
            
            # Ждем до следующей проверки
            self._stop_event.wait(self.check_interval)
    
    def get_memory_usage(self) -> Dict[str, float]:
        """
        Получает текущее использование памяти.
        
        Returns:
            Словарь с информацией об использовании памяти
        """
        memory_info = self._process.memory_info()
        return {
            "current_mb": memory_info.rss / (1024 * 1024),
            "peak_mb": self._peak_memory,
            "percent": self._process.memory_percent(),
            "virtual_mb": memory_info.vms / (1024 * 1024)
        }
    
    @contextmanager
    def measure_memory_usage(self, operation_name: str = "Operation"):
        """
        Контекстный менеджер для измерения использования памяти операцией.
        
        Args:
            operation_name: Название операции для логирования
        """
        gc.collect()  # Принудительный сбор мусора перед измерением
        start_time = time.time()
        start_memory = self._process.memory_info().rss / (1024 * 1024)
        
        try:
            yield
        finally:
            gc.collect()  # Принудительный сбор мусора после операции
            end_time = time.time()
            end_memory = self._process.memory_info().rss / (1024 * 1024)
            
            memory_diff = end_memory - start_memory
            time_diff = end_time - start_time
            
            logger.info(
                f"{operation_name} completed in {time_diff:.2f} seconds. "
                f"Memory change: {memory_diff:.2f} MB (from {start_memory:.2f} MB to {end_memory:.2f} MB)"
            )


class StreamingDataProcessor:
    """
    Класс для потоковой обработки данных для экономии памяти.
    Позволяет обрабатывать большие объемы данных без загрузки всех данных в память одновременно.
    """
    
    @staticmethod
    def stream_file_lines(file_path: str, chunk_size: int = 1000) -> Generator[List[str], None, None]:
        """
        Потоковое чтение строк из файла чанками.
        
        Args:
            file_path: Путь к файлу
            chunk_size: Размер чанка в строках
            
        Yields:
            Список строк из файла
        """
        with open(file_path, 'r', encoding='utf-8') as file:
            lines_buffer = []
            
            for line in file:
                lines_buffer.append(line.rstrip('\n'))
                
                if len(lines_buffer) >= chunk_size:
                    yield lines_buffer
                    lines_buffer = []
            
            # Yield remaining lines
            if lines_buffer:
                yield lines_buffer
    
    @staticmethod
    def stream_process_items(items: List[T], 
                           processor_func: Callable[[T], Any], 
                           chunk_size: int = 100,
                           show_progress: bool = True) -> Generator[List[Any], None, None]:
        """
        Потоковая обработка элементов чанками.
        
        Args:
            items: Список элементов для обработки
            processor_func: Функция для обработки одного элемента
            chunk_size: Размер чанка
            show_progress: Показывать ли прогресс обработки
            
        Yields:
            Список результатов обработки чанка
        """
        total_items = len(items)
        processed_items = 0
        
        if show_progress and total_items > 0:
            logger.info(f"Starting processing of {total_items} items in chunks of {chunk_size}")
        
        for i in range(0, total_items, chunk_size):
            chunk = items[i:i+chunk_size]
            results = []
            
            for item in chunk:
                try:
                    result = processor_func(item)
                    results.append(result)
                except Exception as e:
                    logger.error(f"Error processing item: {str(e)}")
                    results.append(None)
            
            processed_items += len(chunk)
            
            if show_progress and total_items > 0:
                progress = (processed_items / total_items) * 100
                logger.info(f"Processed {processed_items}/{total_items} items ({progress:.1f}%)")
            
            yield results
            
            # Подсказка сборщику мусора
            gc.collect()
    
    @staticmethod
    def process_generator(generator: Iterator[T], 
                        processor_func: Callable[[T], Any],
                        buffer_size: int = 100) -> Generator[Any, None, None]:
        """
        Обработка элементов из генератора с буферизацией.
        
        Args:
            generator: Источник данных
            processor_func: Функция для обработки одного элемента
            buffer_size: Размер буфера
            
        Yields:
            Результаты обработки элементов
        """
        buffer = []
        
        # Обработка элементов из генератора
        for item in generator:
            buffer.append(item)
            
            if len(buffer) >= buffer_size:
                # Обработка буфера
                for buffered_item in buffer:
                    try:
                        result = processor_func(buffered_item)
                        yield result
                    except Exception as e:
                        logger.error(f"Error processing buffered item: {str(e)}")
                        yield None
                
                # Очистка буфера
                buffer = []
                gc.collect()
        
        # Обработка оставшихся элементов в буфере
        for buffered_item in buffer:
            try:
                result = processor_func(buffered_item)
                yield result
            except Exception as e:
                logger.error(f"Error processing remaining buffered item: {str(e)}")
                yield None


def optimize_memory_usage():
    """
    Оптимизирует использование памяти, выполняя сборку мусора и другие оптимизации.
    """
    # Выполняем полную сборку мусора
    collected = gc.collect()
    logger.debug(f"Garbage collector: collected {collected} objects")
    
    # Пытаемся уменьшить использование памяти процессом
    try:
        # Это работает только на Linux
        import ctypes
        libc = ctypes.CDLL("libc.so.6")
        libc.malloc_trim(0)
        logger.debug("Called malloc_trim to release memory")
    except Exception:
        # Игнорируем ошибки, если функция недоступна
        pass


@contextmanager
def memory_efficient_context(operation_name: str = "Memory-efficient operation"):
    """
    Контекстный менеджер для выполнения операций с оптимизацией памяти.
    
    Args:
        operation_name: Название операции для логирования
    """
    memory_monitor = MemoryMonitor()
    
    with memory_monitor.measure_memory_usage(operation_name):
        # Перед выполнением операции
        optimize_memory_usage()
        
        try:
            yield
        finally:
            # После выполнения операции
            optimize_memory_usage()


# Создаем глобальный монитор памяти
memory_monitor = MemoryMonitor()


# Функция для добавления обработчика высокого использования памяти
def register_high_memory_handler(callback: Callable[[float, float], None]):
    """
    Регистрирует обработчик для уведомлений о высоком использовании памяти.
    
    Args:
        callback: Функция, принимающая два аргумента: текущий и пороговый процент памяти
    """
    memory_monitor.register_callback(callback)


# Запускаем мониторинг памяти при импорте модуля
memory_monitor.start_monitoring()


# Регистрируем обработчик по умолчанию для высокого использования памяти
def default_high_memory_handler(current_percent: float, threshold_percent: float):
    """
    Обработчик высокого использования памяти по умолчанию.
    
    Args:
        current_percent: Текущий процент использования памяти
        threshold_percent: Пороговый процент
    """
    logger.warning(
        f"High memory usage detected: {current_percent:.1f}% (threshold: {threshold_percent:.1f}%). "
        "Attempting to optimize memory usage..."
    )
    optimize_memory_usage()


# Регистрируем обработчик по умолчанию
register_high_memory_handler(default_high_memory_handler)
