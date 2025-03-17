# -*- coding: utf-8 -*-
"""
Модуль для асинхронной обработки операций в консультанте по кибербезопасности.
Улучшает отзывчивость при работе с большими объемами данных.
"""

import asyncio
import time
import functools
from typing import List, Dict, Any, Callable, Coroutine, TypeVar, Optional, Union
from concurrent.futures import ThreadPoolExecutor, ProcessPoolExecutor

# Импортируем логгер из модуля обработки ошибок
from cybersec_consultant.error_handling import logger, safe_execute, retry

# Типовая переменная для аннотаций
T = TypeVar('T')


class AsyncProcessor:
    """
    Класс для асинхронной обработки операций.
    Обеспечивает выполнение задач параллельно и асинхронно.
    """
    
    def __init__(self, max_workers: int = None, use_processes: bool = False):
        """
        Инициализация асинхронного процессора.
        
        Args:
            max_workers: Максимальное количество рабочих потоков/процессов
            use_processes: Использовать процессы вместо потоков (для CPU-интенсивных задач)
        """
        self.max_workers = max_workers or min(32, (asyncio.get_event_loop().get_default_executor()._max_workers))
        self.use_processes = use_processes
        self._executor = None
    
    @property
    def executor(self):
        """Ленивая инициализация исполнителя"""
        if self._executor is None:
            if self.use_processes:
                self._executor = ProcessPoolExecutor(max_workers=self.max_workers)
            else:
                self._executor = ThreadPoolExecutor(max_workers=self.max_workers)
        return self._executor
    
    def close(self):
        """Закрыть исполнителя при завершении работы"""
        if self._executor is not None:
            self._executor.shutdown(wait=True)
            self._executor = None
    
    async def run_in_executor(self, func: Callable[..., T], *args, **kwargs) -> T:
        """
        Выполнить блокирующую функцию в пуле потоков/процессов.
        
        Args:
            func: Блокирующая функция для выполнения
            *args, **kwargs: Аргументы для передачи функции
            
        Returns:
            Результат выполнения функции
        """
        loop = asyncio.get_event_loop()
        if kwargs:
            func_with_kwargs = functools.partial(func, **kwargs)
            return await loop.run_in_executor(self.executor, func_with_kwargs, *args)
        else:
            return await loop.run_in_executor(self.executor, func, *args)
    
    async def process_batch(self, 
                          items: List[Any], 
                          process_func: Callable[[Any], T], 
                          batch_size: int = 10,
                          timeout: Optional[float] = None) -> List[T]:
        """
        Асинхронно обрабатывает список элементов пакетами.
        
        Args:
            items: Список элементов для обработки
            process_func: Функция для обработки одного элемента
            batch_size: Размер пакета для параллельной обработки
            timeout: Таймаут на выполнение всей операции в секундах
            
        Returns:
            Список результатов обработки
        """
        results = []
        
        # Создаем задачи для каждого элемента
        async def process_item(item):
            return await self.run_in_executor(process_func, item)
        
        # Обработка по батчам
        for i in range(0, len(items), batch_size):
            batch = items[i:i + batch_size]
            batch_tasks = [process_item(item) for item in batch]
            
            logger.debug(f"Processing batch {i//batch_size + 1}/{(len(items) + batch_size - 1)//batch_size} "
                        f"({len(batch)} items)")
            
            start_time = time.time()
            # Выполняем все задачи пакета одновременно
            batch_results = await asyncio.gather(*batch_tasks, return_exceptions=True)
            
            for idx, result in enumerate(batch_results):
                if isinstance(result, Exception):
                    logger.error(f"Error processing item {i + idx}: {result}")
                    # Оставляем None для элементов с ошибками
                    results.append(None)
                else:
                    results.append(result)
            
            logger.debug(f"Batch processed in {time.time() - start_time:.2f} seconds")
        
        return results
    
    async def map(self, 
                func: Callable[[Any], T], 
                items: List[Any], 
                concurrency: int = 5) -> List[Union[T, None]]:
        """
        Асинхронно применяет функцию к каждому элементу списка с ограничением параллелизма.
        
        Args:
            func: Функция для применения к каждому элементу
            items: Список элементов
            concurrency: Максимальное количество одновременных задач
            
        Returns:
            Список результатов (None для элементов с ошибками)
        """
        semaphore = asyncio.Semaphore(concurrency)
        results = [None] * len(items)
        
        async def process_with_semaphore(index, item):
            async with semaphore:
                try:
                    results[index] = await self.run_in_executor(func, item)
                except Exception as e:
                    logger.error(f"Error in async map for item {index}: {str(e)}")
                    results[index] = None
        
        # Создаем и запускаем задачи
        tasks = []
        for i, item in enumerate(items):
            task = asyncio.create_task(process_with_semaphore(i, item))
            tasks.append(task)
        
        # Ждем завершения всех задач
        await asyncio.gather(*tasks)
        
        return results


# Создаем глобальный экземпляр для использования в других модулях
async_processor = AsyncProcessor()


async def process_documents_async(documents: List[Dict[str, Any]], 
                              processor_func: Callable[[Dict[str, Any]], Any],
                              batch_size: int = 5,
                              show_progress: bool = True) -> List[Any]:
    """
    Асинхронно обрабатывает список документов с отображением прогресса.
    
    Args:
        documents: Список документов
        processor_func: Функция обработки документа
        batch_size: Размер пакета для обработки
        show_progress: Показывать ли прогресс обработки
        
    Returns:
        Результаты обработки документов
    """
    if not documents:
        return []
    
    start_time = time.time()
    total_docs = len(documents)
    
    if show_progress:
        logger.info(f"Начинаем асинхронную обработку {total_docs} документов...")
    
    results = await async_processor.process_batch(
        items=documents,
        process_func=processor_func,
        batch_size=batch_size
    )
    
    elapsed = time.time() - start_time
    if show_progress:
        logger.info(f"Обработка завершена за {elapsed:.2f} секунд. "
                  f"Скорость: {total_docs / elapsed:.2f} документов/сек")
    
    return results


def to_async(func: Callable[..., T]) -> Callable[..., Coroutine[Any, Any, T]]:
    """
    Декоратор для преобразования синхронной функции в асинхронную.
    
    Args:
        func: Синхронная функция
    
    Returns:
        Асинхронная функция-обертка
    """
    @functools.wraps(func)
    async def wrapper(*args, **kwargs):
        return await async_processor.run_in_executor(func, *args, **kwargs)
    
    return wrapper


# Асинхронный вариант безопасного выполнения
def safe_execute_async(default_return: Optional[Any] = None, 
                      log_exception: bool = True) -> Callable:
    """
    Декоратор для безопасного выполнения асинхронной функции.
    
    Args:
        default_return: Значение, возвращаемое при возникновении исключения
        log_exception: Флаг, указывающий нужно ли логировать исключение
    """
    def decorator(func: Callable[..., Coroutine]):
        @functools.wraps(func)
        async def wrapper(*args, **kwargs):
            try:
                return await func(*args, **kwargs)
            except Exception as e:
                if log_exception:
                    logger.error(
                        f"Error in async {func.__name__}: {str(e)}\n"
                        f"Args: {args}, Kwargs: {kwargs}\n"
                        f"Traceback: {traceback.format_exc()}"
                    )
                return default_return
        
        return wrapper
    
    return decorator
