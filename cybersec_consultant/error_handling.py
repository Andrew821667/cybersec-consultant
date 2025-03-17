# -*- coding: utf-8 -*-
"""
Модуль для централизованной обработки ошибок в консультанте по кибербезопасности.
"""

import logging
import traceback
import time
from typing import Dict, Any, Callable, Optional, TypeVar, Union
from functools import wraps

# Настройка логгера
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    handlers=[
        logging.StreamHandler(),
        logging.FileHandler('cybersec_consultant.log')
    ]
)

logger = logging.getLogger('cybersec_consultant')

# Типы для аннотаций
T = TypeVar('T')


class ConsultantError(Exception):
    """Базовый класс для всех ошибок консультанта"""
    def __init__(self, message: str, details: Optional[Dict[str, Any]] = None):
        self.message = message
        self.details = details or {}
        super().__init__(message)


class APIError(ConsultantError):
    """Ошибки связанные с вызовами внешних API"""
    def __init__(self, message: str, api_name: str, status_code: Optional[int] = None, 
                 response: Optional[Any] = None, details: Optional[Dict[str, Any]] = None):
        super().__init__(message, details)
        self.api_name = api_name
        self.status_code = status_code
        self.response = response


class KnowledgeBaseError(ConsultantError):
    """Ошибки связанные с базой знаний"""
    pass


class EmbeddingError(ConsultantError):
    """Ошибки связанные с векторными эмбеддингами"""
    pass


class ConfigurationError(ConsultantError):
    """Ошибки конфигурации"""
    pass


def retry(max_retries: int = 3, initial_delay: float = 1.0, 
          backoff_factor: float = 2.0, allowed_exceptions: tuple = (APIError,)):
    """
    Декоратор для повторных попыток выполнения функции при определенных исключениях.
    
    Args:
        max_retries: Максимальное количество повторных попыток
        initial_delay: Начальная задержка между попытками (секунды)
        backoff_factor: Множитель для увеличения задержки с каждой попыткой
        allowed_exceptions: Типы исключений, при которых будут выполняться повторные попытки
    """
    def decorator(func: Callable[..., T]) -> Callable[..., T]:
        @wraps(func)
        def wrapper(*args, **kwargs) -> T:
            delay = initial_delay
            last_exception = None
            
            for attempt in range(max_retries + 1):
                try:
                    return func(*args, **kwargs)
                except allowed_exceptions as e:
                    last_exception = e
                    
                    if attempt < max_retries:
                        # Логируем попытку
                        logger.warning(
                            f"Attempt {attempt + 1}/{max_retries + 1} for {func.__name__} failed: {str(e)}. "
                            f"Retrying in {delay:.2f} seconds..."
                        )
                        time.sleep(delay)
                        # Увеличиваем задержку для следующей попытки
                        delay *= backoff_factor
                    else:
                        # Последняя попытка не удалась
                        logger.error(
                            f"All {max_retries + 1} attempts for {func.__name__} failed. "
                            f"Last error: {str(last_exception)}"
                        )
                        raise
            
            # Этот код недостижим, но нужен для типизации
            raise last_exception
        
        return wrapper
    
    return decorator


def safe_execute(default_return: Optional[Any] = None, 
                 log_exception: bool = True) -> Callable:
    """
    Декоратор для безопасного выполнения функции с возвратом значения по умолчанию при ошибке.
    
    Args:
        default_return: Значение, возвращаемое при возникновении исключения
        log_exception: Флаг, указывающий нужно ли логировать исключение
    """
    def decorator(func: Callable) -> Callable:
        @wraps(func)
        def wrapper(*args, **kwargs):
            try:
                return func(*args, **kwargs)
            except Exception as e:
                if log_exception:
                    logger.error(
                        f"Error in {func.__name__}: {str(e)}\n"
                        f"Args: {args}, Kwargs: {kwargs}\n"
                        f"Traceback: {traceback.format_exc()}"
                    )
                return default_return
        
        return wrapper
    
    return decorator


def handle_api_errors(api_name: str) -> Callable:
    """
    Декоратор для обработки ошибок API и преобразования их в APIError.
    
    Args:
        api_name: Название API для включения в сообщение об ошибке
    """
    def decorator(func: Callable) -> Callable:
        @wraps(func)
        def wrapper(*args, **kwargs):
            try:
                return func(*args, **kwargs)
            except Exception as e:
                # Определяем тип ошибки и преобразуем её
                error_msg = f"Ошибка при обращении к {api_name}: {str(e)}"
                
                # Извлекаем дополнительную информацию, если возможно
                status_code = getattr(e, 'status_code', None) 
                response = getattr(e, 'response', None)
                
                # Создаем и выбрасываем APIError
                raise APIError(
                    message=error_msg,
                    api_name=api_name,
                    status_code=status_code,
                    response=response
                )
        
        return wrapper
    
    return decorator
