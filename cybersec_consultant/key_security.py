# -*- coding: utf-8 -*-
"""
Модуль для безопасного управления API ключами в консультанте по кибербезопасности.
Реализует шифрование и безопасное хранение API ключей.
"""

import os
import json
import base64
from typing import Dict, Any, Optional, Union
from pathlib import Path
import hashlib
import getpass
import secrets
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC

# Импортируем логгер из модуля обработки ошибок
from cybersec_consultant.error_handling import logger, ConfigurationError

# Путь к директории с ключами
DEFAULT_KEYS_DIR = os.path.join(os.path.expanduser("~"), ".cybersec_consultant", "keys")


class APIKeyManager:
    """
    Класс для безопасного управления API ключами.
    Обеспечивает шифрование и хранение ключей API.
    """
    
    def __init__(self, keys_dir: Optional[str] = None, use_encryption: bool = True):
        """
        Инициализация менеджера API ключей.
        
        Args:
            keys_dir: Директория для хранения ключей (по умолчанию ~/.cybersec_consultant/keys)
            use_encryption: Использовать ли шифрование для хранения ключей
        """
        self.keys_dir = keys_dir or DEFAULT_KEYS_DIR
        self.use_encryption = use_encryption
        self.crypto = KeyEncryption()
        self.api_keys = {}
        
        # Создаем директорию, если она не существует
        os.makedirs(self.keys_dir, exist_ok=True)
        # Устанавливаем безопасные разрешения для директории с ключами
        try:
            os.chmod(self.keys_dir, 0o700)  # Разрешения только для владельца
        except Exception as e:
            logger.warning(f"Failed to set secure permissions for keys directory: {str(e)}")
    
    def set_api_key(self, service_name: str, api_key: str, save: bool = True) -> None:
        """
        Установка и опционально сохранение API ключа.
        
        Args:
            service_name: Название сервиса (например, "openai")
            api_key: API ключ
            save: Сохранять ли ключ на диск
        """
        self.api_keys[service_name] = api_key
        
        if save:
            self._save_api_key(service_name, api_key)
    
    def get_api_key(self, service_name: str) -> Optional[str]:
        """
        Получение API ключа для сервиса.
        
        Args:
            service_name: Название сервиса
            
        Returns:
            API ключ или None, если ключ не найден
        """
        # Пытаемся получить из памяти
        if service_name in self.api_keys:
            return self.api_keys[service_name]
        
        # Пытаемся загрузить с диска
        key_file = os.path.join(self.keys_dir, f"{service_name}_api_key.json")
        if os.path.exists(key_file):
            try:
                with open(key_file, "r") as f:
                    data = json.load(f)
                    
                encrypted_key = data.get("key")
                if encrypted_key:
                    if data.get("encrypted", False) and self.use_encryption:
                        # Расшифровываем ключ
                        api_key = self.crypto.decrypt(encrypted_key)
                    else:
                        api_key = encrypted_key
                        
                    # Сохраняем в память
                    self.api_keys[service_name] = api_key
                    return api_key
            except Exception as e:
                logger.error(f"Error loading API key for {service_name}: {str(e)}")
        
        # Пытаемся получить из переменных окружения
        env_var_name = f"{service_name.upper()}_API_KEY"
        env_api_key = os.environ.get(env_var_name)
        if env_api_key:
            self.api_keys[service_name] = env_api_key
            return env_api_key
            
        return None
    
    def _save_api_key(self, service_name: str, api_key: str) -> None:
        """
        Сохранение API ключа на диск с опциональным шифрованием.
        
        Args:
            service_name: Название сервиса
            api_key: API ключ
        """
        key_file = os.path.join(self.keys_dir, f"{service_name}_api_key.json")
        
        try:
            if self.use_encryption:
                # Шифруем ключ
                encrypted_key = self.crypto.encrypt(api_key)
                data = {
                    "service": service_name,
                    "key": encrypted_key,
                    "encrypted": True
                }
            else:
                # Сохраняем без шифрования (не рекомендуется)
                data = {
                    "service": service_name,
                    "key": api_key,
                    "encrypted": False
                }
            
            # Записываем в файл
            with open(key_file, "w") as f:
                json.dump(data, f)
                
            # Устанавливаем безопасные разрешения для файла с ключом
            try:
                os.chmod(key_file, 0o600)  # Разрешения только для чтения/записи владельцем
            except Exception as e:
                logger.warning(f"Failed to set secure permissions for key file: {str(e)}")
                
            logger.info(f"API key for {service_name} saved successfully")
        except Exception as e:
            logger.error(f"Error saving API key for {service_name}: {str(e)}")
            raise ConfigurationError(f"Failed to save API key: {str(e)}")
    
    def delete_api_key(self, service_name: str) -> bool:
        """
        Удаление API ключа.
        
        Args:
            service_name: Название сервиса
            
        Returns:
            True, если ключ успешно удален, иначе False
        """
        # Удаляем из памяти
        if service_name in self.api_keys:
            del self.api_keys[service_name]
        
        # Удаляем файл, если он существует
        key_file = os.path.join(self.keys_dir, f"{service_name}_api_key.json")
        if os.path.exists(key_file):
            try:
                os.remove(key_file)
                logger.info(f"API key for {service_name} deleted successfully")
                return True
            except Exception as e:
                logger.error(f"Error deleting API key for {service_name}: {str(e)}")
                return False
        return False
    
    def list_api_keys(self) -> Dict[str, bool]:
        """
        Получение списка доступных API ключей.
        
        Returns:
            Словарь с названиями сервисов и статусом шифрования
        """
        keys = {}
        
        # Проверяем файлы в директории с ключами
        for filename in os.listdir(self.keys_dir):
            if filename.endswith("_api_key.json"):
                service_name = filename.split("_api_key.json")[0]
                try:
                    with open(os.path.join(self.keys_dir, filename), "r") as f:
                        data = json.load(f)
                        keys[service_name] = data.get("encrypted", False)
                except Exception:
                    keys[service_name] = "unknown"
        
        # Добавляем ключи, загруженные из переменных окружения
        for service_name in self.api_keys:
            if service_name not in keys:
                keys[service_name] = "env"
                
        return keys
    
    def prompt_for_api_key(self, service_name: str, save: bool = True) -> str:
        """
        Запрашивает API ключ у пользователя через консоль.
        
        Args:
            service_name: Название сервиса
            save: Сохранять ли ключ на диск
            
        Returns:
            Введенный API ключ
        """
        prompt = f"Введите API ключ для {service_name}: "
        api_key = getpass.getpass(prompt)
        
        if api_key and save:
            self.set_api_key(service_name, api_key, save=True)
            
        return api_key


class KeyEncryption:
    """
    Класс для шифрования и расшифровки API ключей.
    Использует Fernet (симметричное шифрование) и PBKDF2 для генерации ключа из пароля.
    """
    
    def __init__(self):
        """Инициализация шифрования"""
        self.key_file = os.path.join(DEFAULT_KEYS_DIR, ".encryption_key")
        self.salt_file = os.path.join(DEFAULT_KEYS_DIR, ".salt")
        self._encryption_key = None
    
    def _get_encryption_key(self) -> bytes:
        """
        Получение ключа шифрования. Если ключ не существует, он будет создан.
        
        Returns:
            Ключ шифрования
        """
        if self._encryption_key is not None:
            return self._encryption_key
            
        # Создаем директорию, если она не существует
        os.makedirs(os.path.dirname(self.key_file), exist_ok=True)
        
        # Проверяем существование ключа
        if os.path.exists(self.key_file):
            # Загружаем существующий ключ
            try:
                with open(self.key_file, "rb") as f:
                    self._encryption_key = f.read()
                return self._encryption_key
            except Exception as e:
                logger.error(f"Error loading encryption key: {str(e)}")
        
        # Генерируем новый ключ
        try:
            self._encryption_key = Fernet.generate_key()
            with open(self.key_file, "wb") as f:
                f.write(self._encryption_key)
            
            # Устанавливаем безопасные разрешения
            os.chmod(self.key_file, 0o600)
            
            return self._encryption_key
        except Exception as e:
            logger.error(f"Error generating encryption key: {str(e)}")
            raise ConfigurationError(f"Failed to generate encryption key: {str(e)}")
    
    def encrypt(self, data: str) -> str:
        """
        Шифрование данных.
        
        Args:
            data: Данные для шифрования
            
        Returns:
            Зашифрованные данные в виде строки base64
        """
        try:
            key = self._get_encryption_key()
            f = Fernet(key)
            encrypted_data = f.encrypt(data.encode())
            return base64.b64encode(encrypted_data).decode()
        except Exception as e:
            logger.error(f"Error encrypting data: {str(e)}")
            raise ConfigurationError(f"Failed to encrypt data: {str(e)}")
    
    def decrypt(self, encrypted_data: str) -> str:
        """
        Расшифровка данных.
        
        Args:
            encrypted_data: Зашифрованные данные в виде строки base64
            
        Returns:
            Расшифрованные данные
        """
        try:
            key = self._get_encryption_key()
            f = Fernet(key)
            decrypted_data = f.decrypt(base64.b64decode(encrypted_data))
            return decrypted_data.decode()
        except Exception as e:
            logger.error(f"Error decrypting data: {str(e)}")
            raise ConfigurationError(f"Failed to decrypt data: {str(e)}")
    
    def create_key_from_password(self, password: str) -> bytes:
        """
        Создание ключа шифрования из пароля с использованием PBKDF2.
        
        Args:
            password: Пароль пользователя
            
        Returns:
            Ключ шифрования
        """
        # Генерируем или загружаем соль
        salt = self._get_or_create_salt()
        
        # Используем PBKDF2 для генерации ключа из пароля
        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=32,
            salt=salt,
            iterations=100000,
        )
        
        # Генерируем ключ из пароля
        key = base64.urlsafe_b64encode(kdf.derive(password.encode()))
        return key
    
    def _get_or_create_salt(self) -> bytes:
        """
        Получение или создание соли для генерации ключа.
        
        Returns:
            Соль
        """
        if os.path.exists(self.salt_file):
            # Загружаем существующую соль
            with open(self.salt_file, "rb") as f:
                return f.read()
        else:
            # Генерируем новую соль
            salt = secrets.token_bytes(16)
            with open(self.salt_file, "wb") as f:
                f.write(salt)
            
            # Устанавливаем безопасные разрешения
            os.chmod(self.salt_file, 0o600)
            
            return salt


# Создаем глобальный экземпляр для использования в других модулях
api_key_manager = APIKeyManager()


def get_api_key(service_name: str, prompt_if_missing: bool = False) -> Optional[str]:
    """
    Получение API ключа для сервиса.
    
    Args:
        service_name: Название сервиса
        prompt_if_missing: Запрашивать ли ключ у пользователя, если он не найден
        
    Returns:
        API ключ или None, если ключ не найден
    """
    api_key = api_key_manager.get_api_key(service_name)
    
    if api_key is None and prompt_if_missing:
        api_key = api_key_manager.prompt_for_api_key(service_name)
        
    return api_key


def set_api_key(service_name: str, api_key: str, save: bool = True) -> None:
    """
    Установка API ключа для сервиса.
    
    Args:
        service_name: Название сервиса
        api_key: API ключ
        save: Сохранять ли ключ на диск
    """
    api_key_manager.set_api_key(service_name, api_key, save=save)
