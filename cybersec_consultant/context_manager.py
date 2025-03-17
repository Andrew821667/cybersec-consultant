# -*- coding: utf-8 -*-
"""
Модуль для управления контекстом диалога в консультанте по кибербезопасности.
Реализует механизм для хранения и обработки истории взаимодействия с пользователем.
"""

import time
import json
import os
from typing import Dict, Any, List, Optional, Tuple, Union
from datetime import datetime
import uuid

# Импортируем логгер из модуля обработки ошибок
from cybersec_consultant.error_handling import logger, safe_execute
from cybersec_consultant.state_management import STATE

# Максимальное количество сообщений в контексте
DEFAULT_MAX_CONTEXT_MESSAGES = 10
# Максимальное количество токенов в контексте
DEFAULT_MAX_CONTEXT_TOKENS = 4000


class DialogContext:
    """
    Класс для управления контекстом диалога.
    Хранит историю взаимодействия и обеспечивает персистентность контекста.
    """
    
    def __init__(self, session_id: Optional[str] = None, max_messages: int = DEFAULT_MAX_CONTEXT_MESSAGES):
        """
        Инициализация контекста диалога.
        
        Args:
            session_id: Идентификатор сессии (если None, будет сгенерирован новый)
            max_messages: Максимальное количество сообщений в контексте
        """
        self.session_id = session_id or f"{datetime.now().strftime('%Y%m%d%H%M%S')}_{uuid.uuid4().hex[:8]}"
        self.max_messages = max_messages
        self.messages = []
        self.metadata = {
            "created_at": datetime.now().isoformat(),
            "last_updated": datetime.now().isoformat(),
            "total_messages": 0,
            "user_info": {}
        }
        
        # Подготавливаем директорию для хранения сессий
        self.sessions_dir = os.path.join(os.path.expanduser("~"), ".cybersec_consultant", "sessions")
        os.makedirs(self.sessions_dir, exist_ok=True)
    
    def add_message(self, role: str, content: str, metadata: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
        """
        Добавление сообщения в контекст диалога.
        
        Args:
            role: Роль отправителя сообщения ("user", "assistant", "system")
            content: Содержимое сообщения
            metadata: Дополнительные метаданные сообщения
            
        Returns:
            Объект добавленного сообщения
        """
        # Создаем объект сообщения
        message = {
            "id": f"msg_{uuid.uuid4().hex[:8]}",
            "role": role,
            "content": content,
            "timestamp": datetime.now().isoformat(),
            "metadata": metadata or {}
        }
        
        # Добавляем в список сообщений
        self.messages.append(message)
        
        # Обновляем метаданные контекста
        self.metadata["total_messages"] += 1
        self.metadata["last_updated"] = datetime.now().isoformat()
        
        # Проверяем ограничение на количество сообщений
        if len(self.messages) > self.max_messages:
            # Удаляем самое старое сообщение (кроме системных инструкций)
            non_system_messages = [msg for msg in self.messages if msg["role"] != "system"]
            if non_system_messages:
                oldest_msg = min(non_system_messages, key=lambda x: x["timestamp"])
                self.messages.remove(oldest_msg)
                logger.debug(f"Removed oldest message from context (ID: {oldest_msg['id']})")
            
        return message
    
    def get_messages(self, include_system: bool = True, last_n: Optional[int] = None) -> List[Dict[str, Any]]:
        """
        Получение сообщений из контекста.
        
        Args:
            include_system: Включать ли системные сообщения
            last_n: Количество последних сообщений для получения
            
        Returns:
            Список сообщений
        """
        # Фильтруем сообщения по роли
        filtered_messages = self.messages
        if not include_system:
            filtered_messages = [msg for msg in filtered_messages if msg["role"] != "system"]
        
        # Ограничиваем количество сообщений
        if last_n is not None and last_n > 0:
            filtered_messages = filtered_messages[-last_n:]
            
        return filtered_messages
    
    def clear(self, keep_system: bool = True) -> None:
        """
        Очистка контекста диалога.
        
        Args:
            keep_system: Сохранять ли системные сообщения
        """
        if keep_system:
            system_messages = [msg for msg in self.messages if msg["role"] == "system"]
            self.messages = system_messages
        else:
            self.messages = []
        
        logger.info(f"Dialog context cleared for session {self.session_id}")
    
    def save(self) -> str:
        """
        Сохранение контекста диалога в файл.
        
        Returns:
            Путь к файлу с сохраненным контекстом
        """
        session_file = os.path.join(self.sessions_dir, f"{self.session_id}.json")
        
        session_data = {
            "session_id": self.session_id,
            "metadata": self.metadata,
            "messages": self.messages
        }
        
        try:
            with open(session_file, "w", encoding="utf-8") as f:
                json.dump(session_data, f, ensure_ascii=False, indent=2)
            
            logger.info(f"Dialog context saved to {session_file}")
            return session_file
        except Exception as e:
            logger.error(f"Error saving dialog context: {str(e)}")
            return ""
    
    @classmethod
    def load(cls, session_id: str) -> 'DialogContext':
        """
        Загрузка контекста диалога из файла.
        
        Args:
            session_id: Идентификатор сессии
            
        Returns:
            Объект контекста диалога
        """
        sessions_dir = os.path.join(os.path.expanduser("~"), ".cybersec_consultant", "sessions")
        session_file = os.path.join(sessions_dir, f"{session_id}.json")
        
        if not os.path.exists(session_file):
            logger.warning(f"Session file not found: {session_file}")
            return cls(session_id)
        
        try:
            with open(session_file, "r", encoding="utf-8") as f:
                session_data = json.load(f)
            
            # Создаем объект контекста
            context = cls(session_id)
            context.messages = session_data.get("messages", [])
            context.metadata = session_data.get("metadata", {})
            
            logger.info(f"Dialog context loaded from {session_file}")
            return context
        except Exception as e:
            logger.error(f"Error loading dialog context: {str(e)}")
            return cls(session_id)
    
    @classmethod
    def list_sessions(cls) -> List[Dict[str, Any]]:
        """
        Получение списка всех сохраненных сессий.
        
        Returns:
            Список с информацией о сессиях
        """
        sessions_dir = os.path.join(os.path.expanduser("~"), ".cybersec_consultant", "sessions")
        os.makedirs(sessions_dir, exist_ok=True)
        
        sessions = []
        for filename in os.listdir(sessions_dir):
            if filename.endswith(".json"):
                session_id = filename.split(".json")[0]
                session_file = os.path.join(sessions_dir, filename)
                
                try:
                    with open(session_file, "r", encoding="utf-8") as f:
                        session_data = json.load(f)
                    
                    metadata = session_data.get("metadata", {})
                    message_count = len(session_data.get("messages", []))
                    
                    sessions.append({
                        "session_id": session_id,
                        "created_at": metadata.get("created_at", ""),
                        "last_updated": metadata.get("last_updated", ""),
                        "message_count": message_count,
                        "total_messages": metadata.get("total_messages", 0)
                    })
                except Exception as e:
                    logger.error(f"Error reading session file {filename}: {str(e)}")
        
        # Сортируем сессии по времени последнего обновления (от новых к старым)
        sessions.sort(key=lambda x: x.get("last_updated", ""), reverse=True)
        return sessions


class ContextManager:
    """
    Менеджер контекста для работы с контекстами диалогов.
    Управляет активным контекстом и возможностью переключения между контекстами.
    """
    
    def __init__(self):
        """Инициализация менеджера контекста"""
        self.active_context = None
        self.default_system_message = """Вы - консультант по кибербезопасности, который помогает отвечать на вопросы в этой области.
Используйте факты из предоставленных документов. Если информации недостаточно, скажите об этом.
Отвечайте подробно и структурированно, приводите примеры там, где это уместно."""
    
    def create_new_context(self, session_id: Optional[str] = None, 
                          system_message: Optional[str] = None) -> DialogContext:
        """
        Создание нового контекста диалога.
        
        Args:
            session_id: Идентификатор сессии (если None, будет сгенерирован новый)
            system_message: Системное сообщение для инициализации контекста
            
        Returns:
            Объект контекста диалога
        """
        # Создаем новый контекст
        context = DialogContext(session_id)
        
        # Добавляем системное сообщение
        if system_message is not None:
            context.add_message("system", system_message)
        elif self.default_system_message:
            context.add_message("system", self.default_system_message)
        
        # Устанавливаем как активный
        self.active_context = context
        
        return context
    
    def load_context(self, session_id: str) -> DialogContext:
        """
        Загрузка контекста диалога по идентификатору сессии.
        
        Args:
            session_id: Идентификатор сессии
            
        Returns:
            Объект контекста диалога
        """
        context = DialogContext.load(session_id)
        self.active_context = context
        return context
    
    def get_active_context(self) -> Optional[DialogContext]:
        """
        Получение активного контекста диалога.
        
        Returns:
            Активный объект контекста диалога или None
        """
        if self.active_context is None:
            # Создаем новый контекст, если активный отсутствует
            self.create_new_context()
            
        return self.active_context
    
    def add_system_message(self, content: str, replace_existing: bool = False) -> Optional[Dict[str, Any]]:
        """
        Добавление системного сообщения в активный контекст.
        
        Args:
            content: Содержимое системного сообщения
            replace_existing: Заменять ли существующие системные сообщения
            
        Returns:
            Объект добавленного сообщения или None
        """
        context = self.get_active_context()
        
        # Удаляем существующие системные сообщения, если требуется
        if replace_existing:
            context.messages = [msg for msg in context.messages if msg["role"] != "system"]
            
        # Добавляем новое системное сообщение
        return context.add_message("system", content)
    
    def add_user_message(self, content: str, metadata: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
        """
        Добавление сообщения пользователя в активный контекст.
        
        Args:
            content: Содержимое сообщения пользователя
            metadata: Дополнительные метаданные сообщения
            
        Returns:
            Объект добавленного сообщения
        """
        context = self.get_active_context()
        return context.add_message("user", content, metadata)
    
    def add_assistant_message(self, content: str, metadata: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
        """
        Добавление сообщения ассистента в активный контекст.
        
        Args:
            content: Содержимое сообщения ассистента
            metadata: Дополнительные метаданные сообщения
            
        Returns:
            Объект добавленного сообщения
        """
        context = self.get_active_context()
        return context.add_message("assistant", content, metadata)
    
    def save_active_context(self) -> str:
        """
        Сохранение активного контекста диалога.
        
        Returns:
            Путь к файлу с сохраненным контекстом
        """
        context = self.get_active_context()
        return context.save()
    
    def clear_active_context(self, keep_system: bool = True) -> None:
        """
        Очистка активного контекста диалога.
        
        Args:
            keep_system: Сохранять ли системные сообщения
        """
        context = self.get_active_context()
        context.clear(keep_system)
    
    def format_context_for_llm(self, include_system: bool = True, 
                             last_n: Optional[int] = None,
                             max_tokens: Optional[int] = DEFAULT_MAX_CONTEXT_TOKENS) -> List[Dict[str, str]]:
        """
        Форматирование контекста для отправки в языковую модель.
        
        Args:
            include_system: Включать ли системные сообщения
            last_n: Количество последних сообщений для включения
            max_tokens: Максимальное количество токенов
            
        Returns:
            Список сообщений в формате для LLM
        """
        context = self.get_active_context()
        messages = context.get_messages(include_system, last_n)
        
        # Преобразуем в формат для LLM
        llm_messages = []
        for msg in messages:
            llm_messages.append({
                "role": msg["role"],
                "content": msg["content"]
            })
        
        # Ограничиваем токены, если необходимо
        if max_tokens is not None:
            llm_messages = self._truncate_messages_to_max_tokens(llm_messages, max_tokens)
            
        return llm_messages
    
    def _truncate_messages_to_max_tokens(self, messages: List[Dict[str, str]], 
                                      max_tokens: int) -> List[Dict[str, str]]:
        """
        Обрезает сообщения до максимального количества токенов.
        
        Args:
            messages: Список сообщений
            max_tokens: Максимальное количество токенов
            
        Returns:
            Обрезанный список сообщений
        """
        # Примитивная оценка токенов (приблизительно 4 символа на токен)
        tokens_estimate = sum(len(msg["content"]) // 4 for msg in messages)
        
        if tokens_estimate <= max_tokens:
            return messages
        
        # Сохраняем системные сообщения и наиболее свежие сообщения
        system_messages = [msg for msg in messages if msg["role"] == "system"]
        other_messages = [msg for msg in messages if msg["role"] != "system"]
        
        # Оценка токенов для системных сообщений
        system_tokens = sum(len(msg["content"]) // 4 for msg in system_messages)
        remaining_tokens = max_tokens - system_tokens
        
        # Если осталось мало токенов, удаляем старые сообщения
        result_messages = system_messages
        
        # Добавляем сообщения с конца (наиболее свежие)
        tokens_used = system_tokens
        for msg in reversed(other_messages):
            msg_tokens = len(msg["content"]) // 4
            if tokens_used + msg_tokens <= max_tokens:
                # Вставляем в начало (после системных)
                result_messages.insert(len(system_messages), msg)
                tokens_used += msg_tokens
            else:
                # Не хватает токенов, пропускаем сообщение
                break
        
        # Переворачиваем сообщения обратно в правильном порядке
        other_messages_reversed = result_messages[len(system_messages):]
        other_messages_reversed.reverse()
        result_messages = system_messages + other_messages_reversed
        
        return result_messages


# Создаем глобальный экземпляр для использования в других модулях
context_manager = ContextManager()
