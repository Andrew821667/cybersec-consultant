# -*- coding: utf-8 -*-
"""
Модуль для поддержки различных языковых моделей в консультанте по кибербезопасности.
Обеспечивает интерфейс для взаимодействия с различными провайдерами моделей.
"""

import os
import json
import time
from typing import Dict, Any, List, Optional, Union, Callable, Type
from abc import ABC, abstractmethod

# Импортируем модули консультанта
from cybersec_consultant.error_handling import logger, APIError, retry, handle_api_errors
from cybersec_consultant.key_security import get_api_key

# Абстрактный класс для провайдера модели
class ModelProvider(ABC):
    """
    Абстрактный базовый класс для провайдеров языковых моделей.
    Определяет общий интерфейс для всех провайдеров.
    """
    
    @abstractmethod
    def generate_text(self, prompt: str, system_prompt: Optional[str] = None, **kwargs) -> Dict[str, Any]:
        """
        Генерация текста моделью.
        
        Args:
            prompt: Запрос пользователя
            system_prompt: Системный промпт для настройки поведения модели
            **kwargs: Дополнительные параметры для модели
            
        Returns:
            Словарь с результатами генерации
        """
        pass
    
    @abstractmethod
    def generate_chat_response(self, messages: List[Dict[str, str]], **kwargs) -> Dict[str, Any]:
        """
        Генерация ответа в формате чата.
        
        Args:
            messages: Список сообщений в формате [{"role": роль, "content": содержание}]
            **kwargs: Дополнительные параметры для модели
            
        Returns:
            Словарь с результатами генерации
        """
        pass
    
    @abstractmethod
    def generate_embeddings(self, texts: List[str], **kwargs) -> List[List[float]]:
        """
        Генерация векторных представлений (эмбеддингов) для текстов.
        
        Args:
            texts: Список текстов для векторизации
            **kwargs: Дополнительные параметры
            
        Returns:
            Список векторов (эмбеддингов)
        """
        pass
    
    @abstractmethod
    def get_available_models(self) -> List[Dict[str, Any]]:
        """
        Получение списка доступных моделей у данного провайдера.
        
        Returns:
            Список с информацией о доступных моделях
        """
        pass


class OpenAIProvider(ModelProvider):
    """
    Провайдер для моделей OpenAI (GPT).
    """
    
    def __init__(self, api_key: Optional[str] = None, organization_id: Optional[str] = None):
        """
        Инициализация провайдера OpenAI.
        
        Args:
            api_key: API ключ OpenAI (если None, будет использован из менеджера ключей)
            organization_id: ID организации в OpenAI
        """
        # Импортируем здесь, чтобы не требовать установки при отсутствии использования
        try:
            from openai import OpenAI
            import tiktoken
            self.tiktoken = tiktoken
        except ImportError:
            raise ImportError("Для использования OpenAI требуется установить пакет: pip install openai tiktoken")
        
        # Получаем API ключ
        self.api_key = api_key or get_api_key("openai")
        if not self.api_key:
            raise APIError("API ключ OpenAI не указан", api_name="openai")
        
        # Создаем клиента OpenAI
        self.client = OpenAI(api_key=self.api_key, organization=organization_id)
        
        # Хранилище для кэширования списка моделей
        self._models_cache = None
        self._models_cache_time = 0
        self._models_cache_ttl = 3600  # 1 час
    
    @handle_api_errors("OpenAI")
    def generate_text(self, prompt: str, system_prompt: Optional[str] = None, 
                     model: str = "gpt-4o-mini", temperature: float = 0.2, 
                     max_tokens: int = 1500, **kwargs) -> Dict[str, Any]:
        """
        Генерация текста с использованием моделей OpenAI.
        
        Args:
            prompt: Запрос пользователя
            system_prompt: Системный промпт для настройки поведения модели
            model: Название модели OpenAI
            temperature: Температура генерации (0.0 - 2.0)
            max_tokens: Максимальное количество токенов в ответе
            **kwargs: Дополнительные параметры
            
        Returns:
            Словарь с результатами генерации
        """
        # Формируем сообщения для API
        messages = []
        if system_prompt:
            messages.append({"role": "system", "content": system_prompt})
        
        messages.append({"role": "user", "content": prompt})
        
        # Выполняем запрос к API
        start_time = time.time()
        response = self.client.chat.completions.create(
            model=model,
            messages=messages,
            temperature=temperature,
            max_tokens=max_tokens,
            **kwargs
        )
        execution_time = time.time() - start_time
        
        # Обрабатываем результат
        result = {
            "response": response.choices[0].message.content,
            "model": model,
            "prompt_tokens": response.usage.prompt_tokens,
            "completion_tokens": response.usage.completion_tokens,
            "total_tokens": response.usage.total_tokens,
            "execution_time": execution_time,
            "finish_reason": response.choices[0].finish_reason
        }
        
        return result
    
    @handle_api_errors("OpenAI")
    def generate_chat_response(self, messages: List[Dict[str, str]], 
                              model: str = "gpt-4o-mini", temperature: float = 0.2,
                              max_tokens: int = 1500, **kwargs) -> Dict[str, Any]:
        """
        Генерация ответа в формате чата с использованием моделей OpenAI.
        
        Args:
            messages: Список сообщений в формате [{"role": роль, "content": содержание}]
            model: Название модели OpenAI
            temperature: Температура генерации (0.0 - 2.0)
            max_tokens: Максимальное количество токенов в ответе
            **kwargs: Дополнительные параметры
            
        Returns:
            Словарь с результатами генерации
        """
        # Выполняем запрос к API
        start_time = time.time()
        response = self.client.chat.completions.create(
            model=model,
            messages=messages,
            temperature=temperature,
            max_tokens=max_tokens,
            **kwargs
        )
        execution_time = time.time() - start_time
        
        # Обрабатываем результат
        result = {
            "response": response.choices[0].message.content,
            "model": model,
            "prompt_tokens": response.usage.prompt_tokens,
            "completion_tokens": response.usage.completion_tokens,
            "total_tokens": response.usage.total_tokens,
            "execution_time": execution_time,
            "finish_reason": response.choices[0].finish_reason
        }
        
        return result
    
    @handle_api_errors("OpenAI")
    def generate_embeddings(self, texts: List[str], model: str = "text-embedding-3-small", **kwargs) -> List[List[float]]:
        """
        Генерация векторных представлений (эмбеддингов) для текстов с использованием OpenAI.
        
        Args:
            texts: Список текстов для векторизации
            model: Название модели для эмбеддингов
            **kwargs: Дополнительные параметры
            
        Returns:
            Список векторов (эмбеддингов)
        """
        if not texts:
            return []
        
        # Выполняем запрос к API
        response = self.client.embeddings.create(
            model=model,
            input=texts,
            **kwargs
        )
        
        # Извлекаем эмбеддинги из ответа
        embeddings = [embedding.embedding for embedding in response.data]
        
        return embeddings
    
    @handle_api_errors("OpenAI")
    def get_available_models(self) -> List[Dict[str, Any]]:
        """
        Получение списка доступных моделей OpenAI.
        
        Returns:
            Список с информацией о доступных моделях
        """
        # Проверяем кэш
        current_time = time.time()
        if self._models_cache is not None and current_time - self._models_cache_time < self._models_cache_ttl:
            return self._models_cache
        
        # Получаем список моделей
        response = self.client.models.list()
        
        # Преобразуем в удобный формат
        models = []
        for model in response.data:
            models.append({
                "id": model.id,
                "created": model.created,
                "owned_by": model.owned_by,
                "type": "chat" if "gpt" in model.id else "embedding" if "embedding" in model.id else "other"
            })
        
        # Обновляем кэш
        self._models_cache = models
        self._models_cache_time = current_time
        
        return models
    
    def count_tokens(self, text: str, model: str = "gpt-4o-mini") -> int:
        """
        Подсчет количества токенов в тексте.
        
        Args:
            text: Текст для подсчета токенов
            model: Название модели для определения токенизатора
            
        Returns:
            Количество токенов
        """
        try:
            # Получаем токенизатор
            if model.startswith("gpt-4"):
                encoding = self.tiktoken.encoding_for_model("gpt-4")
            elif model.startswith("gpt-3.5"):
                encoding = self.tiktoken.encoding_for_model("gpt-3.5-turbo")
            else:
                encoding = self.tiktoken.get_encoding("cl100k_base")
                
            # Подсчитываем токены
            tokens = encoding.encode(text)
            return len(tokens)
        except Exception as e:
            logger.warning(f"Error counting tokens: {str(e)}")
            # Приближенный расчет (примерно 4 символа на токен)
            return len(text) // 4


class HuggingFaceProvider(ModelProvider):
    """
    Провайдер для моделей HuggingFace.
    """
    
    def __init__(self, api_key: Optional[str] = None):
        """
        Инициализация провайдера HuggingFace.
        
        Args:
            api_key: API ключ HuggingFace (если None, будет использован из менеджера ключей)
        """
        # Получаем API ключ
        self.api_key = api_key or get_api_key("huggingface")
        if not self.api_key:
            raise APIError("API ключ HuggingFace не указан", api_name="huggingface")
            
        # Импортируем здесь, чтобы не требовать установки при отсутствии использования
        try:
            from huggingface_hub import HfApi, InferenceApi
            self.hf_api = HfApi(token=self.api_key)
            self.InferenceApi = InferenceApi
        except ImportError:
            raise ImportError("Для использования HuggingFace требуется установить пакет: pip install huggingface_hub")
    
    @handle_api_errors("HuggingFace")
    def generate_text(self, prompt: str, system_prompt: Optional[str] = None, 
                     model: str = "mistralai/Mistral-7B-Instruct-v0.2", 
                     temperature: float = 0.7, max_tokens: int = 1024, **kwargs) -> Dict[str, Any]:
        """
        Генерация текста с использованием моделей HuggingFace.
        
        Args:
            prompt: Запрос пользователя
            system_prompt: Системный промпт для настройки поведения модели
            model: Название модели HuggingFace
            temperature: Температура генерации
            max_tokens: Максимальное количество токенов в ответе
            **kwargs: Дополнительные параметры
            
        Returns:
            Словарь с результатами генерации
        """
        # Формируем запрос с учетом системного промпта
        if system_prompt:
            full_prompt = f"{system_prompt}\n\n{prompt}"
        else:
            full_prompt = prompt
            
        # Создаем клиент для inference API
        inference = self.InferenceApi(repo_id=model, token=self.api_key)
        
        # Параметры для API
        params = {
            "temperature": temperature,
            "max_new_tokens": max_tokens,
            **kwargs
        }
        
        # Выполняем запрос к API
        start_time = time.time()
        response = inference(inputs=full_prompt, params=params)
        execution_time = time.time() - start_time
        
        # Обрабатываем результат
        if isinstance(response, list):
            generated_text = response[0]["generated_text"]
        elif isinstance(response, dict):
            generated_text = response.get("generated_text", str(response))
        else:
            generated_text = str(response)
            
        # Удаляем промпт из ответа, если он присутствует
        if generated_text.startswith(full_prompt):
            generated_text = generated_text[len(full_prompt):].strip()
            
        result = {
            "response": generated_text,
            "model": model,
            "execution_time": execution_time
        }
        
        return result
    
    @handle_api_errors("HuggingFace")
    def generate_chat_response(self, messages: List[Dict[str, str]], 
                              model: str = "mistralai/Mistral-7B-Instruct-v0.2",
                              temperature: float = 0.7, max_tokens: int = 1024, **kwargs) -> Dict[str, Any]:
        """
        Генерация ответа в формате чата с использованием моделей HuggingFace.
        
        Args:
            messages: Список сообщений в формате [{"role": роль, "content": содержание}]
            model: Название модели HuggingFace
            temperature: Температура генерации
            max_tokens: Максимальное количество токенов в ответе
            **kwargs: Дополнительные параметры
            
        Returns:
            Словарь с результатами генерации
        """
        # Преобразуем сообщения в формат для модели
        chat_history = ""
        system_message = None
        
        for message in messages:
            role = message.get("role", "user")
            content = message.get("content", "")
            
            if role == "system":
                system_message = content
            elif role == "user":
                chat_history += f"User: {content}\n"
            elif role == "assistant":
                chat_history += f"Assistant: {content}\n"
        
        # Добавляем системное сообщение в начало
        if system_message:
            prompt = f"{system_message}\n\n{chat_history}Assistant: "
        else:
            prompt = f"{chat_history}Assistant: "
            
        # Создаем клиент для inference API
        inference = self.InferenceApi(repo_id=model, token=self.api_key)
        
        # Параметры для API
        params = {
            "temperature": temperature,
            "max_new_tokens": max_tokens,
            "return_full_text": False,  # Только новый текст, без промпта
            **kwargs
        }
        
        # Выполняем запрос к API
        start_time = time.time()
        response = inference(inputs=prompt, params=params)
        execution_time = time.time() - start_time
        
        # Обрабатываем результат
        if isinstance(response, list):
            generated_text = response[0]["generated_text"]
        elif isinstance(response, dict):
            generated_text = response.get("generated_text", str(response))
        else:
            generated_text = str(response)
            
        result = {
            "response": generated_text,
            "model": model,
            "execution_time": execution_time
        }
        
        return result
    
    @handle_api_errors("HuggingFace")
    def generate_embeddings(self, texts: List[str], 
                          model: str = "sentence-transformers/all-MiniLM-L6-v2", 
                          **kwargs) -> List[List[float]]:
        """
        Генерация векторных представлений (эмбеддингов) для текстов с использованием HuggingFace.
        
        Args:
            texts: Список текстов для векторизации
            model: Название модели для эмбеддингов
            **kwargs: Дополнительные параметры
            
        Returns:
            Список векторов (эмбеддингов)
        """
        if not texts:
            return []
            
        # Создаем клиент для модели эмбеддингов
        inference = self.InferenceApi(repo_id=model, token=self.api_key)
        
        # Генерируем эмбеддинги для каждого текста по отдельности
        embeddings = []
        for text in texts:
            response = inference(inputs={"text": text})
            embeddings.append(response)
            
        return embeddings
    
    @handle_api_errors("HuggingFace")
    def get_available_models(self) -> List[Dict[str, Any]]:
        """
        Получение списка доступных моделей HuggingFace.
        
        Returns:
            Список с информацией о доступных моделях
        """
        # Получаем список моделей с тегами text-generation и sentence-transformers
        text_models = self.hf_api.list_models(filter="text-generation", limit=50)
        embedding_models = self.hf_api.list_models(filter="sentence-transformers", limit=50)
        
        # Объединяем и преобразуем в удобный формат
        models = []
        
        for model in text_models:
            models.append({
                "id": model.id,
                "downloads": model.downloads,
                "likes": model.likes,
                "type": "text-generation"
            })
            
        for model in embedding_models:
            models.append({
                "id": model.id,
                "downloads": model.downloads,
                "likes": model.likes,
                "type": "embedding"
            })
            
        # Сортируем по популярности
        models.sort(key=lambda x: x.get("downloads", 0), reverse=True)
        
        return models


class LocalModelProvider(ModelProvider):
    """
    Провайдер для локальных моделей (llama-cpp-python и др.).
    """
    
    def __init__(self, model_path: Optional[str] = None):
        """
        Инициализация провайдера локальных моделей.
        
        Args:
            model_path: Путь к файлу модели
        """
        self.model_path = model_path
        self.model = None
        self.tokenizer = None
        
        # Флаги доступности локальных библиотек
        self.llama_cpp_available = False
        self.ctransformers_available = False
        self.sentence_transformers_available = False
        
        # Проверяем наличие нужных библиотек
        try:
            import llama_cpp
            self.llama_cpp = llama_cpp
            self.llama_cpp_available = True
        except ImportError:
            logger.warning("llama-cpp-python не установлен. Некоторые локальные модели будут недоступны.")
        
        try:
            import ctransformers
            self.ctransformers = ctransformers
            self.ctransformers_available = True
        except ImportError:
            logger.warning("ctransformers не установлен. Некоторые локальные модели будут недоступны.")
            
        try:
            import sentence_transformers
            self.sentence_transformers = sentence_transformers
            self.sentence_transformers_available = True
        except ImportError:
            logger.warning("sentence-transformers не установлен. Локальные эмбеддинги будут недоступны.")
    
    def _load_model(self, model_path: Optional[str] = None, model_type: str = "llama"):
        """
        Загрузка локальной модели.
        
        Args:
            model_path: Путь к файлу модели (если None, будет использован путь из конструктора)
            model_type: Тип модели ("llama", "ct" для ctransformers, "st" для sentence-transformers)
        """
        model_path = model_path or self.model_path
        if not model_path:
            raise ValueError("Не указан путь к файлу модели")
            
        if not os.path.exists(model_path):
            raise FileNotFoundError(f"Файл модели не найден: {model_path}")
        
        # Загружаем модель в зависимости от типа
        if model_type == "llama":
            if not self.llama_cpp_available:
                raise ImportError("Для использования моделей llama требуется установить llama-cpp-python")
                
            self.model = self.llama_cpp.Llama(
                model_path=model_path,
                n_ctx=4096,
                n_threads=os.cpu_count() or 4
            )
            logger.info(f"Модель llama загружена: {model_path}")
            
        elif model_type == "ct":
            if not self.ctransformers_available:
                raise ImportError("Для использования моделей ctransformers требуется установить ctransformers")
                
            self.model = self.ctransformers.AutoModelForCausalLM.from_pretrained(
                model_path,
                model_type="llama"
            )
            logger.info(f"Модель ctransformers загружена: {model_path}")
            
        elif model_type == "st":
            if not self.sentence_transformers_available:
                raise ImportError("Для использования моделей sentence-transformers требуется установить sentence-transformers")
                
            self.model = self.sentence_transformers.SentenceTransformer(model_path)
            logger.info(f"Модель sentence-transformers загружена: {model_path}")
            
        else:
            raise ValueError(f"Неизвестный тип модели: {model_type}")
    
    def generate_text(self, prompt: str, system_prompt: Optional[str] = None, 
                     model_path: Optional[str] = None, model_type: str = "llama",
                     temperature: float = 0.7, max_tokens: int = 1024, **kwargs) -> Dict[str, Any]:
        """
        Генерация текста с использованием локальной модели.
        
        Args:
            prompt: Запрос пользователя
            system_prompt: Системный промпт для настройки поведения модели
            model_path: Путь к файлу модели
            model_type: Тип модели
            temperature: Температура генерации
            max_tokens: Максимальное количество токенов в ответе
            **kwargs: Дополнительные параметры
            
        Returns:
            Словарь с результатами генерации
        """
        # Загружаем модель, если еще не загружена или указан другой путь
        if self.model is None or (model_path and model_path != self.model_path):
            self._load_model(model_path, model_type)
            
        # Формируем запрос с учетом системного промпта
        if system_prompt:
            if model_type == "llama":
                # Формат для моделей Llama
                full_prompt = f"<s>[INST] <<SYS>>\n{system_prompt}\n<</SYS>>\n\n{prompt} [/INST]"
            else:
                # Общий формат
                full_prompt = f"{system_prompt}\n\n{prompt}"
        else:
            if model_type == "llama":
                full_prompt = f"<s>[INST] {prompt} [/INST]"
            else:
                full_prompt = prompt
        
        # Генерируем текст
        start_time = time.time()
        
        if model_type == "llama":
            output = self.model(
                full_prompt,
                max_tokens=max_tokens,
                temperature=temperature,
                **kwargs
            )
            
            if isinstance(output, dict):
                generated_text = output.get("choices", [{}])[0].get("text", "")
            else:
                generated_text = output
                
        elif model_type == "ct":
            generated_text = self.model(
                full_prompt,
                max_new_tokens=max_tokens,
                temperature=temperature,
                **kwargs
            )
        else:
            raise ValueError(f"Неподдерживаемый тип модели для генерации текста: {model_type}")
            
        execution_time = time.time() - start_time
        
        # Обрабатываем результат
        result = {
            "response": generated_text,
            "model": os.path.basename(self.model_path),
            "execution_time": execution_time
        }
        
        return result
    
    def generate_chat_response(self, messages: List[Dict[str, str]], 
                              model_path: Optional[str] = None, model_type: str = "llama",
                              temperature: float = 0.7, max_tokens: int = 1024, **kwargs) -> Dict[str, Any]:
        """
        Генерация ответа в формате чата с использованием локальной модели.
        
        Args:
            messages: Список сообщений в формате [{"role": роль, "content": содержание}]
            model_path: Путь к файлу модели
            model_type: Тип модели
            temperature: Температура генерации
            max_tokens: Максимальное количество токенов в ответе
            **kwargs: Дополнительные параметры
            
        Returns:
            Словарь с результатами генерации
        """
        # Загружаем модель, если еще не загружена или указан другой путь
        if self.model is None or (model_path and model_path != self.model_path):
            self._load_model(model_path, model_type)
            
        # Преобразуем сообщения в формат для модели
        system_message = None
        conversation = []
        
        for message in messages:
            role = message.get("role", "user")
            content = message.get("content", "")
            
            if role == "system":
                system_message = content
            else:
                conversation.append({"role": role, "content": content})
        
        # Формируем промпт в зависимости от типа модели
        if model_type == "llama":
            # Формат для моделей Llama
            prompt = ""
            if system_message:
                prompt += f"<s>[INST] <<SYS>>\n{system_message}\n<</SYS>>\n\n"
            else:
                prompt += "<s>"
                
            for i, message in enumerate(conversation):
                if message["role"] == "user":
                    if i == 0 and system_message:
                        prompt += f"{message['content']} [/INST]"
                    else:
                        prompt += f"[INST] {message['content']} [/INST]"
                else:
                    prompt += f" {message['content']}"
                    
            # Добавляем маркер для генерации ответа ассистента
            if conversation and conversation[-1]["role"] == "user":
                if not system_message and len(conversation) == 1:
                    prompt += f"[INST] {conversation[-1]['content']} [/INST]"
            else:
                prompt += " [INST] Продолжи диалог [/INST]"
                
        else:
            # Общий формат
            prompt = ""
            if system_message:
                prompt += f"{system_message}\n\n"
                
            for message in conversation:
                if message["role"] == "user":
                    prompt += f"User: {message['content']}\n"
                else:
                    prompt += f"Assistant: {message['content']}\n"
                    
            prompt += "Assistant: "
        
        # Генерируем текст
        start_time = time.time()
        
        if model_type == "llama":
            output = self.model(
                prompt,
                max_tokens=max_tokens,
                temperature=temperature,
                **kwargs
            )
            
            if isinstance(output, dict):
                generated_text = output.get("choices", [{}])[0].get("text", "")
            else:
                generated_text = output
                
        elif model_type == "ct":
            generated_text = self.model(
                prompt,
                max_new_tokens=max_tokens,
                temperature=temperature,
                **kwargs
            )
        else:
            raise ValueError(f"Неподдерживаемый тип модели для генерации чата: {model_type}")
            
        execution_time = time.time() - start_time
        
        # Обрабатываем результат
        result = {
            "response": generated_text,
            "model": os.path.basename(self.model_path),
            "execution_time": execution_time
        }
        
        return result
    
    def generate_embeddings(self, texts: List[str], 
                          model_path: Optional[str] = None, 
                          model_type: str = "st", **kwargs) -> List[List[float]]:
        """
        Генерация векторных представлений (эмбеддингов) для текстов с использованием локальной модели.
        
        Args:
            texts: Список текстов для векторизации
            model_path: Путь к файлу или имя модели
            model_type: Тип модели (поддерживается только "st" для sentence-transformers)
            **kwargs: Дополнительные параметры
            
        Returns:
            Список векторов (эмбеддингов)
        """
        if not texts:
            return []
            
        # Проверяем тип модели
        if model_type != "st":
            raise ValueError(f"Для генерации эмбеддингов поддерживается только тип модели 'st': {model_type}")
            
        # Загружаем модель, если еще не загружена или указан другой путь
        if self.model is None or (model_path and model_path != self.model_path):
            self._load_model(model_path, model_type)
            
        # Генерируем эмбеддинги
        embeddings = self.model.encode(texts, **kwargs)
        
        # Преобразуем в список списков (если numpy array)
        if hasattr(embeddings, 'tolist'):
            embeddings = embeddings.tolist()
            
        return embeddings
    
    def get_available_models(self) -> List[Dict[str, Any]]:
        """
        Получение списка доступных локальных моделей.
        
        Returns:
            Список с информацией о доступных моделях
        """
        models = []
        
        # Добавляем локальную модель, если она загружена
        if self.model_path and os.path.exists(self.model_path):
            models.append({
                "id": os.path.basename(self.model_path),
                "path": self.model_path,
                "type": "local"
            })
            
        return models


class ModelProviderFactory:
    """
    Фабрика для создания провайдеров моделей.
    """
    
    _providers = {}
    
    @classmethod
    def register_provider(cls, name: str, provider_class: Type[ModelProvider]):
        """
        Регистрация провайдера в фабрике.
        
        Args:
            name: Имя провайдера
            provider_class: Класс провайдера
        """
        cls._providers[name] = provider_class
    
    @classmethod
    def create(cls, provider_name: str, **kwargs) -> ModelProvider:
        """
        Создание экземпляра провайдера.
        
        Args:
            provider_name: Имя провайдера
            **kwargs: Аргументы для конструктора провайдера
            
        Returns:
            Экземпляр провайдера
        """
        if provider_name not in cls._providers:
            raise ValueError(f"Неизвестный провайдер: {provider_name}")
            
        return cls._providers[provider_name](**kwargs)
    
    @classmethod
    def get_available_providers(cls) -> List[str]:
        """
        Получение списка доступных провайдеров.
        
        Returns:
            Список имен доступных провайдеров
        """
        return list(cls._providers.keys())


# Регистрируем провайдеров в фабрике
ModelProviderFactory.register_provider("openai", OpenAIProvider)
ModelProviderFactory.register_provider("huggingface", HuggingFaceProvider)
ModelProviderFactory.register_provider("local", LocalModelProvider)


# Создаем функцию для получения провайдера по умолчанию
def get_default_provider() -> ModelProvider:
    """
    Получение провайдера моделей по умолчанию.
    
    Returns:
        Экземпляр провайдера
    """
    # Пытаемся создать провайдер OpenAI, т.к. он самый распространенный
    try:
        return ModelProviderFactory.create("openai")
    except (ImportError, APIError):
        # Если не получается, пробуем HuggingFace
        try:
            return ModelProviderFactory.create("huggingface")
        except (ImportError, APIError):
            # Если и это не получается, пробуем локальные модели
            try:
                # Ищем модели в стандартных местах
                model_dirs = [
                    os.path.join(os.path.expanduser("~"), ".cache", "huggingface", "hub"),
                    os.path.join(os.path.expanduser("~"), "models"),
                    os.path.join(os.getcwd(), "models")
                ]
                
                model_path = None
                for d in model_dirs:
                    if os.path.exists(d):
                        # Ищем первый .gguf или .bin файл
                        for root, _, files in os.walk(d):
                            for file in files:
                                if file.endswith((".gguf", ".bin", ".pt")):
                                    model_path = os.path.join(root, file)
                                    break
                            if model_path:
                                break
                    if model_path:
                        break
                
                if model_path:
                    return ModelProviderFactory.create("local", model_path=model_path)
                else:
                    raise FileNotFoundError("Не найдены локальные модели")
                    
            except (ImportError, FileNotFoundError):
                # Если ни один провайдер не доступен
                raise RuntimeError("Ни один провайдер моделей не доступен. Установите необходимые зависимости.")
