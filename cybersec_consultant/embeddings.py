# -*- coding: utf-8 -*-
"""
Модуль для работы с векторными эмбеддингами и поиском
"""

import os
import time
import json
import pickle
import hashlib
from datetime import datetime
from tqdm.auto import tqdm

from langchain_openai import OpenAIEmbeddings
from langchain_community.vectorstores import FAISS
from langchain.schema import Document

from cybersec_consultant.config import ConfigManager, INDICES_DIR, get_api_key
from cybersec_consultant.state_management import STATE

class VectorSearchManager:
    """Класс для управления векторным поиском"""

    def __init__(self):
        """Инициализация менеджера векторного поиска"""
        self.config_manager = ConfigManager()
        self.embeddings = None
        
        # Инициализация API ключа из централизованного состояния
        if not STATE.api_key:
            STATE.api_key = get_api_key()

        # Создаем директорию для индексов, если она не существует
        os.makedirs(INDICES_DIR, exist_ok=True)

        # Инициализируем модель эмбеддингов
        self._init_embeddings()

    def _init_embeddings(self):
        """Инициализирует модель эмбеддингов"""
        try:
            self.embeddings = OpenAIEmbeddings()
            print("✅ Модель эмбеддингов успешно инициализирована")
        except Exception as e:
            print(f"❌ Ошибка при инициализации модели эмбеддингов: {str(e)}")
            self.embeddings = None

    def create_index(self, documents, index_name="cybersec_index"):
        """
        Создает векторный индекс FAISS из документов

        Args:
            documents (list): Список документов для индексации
            index_name (str): Имя индекса для сохранения

        Returns:
            FAISS: Созданный векторный индекс
        """
        if not documents:
            print("❌ Список документов пуст")
            return None

        if not self.embeddings:
            print("❌ Модель эмбеддингов не инициализирована")
            return None

        print(f"🔄 Создаем векторный индекс из {len(documents)} документов...")

        try:
            # Замеряем время создания индекса
            start_time = time.time()

            # Создаем индекс FAISS
            db = FAISS.from_documents(documents, self.embeddings)

            # Сохраняем индекс
            index_path = os.path.join(INDICES_DIR, index_name)
            os.makedirs(index_path, exist_ok=True)
            db.save_local(index_path)

            # Сохраняем документы отдельно для удобства
            docs_path = os.path.join(index_path, "documents.pkl")
            with open(docs_path, 'wb') as f:
                pickle.dump(documents, f)

            elapsed_time = time.time() - start_time
            print(f"✅ Индекс '{index_name}' успешно создан за {elapsed_time:.2f} секунд.")

            # Сохраняем индекс в состояние
            STATE.vector_db = db

            return db
        except Exception as e:
            print(f"❌ Ошибка при создании индекса: {str(e)}")
            return None

    def load_index(self, index_name="cybersec_index"):
        """
        Загружает векторный индекс

        Args:
            index_name (str): Имя индекса для загрузки

        Returns:
            FAISS: Загруженный векторный индекс
        """
        if not self.embeddings:
            print("❌ Модель эмбеддингов не инициализирована")
            return None

        index_path = os.path.join(INDICES_DIR, index_name)
        if not os.path.exists(index_path) or not os.path.exists(os.path.join(index_path, "index.faiss")):
            print(f"❌ Индекс '{index_name}' не найден.")
            return None

        try:
            print(f"🔄 Загружаем индекс '{index_name}'...")
            start_time = time.time()

            # Загружаем индекс
            db = FAISS.load_local(index_path, self.embeddings, allow_dangerous_deserialization=True)

            elapsed_time = time.time() - start_time
            print(f"✅ Индекс '{index_name}' успешно загружен за {elapsed_time:.2f} секунд.")

            # Сохраняем индекс в состояние
            STATE.vector_db = db

            return db
        except Exception as e:
            print(f"❌ Ошибка при загрузке индекса: {str(e)}")
            return None

    def search_documents_with_score(self, query, k=3, use_cache=True):
        """
        Выполняет поиск документов по запросу и возвращает список кортежей (документ, оценка).

        Args:
            query (str): Поисковый запрос
            k (int): Количество результатов
            use_cache (bool): Использовать кэш или нет

        Returns:
            list: Список кортежей (документ, оценка)
        """
        if STATE.vector_db is None:
            print("❌ Векторный индекс не загружен. Сначала загрузите или создайте индекс.")
            return []

        # Ищем кэшированные результаты
        cached_results = STATE.get_search_from_cache(query, k) if use_cache else None
        if cached_results:
            print(f"🔄 Найденные документы по запросу: '{query}' (результаты взяты из кэша)")
            return cached_results

        try:
            # Выполняем поиск
            print(f"🔍 Поиск документов по запросу: '{query}'")
            start_time = time.time()

            # Выполняем поиск с оценкой сходства
            results_with_scores = STATE.vector_db.similarity_search_with_score(query, k=k)

            # Измеряем время выполнения
            execution_time = time.time() - start_time

            # Сохраняем результаты в кэш
            if results_with_scores and use_cache:
                STATE.add_search_to_cache(query, k, results_with_scores)

            print(f"✅ Поиск выполнен за {execution_time:.2f} сек.")
            print(f"📊 Найдено {len(results_with_scores)} результатов")

            return results_with_scores

        except Exception as e:
            print(f"❌ Ошибка при выполнении запроса: {str(e)}")
            return []
