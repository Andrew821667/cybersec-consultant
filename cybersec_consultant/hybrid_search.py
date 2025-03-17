# -*- coding: utf-8 -*-
"""
Модуль для гибридного поиска (BM25 + векторный поиск)
"""

import os
import math
import pickle
import time
import re
import numpy as np
from collections import Counter

from cybersec_consultant.config import ConfigManager, INDICES_DIR
from cybersec_consultant.state_management import STATE
from cybersec_consultant.embeddings import VectorSearchManager
from cybersec_consultant.utils.text_processing import TextProcessor


class BM25:
    """Класс для реализации алгоритма BM25"""

    def __init__(self, k1=1.5, b=0.75):
        """
        Инициализация модели BM25
        
        Args:
            k1 (float): Параметр насыщения частоты термина
            b (float): Параметр нормализации длины документа
        """
        self.k1 = k1
        self.b = b
        self.corpus = []
        self.doc_freqs = Counter()
        self.idf = {}
        self.doc_len = []
        self.avgdl = 0
        self.text_processor = TextProcessor()
        
    def _tokenize(self, text):
        """
        Токенизирует текст
        
        Args:
            text (str): Текст для токенизации
            
        Returns:
            list: Список токенов
        """
        # Очищаем текст
        text = self.text_processor.clean_text(text)
        # Токенизируем
        tokens = re.findall(r'\b\w+\b', text.lower())
        # Фильтруем стоп-слова
        tokens = [token for token in tokens if token not in self.text_processor.stopwords]
        return tokens
        
    def fit(self, documents):
        """
        Обучает модель BM25 на корпусе документов
        
        Args:
            documents (list): Список документов (объектов Document)
        """
        # Получаем список содержимого документов
        self.corpus = [doc.page_content for doc in documents]
        
        # Токенизируем документы
        tokenized_corpus = [self._tokenize(doc) for doc in self.corpus]
        
        # Вычисляем длины документов
        self.doc_len = [len(tokens) for tokens in tokenized_corpus]
        self.avgdl = sum(self.doc_len) / len(self.doc_len) if self.doc_len else 0
        
        # Вычисляем частоту терминов в документах
        for tokens in tokenized_corpus:
            for token in set(tokens):
                self.doc_freqs[token] += 1
        
        # Вычисляем IDF для каждого термина
        self._compute_idf()
    
    def _compute_idf(self):
        """Вычисляет IDF для всех терминов в корпусе"""
        N = len(self.corpus)
        for term, n in self.doc_freqs.items():
            # BM25 IDF формула
            self.idf[term] = math.log((N - n + 0.5) / (n + 0.5) + 1)
    
    def search(self, query, top_k=10):
        """
        Выполняет поиск документов по запросу с использованием BM25
        
        Args:
            query (str): Поисковый запрос
            top_k (int): Количество результатов
            
        Returns:
            list: Список кортежей (индекс_документа, оценка)
        """
        # Токенизируем запрос
        query_tokens = self._tokenize(query)
        
        # Вычисляем оценки BM25 для всех документов
        scores = [self._score(query_tokens, i) for i in range(len(self.corpus))]
        
        # Сортируем результаты по оценке
        top_docs = sorted(enumerate(scores), key=lambda x: x[1], reverse=True)[:top_k]
        
        return top_docs
    
    def _score(self, query_tokens, doc_idx):
        """
        Вычисляет оценку BM25 для документа
        
        Args:
            query_tokens (list): Токены запроса
            doc_idx (int): Индекс документа
            
        Returns:
            float: Оценка BM25
        """
        # Если нет токенов в запросе, возвращаем 0
        if not query_tokens:
            return 0
        
        # Токенизируем документ
        doc_tokens = self._tokenize(self.corpus[doc_idx])
        
        # Вычисляем частоту терминов в документе
        freq = Counter(doc_tokens)
        
        # Длина документа
        doc_len = self.doc_len[doc_idx]
        
        # Вычисляем оценку BM25
        score = 0.0
        for token in query_tokens:
            if token not in self.idf:
                continue
                
            # Получаем IDF для термина
            idf = self.idf[token]
            
            # Получаем частоту термина в документе
            term_freq = freq[token]
            
            # BM25 формула
            numerator = idf * term_freq * (self.k1 + 1)
            denominator = term_freq + self.k1 * (1 - self.b + self.b * doc_len / self.avgdl)
            score += numerator / denominator
        
        return score


class HybridSearchManager:
    """Класс для управления гибридным поиском (BM25 + векторный)"""
    
    def __init__(self):
        """Инициализация менеджера гибридного поиска"""
        self.config_manager = ConfigManager()
        self.vector_search = VectorSearchManager()
        self.bm25 = BM25()
        self.documents = []
        
        # Вес для смешивания результатов (0 = только BM25, 1 = только векторный поиск)
        STATE.hybrid_weight = self.config_manager.get_setting("settings", "hybrid_weight", 0.5)
    
    def create_indexes(self, documents, index_name="cybersec_index"):
        """
        Создает гибридный индекс (векторный + BM25)
        
        Args:
            documents (list): Список документов для индексации
            index_name (str): Имя индекса
            
        Returns:
            bool: Успешность операции
        """
        if not documents:
            print("❌ Список документов пуст")
            return False
            
        print(f"🔄 Создаем гибридный индекс из {len(documents)} документов...")
        
        # Сохраняем документы
        self.documents = documents
        
        try:
            start_time = time.time()
            
            # 1. Создаем векторный индекс
            vector_db = self.vector_search.create_index(documents, index_name)
            if not vector_db:
                print("❌ Не удалось создать векторный индекс")
                return False
                
            # 2. Создаем BM25 индекс
            print("🔄 Создаем BM25 индекс...")
            self.bm25.fit(documents)
            
            # 3. Сохраняем BM25 индекс
            bm25_path = os.path.join(INDICES_DIR, index_name, "bm25.pkl")
            with open(bm25_path, 'wb') as f:
                pickle.dump(self.bm25, f)
            
            elapsed_time = time.time() - start_time
            print(f"✅ Гибридный индекс '{index_name}' успешно создан за {elapsed_time:.2f} секунд.")
            
            return True
        except Exception as e:
            print(f"❌ Ошибка при создании гибридного индекса: {str(e)}")
            return False
    
    def load_indexes(self, index_name="cybersec_index"):
        """
        Загружает гибридный индекс
        
        Args:
            index_name (str): Имя индекса
            
        Returns:
            bool: Успешность операции
        """
        print(f"🔄 Загружаем гибридный индекс '{index_name}'...")
        
        try:
            start_time = time.time()
            
            # 1. Загружаем векторный индекс
            vector_db = self.vector_search.load_index(index_name)
            if not vector_db:
                print("❌ Не удалось загрузить векторный индекс")
                return False
            
            # 2. Загружаем документы
            docs_path = os.path.join(INDICES_DIR, index_name, "documents.pkl")
            with open(docs_path, 'rb') as f:
                self.documents = pickle.load(f)
            
            # 3. Загружаем BM25 индекс
            bm25_path = os.path.join(INDICES_DIR, index_name, "bm25.pkl")
            if os.path.exists(bm25_path):
                with open(bm25_path, 'rb') as f:
                    self.bm25 = pickle.load(f)
            else:
                # Если BM25 индекс не существует, создаем его
                print("⚠️ BM25 индекс не найден. Создаем новый...")
                self.bm25.fit(self.documents)
                
                # Сохраняем BM25 индекс
                with open(bm25_path, 'wb') as f:
                    pickle.dump(self.bm25, f)
            
            elapsed_time = time.time() - start_time
            print(f"✅ Гибридный индекс '{index_name}' успешно загружен за {elapsed_time:.2f} секунд.")
            
            return True
        except Exception as e:
            print(f"❌ Ошибка при загрузке гибридного индекса: {str(e)}")
            return False
    
    def hybrid_search(self, query, k=3, use_cache=True, weight=None):
        """
        Выполняет гибридный поиск с использованием BM25 и векторного поиска
        
        Args:
            query (str): Поисковый запрос
            k (int): Количество результатов
            use_cache (bool): Использовать кэш
            weight (float): Вес для смешивания (если None, используется значение из настроек)
            
        Returns:
            list: Список кортежей (документ, оценка)
        """
        if STATE.vector_db is None:
            print("❌ Векторный индекс не загружен. Сначала загрузите индексы.")
            return []
            
        # Используем вес из параметра или из настроек
        hybrid_weight = weight if weight is not None else STATE.hybrid_weight
        
        # Ищем кэшированные результаты
        cache_key = f"{query}_{k}_{hybrid_weight}"
        cached_results = STATE.get_search_from_cache(cache_key, k) if use_cache else None
        if cached_results:
            print(f"🔄 Найденные документы по запросу: '{query}' (результаты взяты из кэша)")
            return cached_results
        
        try:
            # Выполняем поиск
            print(f"🔍 Гибридный поиск документов по запросу: '{query}' (вес={hybrid_weight:.2f})")
            start_time = time.time()
            
            # 1. Выполняем векторный поиск
            vector_results = STATE.vector_db.similarity_search_with_score(query, k=k*2)
            
            # 2. Выполняем BM25 поиск
            bm25_results = self.bm25.search(query, top_k=k*2)
            
            # 3. Объединяем результаты с учетом веса
            combined_results = self._combine_results(vector_results, bm25_results, hybrid_weight, k)
            
            # Измеряем время выполнения
            execution_time = time.time() - start_time
            
            # Сохраняем результаты в кэш
            if combined_results and use_cache:
                STATE.add_search_to_cache(cache_key, k, combined_results)
            
            print(f"✅ Поиск выполнен за {execution_time:.2f} сек.")
            print(f"📊 Найдено {len(combined_results)} результатов")
            
            return combined_results
        except Exception as e:
            print(f"❌ Ошибка при выполнении гибридного запроса: {str(e)}")
            return []
    
    def _combine_results(self, vector_results, bm25_results, weight, k):
        """
        Объединяет результаты векторного и BM25 поиска
        
        Args:
            vector_results (list): Результаты векторного поиска [(документ, оценка), ...]
            bm25_results (list): Результаты BM25 поиска [(индекс, оценка), ...]
            weight (float): Вес для смешивания (0 = только BM25, 1 = только векторный)
            k (int): Количество результатов
            
        Returns:
            list: Список кортежей (документ, оценка)
        """
        # Создаем словарь для хранения объединенных оценок
        combined_scores = {}
        
        # Нормализуем оценки векторного поиска (обратная оценка, меньше = лучше)
        if vector_results:
            # Инвертируем оценки расстояния (ближе = лучше)
            vector_scores = [(doc, 1.0 / (1.0 + score)) for doc, score in vector_results]
            # Нормализуем оценки (0-1)
            max_vector_score = max(score for _, score in vector_scores)
            norm_vector_scores = [(doc, score / max_vector_score) for doc, score in vector_scores]
            
            # Добавляем нормализованные оценки в общий словарь
            for doc, score in norm_vector_scores:
                doc_id = id(doc)  # Используем id объекта документа как ключ
                if doc_id not in combined_scores:
                    combined_scores[doc_id] = {"doc": doc, "vector_score": 0, "bm25_score": 0}
                combined_scores[doc_id]["vector_score"] = score
        
        # Нормализуем оценки BM25
        if bm25_results:
            # Нормализуем оценки (0-1)
            max_bm25_score = max(score for _, score in bm25_results) if bm25_results else 1.0
            if max_bm25_score > 0:  # Избегаем деления на ноль
                norm_bm25_scores = [(idx, score / max_bm25_score) for idx, score in bm25_results]
                
                # Добавляем нормализованные оценки в общий словарь
                for idx, score in norm_bm25_scores:
                    doc = self.documents[idx]
                    doc_id = id(doc)  # Используем id объекта документа как ключ
                    if doc_id not in combined_scores:
                        combined_scores[doc_id] = {"doc": doc, "vector_score": 0, "bm25_score": 0}
                    combined_scores[doc_id]["bm25_score"] = score
        
        # Вычисляем окончательную оценку, используя вес для смешивания
        for doc_id in combined_scores:
            vector_score = combined_scores[doc_id]["vector_score"]
            bm25_score = combined_scores[doc_id]["bm25_score"]
            
            # Взвешенная комбинация оценок
            final_score = weight * vector_score + (1 - weight) * bm25_score
            combined_scores[doc_id]["final_score"] = final_score
        
        # Сортируем по финальной оценке и выбираем top-k
        sorted_results = sorted(
            combined_scores.values(), 
            key=lambda x: x["final_score"], 
            reverse=True
        )[:k]
        
        # Форматируем результат как (документ, оценка)
        return [(item["doc"], item["final_score"]) for item in sorted_results]
    
    def adjust_weight(self, weight):
        """
        Регулирует вес смешивания результатов
        
        Args:
            weight (float): Новый вес (0-1)
            
        Returns:
            float: Установленный вес
        """
        # Ограничиваем вес в диапазоне [0, 1]
        weight = max(0.0, min(1.0, weight))
        
        # Устанавливаем новый вес
        STATE.hybrid_weight = weight
        
        # Сохраняем вес в настройках
        self.config_manager.set_setting("settings", "hybrid_weight", weight)
        
        print(f"✅ Вес гибридного поиска установлен: {weight:.2f}")
        print(f"   (0.0 = только BM25, 1.0 = только векторный поиск)")
        
        return weight
