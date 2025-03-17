# -*- coding: utf-8 -*-
"""
Основной модуль консультанта по кибербезопасности
"""

import os
import time
from datetime import datetime

from cybersec_consultant.config import ConfigManager
from cybersec_consultant.knowledge_base import KnowledgeBaseManager
from cybersec_consultant.embeddings import VectorSearchManager
from cybersec_consultant.hybrid_search import HybridSearchManager  # Добавляем импорт гибридного поиска
from cybersec_consultant.llm_interface import LLMInterface
from cybersec_consultant.prompt_management import PromptManager
from cybersec_consultant.state_management import STATE
from cybersec_consultant.context_manager import ContextManager


class CybersecurityConsultant:
    """Основной класс консультанта по кибербезопасности"""

    def __init__(self):
        """Инициализация консультанта"""
        # Инициализация компонентов
        self.config_manager = ConfigManager()
        self.kb_manager = KnowledgeBaseManager()
        self.vector_search = VectorSearchManager()
        self.hybrid_search = HybridSearchManager()  # Добавляем менеджер гибридного поиска
        self.llm_interface = LLMInterface()
        self.prompt_manager = PromptManager()
        self.context_manager = ContextManager()

        # Загружаем настройки из конфигурации
        self.use_hybrid_search = self.config_manager.get_setting("settings", "use_hybrid_search", True)  # По умолчанию включаем гибридный поиск
        
        print("🤖 Консультант по кибербезопасности инициализирован")

    def initialize_knowledge_base(self, file_path=None, force_reindex=False):
        """
        Инициализирует базу знаний и создает/загружает индексы

        Args:
            file_path (str): Путь к файлу базы знаний (опционально)
            force_reindex (bool): Принудительно пересоздать индексы

        Returns:
            bool: Успешность инициализации
        """
        try:
            # Загружаем базу знаний и разбиваем на чанки
            kb_text, documents = self.kb_manager.process_knowledge_base(file_path)
            if not kb_text or not documents:
                print("❌ Не удалось загрузить базу знаний.")
                return False

            # Определяем имя индекса
            index_name = "cybersec_index"
            index_path = os.path.join("indices", index_name)

            # Проверяем, существует ли индекс
            if os.path.exists(index_path) and not force_reindex:
                print(f"📁 Найден существующий индекс: {index_path}")
                
                # Загружаем векторный индекс
                if self.use_hybrid_search:
                    # Загружаем гибридный индекс
                    self.hybrid_search.load_indexes(index_name)
                else:
                    # Загружаем только векторный индекс
                    self.vector_search.load_index(index_name)
            else:
                # Создаем индекс
                print("🔄 Создание новых индексов...")
                
                if self.use_hybrid_search:
                    # Создаем гибридный индекс
                    self.hybrid_search.create_indexes(documents, index_name)
                else:
                    # Создаем только векторный индекс
                    self.vector_search.create_index(documents, index_name)

            return True
        except Exception as e:
            print(f"❌ Ошибка при инициализации базы знаний: {str(e)}")
            return False

    def search_knowledge_base(self, query, k=3, use_cache=True):
        """
        Выполняет поиск по базе знаний

        Args:
            query (str): Поисковый запрос
            k (int): Количество результатов
            use_cache (bool): Использовать кэш

        Returns:
            list: Список релевантных документов с оценками [(doc, score), ...]
        """
        if self.use_hybrid_search:
            # Используем гибридный поиск
            return self.hybrid_search.hybrid_search(query, k, use_cache)
        else:
            # Используем обычный векторный поиск
            return self.vector_search.search_documents_with_score(query, k, use_cache)

    def process_user_query(self, user_query, context=None):
        """
        Обрабатывает запрос пользователя и возвращает ответ

        Args:
            user_query (str): Запрос пользователя
            context (str): Контекст диалога (опционально)

        Returns:
            str: Ответ консультанта
        """
        print(f"🔄 Обработка запроса: '{user_query}'")

        # Засекаем время выполнения
        start_time = time.time()

        try:
            # Получаем релевантные документы из базы знаний
            search_results = self.search_knowledge_base(user_query)
            if not search_results:
                return "Извините, не удалось найти информацию по вашему запросу в базе знаний."

            # Форматируем документы для включения в промпт
            context_documents = []
            for doc, score in search_results:
                context_documents.append(f"--- Документ (релевантность: {score:.2f}) ---\n{doc.page_content}\n")

            # Обновляем контекст диалога
            if context:
                full_context = self.context_manager.update_context(user_query, context)
            else:
                full_context = self.context_manager.update_context(user_query)

            # Составляем промпт с релевантными документами и контекстом
            prompt = self.prompt_manager.create_consultant_prompt(
                user_query=user_query,
                context_documents="\n".join(context_documents),
                dialogue_context=full_context
            )

            # Запрашиваем ответ от языковой модели
            response = self.llm_interface.generate_text(prompt)

            # Обновляем контекст диалога с ответом
            self.context_manager.update_context(response, is_user=False)

            # Рассчитываем время выполнения
            execution_time = time.time() - start_time
            print(f"✅ Запрос обработан за {execution_time:.2f} сек.")

            return response
        except Exception as e:
            print(f"❌ Ошибка при обработке запроса: {str(e)}")
            return f"Произошла ошибка при обработке запроса: {str(e)}"

    def toggle_hybrid_search(self, enabled=None):
        """
        Включает или выключает гибридный поиск
        
        Args:
            enabled (bool): Включить гибридный поиск (если None, переключает текущее значение)
            
        Returns:
            bool: Новое состояние гибридного поиска
        """
        if enabled is None:
            # Переключаем текущее значение
            enabled = not self.use_hybrid_search
            
        # Устанавливаем новое значение
        self.use_hybrid_search = enabled
        
        # Сохраняем значение в настройках
        self.config_manager.set_setting("settings", "use_hybrid_search", enabled)
        
        if enabled:
            print("✅ Гибридный поиск ВКЛЮЧЕН (BM25 + векторный поиск)")
        else:
            print("✅ Гибридный поиск ВЫКЛЮЧЕН (только векторный поиск)")
            
        return enabled
        
    def adjust_hybrid_weight(self, weight):
        """
        Регулирует вес смешивания результатов гибридного поиска
        
        Args:
            weight (float): Вес (0-1), где 0 = только BM25, 1 = только векторный поиск
            
        Returns:
            float: Установленный вес
        """
        if not self.use_hybrid_search:
            print("⚠️ Гибридный поиск выключен. Сначала включите его через toggle_hybrid_search(True)")
            return None
            
        return self.hybrid_search.adjust_weight(weight)

    def run_interactive(self):
        """Запускает интерактивный режим консультанта"""
        print("\n" + "=" * 80)
        print("🤖 КОНСУЛЬТАНТ ПО КИБЕРБЕЗОПАСНОСТИ")
        print("=" * 80)
        print("Введите ваш запрос. Для выхода введите 'exit' или 'quit'.")

        # Инициализируем базу знаний, если она еще не инициализирована
        if not STATE.vector_db:
            self.initialize_knowledge_base()

        context = ""
        while True:
            print("\n" + "-" * 40)
            user_query = input("👤 Ваш запрос: ")
            
            if user_query.lower() in ["exit", "quit", "выход"]:
                print("👋 До свидания!")
                break
                
            # Обрабатываем команды
            if user_query.startswith("!hybrid"):
                parts = user_query.split()
                if len(parts) > 1:
                    if parts[1] == "on":
                        self.toggle_hybrid_search(True)
                    elif parts[1] == "off":
                        self.toggle_hybrid_search(False)
                    elif parts[1] == "weight" and len(parts) > 2:
                        try:
                            weight = float(parts[2])
                            self.adjust_hybrid_weight(weight)
                        except ValueError:
                            print("❌ Некорректное значение веса. Укажите число от 0 до 1.")
                else:
                    current_state = "ВКЛЮЧЕН" if self.use_hybrid_search else "ВЫКЛЮЧЕН"
                    print(f"ℹ️ Статус гибридного поиска: {current_state}")
                    if self.use_hybrid_search:
                        print(f"ℹ️ Вес гибридного поиска: {STATE.hybrid_weight:.2f} (0 = только BM25, 1 = только векторный)")
                    print("Команды:")
                    print("  !hybrid on - Включить гибридный поиск")
                    print("  !hybrid off - Выключить гибридный поиск")
                    print("  !hybrid weight 0.7 - Установить вес гибридного поиска (0-1)")
                continue

            # Обрабатываем обычный запрос
            response = self.process_user_query(user_query, context)
            
            print("\n🤖 Ответ:")
            print(response)
            
            # Обновляем контекст для следующего запроса
            context = f"{context}\nПользователь: {user_query}\nКонсультант: {response}"
