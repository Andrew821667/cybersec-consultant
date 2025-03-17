# -*- coding: utf-8 -*-
"""
Основной модуль консультанта по кибербезопасности
"""

import os
import sys
import time
from datetime import datetime
import hashlib
import json
import re

# Импорт модулей проекта
from cybersec_consultant.config import ConfigManager, DIALOGS_DIR, STATS_DIR
from cybersec_consultant.knowledge_base import KnowledgeBaseManager
from cybersec_consultant.embeddings import VectorSearchManager
from cybersec_consultant.llm_interface import LLMInterface
from cybersec_consultant.prompt_management import PromptManager

class CybersecurityConsultant:
    """Основной класс консультанта по кибербезопасности"""

    def __init__(self):
        """Инициализация консультанта"""
        # Инициализация компонентов
        self.config_manager = ConfigManager()
        self.kb_manager = KnowledgeBaseManager()
        self.vector_search = VectorSearchManager()
        self.llm_interface = LLMInterface()
        self.prompt_manager = PromptManager()
        
        # Создаем директории для сохранения диалогов и статистики
        os.makedirs(DIALOGS_DIR, exist_ok=True)
        os.makedirs(STATS_DIR, exist_ok=True)
        
        # Настройки по умолчанию
        self.model = self.config_manager.get_setting("models", "default", "gpt-4o-mini")
        self.profile = "standard"
        self.k_docs = self.config_manager.get_setting("settings", "search_k", 3)
        self.use_cache = True
        
        # Статистика сессии
        self.session_stats = {
            "start_time": datetime.now().isoformat(),
            "queries": [],
            "models_used": set(),
            "profiles_used": set(),
            "total_tokens": 0,
            "total_cost": 0,
            "total_time": 0
        }
        
        # Идентификатор текущей сессии
        self.session_id = datetime.now().strftime("%Y%m%d_%H%M%S")
        
        # Создаем директорию для текущей сессии
        self.session_dir = os.path.join(DIALOGS_DIR, f"session_{self.session_id}")
        os.makedirs(self.session_dir, exist_ok=True)
        
        # Файл для сохранения статистики
        self.stats_file = os.path.join(STATS_DIR, f"session_stats_{self.session_id}.txt")
        with open(self.stats_file, "w", encoding="utf-8") as f:
            f.write(f"=== НОВАЯ СЕССИЯ: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')} ===\n")
            f.write(f"Модель по умолчанию: {self.model}\n")
            f.write(f"Профиль по умолчанию: {self.profile}\n")
            f.write(f"Документов для поиска: {self.k_docs}\n")
            f.write("=" * 80 + "\n")
            f.write("Запрос | Время | Кэш | Токены | Стоимость | Файл\n")
            f.write("-" * 80 + "\n")
    
    def load_knowledge_base(self, file_path=None):
        """
        Загружает базу знаний и создает индекс

        Args:
            file_path (str): Путь к файлу с базой знаний (опционально)

        Returns:
            bool: True если операция успешна, иначе False
        """
        try:
            # Загружаем базу знаний и разбиваем на чанки
            kb_text, documents = self.kb_manager.process_knowledge_base(file_path)
            if not documents:
                return False
            
            # Создаем индекс
            db = self.vector_search.create_index(documents, "cybersec_index")
            return db is not None
        except Exception as e:
            print(f"❌ Ошибка при загрузке базы знаний: {str(e)}")
            return False
    
    def load_index(self):
        """
        Загружает существующий индекс

        Returns:
            bool: True если операция успешна, иначе False
        """
        try:
            db = self.vector_search.load_index("cybersec_index")
            return db is not None
        except Exception as e:
            print(f"❌ Ошибка при загрузке индекса: {str(e)}")
            return False
    
    def search_documents(self, query, k=None, use_cache=None):
        """
        Ищет документы по запросу

        Args:
            query (str): Поисковый запрос
            k (int): Количество документов для поиска
            use_cache (bool): Использовать кэш или нет

        Returns:
            list: Список кортежей (документ, оценка)
        """
        if k is None:
            k = self.k_docs
        
        if use_cache is None:
            use_cache = self.use_cache
            
        return self.vector_search.search_documents_with_score(query, k=k, use_cache=use_cache)
    
    def prepare_context(self, docs_with_scores):
        """
        Подготавливает контекст для генерации ответа

        Args:
            docs_with_scores (list): Список документов с оценками релевантности

        Returns:
            str: Подготовленный контекст с метаданными
        """
        context_parts = []

        # Сортируем документы по релевантности (от наиболее релевантных к менее)
        sorted_docs = sorted(docs_with_scores, key=lambda x: x[1])

        for i, (doc, score) in enumerate(sorted_docs):
            # Рассчитываем релевантность
            relevance = max(0, min(100, 100 * (1 - score / 2)))

            # Формируем метаданные документа
            metadata = doc.metadata.copy() if hasattr(doc, 'metadata') and doc.metadata else {}
            source = metadata.get('source', 'База знаний по кибербезопасности')
            categories = metadata.get('categories', [])
            categories_info = f" | Категории: {', '.join(categories)}" if categories else ""

            # Создаем заголовок документа
            header = f"ДОКУМЕНТ #{i+1} [Релевантность: {relevance:.2f}%]{categories_info}"

            # Формируем блок контекста
            context_part = f"""
{header}
ИСТОЧНИК: {source}
СОДЕРЖАНИЕ:
{doc.page_content}
"""
            context_parts.append(context_part)

        # Объединяем все части контекста
        combined_context = "\n\n---\n\n".join(context_parts)

        return combined_context

    def generate_answer(self, query, docs_with_scores, model=None, temperature=0, profile=None, use_cache=None):
        """
        Генерирует ответ на основе релевантных документов

        Args:
            query (str): Запрос пользователя
            docs_with_scores (list): Список документов с оценками релевантности
            model (str): Модель для генерации
            temperature (float): Температура генерации
            profile (str): Профиль для ответа
            use_cache (bool): Использовать кэш или нет

        Returns:
            dict: Словарь с ответом и метаданными
        """
        # Используем параметры по умолчанию, если не указаны
        if model is None:
            model = self.model
            
        if profile is None:
            profile = self.profile
            
        if use_cache is None:
            use_cache = self.use_cache
        
        # Получаем системный промпт для выбранного профиля
        system_prompt = self.prompt_manager.get_prompt(profile)
        
        # Получаем инструкцию
        instruction = self.prompt_manager.get_instruction_prompt()
        
        # Подготавливаем контекст
        combined_context = self.prepare_context(docs_with_scores)
        
        # Формируем полный запрос
        user_prompt = f"Информация из базы знаний по кибербезопасности:\n\n{combined_context}\n\nВопрос пользователя:\n{query}"
        
        # Генерируем ответ
        full_system_prompt = system_prompt + "\n" + instruction
        response_data = self.llm_interface.generate_answer(
            system_prompt=full_system_prompt,
            user_prompt=user_prompt,
            model=model,
            temperature=temperature,
            use_cache=use_cache
        )
        
        return response_data
    
    def answer_question(self, query, model=None, temperature=0, profile=None, k=None, use_cache=None):
        """
        Полный процесс ответа на вопрос пользователя

        Args:
            query (str): Запрос пользователя
            model (str): Модель для генерации
            temperature (float): Температура генерации
            profile (str): Профиль для ответа
            k (int): Количество документов для поиска
            use_cache (bool): Использовать кэш или нет

        Returns:
            dict: Словарь с ответом и метаданными
        """
        # Используем параметры по умолчанию, если не указаны
        if model is None:
            model = self.model
            
        if profile is None:
            profile = self.profile
            
        if k is None:
            k = self.k_docs
            
        if use_cache is None:
            use_cache = self.use_cache
        
        try:
            # Общее время выполнения
            start_time = time.time()
            
            # 1. Поиск документов
            print(f"🔍 Поиск документов по запросу: '{query}'")
            search_start = time.time()
            docs_with_scores = self.search_documents(query, k=k, use_cache=use_cache)
            search_time = time.time() - search_start
            
            # Если документы не найдены
            if not docs_with_scores:
                error_message = "К сожалению, не удалось найти релевантные документы по вашему запросу."
                return {
                    "answer": error_message,
                    "success": False,
                    "cached": False,
                    "model": model,
                    "tokens": 0,
                    "execution_time": time.time() - start_time,
                    "cost": 0
                }
            
            # 2. Генерация ответа
            print(f"🤖 Генерация ответа...")
            response_data = self.generate_answer(
                query=query,
                docs_with_scores=docs_with_scores,
                model=model,
                temperature=temperature,
                profile=profile,
                use_cache=use_cache
            )
            
            # Добавляем дополнительные метаданные
            response_data["documents_count"] = len(docs_with_scores)
            response_data["search_time"] = search_time
            response_data["total_time"] = time.time() - start_time
            
            # 3. Сохраняем ответ в файл
            filename = self._save_dialog_to_file(query, response_data)
            response_data["filename"] = filename
            
            # 4. Обновляем статистику сессии
            self._update_session_stats(query, response_data)
            
            return response_data
            
        except Exception as e:
            error_message = f"Ошибка при обработке запроса: {str(e)}"
            print(f"❌ {error_message}")
            
            # Пишем ошибку в лог
            self._log_error(query, str(e))
            
            return {
                "answer": error_message,
                "success": False,
                "cached": False,
                "model": model,
                "tokens": 0,
                "execution_time": time.time() - start_time if 'start_time' in locals() else 0,
                "cost": 0,
                "error": str(e)
            }
    
    def _save_dialog_to_file(self, query, response_data):
        """
        Сохраняет диалог в файл

        Args:
            query (str): Запрос пользователя
            response_data (dict): Данные ответа

        Returns:
            str: Имя сохраненного файла
        """
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        query_part = "".join(x for x in query[:30] if x.isalnum() or x.isspace()).strip().replace(" ", "_")
        if not query_part:
            query_part = "dialog"
        filename = f"{timestamp}_{query_part}.md"
        filepath = os.path.join(self.session_dir, filename)

        answer = response_data.get("answer", "Ответ не получен")
        model = response_data.get("model", "Неизвестная модель")
        profile = response_data.get("profile", self.profile)
        k_docs = response_data.get("documents_count", self.k_docs)
        is_cached = response_data.get("cached", False)
        execution_time = response_data.get("total_time", 0)
        
        dialog_content = f"# Запрос к консультанту по кибербезопасности\n\n"
        dialog_content += f"**Дата и время:** {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n\n"
        dialog_content += f"**Запрос:** {query}\n\n"
        dialog_content += f"**Модель:** {model}\n\n"
        dialog_content += f"**Профиль:** {profile}\n\n"
        dialog_content += f"**Использован кэш:** {'Да' if is_cached else 'Нет'}\n\n"
        dialog_content += f"**Время выполнения:** {execution_time:.2f} сек.\n\n"
        dialog_content += f"**Документов:** {k_docs}\n\n"
        dialog_content += "=" * 80 + "\n\n"
        dialog_content += "## ОТВЕТ КОНСУЛЬТАНТА\n\n"
        dialog_content += answer + "\n\n" + "=" * 80 + "\n"

        with open(filepath, "w", encoding="utf-8") as f:
            f.write(dialog_content)
            
        # Обновляем статистику в файле
        tokens = response_data.get("tokens", 0)
        cost = response_data.get("cost", 0)
        with open(self.stats_file, "a", encoding="utf-8") as f:
            f.write(f"{query[:20].replace('|', ' ')}... | {execution_time:.2f}с | {'Да' if is_cached else 'Нет'} | {tokens} | ${cost:.6f} | {filename}\n")
            
        print(f"💾 Ответ сохранен в файл: {filepath}")
        return filename
        
    def _update_session_stats(self, query, response_data):
        """
        Обновляет статистику сессии

        Args:
            query (str): Запрос пользователя
            response_data (dict): Данные ответа
        """
        model = response_data.get("model", self.model)
        profile = response_data.get("profile", self.profile)
        tokens = response_data.get("tokens", 0)
        cost = response_data.get("cost", 0)
        execution_time = response_data.get("total_time", 0)
        is_cached = response_data.get("cached", False)
        
        # Добавляем информацию о запросе
        self.session_stats["queries"].append({
            "query": query,
            "model": model,
            "profile": profile,
            "time": execution_time,
            "tokens": tokens,
            "cost": cost,
            "cached": is_cached
        })
        
        # Обновляем общую статистику
        self.session_stats["models_used"].add(model)
        self.session_stats["profiles_used"].add(profile)
        self.session_stats["total_tokens"] += 0 if is_cached else tokens
        self.session_stats["total_cost"] += 0 if is_cached else cost
        self.session_stats["total_time"] += execution_time
    
    def _log_error(self, query, error_message):
        """
        Записывает ошибку в лог

        Args:
            query (str): Запрос пользователя
            error_message (str): Сообщение об ошибке
        """
        error_log_path = os.path.join(STATS_DIR, "errors.log")
        with open(error_log_path, "a", encoding="utf-8") as f:
            f.write(f"=== ОШИБКА {datetime.now().strftime('%Y-%m-%d %H:%M:%S')} ===\n")
            f.write(f"Сессия: {self.session_id}\n")
            f.write(f"Запрос: {query}\n")
            f.write(f"Модель: {self.model}\n")
            f.write(f"Профиль: {self.profile}\n")
            f.write(f"Ошибка: {error_message}\n")
            f.write("\n" + "=" * 50 + "\n")
    
    def save_session_stats(self):
        """
        Сохраняет итоговую статистику сессии

        Returns:
            str: Путь к файлу статистики
        """
        # Добавляем время завершения
        self.session_stats["end_time"] = datetime.now().isoformat()
        
        # Преобразуем множества в списки для сохранения в JSON
        self.session_stats["models_used"] = list(self.session_stats["models_used"])
        self.session_stats["profiles_used"] = list(self.session_stats["profiles_used"])
        
        # Сохраняем полную статистику в JSON
        json_stats_file = os.path.join(STATS_DIR, f"session_stats_{self.session_id}.json")
        with open(json_stats_file, "w", encoding="utf-8") as f:
            json.dump(self.session_stats, f, ensure_ascii=False, indent=2)
        
        # Добавляем итоговую статистику в текстовый файл
        with open(self.stats_file, "a", encoding="utf-8") as f:
            f.write("-" * 80 + "\n")
            queries_count = len(self.session_stats["queries"])
            cache_hits = sum(1 for q in self.session_stats["queries"] if q.get("cached", False))
            f.write(f"Итого запросов: {queries_count}, использовано кэша: {cache_hits}, новых запросов: {queries_count - cache_hits}\n")
            if queries_count > 0:
                f.write(f"Эффективность кэширования: {cache_hits/queries_count*100:.2f}%\n")
            f.write(f"Общее время: {self.session_stats['total_time']:.2f} сек.\n")
            f.write(f"Общие токены: {self.session_stats['total_tokens']}\n")
            f.write(f"Общая стоимость: ${self.session_stats['total_cost']:.6f}\n")
            f.write(f"Завершение сессии: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n")
        
        return json_stats_file
    
    def print_session_stats(self):
        """Выводит статистику текущей сессии"""
        queries_count = len(self.session_stats["queries"])
        if queries_count == 0:
            print("Нет данных для статистики. Задайте несколько вопросов.")
            return
            
        cache_hits = sum(1 for q in self.session_stats["queries"] if q.get("cached", False))
        
        print("\nСтатистика текущей сессии:")
        print("=" * 60)
        print(f"- Всего запросов: {queries_count}")
        print(f"- Использовано кэша: {cache_hits} ({cache_hits/queries_count*100:.1f}%)")
        print(f"- Общее время: {self.session_stats['total_time']:.2f} сек.")
        print(f"- Общие токены: {self.session_stats['total_tokens']}")
        print(f"- Общая стоимость: ${self.session_stats['total_cost']:.6f}")
        print(f"- Использованные модели: {', '.join(self.session_stats['models_used'])}")
        print(f"- Использованные профили: {', '.join(self.session_stats['profiles_used'])}")
    
    def run_interactive_mode(self):
        """Запускает интерактивный режим консультанта"""
        
        # Проверяем наличие индекса
        index_loaded = self.load_index()
        if not index_loaded:
            print("⚠️ Не удалось загрузить индекс. Попробуем создать новый.")
            
            create_new = input("Хотите создать индекс из демонстрационной базы знаний? (y/n): ").lower().strip() == 'y'
            if create_new:
                index_created = self.load_knowledge_base()
                if not index_created:
                    print("❌ Не удалось создать индекс. Некоторые функции будут недоступны.")
                    return
            else:
                print("❌ Без индекса невозможно выполнять поиск документов. Завершение работы.")
                return
        
        # Выводим информацию о доступных командах
        self._print_help()
        
        # Статистика кэширования
        cache_hits = 0
        cache_misses = 0
        total_queries = 0
        
        try:
            # Главный цикл интерактивного режима
            while True:
                user_query = input("\nВаш вопрос: ")
                
                # Обработка выхода
                if user_query.lower() in ['выход', 'exit', 'quit', 'q']:
                    print("\nСпасибо за использование консультанта. До свидания!")
                    
                    # Сохраняем итоговую статистику
                    stats_file = self.save_session_stats()
                    print(f"Статистика использования сохранена в файл: {stats_file}")
                    break
                
                # Если пустой запрос, пропускаем
                if not user_query.strip():
                    continue
                
                # Обработка команд
                if user_query.startswith('!'):
                    self._process_command(user_query[1:])
                    continue
                
                # Если не команда, обрабатываем как запрос
                total_queries += 1
                
                # Для отслеживания использования кэша
                cache_key = hashlib.md5(f"{user_query}_{self.k_docs}_{self.model}_{self.profile}".encode()).hexdigest()
                is_cached = cache_key in self.llm_interface.response_cache
                
                if is_cached:
                    cache_hits += 1
                else:
                    cache_misses += 1
                
                # Генерируем ответ
                response_data = self.answer_question(user_query)
                
                # Выводим основную информацию
                answer = response_data.get("answer", "Не удалось получить ответ")
                execution_time = response_data.get("total_time", 0)
                
                print(f"\n{'=' * 80}")
                print(f"ОТВЕТ КОНСУЛЬТАНТА:")
                print(f"{'=' * 80}")
                print(answer)
                print(f"{'=' * 80}")
                
                print(f"\nОтвет сгенерирован за {execution_time:.2f} сек.")
                
                if is_cached:
                    print(f"Использован кэш (токены не потрачены)")
                else:
                    tokens = response_data.get("tokens", 0)
                    cost = response_data.get("cost", 0)
                    print(f"Использовано примерно {tokens} токенов (≈${cost:.4f})")
                
        except KeyboardInterrupt:
            print("\n\nОперация прервана. Введите 'выход' для завершения или продолжайте задавать вопросы.")
        except Exception as e:
            print(f"\nОшибка при обработке запроса: {str(e)}")
            self._log_error("Ошибка в интерактивном режиме", str(e))
    
    def _process_command(self, command):
        """
        Обрабатывает команды в интерактивном режиме

        Args:
            command (str): Команда без префикса '!'
        """
        command = command.lower().strip()
        
        # Команда: модель
        if command.startswith('модель') or command.startswith('model'):
            model_name = command.split(' ', 1)[1] if ' ' in command else None
            available_models = list(self.config_manager.get_setting("models", "available", []))
            available_model_ids = [m.get("id") for m in available_models if "id" in m]
            
            if model_name in available_model_ids:
                self.model = model_name
                print(f"Модель изменена на: {model_name}")
            else:
                print(f"Доступные модели: {', '.join(available_model_ids)}")
                print(f"Текущая модель: {self.model}")
        
        # Команда: профиль
        elif command.startswith('профиль') or command.startswith('profile'):
            profile_name = command.split(' ', 1)[1] if ' ' in command else None
            available_profiles = list(self.prompt_manager.prompts.keys())
            
            if profile_name in available_profiles:
                self.profile = profile_name
                print(f"Профиль ответов изменен на: {profile_name}")
            else:
                print(f"Доступные профили: {', '.join(available_profiles)}")
                print(f"Текущий профиль: {self.profile}")
        
        # Команда: документы
        elif command.startswith('документы') or command.startswith('docs'):
            try:
                k_value = int(command.split(' ', 1)[1]) if ' ' in command else None
                if k_value and 1 <= k_value <= 5:
                    self.k_docs = k_value
                    print(f"Количество документов изменено на: {self.k_docs}")
                else:
                    print(f"Укажите число от 1 до 5. Текущее значение: {self.k_docs}")
            except:
                print(f"Укажите число от 1 до 5. Текущее значение: {self.k_docs}")
        
        # Команда: кэш
        elif command.startswith('кэш') or command.startswith('cache'):
            cache_option = command.split(' ', 1)[1] if ' ' in command else None
            if cache_option in ['вкл', 'on', 'true', '1']:
                self.use_cache = True
                print(f"Использование кэша включено")
            elif cache_option in ['выкл', 'off', 'false', '0']:
                self.use_cache = False
                print(f"Использование кэша выключено")
            else:
                self.use_cache = not self.use_cache
                print(f"Использование кэша {'включено' if self.use_cache else 'выключено'}")
        
        # Команда: инфо
        elif command == 'инфо' or command == 'info':
            self._print_info()
        
        # Команда: статистика
        elif command == 'статистика' or command == 'stats':
            self.print_session_stats()
        
        # Команда: помощь
        elif command == 'помощь' or command == 'help':
            self._print_help()
        
        # Неизвестная команда
        else:
            print(f"Неизвестная команда. Введите !помощь для списка команд.")
    
    def _print_help(self):
        """Выводит справку по доступным командам"""
        print("\nДоступные команды:")
        print("=" * 60)
        print("- !модель [название] - изменить модель")
        print("- !профиль [название] - изменить профиль ответов")
        print("- !документы [число] - изменить количество документов (1-5)")
        print("- !кэш [вкл/выкл] - включить/выключить использование кэша")
        print("- !инфо - показать текущие настройки")
        print("- !статистика - показать статистику текущей сессии")
        print("- !помощь - показать эту справку")
        print("\nДля завершения работы введите 'выход', 'exit', 'quit' или 'q'")
    
    def _print_info(self):
        """Выводит информацию о текущих настройках"""
        index_status = "Загружен" if self.vector_search.vector_db else "Не загружен"
        
        print("\nТекущие настройки:")
        print("=" * 60)
        print(f"- Модель: {self.model}")
        print(f"- Профиль ответов: {self.profile}")
        print(f"- Количество документов: {self.k_docs}")
        print(f"- Использование кэша: {'Включено' if self.use_cache else 'Выключено'}")
        print(f"- Индекс: {index_status}")
        print(f"- ID сессии: {self.session_id}")
        print(f"- Директория сессии: {self.session_dir}")
        
        # Статистика запросов
        queries_count = len(self.session_stats["queries"])
        cache_hits = sum(1 for q in self.session_stats["queries"] if q.get("cached", False))
        print(f"- Всего запросов: {queries_count}")
        print(f"- Использовано кэша: {cache_hits}")
