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
from cybersec_consultant.hybrid_search import HybridSearchManager
from cybersec_consultant.llm_interface import LLMInterface
from cybersec_consultant.prompt_management import PromptManager
from cybersec_consultant.state_management import STATE
from cybersec_consultant.context_manager import ContextManager
from cybersec_consultant.knowledge_enrichment import get_enrichment_manager
from cybersec_consultant.user_profiles import get_profile_manager
from cybersec_consultant.external_services import ExternalServicesManager


class CybersecurityConsultant:
    """Основной класс консультанта по кибербезопасности"""

    def __init__(self):
        """Инициализация консультанта"""
        # Инициализация компонентов
        self.config_manager = ConfigManager()
        self.kb_manager = KnowledgeBaseManager()
        self.vector_search = VectorSearchManager()
        self.hybrid_search = HybridSearchManager()
        self.llm_interface = LLMInterface()
        self.prompt_manager = PromptManager()
        self.context_manager = ContextManager()
        
        # Новые компоненты функциональных улучшений
        self.enrichment_manager = get_enrichment_manager()
        self.profile_manager = get_profile_manager()
        self.external_services = ExternalServicesManager()

        # Загружаем настройки из конфигурации
        self.use_hybrid_search = self.config_manager.get_setting("settings", "use_hybrid_search", True)
        
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
            # Проверяем специальные команды для внешних сервисов
            if user_query.startswith("!cve "):
                cve_id = user_query[5:].strip()
                return self.get_cve_info(cve_id)
            elif user_query.startswith("!mitre "):
                query = user_query[7:].strip()
                return self.search_mitre(query)
            elif user_query.startswith("!threat "):
                query = user_query[8:].strip()
                return self.get_threat_info(query)
            
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

            # Получаем профиль пользователя и применяем персонализацию
            profile = self.profile_manager.get_profile()
            profile_prompt_mod = self.profile_manager.generate_profile_prompt_modification()

            # Составляем промпт с релевантными документами, контекстом и профилем
            prompt = self.prompt_manager.create_consultant_prompt(
                user_query=user_query,
                context_documents="\n".join(context_documents),
                dialogue_context=full_context,
                profile_customization=profile_prompt_mod  # Добавляем модификацию промпта профиля
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

    # Новые методы для работы с обогащением базы знаний
    def enrich_knowledge_base(self, force_update=False):
        """
        Обогащает базу знаний данными из внешних источников
        
        Args:
            force_update (bool): Принудительное обновление
            
        Returns:
            tuple: (успешность операции, сообщение)
        """
        print("🔄 Запуск обогащения базы знаний...")
        success, message = self.enrichment_manager.enrich_knowledge_base(force_update)
        
        if success:
            # Переиндексируем базу знаний после обогащения
            print("🔄 Обновление индексов после обогащения базы знаний...")
            
            # Разбиваем обновленный текст на чанки
            documents = self.kb_manager.split_text_into_chunks(STATE.knowledge_base_text)
            
            # Обновляем индексы
            index_name = "cybersec_index"
            if self.use_hybrid_search:
                # Создаем гибридный индекс
                self.hybrid_search.create_indexes(documents, index_name)
            else:
                # Создаем только векторный индекс
                self.vector_search.create_index(documents, index_name)
                
            print("✅ Индексы успешно обновлены")
            
        return success, message
        
    def start_auto_enrichment(self, interval_hours=None):
        """
        Запускает автоматическое обогащение базы знаний
        
        Args:
            interval_hours (int): Интервал обновления в часах
            
        Returns:
            bool: Успешность запуска
        """
        return self.enrichment_manager.start_auto_update(interval_hours)
        
    def stop_auto_enrichment(self):
        """
        Останавливает автоматическое обогащение базы знаний
        
        Returns:
            bool: Успешность остановки
        """
        return self.enrichment_manager.stop_auto_update()

    # Новые методы для работы с профилями пользователей
    def set_user_profile(self, profile_id):
        """
        Устанавливает профиль пользователя
        
        Args:
            profile_id (str): Идентификатор профиля
            
        Returns:
            bool: Успешность операции
        """
        success = self.profile_manager.set_current_profile(profile_id)
        
        if success:
            print(f"✅ Установлен профиль пользователя: {profile_id}")
        else:
            print(f"❌ Ошибка при установке профиля: {profile_id}")
            
        return success
        
    def get_available_profiles(self):
        """
        Получает список доступных профилей пользователей
        
        Returns:
            dict: Словарь доступных профилей
        """
        return self.profile_manager.profiles
        
    def create_custom_profile(self, profile_id, profile_config):
        """
        Создает пользовательский профиль
        
        Args:
            profile_id (str): Идентификатор профиля
            profile_config (dict): Конфигурация профиля
            
        Returns:
            bool: Успешность операции
        """
        return self.profile_manager.add_custom_profile(profile_id, profile_config)

    # Новые методы для работы с внешними сервисами
    def get_cve_info(self, cve_id):
        """
        Получает информацию о CVE уязвимости
        
        Args:
            cve_id (str): Идентификатор CVE
            
        Returns:
            str: Форматированная информация об уязвимости
        """
        print(f"🔍 Поиск информации о CVE: {cve_id}...")
        cve_data = self.external_services.get_cve_info(cve_id)
        
        if "error" in cve_data:
            return f"Ошибка при получении информации о {cve_id}: {cve_data['error']}"
            
        # Форматируем вывод
        result = f"## Информация об уязвимости {cve_data['id']}\n\n"
        
        # Описание
        result += f"**Описание:** {cve_data['description']}\n\n"
        
        # CVSS оценка
        if cve_data.get('score'):
            severity = cve_data.get('severity', 'Не указана')
            result += f"**Оценка CVSS:** {cve_data['score']} ({severity})\n"
            
            if cve_data.get('vector'):
                result += f"**Вектор CVSS:** `{cve_data['vector']}`\n"
                
        # Даты
        if cve_data.get('published'):
            result += f"**Опубликовано:** {cve_data['published']}\n"
        if cve_data.get('last_modified'):
            result += f"**Последнее обновление:** {cve_data['last_modified']}\n"
            
        # Ссылки
        if cve_data.get('references'):
            result += "\n**Ссылки:**\n"
            for ref in cve_data['references'][:5]:  # Ограничиваем до 5 ссылок
                result += f"- {ref['url']}\n"
                
        result += f"\n**Подробнее:** {cve_data['url']}\n"
        
        return result
        
    def search_mitre(self, query):
        """
        Поиск по базе MITRE ATT&CK
        
        Args:
            query (str): Поисковый запрос
            
        Returns:
            str: Форматированные результаты поиска
        """
        print(f"🔍 Поиск в MITRE ATT&CK: {query}...")
        mitre_data = self.external_services.query_mitre_att_ck(query)
        
        # Форматируем вывод
        result = f"## Результаты поиска в MITRE ATT&CK: '{query}'\n\n"
        
        # Проверяем наличие данных
        has_data = False
        for section, items in mitre_data.items():
            if items:
                has_data = True
                break
                
        if not has_data:
            return f"{result}Ничего не найдено по запросу '{query}'."
            
        # Тактики
        if mitre_data.get('tactics'):
            result += "### Тактики\n\n"
            for tactic in mitre_data['tactics'][:3]:
                name = tactic.get('name', 'Без названия')
                name_ru = tactic.get('name_ru', '')
                if name_ru:
                    name += f" ({name_ru})"
                    
                result += f"**{name}**\n"
                
                if tactic.get('description'):
                    result += f"{tactic['description'][:200]}...\n\n"
                    
        # Техники
        if mitre_data.get('techniques'):
            result += "### Техники\n\n"
            for technique in mitre_data['techniques'][:3]:
                # Ищем ID техники
                technique_id = "Unknown"
                for ref in technique.get('external_references', []):
                    if ref.get('source_name') == 'mitre-attack':
                        technique_id = ref.get('external_id', 'Unknown')
                        break
                        
                result += f"**{technique.get('name', 'Без названия')} ({technique_id})**\n"
                
                if technique.get('description'):
                    result += f"{technique['description'][:200]}...\n\n"
                    
        # Группы
        if mitre_data.get('groups'):
            result += "### Группы угроз\n\n"
            for group in mitre_data['groups'][:3]:
                # Ищем ID группы
                group_id = "Unknown"
                for ref in group.get('external_references', []):
                    if ref.get('source_name') == 'mitre-attack':
                        group_id = ref.get('external_id', 'Unknown')
                        break
                        
                result += f"**{group.get('name', 'Без названия')} ({group_id})**\n"
                
                if group.get('description'):
                    result += f"{group['description'][:200]}...\n\n"
                    
                if group.get('aliases'):
                    result += f"*Также известна как: {', '.join(group['aliases'])}*\n\n"
                    
        # Программное обеспечение
        if mitre_data.get('software'):
            result += "### Вредоносное ПО и инструменты\n\n"
            for sw in mitre_data['software'][:3]:
                # Ищем ID ПО
                sw_id = "Unknown"
                for ref in sw.get('external_references', []):
                    if ref.get('source_name') == 'mitre-attack':
                        sw_id = ref.get('external_id', 'Unknown')
                        break
                        
                sw_type = "Вредоносное ПО" if sw.get('type') == 'malware' else "Инструмент"
                result += f"**{sw.get('name', 'Без названия')} ({sw_id})** - {sw_type}\n"
                
                if sw.get('description'):
                    result += f"{sw['description'][:200]}...\n\n"
                    
                if sw.get('aliases'):
                    result += f"*Также известно как: {', '.join(sw['aliases'])}*\n\n"
                    
        result += "\nПримечание: Показаны только первые 3 результата в каждой категории."
        
        return result
        
    def get_threat_info(self, query):
        """
        Получает информацию об угрозах
        
        Args:
            query (str): Запрос (IP, домен, хэш и т.д.)
            
        Returns:
            str: Форматированная информация об угрозе
        """
        print(f"🔍 Поиск информации об угрозе: {query}...")
        threat_data = self.external_services.get_threat_intelligence(query)
        
        if not threat_data.get('found', False):
            return f"Не удалось найти информацию по запросу: {query}"
            
        # Форматируем вывод в зависимости от типа запроса
        query_type = threat_data.get('query_type', 'unknown')
        data = threat_data.get('data', {})
        
        result = f"## Анализ угроз: {query}\n\n"
        
        # IP адрес
        if query_type == 'ip':
            result += f"**Тип:** IP-адрес\n"
            
            # Геолокация
            if 'geolocation' in data:
                geo = data['geolocation']
                country = geo.get('country', 'Неизвестно')
                city = geo.get('city', '')
                org = geo.get('org', '')
                
                result += f"**Местоположение:** {country}"
                if city:
                    result += f", {city}"
                result += "\n"
                
                if org:
                    result += f"**Организация:** {org}\n"
                    
            # Информация об угрозах
            if 'abuseipdb' in data:
                abuse = data['abuseipdb']
                score = abuse.get('abuse_confidence_score')
                
                if score is not None:
                    result += f"**Оценка угрозы:** {score}%\n"
                    
                reports = abuse.get('total_reports')
                if reports:
                    result += f"**Количество отчетов:** {reports}\n"
                    
                status = data.get('threat_status')
                if status:
                    result += f"**Статус:** {status}\n"
                    
        # Домен
        elif query_type == 'domain':
            result += f"**Тип:** Домен\n"
            
            # IP адрес
            if 'ip' in data:
                result += f"**IP-адрес:** {data['ip']}\n"
                
            # WHOIS информация
            if 'whois' in data:
                whois = data['whois']
                result += "\n### WHOIS информация\n\n"
                
                if 'registrar' in whois:
                    result += f"**Регистратор:** {whois['registrar']}\n"
                    
                if 'creation_date' in whois:
                    result += f"**Дата создания:** {whois['creation_date']}\n"
                    
                if 'expiration_date' in whois:
                    result += f"**Дата истечения:** {whois['expiration_date']}\n"
                    
            # SSL сертификат
            if 'ssl_certificate' in data:
                ssl = data['ssl_certificate']
                result += "\n### SSL сертификат\n\n"
                
                if 'issued_to' in ssl:
                    result += f"**Выдан для:** {ssl['issued_to']}\n"
                    
                if 'issued_by' in ssl:
                    result += f"**Выдан:** {ssl['issued_by']}\n"
                    
                if 'valid_from' in ssl and 'valid_until' in ssl:
                    result += f"**Действителен:** с {ssl['valid_from']} по {ssl['valid_until']}\n"
                    
                if 'is_valid' in ssl:
                    status = "Действителен" if ssl['is_valid'] else "Недействителен"
                    result += f"**Статус:** {status}\n"
                    
        # Хэш файла
        elif query_type in ['hash_md5', 'hash_sha1', 'hash_sha256']:
            hash_type = query_type.replace('hash_', '').upper()
            result += f"**Тип:** Хэш файла ({hash_type})\n"
            
            # VirusTotal информация
            if 'virustotal' in data:
                vt = data['virustotal']
                result += "\n### Результаты проверки VirusTotal\n\n"
                
                if 'meaningful_name' in vt:
                    result += f"**Имя файла:** {vt['meaningful_name']}\n"
                    
                if 'type_description' in vt:
                    result += f"**Тип файла:** {vt['type_description']}\n"
                    
                if 'size' in vt:
                    result += f"**Размер:** {vt['size']} байт\n"
                    
                if 'last_analysis_stats' in vt:
                    stats = vt['last_analysis_stats']
                    result += f"**Результаты анализа:**\n"
                    result += f"- Вредоносный: {stats.get('malicious', 0)}\n"
                    result += f"- Подозрительный: {stats.get('suspicious', 0)}\n"
                    result += f"- Безопасный: {stats.get('harmless', 0)}\n"
                    
                status = data.get('threat_status')
                if status:
                    result += f"\n**Статус:** {status}\n"
                    
        # URL
        elif query_type == 'url':
            result += f"**Тип:** URL\n"
            
            # Анализ URL
            if 'url_analysis' in data:
                url_data = data['url_analysis']
                result += f"**Схема:** {url_data.get('scheme', '')}\n"
                result += f"**Домен:** {url_data.get('domain', '')}\n"
                
            # Информация о безопасности
            if 'safebrowsing' in data:
                sb = data['safebrowsing']
                threats = sb.get('threats', [])
                
                if threats:
                    result += "\n### Угрозы в Google Safe Browsing\n\n"
                    for threat in threats:
                        result += f"- {threat.get('threatType', 'Неизвестная угроза')}\n"
                else:
                    result += "\n**Google Safe Browsing:** Угрозы не обнаружены\n"
                    
            status = data.get('threat_status')
            if status:
                result += f"\n**Статус:** {status}\n"
                
        # Текстовый запрос
        else:
            result += f"**Тип:** Текстовый запрос\n\n"
            
            # Найденные индикаторы
            if 'indicators' in data:
                indicators = data['indicators']
                has_indicators = False
                
                for ind_type, values in indicators.items():
                    if values:
                        has_indicators = True
                        break
                        
                if has_indicators:
                    result += "### Обнаруженные индикаторы\n\n"
                    
                    if indicators.get('ips'):
                        result += f"**IP-адреса:** {', '.join(indicators['ips'][:5])}"
                        if len(indicators['ips']) > 5:
                            result += f" и еще {len(indicators['ips']) - 5}"
                        result += "\n"
                        
                    if indicators.get('domains'):
                        result += f"**Домены:** {', '.join(indicators['domains'][:5])}"
                        if len(indicators['domains']) > 5:
                            result += f" и еще {len(indicators['domains']) - 5}"
                        result += "\n"
                        
                    if indicators.get('urls'):
                        result += f"**URL:** {', '.join(indicators['urls'][:3])}"
                        if len(indicators['urls']) > 3:
                            result += f" и еще {len(indicators['urls']) - 3}"
                        result += "\n"
                        
                    hash_types = []
                    for h_type in ['md5', 'sha1', 'sha256']:
                        if indicators.get(h_type):
                            hash_types.append(f"{h_type.upper()}: {indicators[h_type][0]}")
                            
                    if hash_types:
                        result += f"**Хэши:** {', '.join(hash_types)}\n"
                        
        return result

    def run_interactive(self):
        """Запускает интерактивный режим консультанта"""
        print("\n" + "=" * 80)
        print("🤖 КОНСУЛЬТАНТ ПО КИБЕРБЕЗОПАСНОСТИ")
        print("=" * 80)
        print("Введите ваш запрос. Для выхода введите 'exit' или 'quit'.")
        print("Специальные команды:")
        print("  !profile <id> - Изменить профиль пользователя")
        print("  !profiles - Показать доступные профили")
        print("  !enrich - Обогатить базу знаний из внешних источников")
        print("  !cve <id> - Получить информацию о CVE")
        print("  !mitre <query> - Поиск в MITRE ATT&CK")
        print("  !threat <query> - Анализ угроз (IP, домен, хэш и т.д.)")
        print("  !hybrid [on|off|weight <value>] - Управление гибридным поиском")

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
                
            # Новые команды для работы с профилями
            elif user_query.startswith("!profile "):
                profile_id = user_query[9:].strip()
                success = self.set_user_profile(profile_id)
                if success:
                    print(f"✅ Профиль изменен на '{profile_id}'")
                else:
                    print(f"❌ Профиль '{profile_id}' не найден")
                    profiles = list(self.get_available_profiles().keys())
                    print(f"📋 Доступные профили: {', '.join(profiles)}")
                continue
                
            elif user_query == "!profiles":
                profiles = self.get_available_profiles()
                print("📋 Доступные профили:")
                for profile_id, profile in profiles.items():
                    print(f"  - {profile_id}: {profile.get('name')} ({profile.get('description')})")
                continue
                
            # Команда для обогащения базы знаний
            elif user_query == "!enrich":
                print("🔄 Запуск обогащения базы знаний...")
                success, message = self.enrich_knowledge_base(force_update=True)
                status = "✅ Успешно" if success else "❌ Ошибка"
                print(f"{status}: {message}")
                continue
                
            # Команды для работы с внешними сервисами
            elif user_query.startswith("!cve ") or user_query.startswith("!mitre ") or user_query.startswith("!threat "):
                # Эти команды обрабатываются в process_user_query
                response = self.process_user_query(user_query)
                print("\n🤖 Ответ:")
                print(response)
                continue

            # Обрабатываем обычный запрос
            response = self.process_user_query(user_query, context)
            
            print("\n🤖 Ответ:")
            print(response)
            
            # Обновляем контекст для следующего запроса
            context = f"{context}\nПользователь: {user_query}\nКонсультант: {response}"
