# -*- coding: utf-8 -*-
"""
Модуль для автоматического обогащения базы знаний по кибербезопасности
из внешних источников
"""

import os
import time
import json
import hashlib
import logging
import requests
from datetime import datetime, timedelta
from typing import List, Dict, Any, Optional, Tuple, Union
import threading
import concurrent.futures
from tqdm.auto import tqdm

from cybersec_consultant.config import ConfigManager, DATA_DIR
from cybersec_consultant.state_management import STATE
from cybersec_consultant.knowledge_base import KnowledgeBaseManager, DocumentProcessor
from cybersec_consultant.error_handling import handle_api_errors, retry

# Настройка логирования
logger = logging.getLogger(__name__)

class KnowledgeEnrichmentManager:
    """
    Класс для автоматического обогащения базы знаний информацией 
    из внешних источников по кибербезопасности
    """
    
    def __init__(self):
        """Инициализация менеджера обогащения знаний"""
        self.config_manager = ConfigManager()
        self.kb_manager = KnowledgeBaseManager()
        self.document_processor = DocumentProcessor()
        
        # Директория для хранения кэшированных данных от источников
        self.sources_dir = os.path.join(DATA_DIR, "enrichment_sources")
        os.makedirs(self.sources_dir, exist_ok=True)
        
        # Загружаем конфигурацию источников
        self._load_sources_config()
        
        # Настройки обновления
        self.update_interval = self.config_manager.get_setting(
            "enrichment", "update_interval_hours", 24
        )  # По умолчанию обновляем раз в сутки
        self.last_update_time = {}  # Время последнего обновления для каждого источника
        
        # Флаг для отслеживания, запущено ли автоматическое обновление
        self.auto_update_running = False
        self.auto_update_thread = None
        
    def _load_sources_config(self):
        """Загружает конфигурацию источников данных"""
        # Стандартные источники данных
        default_sources = {
            "nist_nvd": {
                "name": "NIST NVD",
                "description": "National Vulnerability Database (NVD)",
                "url": "https://services.nvd.nist.gov/rest/json/cves/2.0",
                "api_required": False,
                "enabled": True,
                "max_items": 100,
                "update_interval_hours": 24,
                "category": "vulnerabilities"
            },
            "cisa_alerts": {
                "name": "CISA Alerts",
                "description": "Cybersecurity Advisories from CISA",
                "url": "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json",
                "api_required": False,
                "enabled": True,
                "max_items": 50,
                "update_interval_hours": 24,
                "category": "advisories"
            },
            "security_blogs": {
                "name": "Security Blogs",
                "description": "RSS feeds from top security blogs",
                "sources": [
                    "https://krebsonsecurity.com/feed/",
                    "https://www.schneier.com/feed/",
                    "https://www.darkreading.com/rss.xml"
                ],
                "api_required": False,
                "enabled": True,
                "max_items": 30,
                "update_interval_hours": 12,
                "category": "news"
            }
        }
        
        # Загружаем сохраненную конфигурацию или используем стандартную
        self.sources = self.config_manager.get_setting("enrichment", "sources", default_sources)
        
        # Обновляем конфигурацию (добавляем новые стандартные источники)
        for source_id, source_config in default_sources.items():
            if source_id not in self.sources:
                self.sources[source_id] = source_config
                
        # Сохраняем обновленную конфигурацию
        self.config_manager.set_setting("enrichment", "sources", self.sources)
        
        return self.sources
    
    def add_custom_source(self, source_id: str, source_config: Dict[str, Any]) -> bool:
        """
        Добавляет пользовательский источник данных
        
        Args:
            source_id: Идентификатор источника
            source_config: Конфигурация источника
            
        Returns:
            bool: Успешность операции
        """
        # Проверяем наличие необходимых полей
        required_fields = ["name", "url", "api_required", "category"]
        for field in required_fields:
            if field not in source_config:
                logger.error(f"Missing required field '{field}' in source config")
                return False
                
        # Добавляем значения по умолчанию, если не указаны
        source_config.setdefault("enabled", True)
        source_config.setdefault("max_items", 50)
        source_config.setdefault("update_interval_hours", 24)
        
        # Добавляем источник
        self.sources[source_id] = source_config
        
        # Сохраняем обновленную конфигурацию
        self.config_manager.set_setting("enrichment", "sources", self.sources)
        
        logger.info(f"Added custom source: {source_id} - {source_config['name']}")
        return True
    
    def remove_source(self, source_id: str) -> bool:
        """
        Удаляет источник данных
        
        Args:
            source_id: Идентификатор источника
            
        Returns:
            bool: Успешность операции
        """
        if source_id in self.sources:
            del self.sources[source_id]
            self.config_manager.set_setting("enrichment", "sources", self.sources)
            logger.info(f"Removed source: {source_id}")
            return True
        else:
            logger.warning(f"Source not found: {source_id}")
            return False
    
    def enable_source(self, source_id: str, enabled: bool = True) -> bool:
        """
        Включает или отключает источник данных
        
        Args:
            source_id: Идентификатор источника
            enabled: Включить (True) или выключить (False)
            
        Returns:
            bool: Успешность операции
        """
        if source_id in self.sources:
            self.sources[source_id]["enabled"] = enabled
            self.config_manager.set_setting("enrichment", "sources", self.sources)
            status = "enabled" if enabled else "disabled"
            logger.info(f"Source {source_id} {status}")
            return True
        else:
            logger.warning(f"Source not found: {source_id}")
            return False
    
    def get_source_data(self, source_id: str) -> Optional[Dict[str, Any]]:
        """
        Получает данные от конкретного источника
        
        Args:
            source_id: Идентификатор источника
            
        Returns:
            Optional[Dict[str, Any]]: Данные от источника или None в случае ошибки
        """
        if source_id not in self.sources:
            logger.warning(f"Source not found: {source_id}")
            return None
            
        source_config = self.sources[source_id]
        
        # Проверяем, включен ли источник
        if not source_config.get("enabled", True):
            logger.debug(f"Source {source_id} is disabled, skipping")
            return None
            
        # Получаем данные в зависимости от типа источника
        try:
            if source_id == "nist_nvd":
                return self._get_nist_nvd_data(source_config)
            elif source_id == "cisa_alerts":
                return self._get_cisa_alerts_data(source_config)
            elif source_id == "security_blogs":
                return self._get_security_blogs_data(source_config)
            else:
                # Общий метод для остальных источников по URL
                return self._get_generic_source_data(source_id, source_config)
        except Exception as e:
            logger.error(f"Error fetching data from {source_id}: {str(e)}")
            return None
    
    def _get_nist_nvd_data(self, source_config: Dict[str, Any]) -> Dict[str, Any]:
        """
        Получает данные от NIST NVD
        
        Args:
            source_config: Конфигурация источника
            
        Returns:
            Dict[str, Any]: Данные об уязвимостях
        """
        max_items = source_config.get("max_items", 100)
        
        # Формируем URL с параметрами
        base_url = source_config.get("url", "https://services.nvd.nist.gov/rest/json/cves/2.0")
        
        # Получаем уязвимости за последние 30 дней
        thirty_days_ago = (datetime.now() - timedelta(days=30)).strftime("%Y-%m-%dT00:00:00.000")
        
        params = {
            "pubStartDate": thirty_days_ago,
            "resultsPerPage": min(max_items, 50)  # NVD ограничивает до 50 на страницу
        }
        
        logger.info(f"Fetching NVD vulnerabilities from {base_url}")
        
        # Отправляем запрос
        response = requests.get(base_url, params=params)
        response.raise_for_status()
        data = response.json()
        
        if "vulnerabilities" not in data:
            logger.warning("No vulnerabilities found in NVD response")
            return {"items": []}
            
        # Обрабатываем результаты
        vulnerabilities = data.get("vulnerabilities", [])
        results = []
        
        for vuln in vulnerabilities[:max_items]:
            cve_item = vuln.get("cve", {})
            cve_id = cve_item.get("id", "Unknown")
            
            # Извлекаем описание (предпочтительно на русском, если доступно)
            descriptions = cve_item.get("descriptions", [])
            description_en = None
            description_ru = None
            
            for desc in descriptions:
                if desc.get("lang") == "en":
                    description_en = desc.get("value", "")
                elif desc.get("lang") == "ru":
                    description_ru = desc.get("value", "")
            
            description = description_ru or description_en or "Нет описания"
            
            # Извлекаем метрики CVSS
            metrics = cve_item.get("metrics", {})
            cvss_data = metrics.get("cvssMetricV31", [{}])[0] if "cvssMetricV31" in metrics else None
            
            if not cvss_data:
                cvss_data = metrics.get("cvssMetricV30", [{}])[0] if "cvssMetricV30" in metrics else None
                
            if not cvss_data:
                cvss_data = metrics.get("cvssMetricV2", [{}])[0] if "cvssMetricV2" in metrics else None
                
            cvss_score = None
            cvss_severity = None
            
            if cvss_data:
                cvss = cvss_data.get("cvssData", {})
                cvss_score = cvss.get("baseScore")
                cvss_severity = cvss.get("baseSeverity")
            
            # Формируем элемент
            item = {
                "id": cve_id,
                "title": f"Уязвимость {cve_id}",
                "description": description,
                "published": cve_item.get("published"),
                "last_modified": cve_item.get("lastModified"),
                "score": cvss_score,
                "severity": cvss_severity,
                "source": "NIST NVD",
                "url": f"https://nvd.nist.gov/vuln/detail/{cve_id}"
            }
            
            results.append(item)
        
        return {"items": results}
    
    def _get_cisa_alerts_data(self, source_config: Dict[str, Any]) -> Dict[str, Any]:
        """
        Получает данные от CISA о известных эксплуатируемых уязвимостях
        
        Args:
            source_config: Конфигурация источника
            
        Returns:
            Dict[str, Any]: Данные о уязвимостях
        """
        max_items = source_config.get("max_items", 50)
        url = source_config.get("url", "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json")
        
        logger.info(f"Fetching CISA known exploited vulnerabilities from {url}")
        
        # Отправляем запрос
        response = requests.get(url)
        response.raise_for_status()
        data = response.json()
        
        vulnerabilities = data.get("vulnerabilities", [])
        results = []
        
        # Сортируем по дате добавления (самые новые первыми)
        vulnerabilities.sort(key=lambda x: x.get("dateAdded", ""), reverse=True)
        
        for vuln in vulnerabilities[:max_items]:
            item = {
                "id": vuln.get("cveID"),
                "title": f"Эксплуатируемая уязвимость {vuln.get('cveID')}",
                "description": vuln.get("vulnerabilityName", ""),
                "published": vuln.get("dateAdded"),
                "last_modified": vuln.get("dateAdded"),
                "required_action": vuln.get("requiredAction"),
                "due_date": vuln.get("dueDate"),
                "source": "CISA KEV",
                "url": "https://www.cisa.gov/known-exploited-vulnerabilities-catalog"
            }
            
            results.append(item)
        
        return {"items": results}
    
    def _get_security_blogs_data(self, source_config: Dict[str, Any]) -> Dict[str, Any]:
        """
        Получает данные из RSS-лент блогов по безопасности
        
        Args:
            source_config: Конфигурация источника
            
        Returns:
            Dict[str, Any]: Данные из блогов
        """
        max_items = source_config.get("max_items", 30)
        blog_sources = source_config.get("sources", [])
        
        # Импортируем библиотеку для работы с RSS
        try:
            import feedparser
        except ImportError:
            logger.error("feedparser library is not installed. Run: pip install feedparser")
            return {"items": []}
            
        all_entries = []
        
        # Извлекаем данные из каждого источника
        for rss_url in blog_sources:
            try:
                logger.info(f"Fetching security blog feed from {rss_url}")
                feed = feedparser.parse(rss_url)
                
                # Проверяем наличие записей
                if not feed.entries:
                    logger.warning(f"No entries found in feed: {rss_url}")
                    continue
                    
                # Извлекаем записи
                for entry in feed.entries:
                    item = {
                        "id": entry.get("id", entry.get("link", "")),
                        "title": entry.get("title", "Без заголовка"),
                        "description": entry.get("summary", ""),
                        "published": entry.get("published", ""),
                        "source": feed.feed.get("title", rss_url),
                        "url": entry.get("link", "")
                    }
                    
                    all_entries.append(item)
            except Exception as e:
                logger.error(f"Error fetching feed from {rss_url}: {str(e)}")
                continue
                
        # Сортируем все записи по дате (самые новые первыми)
        # Пытаемся парсить дату, если не получается, сортируем по строке
        def get_date(entry):
            try:
                from email.utils import parsedate_to_datetime
                date_str = entry.get("published", "")
                if date_str:
                    return parsedate_to_datetime(date_str)
            except:
                pass
            return datetime.min
            
        all_entries.sort(key=get_date, reverse=True)
        
        # Ограничиваем количество записей
        return {"items": all_entries[:max_items]}
    
    def _get_generic_source_data(self, source_id: str, source_config: Dict[str, Any]) -> Dict[str, Any]:
        """
        Получает данные от произвольного источника по URL
        
        Args:
            source_id: Идентификатор источника
            source_config: Конфигурация источника
            
        Returns:
            Dict[str, Any]: Данные от источника
        """
        url = source_config.get("url")
        if not url:
            logger.error(f"URL not specified for source: {source_id}")
            return {"items": []}
            
        logger.info(f"Fetching data from generic source {source_id} at {url}")
        
        # Параметры запроса
        headers = source_config.get("headers", {})
        params = source_config.get("params", {})
        
        # Проверяем, требуется ли API-ключ
        if source_config.get("api_required", False):
            api_key = source_config.get("api_key") or self.config_manager.get_setting(
                "api_keys", source_id, None
            )
            
            if not api_key:
                logger.error(f"API key required for source {source_id} but not provided")
                return {"items": []}
                
            # Добавляем API-ключ в параметры или заголовки
            api_key_param = source_config.get("api_key_param", "apiKey")
            api_key_in = source_config.get("api_key_in", "params")
            
            if api_key_in == "params":
                params[api_key_param] = api_key
            elif api_key_in == "headers":
                headers[api_key_param] = api_key
                
        # Отправляем запрос
        response = requests.get(url, headers=headers, params=params)
        response.raise_for_status()
        data = response.json()
        
        # Извлекаем элементы из ответа по указанному пути
        items_path = source_config.get("items_path", "items")
        
        if items_path:
            items = data
            for key in items_path.split('.'):
                if key in items:
                    items = items[key]
                else:
                    logger.warning(f"Path {items_path} not found in response for source {source_id}")
                    items = []
                    break
        else:
            items = data
            
        # Если результат не список, преобразуем его в список
        if not isinstance(items, list):
            items = [items]
            
        # Ограничиваем количество элементов
        max_items = source_config.get("max_items", 50)
        items = items[:max_items]
        
        # Преобразуем элементы в стандартный формат
        results = []
        
        for item in items:
            # Применяем маппинг полей
            field_mapping = source_config.get("field_mapping", {})
            result = {}
            
            for target_field, source_field in field_mapping.items():
                if isinstance(source_field, str):
                    # Простое копирование поля
                    result[target_field] = item.get(source_field)
                elif callable(source_field):
                    # Применение функции преобразования
                    result[target_field] = source_field(item)
                    
            # Если маппинг не указан, используем элемент как есть
            if not field_mapping:
                result = item
                
            # Добавляем обязательные поля, если их нет
            if "source" not in result:
                result["source"] = source_config.get("name", source_id)
                
            results.append(result)
            
        return {"items": results}
    
    def fetch_all_sources(self) -> Dict[str, Dict[str, Any]]:
        """
        Получает данные от всех включенных источников
        
        Returns:
            Dict[str, Dict[str, Any]]: Данные от всех источников
        """
        results = {}
        
        for source_id, source_config in self.sources.items():
            # Проверяем, включен ли источник
            if not source_config.get("enabled", True):
                logger.debug(f"Source {source_id} is disabled, skipping")
                continue
                
            # Проверяем, нужно ли обновление
            update_interval = source_config.get("update_interval_hours", self.update_interval)
            last_update = self.last_update_time.get(source_id, 0)
            current_time = time.time()
            
            if current_time - last_update < update_interval * 3600:
                logger.debug(f"Source {source_id} was updated recently, using cached data")
                
                # Пытаемся загрузить кэшированные данные
                cache_file = os.path.join(self.sources_dir, f"{source_id}.json")
                if os.path.exists(cache_file):
                    try:
                        with open(cache_file, 'r', encoding='utf-8') as f:
                            results[source_id] = json.load(f)
                        continue
                    except:
                        pass
                        
            # Получаем данные от источника
            logger.info(f"Fetching data from source {source_id}")
            try:
                data = self.get_source_data(source_id)
                
                if data:
                    # Сохраняем данные в кэш
                    cache_file = os.path.join(self.sources_dir, f"{source_id}.json")
                    with open(cache_file, 'w', encoding='utf-8') as f:
                        json.dump(data, f, ensure_ascii=False, indent=2)
                        
                    # Обновляем время последнего обновления
                    self.last_update_time[source_id] = current_time
                    
                    # Сохраняем результат
                    results[source_id] = data
                    
                    logger.info(f"Successfully fetched data from {source_id}: {len(data.get('items', []))} items")
                else:
                    logger.warning(f"No data received from source {source_id}")
            except Exception as e:
                logger.error(f"Error fetching data from source {source_id}: {str(e)}")
                
        return results
    
    def _format_enrichment_data(self, data: Dict[str, Dict[str, Any]]) -> str:
        """
        Форматирует данные обогащения в текстовый формат
        
        Args:
            data: Данные от всех источников
            
        Returns:
            str: Форматированный текст для добавления в базу знаний
        """
        if not data:
            return ""
            
        formatted_text = "# Автоматически собранные данные по кибербезопасности\n\n"
        formatted_text += f"*Обновлено: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}*\n\n"
        
        # Сортируем по категориям
        categories = {}
        
        for source_id, source_data in data.items():
            source_config = self.sources.get(source_id, {})
            category = source_config.get("category", "other")
            
            if category not in categories:
                categories[category] = []
                
            # Добавляем данные от источника
            source_name = source_config.get("name", source_id)
            source_items = source_data.get("items", [])
            
            categories[category].append({
                "source_id": source_id,
                "source_name": source_name,
                "items": source_items
            })
            
        # Формируем текст по категориям
        for category, sources in categories.items():
            # Заголовок категории
            if category == "vulnerabilities":
                cat_title = "## Уязвимости"
            elif category == "advisories":
                cat_title = "## Рекомендации и предупреждения"
            elif category == "news":
                cat_title = "## Новости кибербезопасности"
            else:
                cat_title = f"## {category.capitalize()}"
                
            formatted_text += f"{cat_title}\n\n"
            
            # Проходим по всем источникам в категории
            for source_info in sources:
                source_name = source_info["source_name"]
                items = source_info["items"]
                
                if not items:
                    continue
                    
                formatted_text += f"### {source_name}\n\n"
                
                # Формируем элементы
                for item in items:
                    title = item.get("title", "Без заголовка")
                    description = item.get("description", "").strip()
                    
                    # Ограничиваем описание для сохранения компактности
                    if len(description) > 500:
                        description = description[:497] + "..."
                        
                    # Добавляем id/код, если есть
                    item_id = item.get("id")
                    if item_id:
                        formatted_text += f"#### {title} ({item_id})\n\n"
                    else:
                        formatted_text += f"#### {title}\n\n"
                        
                    # Добавляем описание
                    if description:
                        formatted_text += f"{description}\n\n"
                        
                    # Добавляем дополнительную информацию
                    additional_info = []
                    
                    # Дата публикации
                    published = item.get("published")
                    if published:
                        additional_info.append(f"Опубликовано: {published}")
                        
                    # Оценка CVSS для уязвимостей
                    score = item.get("score")
                    severity = item.get("severity")
                    if score:
                        if severity:
                            additional_info.append(f"Оценка: {score} ({severity})")
                        else:
                            additional_info.append(f"Оценка: {score}")
                            
                    # URL источника
                    url = item.get("url")
                    if url:
                        additional_info.append(f"Подробнее: {url}")
                        
                    if additional_info:
                        formatted_text += "*" + " | ".join(additional_info) + "*\n\n"
                        
                formatted_text += "\n"
                
        return formatted_text
    
    def enrich_knowledge_base(self, force_update: bool = False) -> Tuple[bool, str]:
        """
        Обогащает базу знаний данными из внешних источников
        
        Args:
            force_update: Принудительное обновление, игнорируя кэш
            
        Returns:
            Tuple[bool, str]: (успешность операции, текст результата)
        """
        print("🔄 Сбор информации из внешних источников...")
        
        # Если принудительное обновление, очищаем кэш времени
        if force_update:
            self.last_update_time = {}
            
        # Получаем данные от всех источников
        enrichment_data = self.fetch_all_sources()
        
        if not enrichment_data:
            print("❌ Не удалось получить данные ни от одного источника")
            return False, "Не удалось получить данные от источников"
            
        # Форматируем данные в текст
        enrichment_text = self._format_enrichment_data(enrichment_data)
        
        if not enrichment_text:
            print("⚠️ Нет данных для обогащения базы знаний")
            return False, "Нет данных для обогащения"
            
        # Сохраняем в файл
        enrichment_file = os.path.join(self.sources_dir, "enrichment_data.md")
        with open(enrichment_file, 'w', encoding='utf-8') as f:
            f.write(enrichment_text)
            
        print(f"✅ Данные из {len(enrichment_data)} источников сохранены в {enrichment_file}")
        
        # Проверяем наличие базы знаний
        if not STATE.knowledge_base_text:
            print("⚠️ База знаний не инициализирована. Запустите сначала load_knowledge_base()")
            return False, "База знаний не инициализирована"
            
        # Добавляем к существующей базе знаний
        print("🔄 Обновление базы знаний...")
        
        # Проверяем наличие раздела с автоматически собранными данными
        kb_text = STATE.knowledge_base_text
        
        # Ищем начало секции автоматически собранных данных
        auto_section_marker = "# Автоматически собранные данные по кибербезопасности"
        if auto_section_marker in kb_text:
            # Удаляем старую секцию
            start_idx = kb_text.find(auto_section_marker)
            next_section_idx = kb_text.find("\n# ", start_idx + 1)
            
            if next_section_idx > start_idx:
                # Есть следующий раздел - вставляем перед ним
                updated_kb = kb_text[:start_idx] + enrichment_text + "\n\n" + kb_text[next_section_idx:]
            else:
                # Это последний раздел - заменяем до конца
                updated_kb = kb_text[:start_idx] + enrichment_text
        else:
            # Добавляем новую секцию в конец
            updated_kb = kb_text + "\n\n" + enrichment_text
            
        # Обновляем текст в состоянии
        STATE.knowledge_base_text = updated_kb
        
        # Сохраняем обновленную базу знаний
        if STATE.knowledge_base_path:
            with open(STATE.knowledge_base_path, 'w', encoding='utf-8') as f:
                f.write(updated_kb)
                
        # Обновляем чанки для векторного поиска
        documents = self.kb_manager.split_text_into_chunks(updated_kb)
        
        print(f"✅ База знаний обновлена ({len(enrichment_data)} источников, {len(documents)} чанков)")
        
        return True, f"База знаний обновлена данными из {len(enrichment_data)} источников"
    
    def start_auto_update(self, interval_hours: int = None) -> bool:
        """
        Запускает поток для автоматического обновления базы знаний
        
        Args:
            interval_hours: Интервал обновления в часах (если None, используется значение из конфигурации)
            
        Returns:
            bool: Успешность запуска
        """
        if self.auto_update_running:
            logger.warning("Auto-update is already running")
            return False
            
        # Устанавливаем интервал обновления
        if interval_hours is not None:
            self.update_interval = interval_hours
            self.config_manager.set_setting("enrichment", "update_interval_hours", interval_hours)
            
        # Функция для потока обновления
        def update_thread():
            self.auto_update_running = True
            logger.info(f"Starting auto-update thread with interval {self.update_interval} hours")
            
            while self.auto_update_running:
                try:
                    success, message = self.enrich_knowledge_base()
                    if success:
                        logger.info(f"Auto-update successful: {message}")
                    else:
                        logger.warning(f"Auto-update failed: {message}")
                except Exception as e:
                    logger.error(f"Error in auto-update thread: {str(e)}")
                    
                # Ждем до следующего обновления
                for _ in range(int(self.update_interval * 3600 / 10)):
                    if not self.auto_update_running:
                        break
                    time.sleep(10)
                    
        # Запускаем поток
        self.auto_update_thread = threading.Thread(target=update_thread, daemon=True)
        self.auto_update_thread.start()
        
        logger.info(f"Auto-update thread started with interval {self.update_interval} hours")
        return True
        
    def stop_auto_update(self) -> bool:
        """
        Останавливает автоматическое обновление базы знаний
        
        Returns:
            bool: Успешность остановки
        """
        if not self.auto_update_running:
            logger.warning("Auto-update is not running")
            return False
            
        self.auto_update_running = False
        
        # Ждем завершения потока
        if self.auto_update_thread and self.auto_update_thread.is_alive():
            self.auto_update_thread.join(timeout=1.0)
            
        logger.info("Auto-update thread stopped")
        return True

# Функция для создания менеджера обогащения знаний
def get_enrichment_manager():
    """
    Получает экземпляр менеджера обогащения знаний
    
    Returns:
        KnowledgeEnrichmentManager: Экземпляр менеджера
    """
    return KnowledgeEnrichmentManager()
