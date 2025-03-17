# -*- coding: utf-8 -*-
"""
Модуль для интеграции с внешними сервисами по кибербезопасности:
MITRE ATT&CK, CVE базы данных и другие ресурсы
"""

import os
import time
import json
import hashlib
import logging
import requests
from datetime import datetime, timedelta
from typing import List, Dict, Any, Optional, Tuple, Union
import concurrent.futures
from tqdm.auto import tqdm

from cybersec_consultant.config import ConfigManager, DATA_DIR
from cybersec_consultant.state_management import STATE
from cybersec_consultant.error_handling import handle_api_errors, retry

# Настройка логирования
logger = logging.getLogger(__name__)

class ExternalServicesManager:
    """
    Класс для интеграции с внешними сервисами и базами данных по кибербезопасности
    """
    
    def __init__(self):
        """Инициализация менеджера внешних сервисов"""
        self.config_manager = ConfigManager()
        
        # Директория для кэширования данных от внешних сервисов
        self.cache_dir = os.path.join(DATA_DIR, "external_services_cache")
        os.makedirs(self.cache_dir, exist_ok=True)
        
        # Настройки кэширования
        self.cache_ttl = self.config_manager.get_setting(
            "external_services", "cache_ttl_hours", 24
        )  # Время жизни кэша в часах
        
        # Инициализация сервисов
        self.mitre_service = MitreAttackService(self.cache_dir, self.cache_ttl)
        self.cve_service = CVEService(self.cache_dir, self.cache_ttl)
        self.osint_service = OSINTService(self.cache_dir, self.cache_ttl)

    def refresh_all_caches(self):
        """
        Принудительно обновляет кэши всех внешних сервисов
        
        Returns:
            Dict[str, bool]: Результаты обновления для каждого сервиса
        """
        results = {}
        
        # Обновляем кэши каждого сервиса
        print("🔄 Обновление кэша внешних сервисов...")
        
        # MITRE ATT&CK
        print("🔄 Обновление MITRE ATT&CK...")
        try:
            success = self.mitre_service.refresh_cache()
            results["mitre_attack"] = success
            status = "✅ Успешно" if success else "❌ Ошибка"
            print(f"{status} обновления MITRE ATT&CK")
        except Exception as e:
            results["mitre_attack"] = False
            print(f"❌ Ошибка обновления MITRE ATT&CK: {str(e)}")
            
        # CVE
        print("🔄 Обновление базы CVE...")
        try:
            success = self.cve_service.refresh_cache()
            results["cve"] = success
            status = "✅ Успешно" if success else "❌ Ошибка"
            print(f"{status} обновления базы CVE")
        except Exception as e:
            results["cve"] = False
            print(f"❌ Ошибка обновления базы CVE: {str(e)}")
            
        # OSINT
        print("🔄 Обновление данных OSINT...")
        try:
            success = self.osint_service.refresh_cache()
            results["osint"] = success
            status = "✅ Успешно" if success else "❌ Ошибка"
            print(f"{status} обновления данных OSINT")
        except Exception as e:
            results["osint"] = False
            print(f"❌ Ошибка обновления данных OSINT: {str(e)}")
            
        return results
        
    def query_mitre_att_ck(self, query: str) -> Dict[str, Any]:
        """
        Поиск информации в MITRE ATT&CK
        
        Args:
            query: Поисковый запрос (техника, тактика, группа и т.д.)
            
        Returns:
            Dict[str, Any]: Результаты поиска
        """
        return self.mitre_service.search(query)
        
    def get_cve_info(self, cve_id: str) -> Dict[str, Any]:
        """
        Получает информацию о конкретной уязвимости CVE
        
        Args:
            cve_id: Идентификатор CVE (например, CVE-2021-44228)
            
        Returns:
            Dict[str, Any]: Информация об уязвимости
        """
        return self.cve_service.get_cve(cve_id)
        
    def search_cve(self, query: str, limit: int = 10) -> List[Dict[str, Any]]:
        """
        Поиск уязвимостей CVE по ключевым словам
        
        Args:
            query: Поисковый запрос
            limit: Максимальное количество результатов
            
        Returns:
            List[Dict[str, Any]]: Список найденных уязвимостей
        """
        return self.cve_service.search(query, limit)
        
    def get_threat_intelligence(self, query: str) -> Dict[str, Any]:
        """
        Получает данные Threat Intelligence по запросу
        
        Args:
            query: Поисковый запрос (IP, домен, хэш и т.д.)
            
        Returns:
            Dict[str, Any]: Результаты анализа угроз
        """
        return self.osint_service.get_threat_intelligence(query)


class MitreAttackService:
    """
    Сервис для работы с MITRE ATT&CK - базой знаний о тактиках, 
    техниках и процедурах (TTP) киберугроз
    """
    
    def __init__(self, cache_dir: str, cache_ttl: int):
        """
        Инициализация сервиса MITRE ATT&CK
        
        Args:
            cache_dir: Директория для кэширования данных
            cache_ttl: Время жизни кэша в часах
        """
        self.cache_dir = cache_dir
        self.cache_ttl = cache_ttl
        
        # Файлы кэша для различных типов данных
        self.tactics_cache_file = os.path.join(cache_dir, "mitre_tactics.json")
        self.techniques_cache_file = os.path.join(cache_dir, "mitre_techniques.json")
        self.groups_cache_file = os.path.join(cache_dir, "mitre_groups.json")
        self.software_cache_file = os.path.join(cache_dir, "mitre_software.json")
        
        # STIX/TAXII API MITRE ATT&CK
        self.base_url = "https://raw.githubusercontent.com/mitre/cti/master"
        
        # Проверяем и загружаем кэш при необходимости
        self._load_cache()
    
    def _load_cache(self):
        """Загружает кэшированные данные или скачивает их, если нужно"""
        # Словари для хранения данных
        self.tactics = {}
        self.techniques = {}
        self.groups = {}
        self.software = {}
        
        # Функция для проверки актуальности кэша
        def is_cache_valid(cache_file):
            if not os.path.exists(cache_file):
                return False
                
            # Проверяем время создания файла
            file_time = os.path.getmtime(cache_file)
            current_time = time.time()
            
            # Сравниваем с TTL
            return (current_time - file_time) / 3600 < self.cache_ttl
            
        # Функция для загрузки кэша
        def load_cached_data(cache_file, default_value=None):
            try:
                if os.path.exists(cache_file):
                    with open(cache_file, 'r', encoding='utf-8') as f:
                        return json.load(f)
                return default_value or {}
            except Exception as e:
                logger.error(f"Error loading cache from {cache_file}: {str(e)}")
                return default_value or {}
                
        # Загружаем или обновляем кэши по необходимости
        cache_files = [
            (self.tactics_cache_file, "tactics"),
            (self.techniques_cache_file, "techniques"),
            (self.groups_cache_file, "groups"),
            (self.software_cache_file, "software")
        ]
        
        # Проверяем актуальность кэшей
        all_valid = True
        for cache_file, _ in cache_files:
            if not is_cache_valid(cache_file):
                all_valid = False
                break
                
        # Если хотя бы один кэш устарел, обновляем все
        if not all_valid:
            logger.info("MITRE ATT&CK cache is outdated, refreshing...")
            self.refresh_cache()
        else:
            # Загружаем данные из кэша
            self.tactics = load_cached_data(self.tactics_cache_file)
            self.techniques = load_cached_data(self.techniques_cache_file)
            self.groups = load_cached_data(self.groups_cache_file)
            self.software = load_cached_data(self.software_cache_file)
            
            logger.info(f"Loaded MITRE ATT&CK cache: {len(self.tactics)} tactics, {len(self.techniques)} techniques, {len(self.groups)} groups, {len(self.software)} software")
    
    @retry(attempts=3, delay=2)
    def _fetch_mitre_data(self, data_type: str) -> Dict[str, Any]:
        """
        Получает данные MITRE ATT&CK по типу
        
        Args:
            data_type: Тип данных (enterprise-attack, mobile-attack, ics-attack)
            
        Returns:
            Dict[str, Any]: Данные MITRE ATT&CK
        """
        url = f"{self.base_url}/{data_type}/{data_type}.json"
        
        logger.info(f"Fetching MITRE ATT&CK data from {url}")
        response = requests.get(url)
        response.raise_for_status()
        
        return response.json()
    
    def refresh_cache(self) -> bool:
        """
        Обновляет кэш данных MITRE ATT&CK
        
        Returns:
            bool: Успешность обновления
        """
        try:
            # Получаем данные для различных платформ
            enterprise_data = self._fetch_mitre_data("enterprise-attack")
            # mobile_data = self._fetch_mitre_data("mobile-attack")  # Опционально
            # ics_data = self._fetch_mitre_data("ics-attack")  # Опционально
            
            # Объединяем объекты из разных источников (сейчас только enterprise)
            all_objects = enterprise_data.get("objects", [])
            
            # Парсим данные по типам
            tactics = {}
            techniques = {}
            groups = {}
            software = {}
            
            for obj in all_objects:
                obj_type = obj.get("type")
                obj_id = obj.get("id")
                
                if not obj_id:
                    continue
                    
                # Преобразуем название на русский (для некоторых базовых тактик)
                name_ru = None
                name = obj.get("name", "")
                
                # Словарь для базового перевода некоторых тактик
                translations = {
                    "Reconnaissance": "Разведка",
                    "Resource Development": "Разработка ресурсов",
                    "Initial Access": "Первоначальный доступ",
                    "Execution": "Выполнение",
                    "Persistence": "Закрепление",
                    "Privilege Escalation": "Повышение привилегий",
                    "Defense Evasion": "Обход защиты",
                    "Credential Access": "Доступ к учетным данным",
                    "Discovery": "Исследование",
                    "Lateral Movement": "Горизонтальное перемещение",
                    "Collection": "Сбор данных",
                    "Command and Control": "Управление и контроль",
                    "Exfiltration": "Эксфильтрация",
                    "Impact": "Воздействие",
                }
                
                if name in translations:
                    name_ru = translations[name]
                
                # В зависимости от типа объекта
                if obj_type == "x-mitre-tactic":
                    # Это тактика
                    tactics[obj_id] = {
                        "id": obj_id,
                        "name": name,
                        "name_ru": name_ru,
                        "description": obj.get("description", ""),
                        "external_references": obj.get("external_references", [])
                    }
                elif obj_type == "attack-pattern":
                    # Это техника
                    kill_chain_phases = obj.get("kill_chain_phases", [])
                    tactics_ids = []
                    
                    # Извлекаем связанные тактики
                    for phase in kill_chain_phases:
                        if phase.get("kill_chain_name") == "mitre-attack":
                            tactics_ids.append(phase.get("phase_name"))
                    
                    techniques[obj_id] = {
                        "id": obj_id,
                        "name": name,
                        "description": obj.get("description", ""),
                        "external_references": obj.get("external_references", []),
                        "tactics": tactics_ids,
                        "detection": obj.get("x_mitre_detection", ""),
                        "platforms": obj.get("x_mitre_platforms", [])
                    }
                elif obj_type == "intrusion-set":
                    # Это группа угроз
                    groups[obj_id] = {
                        "id": obj_id,
                        "name": name,
                        "description": obj.get("description", ""),
                        "external_references": obj.get("external_references", []),
                        "aliases": obj.get("aliases", []),
                        "first_seen": obj.get("first_seen", ""),
                        "last_seen": obj.get("last_seen", "")
                    }
                elif obj_type == "malware" or obj_type == "tool":
                    # Это вредоносное ПО или инструмент
                    software[obj_id] = {
                        "id": obj_id,
                        "name": name,
                        "type": obj_type,
                        "description": obj.get("description", ""),
                        "external_references": obj.get("external_references", []),
                        "platforms": obj.get("x_mitre_platforms", []),
                        "aliases": obj.get("aliases", [])
                    }
            
            # Сохраняем данные в кэш
            with open(self.tactics_cache_file, 'w', encoding='utf-8') as f:
                json.dump(tactics, f, ensure_ascii=False, indent=2)
                
            with open(self.techniques_cache_file, 'w', encoding='utf-8') as f:
                json.dump(techniques, f, ensure_ascii=False, indent=2)
                
            with open(self.groups_cache_file, 'w', encoding='utf-8') as f:
                json.dump(groups, f, ensure_ascii=False, indent=2)
                
            with open(self.software_cache_file, 'w', encoding='utf-8') as f:
                json.dump(software, f, ensure_ascii=False, indent=2)
                
            # Обновляем объекты в памяти
            self.tactics = tactics
            self.techniques = techniques
            self.groups = groups
            self.software = software
            
            logger.info(f"Updated MITRE ATT&CK cache: {len(tactics)} tactics, {len(techniques)} techniques, {len(groups)} groups, {len(software)} software")
            
            return True
        except Exception as e:
            logger.error(f"Error refreshing MITRE ATT&CK cache: {str(e)}")
            return False
    
    def search(self, query: str) -> Dict[str, Any]:
        """
        Поиск по базе MITRE ATT&CK
        
        Args:
            query: Поисковый запрос (название техники, тактики, группы или ID)
            
        Returns:
            Dict[str, Any]: Результаты поиска
        """
        query = query.lower().strip()
        results = {
            "tactics": [],
            "techniques": [],
            "groups": [],
            "software": []
        }
        
        # Если запрос похож на ID (например, T1234, G0001)
        is_id_query = False
        for prefix in ["t", "g", "s"]:
            if query.startswith(prefix) and len(query) > 1 and query[1:].isdigit():
                is_id_query = True
                break
                
        # Поиск по тактикам
        for tactic_id, tactic in self.tactics.items():
            if is_id_query and tactic_id.lower() == query:
                results["tactics"].append(tactic)
                continue
                
            # Поиск по имени
            name = tactic.get("name", "").lower()
            name_ru = tactic.get("name_ru", "").lower()
            
            if query in name or query in name_ru:
                results["tactics"].append(tactic)
                
        # Поиск по техникам
        for technique_id, technique in self.techniques.items():
            if is_id_query:
                # Для техник ID имеет специальный формат
                for ref in technique.get("external_references", []):
                    if ref.get("source_name") == "mitre-attack" and ref.get("external_id", "").lower() == query:
                        results["techniques"].append(technique)
                        break
                continue
                
            # Поиск по имени
            if query in technique.get("name", "").lower() or query in technique.get("description", "").lower():
                results["techniques"].append(technique)
                
        # Поиск по группам
        for group_id, group in self.groups.items():
            if is_id_query:
                # Для групп ID имеет специальный формат
                for ref in group.get("external_references", []):
                    if ref.get("source_name") == "mitre-attack" and ref.get("external_id", "").lower() == query:
                        results["groups"].append(group)
                        break
                continue
                
            # Поиск по имени и алиасам
            if query in group.get("name", "").lower() or query in group.get("description", "").lower():
                results["groups"].append(group)
                continue
                
            # Поиск по алиасам
            for alias in group.get("aliases", []):
                if query in alias.lower():
                    results["groups"].append(group)
                    break
                    
        # Поиск по ПО
        for sw_id, sw in self.software.items():
            if is_id_query:
                # Для ПО ID имеет специальный формат
                for ref in sw.get("external_references", []):
                    if ref.get("source_name") == "mitre-attack" and ref.get("external_id", "").lower() == query:
                        results["software"].append(sw)
                        break
                continue
                
            # Поиск по имени и алиасам
            if query in sw.get("name", "").lower() or query in sw.get("description", "").lower():
                results["software"].append(sw)
                continue
                
            # Поиск по алиасам
            for alias in sw.get("aliases", []):
                if query in alias.lower():
                    results["software"].append(sw)
                    break
        
        # Ограничиваем количество результатов
        for key in results:
            results[key] = results[key][:10]  # Максимум 10 результатов каждого типа
            
        return results
        
    def get_tactics(self) -> List[Dict[str, Any]]:
        """
        Получает список всех тактик
        
        Returns:
            List[Dict[str, Any]]: Список тактик
        """
        return list(self.tactics.values())
        
    def get_techniques_by_tactic(self, tactic_id: str) -> List[Dict[str, Any]]:
        """
        Получает список техник для указанной тактики
        
        Args:
            tactic_id: Идентификатор тактики
            
        Returns:
            List[Dict[str, Any]]: Список техник
        """
        result = []
        
        # MITRE ATT&CK использует короткие ID для тактик в связях
        short_id = None
        
        # Ищем короткий ID в external_references
        if tactic_id in self.tactics:
            for ref in self.tactics[tactic_id].get("external_references", []):
                if ref.get("source_name") == "mitre-attack":
                    short_id = ref.get("external_id")
                    break
                    
        if not short_id:
            return []
            
        # Ищем техники, связанные с этой тактикой
        for technique in self.techniques.values():
            if short_id in technique.get("tactics", []):
                result.append(technique)
                
        return result
        
    def get_technique_details(self, technique_id: str) -> Optional[Dict[str, Any]]:
        """
        Получает детальную информацию о технике
        
        Args:
            technique_id: Идентификатор техники (полный ID или T-номер)
            
        Returns:
            Optional[Dict[str, Any]]: Детали техники или None, если не найдена
        """
        # Если передан полный ID
        if technique_id in self.techniques:
            return self.techniques[technique_id]
            
        # Если передан T-номер, ищем по external_references
        for tech_id, technique in self.techniques.items():
            for ref in technique.get("external_references", []):
                if ref.get("source_name") == "mitre-attack" and ref.get("external_id") == technique_id:
                    return technique
                    
        return None
        
    def get_group_details(self, group_id: str) -> Optional[Dict[str, Any]]:
        """
        Получает детальную информацию о группе угроз
        
        Args:
            group_id: Идентификатор группы (полный ID или G-номер)
            
        Returns:
            Optional[Dict[str, Any]]: Детали группы или None, если не найдена
        """
        # Если передан полный ID
        if group_id in self.groups:
            return self.groups[group_id]
            
        # Если передан G-номер, ищем по external_references
        for g_id, group in self.groups.items():
            for ref in group.get("external_references", []):
                if ref.get("source_name") == "mitre-attack" and ref.get("external_id") == group_id:
                    return group
                    
        return None


class CVEService:
    """
    Сервис для работы с базой данных уязвимостей CVE
    """
    
    def __init__(self, cache_dir: str, cache_ttl: int):
        """
        Инициализация сервиса CVE
        
        Args:
            cache_dir: Директория для кэширования данных
            cache_ttl: Время жизни кэша в часах
        """
        self.cache_dir = cache_dir
        self.cache_ttl = cache_ttl
        
        # Основной кэш для недавних CVE
        self.recent_cve_cache_file = os.path.join(cache_dir, "recent_cve.json")
        
        # Кэш для отдельных CVE (используется как ключ-значение)
        self.cve_cache_dir = os.path.join(cache_dir, "cve_details")
        os.makedirs(self.cve_cache_dir, exist_ok=True)
        
        # API-конечные точки
        self.nvd_api_url = "https://services.nvd.nist.gov/rest/json/cves/2.0"
        
        # Загружаем кэш при инициализации
        self._load_cache()
    
    def _load_cache(self):
        """Загружает кэшированные данные или скачивает их, если нужно"""
        # Загружаем кэш недавних CVE
        if os.path.exists(self.recent_cve_cache_file):
            # Проверяем актуальность
            file_time = os.path.getmtime(self.recent_cve_cache_file)
            current_time = time.time()
            
            if (current_time - file_time) / 3600 < self.cache_ttl:
                # Кэш актуален, загружаем
                try:
                    with open(self.recent_cve_cache_file, 'r', encoding='utf-8') as f:
                        self.recent_cve = json.load(f)
                    logger.info(f"Loaded recent CVE cache: {len(self.recent_cve)} entries")
                    return
                except Exception as e:
                    logger.error(f"Error loading CVE cache: {str(e)}")
                
        # Если кэш не загружен или устарел, обновляем его
        logger.info("CVE cache is outdated or not found, refreshing...")
        self.refresh_cache()
    
    def _get_cve_cache_file(self, cve_id: str) -> str:
        """
        Получает путь к файлу кэша для конкретного CVE
        
        Args:
            cve_id: Идентификатор CVE
            
        Returns:
            str: Путь к файлу кэша
        """
        # Нормализуем ID
        cve_id = cve_id.upper()
        if not cve_id.startswith("CVE-"):
            cve_id = f"CVE-{cve_id}"
            
        # Хэшируем идентификатор для получения имени файла
        filename = hashlib.md5(cve_id.encode()).hexdigest() + ".json"
        return os.path.join(self.cve_cache_dir, filename)
    
    @retry(attempts=3, delay=2)
    def refresh_cache(self) -> bool:
        """
        Обновляет кэш данных CVE для недавних уязвимостей
        
        Returns:
            bool: Успешность обновления
        """
        try:
            # Получаем уязвимости за последние 30 дней
            thirty_days_ago = (datetime.now() - timedelta(days=30)).strftime("%Y-%m-%dT00:00:00.000")
            
            params = {
                "pubStartDate": thirty_days_ago,
                "resultsPerPage": 50  # NVD ограничивает до 50 на страницу
            }
            
            logger.info(f"Fetching recent CVEs from {self.nvd_api_url}")
            
            response = requests.get(self.nvd_api_url, params=params)
            response.raise_for_status()
            data = response.json()
            
            if "vulnerabilities" not in data:
                logger.warning("No vulnerabilities found in NVD response")
                return False
                
            # Обрабатываем и сохраняем результаты
            vulnerabilities = data.get("vulnerabilities", [])
            recent_cve = []
            
            for vuln in vulnerabilities:
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
                    "description": description,
                    "published": cve_item.get("published"),
                    "last_modified": cve_item.get("lastModified"),
                    "score": cvss_score,
                    "severity": cvss_severity,
                    "url": f"https://nvd.nist.gov/vuln/detail/{cve_id}"
                }
                
                # Сохраняем также в отдельный кэш
                cache_file = self._get_cve_cache_file(cve_id)
                with open(cache_file, 'w', encoding='utf-8') as f:
                    json.dump(item, f, ensure_ascii=False, indent=2)
                
                recent_cve.append(item)
                
            # Сохраняем в кэш
            self.recent_cve = recent_cve
            with open(self.recent_cve_cache_file, 'w', encoding='utf-8') as f:
                json.dump(recent_cve, f, ensure_ascii=False, indent=2)
                
            logger.info(f"Updated recent CVE cache: {len(recent_cve)} entries")
            
            return True
        except Exception as e:
            logger.error(f"Error refreshing CVE cache: {str(e)}")
            self.recent_cve = []
            return False
    
    @retry(attempts=3, delay=1)
    def get_cve(self, cve_id: str) -> Dict[str, Any]:
        """
        Получает информацию о конкретной уязвимости CVE
        
        Args:
            cve_id: Идентификатор CVE (например, CVE-2021-44228)
            
        Returns:
            Dict[str, Any]: Информация об уязвимости
        """
        # Нормализуем ID
        cve_id = cve_id.upper()
        if not cve_id.startswith("CVE-"):
            cve_id = f"CVE-{cve_id}"
            
        # Проверяем наличие в кэше
        cache_file = self._get_cve_cache_file(cve_id)
        
        if os.path.exists(cache_file):
            # Проверяем актуальность
            file_time = os.path.getmtime(cache_file)
            current_time = time.time()
            
            if (current_time - file_time) / 3600 < self.cache_ttl:
                # Кэш актуален, загружаем
                try:
                    with open(cache_file, 'r', encoding='utf-8') as f:
                        return json.load(f)
                except Exception as e:
                    logger.error(f"Error loading CVE cache for {cve_id}: {str(e)}")
        
        # Если не найдено в кэше или кэш устарел, запрашиваем с NVD
        params = {
            "cveId": cve_id
        }
        
        logger.info(f"Fetching CVE {cve_id} from {self.nvd_api_url}")
        
        response = requests.get(self.nvd_api_url, params=params)
        response.raise_for_status()
        data = response.json()
        
        if "vulnerabilities" not in data or not data["vulnerabilities"]:
            logger.warning(f"CVE {cve_id} not found in NVD")
            return {
                "id": cve_id,
                "description": "Информация не найдена",
                "error": "CVE не найден в базе NVD"
            }
            
        # Обрабатываем результат
        cve_item = data["vulnerabilities"][0].get("cve", {})
        
        # Извлекаем описание
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
        cvss_vector = None
        
        if cvss_data:
            cvss = cvss_data.get("cvssData", {})
            cvss_score = cvss.get("baseScore")
            cvss_severity = cvss.get("baseSeverity")
            cvss_vector = cvss.get("vectorString")
            
        # Извлекаем ссылки
        references = []
        for ref in cve_item.get("references", []):
            references.append({
                "url": ref.get("url", ""),
                "source": ref.get("source", ""),
                "tags": ref.get("tags", [])
            })
            
        # Формируем результат
        result = {
            "id": cve_id,
            "description": description,
            "published": cve_item.get("published"),
            "last_modified": cve_item.get("lastModified"),
            "score": cvss_score,
            "severity": cvss_severity,
            "vector": cvss_vector,
            "references": references,
            "url": f"https://nvd.nist.gov/vuln/detail/{cve_id}"
        }
        
        # Сохраняем в кэш
        with open(cache_file, 'w', encoding='utf-8') as f:
            json.dump(result, f, ensure_ascii=False, indent=2)
            
        return result
    
    def search(self, query: str, limit: int = 10) -> List[Dict[str, Any]]:
        """
        Поиск уязвимостей CVE по ключевым словам
        
        Args:
            query: Поисковый запрос (строка для поиска)
            limit: Максимальное количество результатов
            
        Returns:
            List[Dict[str, Any]]: Список найденных уязвимостей
        """
        # Если запрос похож на CVE ID, используем точный поиск
        if query.upper().startswith("CVE-") or query.upper().startswith("CVE:"):
            cve_id = query.upper().replace("CVE:", "CVE-")
            result = self.get_cve(cve_id)
            return [result] if result.get("error") is None else []
            
        # Для обычного поиска запрашиваем NVD API
        params = {
            "keywordSearch": query,
            "resultsPerPage": min(limit, 50)  # NVD ограничивает до 50 на страницу
        }
        
        logger.info(f"Searching for CVEs with query '{query}' from {self.nvd_api_url}")
        
        try:
            response = requests.get(self.nvd_api_url, params=params)
            response.raise_for_status()
            data = response.json()
            
            if "vulnerabilities" not in data or not data["vulnerabilities"]:
                logger.warning(f"No CVEs found for query '{query}'")
                return []
                
            # Обрабатываем результаты
            results = []
            
            for vuln in data["vulnerabilities"][:limit]:
                cve_item = vuln.get("cve", {})
                cve_id = cve_item.get("id", "Unknown")
                
                # Извлекаем описание
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
                    "description": description,
                    "published": cve_item.get("published"),
                    "last_modified": cve_item.get("lastModified"),
                    "score": cvss_score,
                    "severity": cvss_severity,
                    "url": f"https://nvd.nist.gov/vuln/detail/{cve_id}"
                }
                
                # Сохраняем также в отдельный кэш
                cache_file = self._get_cve_cache_file(cve_id)
                with open(cache_file, 'w', encoding='utf-8') as f:
                    json.dump(item, f, ensure_ascii=False, indent=2)
                    
                results.append(item)
                
            return results
        except Exception as e:
            logger.error(f"Error searching CVEs: {str(e)}")
            return []


class OSINTService:
    """
    Сервис для работы с данными OSINT (Open Source Intelligence)
    по кибербезопасности
    """
    
    def __init__(self, cache_dir: str, cache_ttl: int):
        """
        Инициализация сервиса OSINT
        
        Args:
            cache_dir: Директория для кэширования данных
            cache_ttl: Время жизни кэша в часах
        """
        self.cache_dir = cache_dir
        self.cache_ttl = cache_ttl
        
        # Директория для кэширования OSINT данных
        self.osint_cache_dir = os.path.join(cache_dir, "osint_data")
        os.makedirs(self.osint_cache_dir, exist_ok=True)
        
    def refresh_cache(self) -> bool:
        """
        Обновляет кэш данных OSINT
        
        Returns:
            bool: Успешность обновления
        """
        # В отличие от других сервисов, OSINT не имеет предварительного кэша
        # Кэширование происходит при каждом запросе
        return True
    
    def _get_cache_file(self, query_type: str, query: str) -> str:
        """
        Получает путь к файлу кэша для конкретного OSINT-запроса
        
        Args:
            query_type: Тип запроса (ip, domain, hash, etc)
            query: Запрос
            
        Returns:
            str: Путь к файлу кэша
        """
        # Хэшируем идентификатор для получения имени файла
        key = f"{query_type}_{query}"
        filename = hashlib.md5(key.encode()).hexdigest() + ".json"
        return os.path.join(self.osint_cache_dir, filename)
    
    def _is_cache_valid(self, cache_file: str) -> bool:
        """
        Проверяет актуальность кэша
        
        Args:
            cache_file: Путь к файлу кэша
            
        Returns:
            bool: True, если кэш актуален
        """
        if not os.path.exists(cache_file):
            return False
            
        # Проверяем время создания файла
        file_time = os.path.getmtime(cache_file)
        current_time = time.time()
        
        # Сравниваем с TTL
        return (current_time - file_time) / 3600 < self.cache_ttl
    
    def get_threat_intelligence(self, query: str) -> Dict[str, Any]:
        """
        Получает данные Threat Intelligence по запросу
        
        Args:
            query: Поисковый запрос (IP, домен, хэш и т.д.)
            
        Returns:
            Dict[str, Any]: Результаты анализа угроз
        """
        query = query.strip()
        query_type = self._detect_query_type(query)
        
        # Проверяем кэш
        cache_file = self._get_cache_file(query_type, query)
        
        if self._is_cache_valid(cache_file):
            try:
                with open(cache_file, 'r', encoding='utf-8') as f:
                    return json.load(f)
            except Exception as e:
                logger.error(f"Error loading OSINT cache: {str(e)}")
                
        # Если кэш не актуален, получаем новые данные
        result = self._get_threat_data(query_type, query)
        
        # Сохраняем в кэш
        try:
            with open(cache_file, 'w', encoding='utf-8') as f:
                json.dump(result, f, ensure_ascii=False, indent=2)
        except Exception as e:
            logger.error(f"Error saving OSINT cache: {str(e)}")
            
        return result
    
    def _detect_query_type(self, query: str) -> str:
        """
        Определяет тип запроса (IP, домен, хэш и т.д.)
        
        Args:
            query: Запрос
            
        Returns:
            str: Тип запроса
        """
        import re
        
        # Проверка на IP
        ip_pattern = r"^(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)$"
        if re.match(ip_pattern, query):
            return "ip"
            
        # Проверка на домен
        domain_pattern = r"^(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}$"
        if re.match(domain_pattern, query):
            return "domain"
            
        # Проверка на хэш MD5
        if re.match(r"^[a-fA-F0-9]{32}$", query):
            return "hash_md5"
            
        # Проверка на хэш SHA1
        if re.match(r"^[a-fA-F0-9]{40}$", query):
            return "hash_sha1"
            
        # Проверка на хэш SHA256
        if re.match(r"^[a-fA-F0-9]{64}$", query):
            return "hash_sha256"
            
        # URL
        if query.startswith("http://") or query.startswith("https://"):
            return "url"
            
        # Если не удалось определить, считаем текстовым запросом
        return "text"
    
    def _get_threat_data(self, query_type: str, query: str) -> Dict[str, Any]:
        """
        Получает данные об угрозах в зависимости от типа запроса
        
        Args:
            query_type: Тип запроса
            query: Запрос
            
        Returns:
            Dict[str, Any]: Данные об угрозах
        """
        result = {
            "query": query,
            "query_type": query_type,
            "found": False,
            "data": {}
        }
        
        try:
            if query_type == "ip":
                return self._get_ip_threat_data(query, result)
            elif query_type == "domain":
                return self._get_domain_threat_data(query, result)
            elif query_type in ["hash_md5", "hash_sha1", "hash_sha256"]:
                return self._get_hash_threat_data(query, query_type, result)
            elif query_type == "url":
                return self._get_url_threat_data(query, result)
            else:
                return self._get_text_threat_data(query, result)
        except Exception as e:
            logger.error(f"Error getting threat data for {query_type} {query}: {str(e)}")
            result["error"] = str(e)
            return result
    
    def _get_ip_threat_data(self, ip: str, result: Dict[str, Any]) -> Dict[str, Any]:
        """
        Получает данные об угрозах для IP-адреса
        
        Args:
            ip: IP-адрес
            result: Базовый результат для заполнения
            
        Returns:
            Dict[str, Any]: Данные об угрозах
        """
        # Используем API AbuseIPDB для проверки IP
        try:
            headers = {
                "Accept": "application/json",
                "Key": os.environ.get("ABUSEIPDB_API_KEY", "")  # API ключ из переменных окружения
            }
            
            # Если ключ не указан, используем только информацию о геолокации
            if not headers["Key"]:
                # Получение геолокации (бесплатный API)
                geo_response = requests.get(f"https://ipapi.co/{ip}/json/")
                geo_response.raise_for_status()
                geo_data = geo_response.json()
                
                result["data"]["geolocation"] = {
                    "country": geo_data.get("country_name"),
                    "country_code": geo_data.get("country_code"),
                    "city": geo_data.get("city"),
                    "region": geo_data.get("region"),
                    "org": geo_data.get("org"),
                    "asn": geo_data.get("asn")
                }
                
                result["found"] = True
                return result
                
            # Если ключ указан, получаем данные от AbuseIPDB
            params = {
                "ipAddress": ip,
                "maxAgeInDays": 90,
                "verbose": True
            }
            
            response = requests.get(
                "https://api.abuseipdb.com/api/v2/check",
                headers=headers,
                params=params
            )
            
            if response.status_code == 200:
                abuse_data = response.json().get("data", {})
                
                result["data"]["abuseipdb"] = {
                    "abuse_confidence_score": abuse_data.get("abuseConfidenceScore"),
                    "is_whitelisted": abuse_data.get("isWhitelisted"),
                    "total_reports": abuse_data.get("totalReports"),
                    "last_reported_at": abuse_data.get("lastReportedAt"),
                    "country": abuse_data.get("countryName"),
                    "country_code": abuse_data.get("countryCode"),
                    "isp": abuse_data.get("isp"),
                    "usage_type": abuse_data.get("usageType"),
                    "domain": abuse_data.get("domain")
                }
                
                # Определяем статус угрозы
                if abuse_data.get("abuseConfidenceScore", 0) > 50:
                    result["data"]["threat_status"] = "Высокая вероятность угрозы"
                elif abuse_data.get("abuseConfidenceScore", 0) > 20:
                    result["data"]["threat_status"] = "Средняя вероятность угрозы"
                else:
                    result["data"]["threat_status"] = "Низкая вероятность угрозы"
                    
                result["found"] = True
            
            # В любом случае попробуем получить геолокацию
            try:
                geo_response = requests.get(f"https://ipapi.co/{ip}/json/")
                if geo_response.status_code == 200:
                    geo_data = geo_response.json()
                    
                    result["data"]["geolocation"] = {
                        "country": geo_data.get("country_name"),
                        "country_code": geo_data.get("country_code"),
                        "city": geo_data.get("city"),
                        "region": geo_data.get("region"),
                        "org": geo_data.get("org"),
                        "asn": geo_data.get("asn")
                    }
            except Exception:
                pass
                
            return result
        except Exception as e:
            logger.error(f"Error checking IP {ip}: {str(e)}")
            result["error"] = str(e)
            return result
    
    def _get_domain_threat_data(self, domain: str, result: Dict[str, Any]) -> Dict[str, Any]:
        """
        Получает данные об угрозах для домена
        
        Args:
            domain: Домен
            result: Базовый результат для заполнения
            
        Returns:
            Dict[str, Any]: Данные об угрозах
        """
        # Используем WHOIS для получения базовой информации
        try:
            import socket
            # Получаем IP адрес домена
            try:
                ip = socket.gethostbyname(domain)
                result["data"]["ip"] = ip
                
                # Дополняем информацией об IP
                ip_result = self._get_ip_threat_data(ip, {"data": {}})
                if "data" in ip_result and "geolocation" in ip_result["data"]:
                    result["data"]["geolocation"] = ip_result["data"]["geolocation"]
                if "data" in ip_result and "abuseipdb" in ip_result["data"]:
                    result["data"]["ip_threat_info"] = ip_result["data"]["abuseipdb"]
            except:
                pass
                
            # Получаем WHOIS информацию
            try:
                # Не всегда доступно, поэтому в try/except
                import whois
                domain_info = whois.whois(domain)
                
                result["data"]["whois"] = {
                    "domain_name": domain_info.domain_name,
                    "registrar": domain_info.registrar,
                    "creation_date": str(domain_info.creation_date),
                    "expiration_date": str(domain_info.expiration_date),
                    "updated_date": str(domain_info.updated_date),
                    "name_servers": domain_info.name_servers
                }
                
                result["found"] = True
            except Exception:
                pass
                
            # Проверяем SSL-сертификат
            try:
                import ssl
                import socket
                from datetime import datetime
                
                context = ssl.create_default_context()
                with socket.create_connection((domain, 443)) as sock:
                    with context.wrap_socket(sock, server_hostname=domain) as ssock:
                        cert = ssock.getpeercert()
                        
                        # Извлекаем информацию о сертификате
                        issued_to = dict(x[0] for x in cert['subject'])
                        issued_by = dict(x[0] for x in cert['issuer'])
                        
                        # Даты действия
                        not_before = datetime.strptime(cert['notBefore'], '%b %d %H:%M:%S %Y %Z')
                        not_after = datetime.strptime(cert['notAfter'], '%b %d %H:%M:%S %Y %Z')
                        
                        result["data"]["ssl_certificate"] = {
                            "issued_to": issued_to.get('commonName'),
                            "issued_by": issued_by.get('commonName'),
                            "valid_from": not_before.strftime('%Y-%m-%d'),
                            "valid_until": not_after.strftime('%Y-%m-%d'),
                            "is_valid": datetime.now() < not_after and datetime.now() > not_before
                        }
            except Exception:
                pass
                
            return result
        except Exception as e:
            logger.error(f"Error checking domain {domain}: {str(e)}")
            result["error"] = str(e)
            return result
    
    def _get_hash_threat_data(self, file_hash: str, hash_type: str, result: Dict[str, Any]) -> Dict[str, Any]:
        """
        Получает данные об угрозах для хэша файла
        
        Args:
            file_hash: Хэш файла
            hash_type: Тип хэша (md5, sha1, sha256)
            result: Базовый результат для заполнения
            
        Returns:
            Dict[str, Any]: Данные об угрозах
        """
        # Используем API VirusTotal для проверки хэша
        try:
            api_key = os.environ.get("VIRUSTOTAL_API_KEY", "")
            
            if not api_key:
                result["error"] = "API ключ VirusTotal не указан"
                return result
                
            headers = {
                "x-apikey": api_key
            }
            
            response = requests.get(
                f"https://www.virustotal.com/api/v3/files/{file_hash}",
                headers=headers
            )
            
            if response.status_code == 200:
                vt_data = response.json().get("data", {})
                attributes = vt_data.get("attributes", {})
                
                result["data"]["virustotal"] = {
                    "last_analysis_date": attributes.get("last_analysis_date"),
                    "last_analysis_stats": attributes.get("last_analysis_stats"),
                    "meaningful_name": attributes.get("meaningful_name"),
                    "type_description": attributes.get("type_description"),
                    "size": attributes.get("size"),
                    "md5": attributes.get("md5"),
                    "sha1": attributes.get("sha1"),
                    "sha256": attributes.get("sha256")
                }
                
                # Определяем статус угрозы
                if attributes.get("last_analysis_stats", {}).get("malicious", 0) > 10:
                    result["data"]["threat_status"] = "Высокая вероятность угрозы"
                elif attributes.get("last_analysis_stats", {}).get("malicious", 0) > 3:
                    result["data"]["threat_status"] = "Средняя вероятность угрозы"
                elif attributes.get("last_analysis_stats", {}).get("malicious", 0) > 0:
                    result["data"]["threat_status"] = "Низкая вероятность угрозы"
                else:
                    result["data"]["threat_status"] = "Угроз не обнаружено"
                    
                result["found"] = True
                
            return result
        except Exception as e:
            logger.error(f"Error checking hash {file_hash}: {str(e)}")
            result["error"] = str(e)
            return result
    
    def _get_url_threat_data(self, url: str, result: Dict[str, Any]) -> Dict[str, Any]:
        """
        Получает данные об угрозах для URL
        
        Args:
            url: URL
            result: Базовый результат для заполнения
            
        Returns:
            Dict[str, Any]: Данные об угрозах
        """
        # Базовый анализ URL
        import urllib.parse
        
        try:
            parsed_url = urllib.parse.urlparse(url)
            domain = parsed_url.netloc
            
            result["data"]["url_analysis"] = {
                "scheme": parsed_url.scheme,
                "domain": domain,
                "path": parsed_url.path,
                "query": parsed_url.query
            }
            
            # Дополняем информацией о домене
            if domain:
                domain_result = self._get_domain_threat_data(domain, {"data": {}})
                if "data" in domain_result:
                    for key, value in domain_result["data"].items():
                        result["data"][key] = value
                        
            # Используем API SafeBrowsing для проверки URL
            api_key = os.environ.get("SAFEBROWSING_API_KEY", "")
            
            if api_key:
                # Создаем запрос
                payload = {
                    "client": {
                        "clientId": "cybersec-consultant",
                        "clientVersion": "1.0"
                    },
                    "threatInfo": {
                        "threatTypes": ["MALWARE", "SOCIAL_ENGINEERING", "UNWANTED_SOFTWARE", "POTENTIALLY_HARMFUL_APPLICATION"],
                        "platformTypes": ["ANY_PLATFORM"],
                        "threatEntryTypes": ["URL"],
                        "threatEntries": [
                            {"url": url}
                        ]
                    }
                }
                
                response = requests.post(
                    f"https://safebrowsing.googleapis.com/v4/threatMatches:find?key={api_key}",
                    json=payload
                )
                
                if response.status_code == 200:
                    sb_data = response.json()
                    
                    if "matches" in sb_data and sb_data["matches"]:
                        result["data"]["safebrowsing"] = {
                            "threats": sb_data["matches"]
                        }
                        result["data"]["threat_status"] = "Обнаружены угрозы в Safe Browsing"
                    else:
                        result["data"]["safebrowsing"] = {
                            "threats": []
                        }
                        result["data"]["threat_status"] = "Угроз не обнаружено в Safe Browsing"
                        
            result["found"] = True
            return result
        except Exception as e:
            logger.error(f"Error checking URL {url}: {str(e)}")
            result["error"] = str(e)
            return result
    
    def _get_text_threat_data(self, text: str, result: Dict[str, Any]) -> Dict[str, Any]:
        """
        Анализирует текстовый запрос на предмет угроз
        
        Args:
            text: Текстовый запрос
            result: Базовый результат для заполнения
            
        Returns:
            Dict[str, Any]: Данные об угрозах
        """
        # Базовый анализ текста
        try:
            import re
            
            # Ищем потенциальные индикаторы угроз в тексте
            indicators = {
                "ips": re.findall(r"\b(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\b", text),
                "domains": re.findall(r"\b(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}\b", text),
                "md5": re.findall(r"\b[a-fA-F0-9]{32}\b", text),
                "sha1": re.findall(r"\b[a-fA-F0-9]{40}\b", text),
                "sha256": re.findall(r"\b[a-fA-F0-9]{64}\b", text),
                "urls": re.findall(r"https?://(?:[-\w.]|(?:%[\da-fA-F]{2}))+", text)
            }
            
            # Удаляем дубликаты
            for key in indicators:
                indicators[key] = list(set(indicators[key]))
                
            result["data"]["indicators"] = indicators
            
            # Анализируем первые найденные индикаторы
            for indicator_type, values in indicators.items():
                if values:
                    if indicator_type == "ips" and values[0]:
                        ip_result = self._get_ip_threat_data(values[0], {"data": {}})
                        if "data" in ip_result:
                            result["data"]["ip_analysis"] = {
                                "ip": values[0],
                                "data": ip_result["data"]
                            }
                    elif indicator_type == "domains" and values[0]:
                        domain_result = self._get_domain_threat_data(values[0], {"data": {}})
                        if "data" in domain_result:
                            result["data"]["domain_analysis"] = {
                                "domain": values[0],
                                "data": domain_result["data"]
                            }
                    elif indicator_type in ["md5", "sha1", "sha256"] and values[0]:
                        hash_type = indicator_type
                        hash_result = self._get_hash_threat_data(values[0], hash_type, {"data": {}})
                        if "data" in hash_result:
                            result["data"]["hash_analysis"] = {
                                "hash": values[0],
                                "type": hash_type,
                                "data": hash_result["data"]
                            }
                    elif indicator_type == "urls" and values[0]:
                        url_result = self._get_url_threat_data(values[0], {"data": {}})
                        if "data" in url_result:
                            result["data"]["url_analysis"] = {
                                "url": values[0],
                                "data": url_result["data"]
                            }
                            
            result["found"] = True
            return result
        except Exception as e:
            logger.error(f"Error analyzing text: {str(e)}")
            result["error"] = str(e)
            return result
