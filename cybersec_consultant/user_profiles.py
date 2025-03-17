# -*- coding: utf-8 -*-
"""
Модуль для персонализации ответов в зависимости от 
уровня технической подготовки пользователя
"""

import os
import json
import logging
from typing import Dict, Any, List, Optional

from cybersec_consultant.config import ConfigManager, DATA_DIR
from cybersec_consultant.state_management import STATE

# Настройка логирования
logger = logging.getLogger(__name__)

class UserProfileManager:
    """
    Класс для управления профилями пользователей и персонализации ответов
    """
    
    def __init__(self):
        """Инициализация менеджера профилей пользователей"""
        self.config_manager = ConfigManager()
        
        # Директория для хранения профилей
        self.profiles_dir = os.path.join(DATA_DIR, "user_profiles")
        os.makedirs(self.profiles_dir, exist_ok=True)
        
        # Загружаем стандартные профили
        self._load_default_profiles()
        
        # Текущий профиль (из состояния или по умолчанию)
        self.current_profile_id = STATE.profile or "standard"
        
    def _load_default_profiles(self):
        """Загружает стандартные профили пользователей"""
        # Стандартные профили
        default_profiles = {
            "beginner": {
                "name": "Начинающий",
                "description": "Профиль для пользователей с базовыми знаниями в кибербезопасности",
                "technical_level": "low",
                "style": "educational",
                "details_level": "basic",
                "examples": True,
                "analogies": True,
                "step_by_step": True,
                "avoid_jargon": True,
                "include_visuals": True,
                "prompt_modifiers": [
                    "Объясни простыми словами, как если бы объяснял человеку без технического образования.",
                    "Избегай технического жаргона, а если используешь специальные термины, объясняй их значение.",
                    "Приводи простые понятные примеры из повседневной жизни.",
                    "Используй аналогии для объяснения сложных концепций.",
                    "Объясняй шаг за шагом."
                ]
            },
            "standard": {
                "name": "Стандартный",
                "description": "Стандартный профиль для пользователей со средними знаниями",
                "technical_level": "medium",
                "style": "balanced",
                "details_level": "moderate",
                "examples": True,
                "analogies": False,
                "step_by_step": False,
                "avoid_jargon": False,
                "include_visuals": True,
                "prompt_modifiers": [
                    "Используй сбалансированный подход в объяснениях, с умеренным количеством технических деталей.",
                    "Приводи практические примеры там, где это уместно.",
                    "Можешь использовать технические термины, но поясняй сложные или специфические."
                ]
            },
            "expert": {
                "name": "Эксперт",
                "description": "Профиль для продвинутых пользователей и специалистов по ИБ",
                "technical_level": "high",
                "style": "technical",
                "details_level": "detailed",
                "examples": False,
                "analogies": False,
                "step_by_step": False,
                "avoid_jargon": False,
                "include_visuals": False,
                "prompt_modifiers": [
                    "Используй профессиональную техническую терминологию без упрощений.",
                    "Предоставляй детальные и точные технические объяснения.",
                    "Фокусируйся на фактах и технических деталях, минимизируя вводную информацию.",
                    "Можешь использовать специализированные термины без пояснений."
                ]
            },
            "educational": {
                "name": "Образовательный",
                "description": "Профиль для обучения основам кибербезопасности",
                "technical_level": "medium",
                "style": "educational",
                "details_level": "comprehensive",
                "examples": True,
                "analogies": True,
                "step_by_step": True,
                "avoid_jargon": False,
                "include_visuals": True,
                "prompt_modifiers": [
                    "Отвечай как преподаватель кибербезопасности, который объясняет концепции студентам.",
                    "Структурируй информацию логически, от общего к частному.",
                    "Объясняй базовые концепции, прежде чем переходить к более сложным.",
                    "Включай 'интересные факты' или исторический контекст, где это уместно.",
                    "Предлагай вопросы для самопроверки понимания материала."
                ]
            },
            "incident_response": {
                "name": "Реагирование на инциденты",
                "description": "Профиль для ситуаций реагирования на инциденты ИБ",
                "technical_level": "high",
                "style": "concise",
                "details_level": "actionable",
                "examples": False,
                "analogies": False,
                "step_by_step": True,
                "avoid_jargon": False,
                "include_visuals": False,
                "prompt_modifiers": [
                    "Предоставляй четкие, краткие и конкретные рекомендации по действиям.",
                    "Структурируй ответ в виде пошаговых инструкций или чек-листа, где это применимо.",
                    "Приоритизируй информацию от наиболее критичной к менее важной.",
                    "Фокусируйся на практических действиях, которые нужно предпринять."
                ]
            }
        }
        
        # Загружаем сохраненные профили или используем стандартные
        self.profiles = self.config_manager.get_setting("user_profiles", "profiles", default_profiles)
        
        # Обновляем профили (добавляем новые стандартные, если их нет)
        for profile_id, profile_config in default_profiles.items():
            if profile_id not in self.profiles:
                self.profiles[profile_id] = profile_config
                
        # Сохраняем обновленные профили
        self.config_manager.set_setting("user_profiles", "profiles", self.profiles)
        
        logger.info(f"Loaded {len(self.profiles)} user profiles")
        return self.profiles
    
    def get_profile(self, profile_id: Optional[str] = None) -> Dict[str, Any]:
        """
        Получает профиль пользователя по идентификатору
        
        Args:
            profile_id: Идентификатор профиля (если None, используется текущий)
            
        Returns:
            Dict[str, Any]: Конфигурация профиля
        """
        profile_id = profile_id or self.current_profile_id
        
        if profile_id not in self.profiles:
            logger.warning(f"Profile {profile_id} not found, using 'standard' profile")
            profile_id = "standard"
            
        return self.profiles[profile_id]
    
    def set_current_profile(self, profile_id: str) -> bool:
        """
        Устанавливает текущий профиль пользователя
        
        Args:
            profile_id: Идентификатор профиля
            
        Returns:
            bool: Успешность операции
        """
        if profile_id not in self.profiles:
            logger.warning(f"Profile {profile_id} not found")
            return False
            
        self.current_profile_id = profile_id
        STATE.profile = profile_id
        
        logger.info(f"Current profile set to: {profile_id}")
        return True
    
    def add_custom_profile(self, profile_id: str, profile_config: Dict[str, Any]) -> bool:
        """
        Добавляет пользовательский профиль
        
        Args:
            profile_id: Идентификатор профиля
            profile_config: Конфигурация профиля
            
        Returns:
            bool: Успешность операции
        """
        # Проверяем наличие необходимых полей
        required_fields = ["name", "technical_level", "style"]
        for field in required_fields:
            if field not in profile_config:
                logger.error(f"Missing required field '{field}' in profile config")
                return False
                
        # Добавляем профиль
        self.profiles[profile_id] = profile_config
        
        # Сохраняем обновленные профили
        self.config_manager.set_setting("user_profiles", "profiles", self.profiles)
        
        logger.info(f"Added custom profile: {profile_id} - {profile_config['name']}")
        return True
    
    def remove_profile(self, profile_id: str) -> bool:
        """
        Удаляет профиль пользователя
        
        Args:
            profile_id: Идентификатор профиля
            
        Returns:
            bool: Успешность операции
        """
        # Проверяем, является ли профиль стандартным
        if profile_id in ["beginner", "standard", "expert", "educational", "incident_response"]:
            logger.warning(f"Cannot remove default profile: {profile_id}")
            return False
            
        if profile_id in self.profiles:
            del self.profiles[profile_id]
            self.config_manager.set_setting("user_profiles", "profiles", self.profiles)
            
            # Если удален текущий профиль, переключаемся на стандартный
            if self.current_profile_id == profile_id:
                self.current_profile_id = "standard"
                STATE.profile = "standard"
                
            logger.info(f"Removed profile: {profile_id}")
            return True
        else:
            logger.warning(f"Profile not found: {profile_id}")
            return False
    
    def update_profile(self, profile_id: str, updates: Dict[str, Any]) -> bool:
        """
        Обновляет параметры профиля пользователя
        
        Args:
            profile_id: Идентификатор профиля
            updates: Обновляемые параметры
            
        Returns:
            bool: Успешность операции
        """
        if profile_id not in self.profiles:
            logger.warning(f"Profile not found: {profile_id}")
            return False
            
        # Обновляем параметры
        self.profiles[profile_id].update(updates)
        
        # Сохраняем обновленные профили
        self.config_manager.set_setting("user_profiles", "profiles", self.profiles)
        
        logger.info(f"Updated profile: {profile_id}")
        return True
    
    def get_profile_prompt_modifiers(self, profile_id: Optional[str] = None) -> List[str]:
        """
        Получает модификаторы промптов для профиля
        
        Args:
            profile_id: Идентификатор профиля (если None, используется текущий)
            
        Returns:
            List[str]: Список модификаторов промптов
        """
        profile = self.get_profile(profile_id)
        return profile.get("prompt_modifiers", [])
    
    def adapt_content_to_profile(self, content: str, profile_id: Optional[str] = None) -> str:
        """
        Адаптирует содержимое под профиль пользователя
        
        Args:
            content: Исходное содержимое
            profile_id: Идентификатор профиля (если None, используется текущий)
            
        Returns:
            str: Адаптированное содержимое
        """
        # Получаем профиль
        profile = self.get_profile(profile_id)
        
        # В будущем здесь может быть более сложная логика адаптации контента,
        # но сейчас это делается через модификаторы промптов при генерации ответа
        
        return content
    
    def generate_profile_prompt_modification(self, profile_id: Optional[str] = None) -> str:
        """
        Генерирует модификацию системного промпта на основе профиля
        
        Args:
            profile_id: Идентификатор профиля (если None, используется текущий)
            
        Returns:
            str: Текст модификации для системного промпта
        """
        profile = self.get_profile(profile_id)
        
        # Получаем базовые характеристики профиля
        name = profile.get("name", "")
        technical_level = profile.get("technical_level", "medium")
        details_level = profile.get("details_level", "moderate")
        style = profile.get("style", "balanced")
        
        # Формируем базовую модификацию
        prompt_mod = f"При ответе используй настройки профиля '{name}':\n"
        
        # Добавляем характеристики
        if technical_level == "low":
            prompt_mod += "- Технический уровень: Низкий. Избегай сложной терминологии, объясняй концепции простыми словами.\n"
        elif technical_level == "medium":
            prompt_mod += "- Технический уровень: Средний. Используй умеренное количество технических терминов с пояснениями.\n"
        elif technical_level == "high":
            prompt_mod += "- Технический уровень: Высокий. Можешь использовать специализированную терминологию без упрощений.\n"
            
        if details_level == "basic":
            prompt_mod += "- Уровень детализации: Базовый. Фокусируйся на общих концепциях без глубокого погружения в детали.\n"
        elif details_level == "moderate":
            prompt_mod += "- Уровень детализации: Умеренный. Баланс между общими концепциями и техническими деталями.\n"
        elif details_level == "detailed":
            prompt_mod += "- Уровень детализации: Детальный. Предоставляй исчерпывающую техническую информацию.\n"
        elif details_level == "comprehensive":
            prompt_mod += "- Уровень детализации: Комплексный. Объясняй как общие принципы, так и технические детали.\n"
        elif details_level == "actionable":
            prompt_mod += "- Уровень детализации: Практический. Фокусируйся на конкретных действиях и рекомендациях.\n"
            
        if style == "educational":
            prompt_mod += "- Стиль: Образовательный. Объясняй как учитель, фокусируясь на понимании концепций.\n"
        elif style == "balanced":
            prompt_mod += "- Стиль: Сбалансированный. Сочетай информативность и доступность изложения.\n"
        elif style == "technical":
            prompt_mod += "- Стиль: Технический. Фокусируйся на точных технических деталях и терминологии.\n"
        elif style == "concise":
            prompt_mod += "- Стиль: Лаконичный. Предоставляй краткую и четкую информацию без лишних деталей.\n"
            
        # Дополнительные настройки
        if profile.get("examples", False):
            prompt_mod += "- Включай практические примеры для иллюстрации концепций.\n"
            
        if profile.get("analogies", False):
            prompt_mod += "- Используй аналогии для объяснения сложных концепций.\n"
            
        if profile.get("step_by_step", False):
            prompt_mod += "- Объясняй материал пошагово, структурируя информацию.\n"
            
        if profile.get("avoid_jargon", False):
            prompt_mod += "- Избегай технического жаргона, а если используешь специальные термины, объясняй их значение.\n"
            
        # Добавляем список специфических модификаторов, если они есть
        modifiers = profile.get("prompt_modifiers", [])
        if modifiers:
            prompt_mod += "\nДополнительные инструкции:\n"
            for modifier in modifiers:
                prompt_mod += f"- {modifier}\n"
                
        return prompt_mod

# Функция для получения менеджера профилей пользователей
def get_profile_manager():
    """
    Получает экземпляр менеджера профилей пользователей
    
    Returns:
        UserProfileManager: Экземпляр менеджера
    """
    return UserProfileManager()
