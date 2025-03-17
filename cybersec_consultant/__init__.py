# -*- coding: utf-8 -*-
"""
Пакет консультанта по кибербезопасности с модульной структурой
"""

__version__ = '0.1.0'
__author__ = 'Cybersecurity Consultant Team'

from cybersec_consultant.consultant import CybersecurityConsultant
from cybersec_consultant.knowledge_base import KnowledgeBaseManager
from cybersec_consultant.embeddings import VectorSearchManager
from cybersec_consultant.llm_interface import LLMInterface
from cybersec_consultant.prompt_management import PromptManager
from cybersec_consultant.config import ConfigManager

# Создаем точку входа для основного приложения
def create_consultant():
    """
    Создает и возвращает экземпляр консультанта по кибербезопасности
    
    Returns:
        CybersecurityConsultant: Экземпляр консультанта
    """
    return CybersecurityConsultant()
