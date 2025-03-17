# -*- coding: utf-8 -*-
"""
Пакет для консультанта по кибербезопасности
"""

from cybersec_consultant.consultant import CybersecurityConsultant
from cybersec_consultant.knowledge_base import KnowledgeBaseManager
from cybersec_consultant.knowledge_enrichment import get_enrichment_manager
from cybersec_consultant.user_profiles import get_profile_manager
from cybersec_consultant.external_services import ExternalServicesManager

# Функция для создания экземпляра консультанта
def create_consultant():
    """
    Создает экземпляр консультанта по кибербезопасности
    
    Returns:
        CybersecurityConsultant: Экземпляр консультанта
    """
    return CybersecurityConsultant()
