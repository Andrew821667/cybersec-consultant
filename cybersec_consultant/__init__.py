# -*- coding: utf-8 -*-
"""
Пакет консультанта по кибербезопасности
"""

from cybersec_consultant.consultant import CybersecurityConsultant
from cybersec_consultant.knowledge_base import KnowledgeBaseManager
from cybersec_consultant.embeddings import VectorSearchManager
from cybersec_consultant.hybrid_search import HybridSearchManager
from cybersec_consultant.llm_interface import LLMInterface
from cybersec_consultant.state_management import STATE

__version__ = "1.1.0"
