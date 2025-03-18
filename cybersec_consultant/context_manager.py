# -*- coding: utf-8 -*-
"""
Модуль управления контекстом диалога
"""
import os
import json
from datetime import datetime
from cybersec_consultant.config import DATA_DIR
from cybersec_consultant.state_management import STATE

class ContextManager:
    """Класс для управления контекстом диалога"""
    
    def __init__(self):
        """Инициализация менеджера контекста"""
        self.history = []
        self.history_dir = os.path.join(DATA_DIR, "history")
        os.makedirs(self.history_dir, exist_ok=True)
        self.session_id = datetime.now().strftime("%Y%m%d_%H%M%S")
        self.max_history_length = 10
        
    def update_context(self, user_query, documents, response):
        """
        Обновляет контекст диалога, добавляя новый запрос и ответ
        
        Args:
            user_query (str): Запрос пользователя
            documents (list): Найденные документы
            response (str): Ответ системы
            
        Returns:
            dict: Текущий контекст
        """
        entry = {
            "timestamp": datetime.now().isoformat(),
            "user_query": user_query,
            "documents": [doc.page_content for doc in documents[:3]] if documents else [],
            "response": response
        }
        
        self.history.append(entry)
        
        # Ограничиваем историю заданной длиной
        if len(self.history) > self.max_history_length:
            self.history = self.history[-self.max_history_length:]
            
        return self.get_current_context()
    
    def get_current_context(self):
        """
        Возвращает текущий контекст диалога
        
        Returns:
            dict: Текущий контекст
        """
        return {
            "session_id": self.session_id,
            "history": self.history,
            "history_length": len(self.history)
        }
    
    def save_history(self):
        """
        Сохраняет историю диалога в файл
        
        Returns:
            bool: Успешность операции
        """
        try:
            filename = f"history_{self.session_id}.json"
            filepath = os.path.join(self.history_dir, filename)
            
            with open(filepath, "w", encoding="utf-8") as f:
                json.dump(self.history, f, ensure_ascii=False, indent=2)
                
            return True
        except Exception as e:
            print(f"Ошибка при сохранении истории: {str(e)}")
            return False
            
    def clear_history(self):
        """
        Очищает историю диалога
        
        Returns:
            bool: Успешность операции
        """
        self.history = []
        return True
