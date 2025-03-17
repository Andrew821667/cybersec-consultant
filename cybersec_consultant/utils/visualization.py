# -*- coding: utf-8 -*-
"""
Утилиты для визуализации данных
"""

import json
import time
import numpy as np
import matplotlib.pyplot as plt
from datetime import datetime, timedelta

class DataVisualizer:
    """Класс для визуализации данных в консультанте"""

    def __init__(self):
        """Инициализация визуализатора"""
        # Настраиваем стиль визуализации
        plt.style.use('fivethirtyeight')
        self.colors = ['#4C72B0', '#55A868', '#C44E52', '#8172B2', '#CCB974', '#64B5CD']
    
    def visualize_search_results(self, query, results_with_scores):
        """
        Визуализирует результаты поиска

        Args:
            query (str): Поисковый запрос
            results_with_scores (list): Список кортежей (документ, оценка)

        Returns:
            plt.Figure: Объект фигуры matplotlib
        """
        if not results_with_scores:
            return None
        
        # Извлекаем оценки релевантности
        relevance_scores = [max(0, min(100, 100 * (1 - score / 2))) for _, score in results_with_scores]
        
        # Извлекаем метаданные источников
        doc_ids = [f"Док {i+1}" for i in range(len(results_with_scores))]
        
        # Создаем фигуру
        fig, ax = plt.subplots(figsize=(10, 6))
        
        # Создаем график релевантности
        bars = ax.bar(doc_ids, relevance_scores, color=self.colors)
        
        # Добавляем подписи и оформление
        ax.set_title(f'Релевантность результатов для запроса: "{query}"')
        ax.set_xlabel('Документы')
        ax.set_ylabel('Релевантность (%)')
        ax.set_ylim(0, 105)  # Немного увеличиваем верхний предел для аннотаций
        
        # Добавляем значения над столбцами
        for bar in bars:
            height = bar.get_height()
            ax.text(bar.get_x() + bar.get_width()/2., height + 1,
                   f'{height:.1f}%', ha='center', va='bottom')
        
        # Добавляем сетку для читаемости
        ax.grid(axis='y', linestyle='--', alpha=0.7)
        
        # Настраиваем отступы
        plt.tight_layout()
        
        return fig
    
    def visualize_session_stats(self, session_stats):
        """
        Визуализирует статистику сессии

        Args:
            session_stats (dict): Статистика сессии

        Returns:
            list: Список объектов matplotlib.Figure
        """
        figures = []
        
        # Проверяем наличие запросов
        if not session_stats.get("queries"):
            return figures
        
        # 1. График времени выполнения запросов
        execution_times = [q.get("time", 0) for q in session_stats["queries"]]
        query_labels = [f"Q{i+1}" for i in range(len(execution_times))]
        
        fig1, ax1 = plt.subplots(figsize=(10, 6))
        ax1.plot(query_labels, execution_times, marker='o', linestyle='-', color=self.colors[0], linewidth=2)
        ax1.set_title('Время выполнения запросов')
        ax1.set_xlabel('Запросы')
        ax1.set_ylabel('Время (сек.)')
        ax1.grid(True, linestyle='--', alpha=0.7)
        plt.tight_layout()
        figures.append(fig1)
        
        # 2. График использования кэша
        cache_usage = [1 if q.get("cached", False) else 0 for q in session_stats["queries"]]
        cached_count = sum(cache_usage)
        not_cached_count = len(cache_usage) - cached_count
        
        fig2, ax2 = plt.subplots(figsize=(8, 8))
        ax2.pie([cached_count, not_cached_count], 
               labels=['Кэшировано', 'Новые запросы'],
               autopct='%1.1f%%',
               startangle=90,
               colors=[self.colors[1], self.colors[2]])
        ax2.set_title('Использование кэша')
        plt.tight_layout()
        figures.append(fig2)
        
        # 3. График использования моделей
        if "models_used" in session_stats:
            model_counts = {}
            for q in session_stats["queries"]:
                model = q.get("model", "unknown")
                model_counts[model] = model_counts.get(model, 0) + 1
            
            fig3, ax3 = plt.subplots(figsize=(10, 6))
            ax3.bar(model_counts.keys(), model_counts.values(), color=self.colors[3])
            ax3.set_title('Использование моделей')
            ax3.set_xlabel('Модель')
            ax3.set_ylabel('Количество запросов')
            plt.xticks(rotation=45, ha='right')
            plt.tight_layout()
            figures.append(fig3)
        
        # 4. График стоимости запросов
        costs = [q.get("cost", 0) for q in session_stats["queries"]]
        cumulative_cost = np.cumsum(costs)
        
        fig4, ax4 = plt.subplots(figsize=(10, 6))
        ax4.plot(query_labels, cumulative_cost, marker='o', linestyle='-', color=self.colors[4], linewidth=2)
        ax4.set_title('Накопительная стоимость запросов')
        ax4.set_xlabel('Запросы')
        ax4.set_ylabel('Стоимость ($)')
        ax4.grid(True, linestyle='--', alpha=0.7)
        plt.tight_layout()
        figures.append(fig4)
        
        return figures
    
    def visualize_topic_distribution(self, documents):
        """
        Визуализирует распределение тем в документах

        Args:
            documents (list): Список документов

        Returns:
            plt.Figure: Объект фигуры matplotlib
        """
        if not documents:
            return None
        
        # Собираем категории из метаданных документов
        categories = {}
        for doc in documents:
            metadata = getattr(doc, 'metadata', {})
            doc_categories = metadata.get('categories', [])
            
            for category in doc_categories:
                categories[category] = categories.get(category, 0) + 1
        
        if not categories:
            return None
        
        # Сортируем категории по количеству
        sorted_categories = sorted(categories.items(), key=lambda x: x[1], reverse=True)
        category_names = [c[0] for c in sorted_categories]
        category_counts = [c[1] for c in sorted_categories]
        
        # Создаем фигуру
        fig, ax = plt.subplots(figsize=(12, 8))
        
        # Создаем график
        bars = ax.barh(category_names, category_counts, color=self.colors)
        
        # Добавляем подписи и оформление
        ax.set_title('Распределение категорий в базе знаний')
        ax.set_xlabel('Количество документов')
        ax.set_ylabel('Категория')
        
        # Добавляем значения рядом со столбцами
        for i, bar in enumerate(bars):
            width = bar.get_width()
            ax.text(width + 0.5, bar.get_y() + bar.get_height()/2.,
                   f'{width}', ha='left', va='center')
        
        # Инвертируем ось Y для лучшего отображения (сверху вниз)
        ax.invert_yaxis()
        
        # Добавляем сетку для читаемости
        ax.grid(axis='x', linestyle='--', alpha=0.7)
        
        # Настраиваем отступы
        plt.tight_layout()
        
        return fig
