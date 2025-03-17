# -*- coding: utf-8 -*-
"""
Утилиты для обработки текста
"""

import re
import hashlib
from collections import Counter

class TextProcessor:
    """Класс для обработки и анализа текста"""

    def __init__(self):
        """Инициализация обработчика текста"""
        self.stopwords = {
            'и', 'в', 'на', 'с', 'по', 'для', 'от', 'к', 'за', 'из', 'о', 'что', 'как',
            'не', 'или', 'а', 'но', 'ни', 'да', 'бы', 'же', 'ли', 'если', 'чтобы', 'это',
            'то', 'так', 'вот', 'только', 'уже', 'вы', 'он', 'она', 'оно', 'они', 'мы',
            'я', 'этот', 'тот', 'такой', 'который', 'где', 'когда', 'быть', 'весь'
        }
    
    def clean_text(self, text):
        """
        Очищает текст от лишних символов и нормализует его

        Args:
            text (str): Текст для очистки

        Returns:
            str: Очищенный текст
        """
        # Приводим к нижнему регистру
        text = text.lower()
        
        # Удаляем HTML-теги
        text = re.sub(r'<[^>]+>', '', text)
        
        # Заменяем множественные пробелы и переносы строк одиночным пробелом
        text = re.sub(r'\s+', ' ', text)
        
        # Удаляем специальные символы (оставляем буквы, цифры и пробелы)
        text = re.sub(r'[^\w\s]', '', text)
        
        return text.strip()
    
    def extract_keywords(self, text, max_keywords=10, min_word_length=4):
        """
        Извлекает ключевые слова из текста

        Args:
            text (str): Текст для анализа
            max_keywords (int): Максимальное количество ключевых слов
            min_word_length (int): Минимальная длина слова

        Returns:
            list: Список ключевых слов
        """
        # Очищаем текст
        cleaned_text = self.clean_text(text)
        
        # Разбиваем на слова и считаем частоту
        words = re.findall(rf'\b\w{{{min_word_length},}}\b', cleaned_text)
        word_counter = Counter(words)
        
        # Фильтруем стоп-слова
        filtered_words = [(word, count) for word, count in word_counter.most_common(max_keywords * 2)
                         if word not in self.stopwords]
        
        # Возвращаем топ слова
        return [word for word, _ in filtered_words[:max_keywords]]
    
    def summarize_text(self, text, max_sentences=3):
        """
        Создает краткое резюме текста

        Args:
            text (str): Текст для сводки
            max_sentences (int): Максимальное количество предложений

        Returns:
            str: Резюме текста
        """
        # Разбиваем текст на предложения
        sentences = re.split(r'(?<=[.!?])\s+', text)
        
        if len(sentences) <= max_sentences:
            return text
        
        # Очищаем предложения
        clean_sentences = [s.strip() for s in sentences if s.strip()]
        
        # Если текст слишком короткий, возвращаем его целиком
        if len(clean_sentences) <= max_sentences:
            return text
        
        # Вычисляем вес предложений
        sentence_weights = {}
        
        for i, sentence in enumerate(clean_sentences):
            # Вес на основе позиции (первые и последние предложения обычно более важные)
            position_weight = 1.0
            if i == 0 or i == len(clean_sentences) - 1:
                position_weight = 1.5
            
            # Вес на основе длины предложения
            length_weight = min(1.0, len(sentence) / 100.0)
            
            # Вес на основе ключевых слов
            keywords = self.extract_keywords(sentence, max_keywords=5)
            keyword_weight = len(keywords) / 5.0
            
            # Итоговый вес
            sentence_weights[i] = position_weight * length_weight * keyword_weight
        
        # Выбираем предложения с наибольшим весом
        top_sentences = sorted(sentence_weights.items(), key=lambda x: x[1], reverse=True)[:max_sentences]
        top_sentences = sorted(top_sentences, key=lambda x: x[0])  # Сортируем по оригинальному порядку
        
        # Составляем резюме
        summary = " ".join(clean_sentences[i] for i, _ in top_sentences)
        
        return summary
    
    def detect_language(self, text):
        """
        Определяет язык текста

        Args:
            text (str): Текст для анализа

        Returns:
            str: Код языка (ru, en, etc.)
        """
        # Простое определение языка на основе частотного анализа букв
        text = self.clean_text(text)
        
        # Если текст пустой, вернуть неизвестный язык
        if not text:
            return "unknown"
        
        # Частотные характеристики для русского и английского языков
        ru_chars = set('абвгдеёжзийклмнопрстуфхцчшщъыьэюя')
        en_chars = set('abcdefghijklmnopqrstuvwxyz')
        
        # Считаем количество символов каждого языка
        ru_count = sum(1 for c in text if c in ru_chars)
        en_count = sum(1 for c in text if c in en_chars)
        
        # Определяем язык на основе большего количества символов
        if ru_count > en_count:
            return "ru"
        elif en_count > ru_count:
            return "en"
        else:
            return "unknown"
    
    def detect_cybersecurity_topics(self, text):
        """
        Определяет темы кибербезопасности в тексте

        Args:
            text (str): Текст для анализа

        Returns:
            list: Список обнаруженных тем
        """
        # Словарь тем и ключевых слов
        topics = {
            "аутентификация": ["аутентификация", "пароль", "логин", "2fa", "мфа", "биометрия", "токен"],
            "шифрование": ["шифрование", "криптография", "ключ", "алгоритм", "хэширование", "шифр"],
            "сетевая_безопасность": ["сеть", "файрвол", "брандмауэр", "vpn", "прокси", "туннель", "маршрутизатор"],
            "вредоносное_по": ["вирус", "троян", "червь", "малварь", "вымогатель", "ботнет", "шпион"],
            "уязвимости": ["уязвимость", "эксплойт", "патч", "дыра", "cve", "0day", "обход"],
            "ddos": ["ddos", "dos", "отказ", "атака", "флуд", "перегрузка", "amplification"],
            "социальная_инженерия": ["фишинг", "социальная", "инженерия", "обман", "манипуляция", "доверие"],
            "безопасность_приложений": ["owasp", "инъекция", "xss", "csrf", "веб", "приложение"],
            "мониторинг": ["мониторинг", "логирование", "siem", "идентификация", "детект", "обнаружение"],
            "реагирование": ["инцидент", "реагирование", "форензика", "анализ", "расследование"]
        }
        
        # Очищаем текст
        cleaned_text = self.clean_text(text)
        
        # Определяем темы на основе ключевых слов
        detected_topics = []
        
        for topic, keywords in topics.items():
            for keyword in keywords:
                if keyword in cleaned_text:
                    detected_topics.append(topic)
                    break
        
        return detected_topics
