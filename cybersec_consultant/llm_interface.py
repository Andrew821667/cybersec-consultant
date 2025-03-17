# -*- coding: utf-8 -*-
"""
Модуль для взаимодействия с API языковых моделей
"""

import os
import time
import json
import hashlib
from datetime import datetime
from tqdm.auto import tqdm

try:
    import openai
    from openai import OpenAI
    OPENAI_AVAILABLE = True
except ImportError:
    OPENAI_AVAILABLE = False
    print("⚠️ Библиотека OpenAI не установлена. Установите ее с помощью pip install openai")

from cybersec_consultant.config import ConfigManager, RESPONSES_DIR, CACHE_DIR, get_api_key

class LLMInterface:
    """Класс для взаимодействия с языковыми моделями"""

    def __init__(self):
        """Инициализация интерфейса языковых моделей"""
        self.config_manager = ConfigManager()
        self.client = None
        
        # Инициализация API ключа
        self.api_key = get_api_key()
        
        # Проверяем версию OpenAI API
        self.is_new_api = self._check_openai_version()
        
        # Инициализируем клиент OpenAI
        self._init_client()
        
        # Директория для кэша
        self.cache_dir = os.path.join(CACHE_DIR, "responses")
        os.makedirs(self.cache_dir, exist_ok=True)
        
        # Загружаем кэш ответов
        self.response_cache = self._load_response_cache()

    def _check_openai_version(self):
        """Проверяет версию OpenAI API"""
        if not OPENAI_AVAILABLE:
            return True  # Предполагаем новый API по умолчанию
        
        try:
            openai_version = openai.__version__
            is_new_api = int(openai_version.split('.')[0]) >= 1
            print(f"✅ Обнаружена версия OpenAI API: {openai_version}")
            print(f"   {'Используем новый интерфейс API (>=1.0.0)' if is_new_api else 'Используем старый интерфейс API (<1.0.0)'}")
            return is_new_api
        except Exception as e:
            print(f"⚠️ Не удалось определить версию OpenAI API: {e}")
            return True  # Предполагаем новый API по умолчанию

    def _init_client(self):
        """Инициализирует клиент OpenAI"""
        if not OPENAI_AVAILABLE:
            print("❌ Библиотека OpenAI не установлена")
            return
        
        try:
            if self.is_new_api:
                self.client = OpenAI(api_key=self.api_key)
            else:
                openai.api_key = self.api_key
            print("✅ Клиент OpenAI успешно инициализирован")
        except Exception as e:
            print(f"❌ Ошибка при инициализации клиента OpenAI: {str(e)}")
    
    def _load_response_cache(self):
        """Загружает кэш ответов из файла"""
        cache_file = os.path.join(self.cache_dir, "response_cache.json")
        if os.path.exists(cache_file):
            try:
                with open(cache_file, 'r', encoding='utf-8') as f:
                    cache = json.load(f)
                print(f"✅ Загружен кэш ответов ({len(cache)} записей)")
                return cache
            except Exception as e:
                print(f"❌ Ошибка при загрузке кэша ответов: {str(e)}")
        return {}
    
    def _save_response_cache(self):
        """Сохраняет кэш ответов в файл"""
        cache_file = os.path.join(self.cache_dir, "response_cache.json")
        try:
            with open(cache_file, 'w', encoding='utf-8') as f:
                json.dump(self.response_cache, f, ensure_ascii=False, indent=2)
            return True
        except Exception as e:
            print(f"❌ Ошибка при сохранении кэша ответов: {str(e)}")
            return False

    def generate_answer(self, system_prompt, user_prompt, 
                       model=None, temperature=0, use_cache=True):
        """
        Генерирует ответ с использованием языковой модели

        Args:
            system_prompt (str): Системный промпт
            user_prompt (str): Запрос пользователя
            model (str): Модель для генерации ответа
            temperature (float): Температура генерации
            use_cache (bool): Использовать кэш или нет

        Returns:
            dict: Словарь с ответом и метаданными
        """
        if not OPENAI_AVAILABLE or not self.client:
            return {
                "answer": "Ошибка: API OpenAI недоступен. Установите библиотеку с помощью pip install openai",
                "success": False,
                "cached": False,
                "model": model,
                "tokens": 0,
                "execution_time": 0,
                "cost": 0
            }
        
        # Если модель не указана, берем из конфигурации
        if model is None:
            model = self.config_manager.get_setting("models", "default", "gpt-4o-mini")
        
        # Создаем ключ кэша
        cache_key = hashlib.md5(f"{system_prompt}_{user_prompt}_{model}_{temperature}".encode()).hexdigest()

        # Проверяем наличие в кэше
        if use_cache and cache_key in self.response_cache:
            cached_response = self.response_cache[cache_key]
            cached_response["cached"] = True
            return cached_response

        # Если нет в кэше, генерируем ответ
        messages = [
            {"role": "system", "content": system_prompt},
            {"role": "user", "content": user_prompt}
        ]

        try:
            print(f"\n🤖 Отправляем запрос к API OpenAI (модель: {model})...")
            
            # Отображаем прогресс-бар
            with tqdm(total=100, desc="Генерация ответа") as pbar:
                start_time = time.time()
                
                # Обновляем прогресс-бар для имитации процесса
                pbar.update(10)  # 10% - начало запроса
                
                # Выполняем запрос к API в зависимости от версии
                if self.is_new_api:
                    # Используем новый API (>=1.0.0)
                    completion = self.client.chat.completions.create(
                        model=model,
                        messages=messages,
                        temperature=temperature
                    )
                    answer = completion.choices[0].message.content
                else:
                    # Используем старый API (<1.0.0)
                    completion = openai.ChatCompletion.create(
                        model=model,
                        messages=messages,
                        temperature=temperature
                    )
                    answer = completion.choices[0].message.content
                
                # Обновляем прогресс-бар (как будто запрос в процессе)
                pbar.update(40)  # 50% - отправка запроса
                
                # Финальное обновление прогресс-бара
                pbar.update(50)  # 100% - получение ответа

            # Подсчитываем примерное количество токенов
            input_tokens = (len(system_prompt) + len(user_prompt)) // 3
            output_tokens = len(answer) // 3
            total_tokens = input_tokens + output_tokens

            # Оцениваем стоимость (примерно)
            input_cost_per_1000 = 0.01
            output_cost_per_1000 = 0.03
            input_cost = (input_tokens / 1000) * input_cost_per_1000
            output_cost = (output_tokens / 1000) * output_cost_per_1000
            total_cost = input_cost + output_cost

            # Измеряем время выполнения
            execution_time = time.time() - start_time

            # Создаем результат
            result = {
                "answer": answer,
                "success": True,
                "cached": False,
                "model": model,
                "tokens": total_tokens,
                "execution_time": execution_time,
                "cost": total_cost,
                "timestamp": datetime.now().isoformat()
            }

            # Сохраняем в кэш
            self.response_cache[cache_key] = result
            self._save_response_cache()

            # Выводим информацию о генерации
            print(f"\n✅ Получен ответ от API за {execution_time:.2f} сек.")
            print(f"📊 Модель: {model}")
            print(f"📝 Примерная оценка использования: {total_tokens} токенов (ввод: {input_tokens}, вывод: {output_tokens})")
            print(f"💰 Примерная стоимость запроса: ${total_cost:.6f}")

            return result

        except Exception as e:
            error_message = f"❌ Ошибка при получении ответа от модели {model}: {str(e)}"
            print(error_message)
            
            return {
                "answer": f"Ошибка при генерации ответа: {str(e)}",
                "success": False,
                "cached": False,
                "model": model,
                "tokens": 0,
                "execution_time": time.time() - start_time if 'start_time' in locals() else 0,
                "cost": 0,
                "error": str(e)
            }

    def save_response_to_file(self, query, response_data, filename=None):
        """
        Сохраняет ответ в файл

        Args:
            query (str): Запрос пользователя
            response_data (dict): Данные ответа
            filename (str): Имя файла (если None, генерируется автоматически)

        Returns:
            str: Путь к сохраненному файлу
        """
        # Создаем директорию для ответов, если она не существует
        os.makedirs(RESPONSES_DIR, exist_ok=True)
        
        # Если имя файла не указано, генерируем его на основе даты и времени
        if filename is None:
            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            query_part = "".join(x for x in query[:30] if x.isalnum() or x.isspace()).strip().replace(" ", "_")
            if not query_part:
                query_part = "response"
            filename = f"{timestamp}_{query_part}.md"
        
        filepath = os.path.join(RESPONSES_DIR, filename)
        
        # Формируем содержимое файла
        answer = response_data.get("answer", "Ответ не получен")
        model = response_data.get("model", "Неизвестная модель")
        tokens = response_data.get("tokens", 0)
        cost = response_data.get("cost", 0)
        cached = response_data.get("cached", False)
        execution_time = response_data.get("execution_time", 0)
        
        content = f"# Ответ консультанта по кибербезопасности\n\n"
        content += f"**Дата и время:** {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n\n"
        content += f"## Вопрос\n\n{query}\n\n"
        content += f"## Ответ\n\n{answer}\n\n"
        content += f"---\n\n"
        content += f"**Модель:** {model}\n\n"
        content += f"**Использован кэш:** {'Да' if cached else 'Нет'}\n\n"
        if not cached:
            content += f"**Использовано токенов:** {tokens}\n\n"
            content += f"**Примерная стоимость:** ${cost:.6f}\n\n"
        content += f"**Время выполнения:** {execution_time:.2f} сек.\n"
        
        # Сохраняем в файл
        try:
            with open(filepath, 'w', encoding='utf-8') as f:
                f.write(content)
            print(f"💾 Ответ сохранен в файл: {filepath}")
            return filepath
        except Exception as e:
            print(f"⚠️ Ошибка при сохранении ответа в файл: {str(e)}")
            return None
