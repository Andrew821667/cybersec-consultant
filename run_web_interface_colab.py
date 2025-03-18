# Запуск веб-интерфейса для нейроконсультанта по кибербезопасности
import os
import sys
import traceback
import json
from threading import Thread
import subprocess
from IPython.display import display, HTML, clear_output

# Импортируем необходимые библиотеки
try:
    from flask import Flask, request, jsonify, render_template
    import nest_asyncio
except ImportError:
    # Если библиотеки не установлены, устанавливаем их
    subprocess.check_call([sys.executable, "-m", "pip", "install", "flask", "nest-asyncio"])
    from flask import Flask, request, jsonify, render_template
    import nest_asyncio

# Применяем патч для поддержки асинхронности в Colab
nest_asyncio.apply()

# Создаем путь к проекту
sys.path.append(os.path.abspath('.'))

# Импортируем консультанта
from cybersec_consultant import create_consultant
from cybersec_consultant.state_management import STATE
from cybersec_consultant.error_handling import logger

# Создаем Flask приложение
app = Flask(__name__, 
            template_folder='cybersec_consultant/templates',
            static_folder='cybersec_consultant/static')

# Маршруты для веб-интерфейса
@app.route('/')
def index():
    return render_template('index.html')

@app.route('/api/query', methods=['POST'])
def api_query():
    try:
        # Логгируем получение запроса
        print("Получен запрос к API")
        
        data = request.json
        query = data.get('query', '')
        
        print(f"Запрос: {query}")
        
        if not query:
            return jsonify({'error': 'Запрос не может быть пустым'}), 400
        
        print("Поиск документов в базе знаний...")
        # Поиск документов
        try:
            search_results = consultant.search_knowledge_base(query, k=3)
            print(f"Найдено документов: {len(search_results)}")
        except Exception as e:
            print(f"Ошибка при поиске документов: {e}")
            traceback.print_exc()
            return jsonify({'error': f'Ошибка при поиске документов: {str(e)}'}), 500
        
        # Подготовка контекста
        print("Подготовка контекста...")
        user_prompt = f"Запрос пользователя: {query}\n\nРелевантная информация:\n"
        
        for i, result in enumerate(search_results):
            try:
                if isinstance(result, tuple) and len(result) >= 2:
                    if hasattr(result[0], 'page_content'):
                        user_prompt += f"[Документ {i+1}]\n{result[0].page_content}\n\n"
            except Exception as e:
                print(f"Ошибка при обработке документа {i}: {e}")
        
        user_prompt += "Составьте полный и информативный ответ на запрос пользователя, используя только предоставленную информацию."
        
        # Получаем системный промпт
        try:
            print("Получение системного промпта...")
            system_prompt = consultant.prompt_manager.get_prompt('standard')
        except Exception as e:
            print(f"Ошибка при получении промпта: {e}")
            traceback.print_exc()
            return jsonify({'error': f'Ошибка при получении промпта: {str(e)}'}), 500
        
        # Генерация ответа
        try:
            print("Генерация ответа...")
            response = consultant.llm_interface.generate_answer(
                system_prompt=system_prompt,
                user_prompt=user_prompt
            )
            print("Ответ успешно сгенерирован")
        except Exception as e:
            print(f"Ошибка при генерации ответа: {e}")
            traceback.print_exc()
            return jsonify({'error': f'Ошибка при генерации ответа: {str(e)}'}), 500
        
        # Форматирование ответа
        if isinstance(response, dict) and 'answer' in response:
            answer = response['answer']
        else:
            answer = str(response)
        
        print(f"Отправка ответа размером {len(answer)} символов")
        return jsonify({'answer': answer})
    
    except Exception as e:
        print(f"Неожиданная ошибка в API: {e}")
        traceback.print_exc()
        return jsonify({'error': f'Произошла ошибка: {str(e)}'}), 500

# Запуск веб-интерфейса
def main():
    # Запрос API ключа
    api_key = input("Введите ваш API ключ OpenAI: ")
    os.environ["OPENAI_API_KEY"] = api_key
    
    # Создание консультанта
    global consultant
    consultant = create_consultant()
    
    # Проверяем существование базы знаний в памяти приложения
    kb_path = "knowledge_base/knowledge_base_cybernexus.txt"
    indices_path = os.path.join(os.getcwd(), "indices")
    
    if not os.path.exists(indices_path):
        os.makedirs(indices_path, exist_ok=True)
    
    # Модифицируем процесс инициализации: загрузка базы знаний с принудительным созданием нового индекса,
    # только если индекс не существует или поврежден
    try:
        # Пробуем загрузить существующий индекс
        consultant.initialize_knowledge_base(kb_path, force_reindex=False)
        print("✅ Успешно загружен существующий индекс базы знаний")
    except Exception as e:
        print(f"⚠️ Ошибка при загрузке индекса: {e}")
        print("🔄 Создаем новый индекс базы знаний...")
        # При ошибке создаем новый индекс
        consultant.initialize_knowledge_base(kb_path, force_reindex=True)
    
    # Запуск веб-интерфейса с использованием google.colab
    try:
        from google.colab import output
        # Используем iframe вместо window для лучшей совместимости
        output.serve_kernel_port_as_iframe(5000, height=600)
        print("Веб-интерфейс запущен и доступен в iframe ниже")
    except Exception as e:
        print(f"⚠️ Ошибка при создании iframe: {e}")
        print("Веб-интерфейс доступен по адресу: http://127.0.0.1:5000")
    
    # Создаем маршрут для простого тестирования
    @app.route('/test')
    def test():
        return "API работает!"
    
    # Запуск Flask-приложения
    app.run(port=5000)

if __name__ == '__main__':
    main()
