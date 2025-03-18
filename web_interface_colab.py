
import os
import json
from flask import Flask, request, jsonify, send_from_directory
from google.colab import output
import openai
import nest_asyncio
import threading

# Применяем патч для асинхронности
nest_asyncio.apply()

# Загружаем API-ключ из файла или запрашиваем его
def get_api_key():
    key_file = '.api_key'
    if os.path.exists(key_file):
        with open(key_file, 'r') as f:
            api_key = f.read().strip()
        if api_key:
            print("✅ Загружен сохраненный API-ключ")
            return api_key
    
    api_key = input("Введите ваш API ключ OpenAI: ")
    with open(key_file, 'w') as f:
        f.write(api_key)
    print("✅ API-ключ сохранен для будущего использования")
    return api_key

# Получаем API-ключ
api_key = get_api_key()
os.environ["OPENAI_API_KEY"] = api_key

# Инициализируем клиент OpenAI
client = openai.OpenAI(api_key=api_key)

# Проверяем работу API
try:
    response = client.chat.completions.create(
        model="gpt-3.5-turbo",
        messages=[
            {"role": "system", "content": "Вы - ассистент."},
            {"role": "user", "content": "Привет!"}
        ],
        max_tokens=10
    )
    print("✅ Соединение с OpenAI API успешно установлено")
except Exception as e:
    print(f"❌ Ошибка при подключении к OpenAI API: {e}")

# Создаем Flask-приложение
app = Flask(__name__)

@app.route('/')
def index():
    return send_from_directory('.', 'simple_interface.html')

@app.route('/api/query', methods=['POST'])
def handle_query():
    data = request.json
    query = data.get('query', '')
    
    if not query:
        return jsonify({'error': 'Запрос не может быть пустым'}), 400
    
    try:
        # Отправляем запрос в OpenAI API
        response = client.chat.completions.create(
            model="gpt-3.5-turbo",
            messages=[
                {"role": "system", "content": "Вы - консультант по кибербезопасности, который отвечает на вопросы пользователей кратко и по существу."},
                {"role": "user", "content": f"Вопрос по кибербезопасности: {query}"}
            ],
            max_tokens=500,
            temperature=0.7
        )
        
        answer = response.choices[0].message.content
        return jsonify({'answer': answer})
    
    except Exception as e:
        print(f"Ошибка API: {e}")
        return jsonify({'error': str(e)}), 500

# Функция запуска сервера в отдельном потоке
def run_server():
    app.run(port=5000)

# Запускаем сервер в отдельном потоке
server_thread = threading.Thread(target=run_server)
server_thread.daemon = True
server_thread.start()

# Создаем JavaScript для взаимодействия с API
output.eval_js('''
document.addEventListener('DOMContentLoaded', function() {
    const chatContainer = document.getElementById('chatContainer');
    const queryInput = document.getElementById('queryInput');
    const sendBtn = document.getElementById('sendBtn');
    const examples = document.querySelectorAll('.example');
    
    // Обработка примеров запросов
    examples.forEach(example => {
        example.addEventListener('click', function() {
            queryInput.value = this.textContent;
            sendQuery();
        });
    });
    
    // Отправка запроса при нажатии на кнопку
    sendBtn.addEventListener('click', sendQuery);
    
    // Отправка запроса при нажатии Enter
    queryInput.addEventListener('keypress', function(e) {
        if (e.key === 'Enter') {
            sendQuery();
        }
    });
    
    // Функция отправки запроса
    function sendQuery() {
        const query = queryInput.value.trim();
        if (!query) return;
        
        // Добавляем сообщение пользователя
        addMessage(query, 'user');
        
        // Очищаем поле ввода
        queryInput.value = '';
        
        // Показываем индикатор загрузки
        const loadingMessage = addMessage('Анализирую информацию...', 'bot');
        
        // Отправляем запрос на сервер
        fetch('/api/query', {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json',
            },
            body: JSON.stringify({ query: query }),
        })
        .then(response => response.json())
        .then(data => {
            // Удаляем индикатор загрузки
            chatContainer.removeChild(loadingMessage);
            
            // Добавляем ответ бота
            if (data.answer) {
                addMessage(data.answer, 'bot');
            } else if (data.error) {
                addMessage('Произошла ошибка: ' + data.error, 'bot');
            }
        })
        .catch(error => {
            // Удаляем индикатор загрузки
            chatContainer.removeChild(loadingMessage);
            
            // Добавляем сообщение об ошибке
            addMessage('Произошла ошибка при обработке запроса. Попробуйте еще раз.', 'bot');
        });
    }
    
    // Функция добавления сообщения
    function addMessage(text, type) {
        const message = document.createElement('div');
        message.className = `message ${type}`;
        message.textContent = text;
        chatContainer.appendChild(message);
        chatContainer.scrollTop = chatContainer.scrollHeight;
        return message;
    }
});
''')

# Открываем веб-интерфейс в iframe
output.serve_kernel_port_as_iframe(5000, height=700)
print("✅ Интерфейс запущен. Если он не отображается выше, перезагрузите страницу Colab.")
