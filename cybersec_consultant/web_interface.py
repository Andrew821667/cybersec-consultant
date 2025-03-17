# -*- coding: utf-8 -*-
"""
Модуль веб-интерфейса для консультанта по кибербезопасности.
Реализует веб-интерфейс на основе Flask.
"""

import os
import json
import threading
from typing import Dict, Any, List, Optional
from functools import wraps
from flask import Flask, request, jsonify, render_template, session, redirect, url_for, send_from_directory
from werkzeug.utils import secure_filename

# Импортируем основные модули консультанта
from cybersec_consultant.state_management import STATE
from cybersec_consultant.error_handling import logger, ConfigurationError, safe_execute
from cybersec_consultant.key_security import get_api_key, set_api_key

# Создаем приложение Flask
app = Flask(__name__, template_folder="templates", static_folder="static")
app.secret_key = os.urandom(24)  # Для сессий

# Путь для загрузки файлов
UPLOAD_FOLDER = os.path.join(os.path.expanduser("~"), ".cybersec_consultant", "uploads")
os.makedirs(UPLOAD_FOLDER, exist_ok=True)
app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER
app.config['MAX_CONTENT_LENGTH'] = 16 * 1024 * 1024  # 16 MB


# Создаем глобальную переменную для хранения консультанта
consultant = None


def login_required(f):
    """
    Декоратор для проверки аутентификации пользователя.
    """
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'authenticated' not in session or not session['authenticated']:
            return redirect(url_for('login', next=request.url))
        return f(*args, **kwargs)
    return decorated_function


@app.route('/')
def index():
    """
    Главная страница веб-интерфейса.
    """
    if 'authenticated' in session and session['authenticated']:
        return render_template('index.html')
    return redirect(url_for('login'))


@app.route('/login', methods=['GET', 'POST'])
def login():
    """
    Страница входа в систему.
    """
    error = None
    if request.method == 'POST':
        # Простая аутентификация по паролю
        password = request.form.get('password')
        if password == os.environ.get('CYBERSEC_PASSWORD', 'admin'):  # Пароль по умолчанию 'admin'
            session['authenticated'] = True
            return redirect(url_for('index'))
        else:
            error = 'Invalid password. Please try again.'
    
    return render_template('login.html', error=error)


@app.route('/logout')
def logout():
    """
    Выход из системы.
    """
    session.pop('authenticated', None)
    return redirect(url_for('login'))


@app.route('/api/query', methods=['POST'])
@login_required
def api_query():
    """
    API для отправки запросов консультанту.
    """
    if not consultant:
        return jsonify({"error": "Консультант не инициализирован"}), 500
    
    data = request.json
    query = data.get('query')
    profile = data.get('profile', 'standard')
    
    if not query:
        return jsonify({"error": "Запрос отсутствует"}), 400
    
    try:
        # Получение ответа от консультанта
        response = consultant.get_response(query, profile=profile)
        return jsonify(response)
    except Exception as e:
        logger.error(f"Error processing query: {str(e)}")
        return jsonify({"error": str(e)}), 500


@app.route('/api/upload', methods=['POST'])
@login_required
def api_upload():
    """
    API для загрузки документов для базы знаний.
    """
    if 'file' not in request.files:
        return jsonify({"error": "Нет файла"}), 400
        
    file = request.files['file']
    
    if file.filename == '':
        return jsonify({"error": "Файл не выбран"}), 400
        
    if file:
        filename = secure_filename(file.filename)
        file_path = os.path.join(app.config['UPLOAD_FOLDER'], filename)
        file.save(file_path)
        
        try:
            # Добавление документа в базу знаний
            if consultant:
                result = consultant.add_document_to_knowledge_base(file_path, reindex=True)
                return jsonify({"success": True, "message": f"Файл {filename} добавлен в базу знаний", "result": result})
            else:
                return jsonify({"error": "Консультант не инициализирован"}), 500
        except Exception as e:
            logger.error(f"Error adding document to knowledge base: {str(e)}")
            return jsonify({"error": str(e)}), 500


@app.route('/api/settings', methods=['GET', 'POST'])
@login_required
def api_settings():
    """
    API для получения и обновления настроек.
    """
    if request.method == 'GET':
        # Получение текущих настроек
        settings = {
            "model_name": STATE.model_name,
            "embedding_model": STATE.embedding_model,
            "temperature": STATE.temperature,
            "use_cache": STATE.use_cache,
            "profile": STATE.profile,
        }
        return jsonify(settings)
    else:
        # Обновление настроек
        data = request.json
        try:
            if 'model_name' in data:
                STATE.model_name = data['model_name']
            if 'embedding_model' in data:
                STATE.embedding_model = data['embedding_model']
            if 'temperature' in data:
                STATE.temperature = float(data['temperature'])
            if 'use_cache' in data:
                STATE.use_cache = bool(data['use_cache'])
            if 'profile' in data:
                STATE.profile = data['profile']
                
            return jsonify({"success": True, "message": "Настройки обновлены"})
        except Exception as e:
            logger.error(f"Error updating settings: {str(e)}")
            return jsonify({"error": str(e)}), 500


@app.route('/api/stats', methods=['GET'])
@login_required
def api_stats():
    """
    API для получения статистики использования.
    """
    return jsonify(STATE.session_stats)


@app.route('/api/documents', methods=['GET'])
@login_required
def api_documents():
    """
    API для получения списка документов в базе знаний.
    """
    if consultant:
        try:
            documents = consultant.list_knowledge_base_documents()
            return jsonify(documents)
        except Exception as e:
            logger.error(f"Error listing documents: {str(e)}")
            return jsonify({"error": str(e)}), 500
    return jsonify({"error": "Консультант не инициализирован"}), 500


@app.route('/api/documents/<document_id>', methods=['DELETE'])
@login_required
def api_delete_document(document_id):
    """
    API для удаления документа из базы знаний.
    """
    if consultant:
        try:
            success = consultant.remove_document_from_knowledge_base(document_id, reindex=True)
            if success:
                return jsonify({"success": True, "message": f"Документ {document_id} удален"})
            return jsonify({"error": "Документ не найден"}), 404
        except Exception as e:
            logger.error(f"Error deleting document: {str(e)}")
            return jsonify({"error": str(e)}), 500
    return jsonify({"error": "Консультант не инициализирован"}), 500


@app.route('/api/apikey', methods=['GET', 'POST'])
@login_required
def api_apikey():
    """
    API для управления API ключами.
    """
    if request.method == 'GET':
        # Проверяем наличие ключа OpenAI
        openai_key = get_api_key("openai")
        return jsonify({"has_openai_key": openai_key is not None})
    else:
        # Устанавливаем API ключ
        data = request.json
        api_key = data.get('api_key')
        service = data.get('service', 'openai')
        
        if not api_key:
            return jsonify({"error": "API ключ отсутствует"}), 400
            
        try:
            set_api_key(service, api_key)
            return jsonify({"success": True, "message": f"API ключ для {service} установлен"})
        except Exception as e:
            logger.error(f"Error setting API key: {str(e)}")
            return jsonify({"error": str(e)}), 500


def run_web_interface(host='0.0.0.0', port=5000, debug=False, consultant_instance=None):
    """
    Запуск веб-интерфейса.
    
    Args:
        host: Хост для запуска веб-сервера
        port: Порт для запуска веб-сервера
        debug: Флаг режима отладки
        consultant_instance: Экземпляр консультанта
    """
    global consultant
    consultant = consultant_instance
    
    # Создаем простые HTML шаблоны, если они отсутствуют
    create_default_templates()
    
    app.run(host=host, port=port, debug=debug)


def create_default_templates():
    """
    Создание базовых HTML шаблонов для веб-интерфейса.
    """
    templates_dir = os.path.join(os.path.dirname(__file__), "templates")
    static_dir = os.path.join(os.path.dirname(__file__), "static")
    
    os.makedirs(templates_dir, exist_ok=True)
    os.makedirs(static_dir, exist_ok=True)
    
    # Создаем базовый шаблон
    base_template = """
    <!DOCTYPE html>
    <html lang="ru">
    <head>
        <meta charset="UTF-8">
        <meta name="viewport" content="width=device-width, initial-scale=1.0">
        <title>{% block title %}Консультант по кибербезопасности{% endblock %}</title>
        <link rel="stylesheet" href="{{ url_for('static', filename='style.css') }}">
    </head>
    <body>
        <header>
            <h1>Консультант по кибербезопасности</h1>
            <nav>
                <ul>
                    <li><a href="{{ url_for('index') }}">Главная</a></li>
                    {% if session.authenticated %}
                    <li><a href="{{ url_for('logout') }}">Выход</a></li>
                    {% endif %}
                </ul>
            </nav>
        </header>
        
        <main>
            {% block content %}{% endblock %}
        </main>
        
        <footer>
            <p>&copy; 2025 Консультант по кибербезопасности</p>
        </footer>
        
        <script src="{{ url_for('static', filename='script.js') }}"></script>
    </body>
    </html>
    """
    
    # Создаем шаблон для страницы входа
    login_template = """
    {% extends 'base.html' %}
    
    {% block title %}Вход - Консультант по кибербезопасности{% endblock %}
    
    {% block content %}
    <div class="login-container">
        <h2>Вход в систему</h2>
        {% if error %}
        <div class="error-message">
            {{ error }}
        </div>
        {% endif %}
        <form method="post">
            <div class="form-group">
                <label for="password">Пароль:</label>
                <input type="password" id="password" name="password" required>
            </div>
            <button type="submit">Войти</button>
        </form>
    </div>
    {% endblock %}
    """
    
    # Создаем шаблон для главной страницы
    index_template = """
    {% extends 'base.html' %}
    
    {% block title %}Главная - Консультант по кибербезопасности{% endblock %}
    
    {% block content %}
    <div class="dashboard">
        <div class="chat-container">
            <div class="chat-messages" id="chat-messages">
                <div class="message system">
                    Добро пожаловать! Я консультант по кибербезопасности. Чем могу помочь?
                </div>
            </div>
            <div class="chat-input">
                <form id="query-form">
                    <input type="text" id="query-input" placeholder="Введите ваш вопрос...">
                    <button type="submit">Отправить</button>
                </form>
            </div>
        </div>
        
        <div class="sidebar">
            <div class="sidebar-section">
                <h3>Настройки</h3>
                <form id="settings-form">
                    <div class="form-group">
                        <label for="model-select">Модель:</label>
                        <select id="model-select" name="model_name">
                            <option value="gpt-4o-mini">GPT-4o Mini</option>
                            <option value="gpt-4o">GPT-4o</option>
                        </select>
                    </div>
                    <div class="form-group">
                        <label for="temperature">Температура:</label>
                        <input type="range" id="temperature" name="temperature" min="0" max="1" step="0.1" value="0.2">
                        <span id="temperature-value">0.2</span>
                    </div>
                    <div class="form-group">
                        <label for="profile-select">Профиль:</label>
                        <select id="profile-select" name="profile">
                            <option value="standard">Стандартный</option>
                            <option value="detailed">Детальный</option>
                            <option value="concise">Краткий</option>
                        </select>
                    </div>
                    <div class="form-group">
                        <label>
                            <input type="checkbox" id="use-cache" name="use_cache" checked>
                            Использовать кэш
                        </label>
                    </div>
                    <button type="submit">Сохранить настройки</button>
                </form>
            </div>
            
            <div class="sidebar-section">
                <h3>Загрузка документов</h3>
                <form id="upload-form" enctype="multipart/form-data">
                    <div class="form-group">
                        <label for="file-upload">Выберите файл:</label>
                        <input type="file" id="file-upload" name="file">
                    </div>
                    <button type="submit">Загрузить</button>
                </form>
            </div>
            
            <div class="sidebar-section">
                <h3>Документы в базе знаний</h3>
                <ul id="documents-list">
                    <!-- Список документов будет загружен через JavaScript -->
                </ul>
            </div>
        </div>
    </div>
    {% endblock %}
    """
    
    # Создаем CSS
    css = """
    * {
        box-sizing: border-box;
        margin: 0;
        padding: 0;
    }
    
    body {
        font-family: 'Arial', sans-serif;
        line-height: 1.6;
        color: #333;
        background-color: #f4f7fa;
    }
    
    header {
        background-color: #2c3e50;
        color: white;
        padding: 1rem;
    }
    
    header h1 {
        margin: 0;
        font-size: 1.5rem;
    }
    
    nav ul {
        list-style: none;
        display: flex;
    }
    
    nav ul li {
        margin-right: 1rem;
    }
    
    nav a {
        color: white;
        text-decoration: none;
    }
    
    main {
        max-width: 1200px;
        margin: 0 auto;
        padding: 1rem;
    }
    
    footer {
        background-color: #2c3e50;
        color: white;
        text-align: center;
        padding: 1rem;
        margin-top: 2rem;
    }
    
    .dashboard {
        display: flex;
        flex-wrap: wrap;
        gap: 1rem;
    }
    
    .chat-container {
        flex: 2;
        min-width: 300px;
        background: white;
        border-radius: 8px;
        box-shadow: 0 2px 4px rgba(0,0,0,0.1);
        display: flex;
        flex-direction: column;
        height: 70vh;
    }
    
    .chat-messages {
        flex: 1;
        overflow-y: auto;
        padding: 1rem;
    }
    
    .message {
        margin-bottom: 1rem;
        padding: 0.8rem;
        border-radius: 8px;
    }
    
    .message.system {
        background-color: #f0f0f0;
    }
    
    .message.user {
        background-color: #e3f2fd;
        margin-left: 1rem;
    }
    
    .message.consultant {
        background-color: #e8f5e9;
        margin-right: 1rem;
    }
    
    .chat-input {
        padding: 1rem;
        border-top: 1px solid #eee;
    }
    
    .chat-input form {
        display: flex;
    }
    
    .chat-input input {
        flex: 1;
        padding: 0.8rem;
        border: 1px solid #ddd;
        border-radius: 4px;
    }
    
    .chat-input button {
        margin-left: 0.5rem;
    }
    
    .sidebar {
        flex: 1;
        min-width: 250px;
    }
    
    .sidebar-section {
        background: white;
        border-radius: 8px;
        box-shadow: 0 2px 4px rgba(0,0,0,0.1);
        padding: 1rem;
        margin-bottom: 1rem;
    }
    
    .sidebar-section h3 {
        margin-bottom: 1rem;
        padding-bottom: 0.5rem;
        border-bottom: 1px solid #eee;
    }
    
    .form-group {
        margin-bottom: 1rem;
    }
    
    .form-group label {
        display: block;
        margin-bottom: 0.5rem;
    }
    
    input, select, button {
        width: 100%;
        padding: 0.8rem;
        border: 1px solid #ddd;
        border-radius: 4px;
    }
    
    button {
        background-color: #2c3e50;
        color: white;
        border: none;
        cursor: pointer;
        transition: background-color 0.3s;
    }
    
    button:hover {
        background-color: #3c5a76;
    }
    
    .login-container {
        max-width: 400px;
        margin: 2rem auto;
        background: white;
        border-radius: 8px;
        box-shadow: 0 2px 4px rgba(0,0,0,0.1);
        padding: 2rem;
    }
    
    .error-message {
        background-color: #ffebee;
        color: #c62828;
        padding: 0.8rem;
        border-radius: 4px;
        margin-bottom: 1rem;
    }
    
    #documents-list {
        list-style: none;
    }
    
    #documents-list li {
        display: flex;
        justify-content: space-between;
        align-items: center;
        padding: 0.5rem;
        border-bottom: 1px solid #eee;
    }
    
    #documents-list button {
        width: auto;
        padding: 0.3rem 0.6rem;
        background-color: #e53935;
    }
    
    @media (max-width: 768px) {
        .dashboard {
            flex-direction: column;
        }
        
        .chat-container, .sidebar {
            width: 100%;
        }
    }
    """
    
    # Создаем JavaScript
    js = """
    document.addEventListener('DOMContentLoaded', function() {
        // Получаем элементы
        const chatMessages = document.getElementById('chat-messages');
        const queryForm = document.getElementById('query-form');
        const queryInput = document.getElementById('query-input');
        const settingsForm = document.getElementById('settings-form');
        const uploadForm = document.getElementById('upload-form');
        const documentsList = document.getElementById('documents-list');
        const temperatureRange = document.getElementById('temperature');
        const temperatureValue = document.getElementById('temperature-value');
        
        // Обновляем значение температуры при изменении ползунка
        if (temperatureRange && temperatureValue) {
            temperatureRange.addEventListener('input', function() {
                temperatureValue.textContent = this.value;
            });
        }
        
        // Загружаем текущие настройки
        fetch('/api/settings')
            .then(response => response.json())
            .then(data => {
                if (data.model_name) {
                    document.getElementById('model-select').value = data.model_name;
                }
                if (data.temperature) {
                    document.getElementById('temperature').value = data.temperature;
                    document.getElementById('temperature-value').textContent = data.temperature;
                }
                if (data.profile) {
                    document.getElementById('profile-select').value = data.profile;
                }
                if (data.use_cache !== undefined) {
                    document.getElementById('use-cache').checked = data.use_cache;
                }
            })
            .catch(error => console.error('Ошибка при загрузке настроек:', error));
        
        // Загружаем список документов
        loadDocuments();
        
        // Обработка отправки запроса
        if (queryForm) {
            queryForm.addEventListener('submit', function(e) {
                e.preventDefault();
                
                const query = queryInput.value.trim();
                if (!query) return;
                
                // Добавляем сообщение пользователя в чат
                addMessage('user', query);
                
                // Очищаем поле ввода
                queryInput.value = '';
                
                // Отправляем запрос
                fetch('/api/query', {
                    method: 'POST',
                    headers: {
                        'Content-Type': 'application/json'
                    },
                    body: JSON.stringify({
                        query: query,
                        profile: document.getElementById('profile-select').value
                    })
                })
                .then(response => response.json())
                .then(data => {
                    if (data.error) {
                        addMessage('system', `Ошибка: ${data.error}`);
                    } else {
                        addMessage('consultant', data.response || 'Нет ответа');
                    }
                })
                .catch(error => {
                    console.error('Ошибка:', error);
                    addMessage('system', `Произошла ошибка: ${error.message}`);
                });
            });
        }
        
        // Обработка сохранения настроек
        if (settingsForm) {
            settingsForm.addEventListener('submit', function(e) {
                e.preventDefault();
                
                const formData = new FormData(settingsForm);
                const settings = {
                    model_name: formData.get('model_name'),
                    temperature: parseFloat(formData.get('temperature')),
                    profile: formData.get('profile'),
                    use_cache: formData.get('use_cache') === 'on'
                };
                
                fetch('/api/settings', {
                    method: 'POST',
                    headers: {
                        'Content-Type': 'application/json'
                    },
                    body: JSON.stringify(settings)
                })
                .then(response => response.json())
                .then(data => {
                    if (data.success) {
                        addMessage('system', 'Настройки успешно сохранены');
                    } else {
                        addMessage('system', `Ошибка: ${data.error}`);
                    }
                })
                .catch(error => {
                    console.error('Ошибка:', error);
                    addMessage('system', `Произошла ошибка: ${error.message}`);
                });
            });
        }
        
        // Обработка загрузки файла
        if (uploadForm) {
            uploadForm.addEventListener('submit', function(e) {
                e.preventDefault();
                
                const formData = new FormData();
                const fileInput = document.getElementById('file-upload');
                
                if (fileInput.files.length === 0) {
                    addMessage('system', 'Выберите файл для загрузки');
                    return;
                }
                
                formData.append('file', fileInput.files[0]);
                
                fetch('/api/upload', {
                    method: 'POST',
                    body: formData
                })
                .then(response => response.json())
                .then(data => {
                    if (data.success) {
                        addMessage('system', `Файл успешно загружен: ${data.message}`);
                        loadDocuments(); // Обновляем список документов
                    } else {
                        addMessage('system', `Ошибка: ${data.error}`);
                    }
                })
                .catch(error => {
                    console.error('Ошибка:', error);
                    addMessage('system', `Произошла ошибка: ${error.message}`);
                });
                
                // Очищаем поле выбора файла
                fileInput.value = '';
            });
        }
        
        // Функция для добавления сообщения в чат
        function addMessage(type, text) {
            const messageDiv = document.createElement('div');
            messageDiv.className = `message ${type}`;
            messageDiv.textContent = text;
            
            chatMessages.appendChild(messageDiv);
            chatMessages.scrollTop = chatMessages.scrollHeight;
        }
        
        // Функция для загрузки списка документов
        function loadDocuments() {
            if (!documentsList) return;
            
            fetch('/api/documents')
                .then(response => response.json())
                .then(data => {
                    documentsList.innerHTML = '';
                    
                    if (Array.isArray(data)) {
                        if (data.length === 0) {
                            const emptyItem = document.createElement('li');
                            emptyItem.textContent = 'Нет загруженных документов';
                            documentsList.appendChild(emptyItem);
                        } else {
                            data.forEach(doc => {
                                const item = document.createElement('li');
                                
                                const docName = document.createElement('span');
                                docName.textContent = doc.name || doc.id || 'Документ';
                                
                                const deleteBtn = document.createElement('button');
                                deleteBtn.textContent = 'Удалить';
                                deleteBtn.addEventListener('click', function() {
                                    deleteDocument(doc.id);
                                });
                                
                                item.appendChild(docName);
                                item.appendChild(deleteBtn);
                                documentsList.appendChild(item);
                            });
                        }
                    } else {
                        const errorItem = document.createElement('li');
                        errorItem.textContent = 'Ошибка загрузки документов';
                        documentsList.appendChild(errorItem);
                    }
                })
                .catch(error => {
                    console.error('Ошибка при загрузке документов:', error);
                    documentsList.innerHTML = '<li>Ошибка загрузки документов</li>';
                });
        }
        
        // Функция для удаления документа
        function deleteDocument(docId) {
            if (!docId) return;
            
            fetch(`/api/documents/${docId}`, {
                method: 'DELETE'
            })
            .then(response => response.json())
            .then(data => {
                if (data.success) {
                    addMessage('system', `Документ успешно удален`);
                    loadDocuments(); // Обновляем список документов
                } else {
                    addMessage('system', `Ошибка: ${data.error}`);
                }
            })
            .catch(error => {
                console.error('Ошибка:', error);
                addMessage('system', `Произошла ошибка: ${error.message}`);
            });
        }
    });
    """
    
    # Записываем файлы
    with open(os.path.join(templates_dir, "base.html"), "w") as f:
        f.write(base_template)
    
    with open(os.path.join(templates_dir, "login.html"), "w") as f:
        f.write(login_template)
    
    with open(os.path.join(templates_dir, "index.html"), "w") as f:
        f.write(index_template)
    
    with open(os.path.join(static_dir, "style.css"), "w") as f:
        f.write(css)
    
    with open(os.path.join(static_dir, "script.js"), "w") as f:
        f.write(js)
