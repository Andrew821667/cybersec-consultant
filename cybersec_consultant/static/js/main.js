document.addEventListener('DOMContentLoaded', function() {
    // Элементы DOM
    const chatHistory = document.getElementById('chatHistory');
    const userQuery = document.getElementById('userQuery');
    const sendBtn = document.getElementById('sendBtn');
    const exampleQueries = document.getElementById('exampleQueries');
    
    // Примеры запросов
    const examples = [
        "Что такое фишинг и как защититься от него?",
        "Какие методы шифрования данных наиболее эффективны?",
        "Как организовать защиту от DDoS атак?",
        "Какие основные принципы безопасности в интернете?",
        "Как защитить персональные данные от утечки?"
    ];
    
    // Добавляем примеры запросов на страницу
    examples.forEach((example, index) => {
        const li = document.createElement('li');
        li.className = 'example-item';
        li.textContent = example;
        li.addEventListener('click', () => {
            userQuery.value = example;
            sendMessage();
        });
        exampleQueries.appendChild(li);
    });
    
    // Отправка сообщения при нажатии на кнопку
    sendBtn.addEventListener('click', sendMessage);
    
    // Отправка сообщения при нажатии Enter
    userQuery.addEventListener('keypress', function(e) {
        if (e.key === 'Enter') {
            sendMessage();
        }
    });
    
    // Функция отправки сообщения
    function sendMessage() {
        const query = userQuery.value.trim();
        if (query === '') return;
        
        // Добавляем сообщение пользователя в историю
        addMessageToChat(query, 'user');
        
        // Очищаем поле ввода
        userQuery.value = '';
        
        // Показываем индикатор загрузки
        const loadingIndicator = document.createElement('div');
        loadingIndicator.className = 'message bot-message';
        loadingIndicator.textContent = 'Анализирую информацию...';
        loadingIndicator.id = 'loadingIndicator';
        chatHistory.appendChild(loadingIndicator);
        chatHistory.scrollTop = chatHistory.scrollHeight;
        
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
            const loadingIndicator = document.getElementById('loadingIndicator');
            if (loadingIndicator) {
                chatHistory.removeChild(loadingIndicator);
            }
            
            // Добавляем ответ бота в историю
            addMessageToChat(data.answer, 'bot');
        })
        .catch(error => {
            console.error('Error:', error);
            
            // Удаляем индикатор загрузки
            const loadingIndicator = document.getElementById('loadingIndicator');
            if (loadingIndicator) {
                chatHistory.removeChild(loadingIndicator);
            }
            
            // Добавляем сообщение об ошибке
            addMessageToChat('Произошла ошибка при обработке запроса. Пожалуйста, попробуйте еще раз.', 'bot');
        });
    }
    
    // Функция добавления сообщения в историю чата
    function addMessageToChat(text, sender) {
        const message = document.createElement('div');
        message.className = `message ${sender}-message`;
        
        // Форматируем сообщение (можно улучшить с использованием markdown)
        const formattedText = text.replace(/\n/g, '<br>');
        message.innerHTML = formattedText;
        
        chatHistory.appendChild(message);
        chatHistory.scrollTop = chatHistory.scrollHeight;
    }
});