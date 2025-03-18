# Запуск нейроконсультанта по кибербезопасности

# Клонирование репозитория
!git clone https://github.com/Andrew821667/cybersec-consultant.git
%cd cybersec-consultant

# Установка зависимостей
!pip install -r requirements.txt

# Создание и настройка консультанта
from cybersec_consultant import create_consultant

# Запрос API ключа
api_key = input("Введите ваш API ключ OpenAI: ")
import os
os.environ["OPENAI_API_KEY"] = api_key

# Создание консультанта
consultant = create_consultant()

# Загрузка базы знаний
consultant.initialize_knowledge_base("knowledge_base/knowledge_base_cybernexus.txt")

# Функция для интерактивного запроса
def ask_consultant(query):
    print("\n" + "="*80)
    print(f"🔍 Запрос: {query}")
    print("="*80)
    
    # Поиск документов
    search_results = consultant.search_knowledge_base(query, k=3)
    
    # Подготовка контекста
    user_prompt = f"Запрос пользователя: {query}\n\nРелевантная информация:\n"
    for i, result in enumerate(search_results):
        if isinstance(result, tuple) and len(result) >= 2:
            if hasattr(result[0], 'page_content'):
                user_prompt += f"[Документ {i+1}]\n{result[0].page_content}\n\n"
    
    user_prompt += "Составьте полный и информативный ответ на запрос пользователя, используя только предоставленную информацию."
    
    # Получаем системный промпт
    system_prompt = consultant.prompt_manager.get_prompt('standard')
    
    # Генерация ответа
    response = consultant.llm_interface.generate_answer(
        system_prompt=system_prompt,
        user_prompt=user_prompt
    )
    
    # Вывод ответа
    if isinstance(response, dict) and 'answer' in response:
        print("\n📝 Ответ консультанта:")
        print(response['answer'])
    else:
        print("\n📝 Ответ консультанта:")
        print(response)

# Пример запросов
sample_queries = [
    "Что такое фишинг и как защититься от него?",
    "Какие методы шифрования данных наиболее эффективны?",
    "Как организовать защиту от DDoS атак?",
    "Какие основные принципы безопасности в интернете?",
    "Как защитить персональные данные от утечки?"
]

# Вывод примеров запросов
print("\n📊 Примеры запросов для тестирования:")
for i, q in enumerate(sample_queries):
    print(f"{i+1}. {q}")

# Интерактивный режим
while True:
    user_input = input("\n✏️ Введите ваш запрос (или 'выход' для завершения): ")
    
    if user_input.lower() in ['выход', 'exit', 'quit']:
        break
        
    if user_input.isdigit() and 1 <= int(user_input) <= len(sample_queries):
        ask_consultant(sample_queries[int(user_input)-1])
    else:
        ask_consultant(user_input)
