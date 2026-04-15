"""Скрипт перевода названий CAPEC на русский язык."""
import sqlite3
import os

DB_PATH = os.path.join(os.path.dirname(__file__), "..", "database", "capec_database.db")

# Словарь перевода: от длинных фраз к коротким
TRANSLATIONS = {
    "Buffer Overflow": "Переполнение буфера",
    "SQL Injection": "SQL-инъекция",
    "Blind SQL Injection": "Слепая SQL-инъекция",
    "Cross-Site Scripting": "Межсайтовый скриптинг (XSS)",
    "Cross-Site Request Forgery": "Подделка межсайтовых запросов (CSRF)",
    "Cross Site Scripting": "Межсайтовый скриптинг (XSS)",
    "Command Injection": "Внедрение команд",
    "Command Delimiters": "Разделители команд",
    "Code Injection": "Внедрение кода",
    "Code Inclusion": "Включение кода",
    "LDAP Injection": "LDAP-инъекция",
    "XML Injection": "XML-инъекция",
    "XPath Injection": "XPath-инъекция",
    "XQuery Injection": "XQuery-инъекция",
    "JSON Hijacking": "Перехват JSON",
    "JSON Parsing": "Разбор JSON",
    "Session Hijacking": "Перехват сеанса",
    "Session Fixation": "Фиксация сеанса",
    "Session Credential": "Учётные данные сеанса",
    "Denial of Service": "Отказ в обслуживании (DoS)",
    "Man in the Middle": "Человек посередине (MitM)",
    "Man-in-the-Middle": "Человек посередине (MitM)",
    "Browser in the Middle": "Браузер посередине (BiTM)",
    "Brute Force": "Перебор (Brute Force)",
    "Password Attack": "Атака на пароли",
    "Password Brute Forcing": "Подбор паролей перебором",
    "Password Recovery": "Восстановление паролей",
    "Password Spraying": "Распыление паролей",
    "Credential Stuffing": "Подстановка учётных данных",
    "Dictionary-based": "Атака по словарю",
    "Phishing": "Фишинг",
    "Spear Phishing": "Целевой фишинг",
    "Social Engineering": "Социальная инженерия",
    "Privilege Escalation": "Повышение привилегий",
    "Privilege Abuse": "Злоупотребление привилегиями",
    "Access Control": "Контроль доступа",
    "Authentication Bypass": "Обход аутентификации",
    "Authentication Abuse": "Злоупотребление аутентификацией",
    "Authorization Bypass": "Обход авторизации",
    "Input Validation": "Валидация ввода",
    "Input Filters": "Фильтры ввода",
    "Information Disclosure": "Раскрытие информации",
    "Information Gathering": "Сбор информации",
    "Information Elicitation": "Выведывание информации",
    "Information Leakage": "Утечка информации",
    "Data Serialization": "Сериализация данных",
    "Data Interception": "Перехват данных",
    "Data Leakage": "Утечка данных",
    "Eavesdropping": "Прослушивание",
    "Traffic Injection": "Внедрение трафика",
    "Traffic Analysis": "Анализ трафика",
    "Packet Injection": "Внедрение пакетов",
    "Protocol Analysis": "Анализ протоколов",
    "Protocol Manipulation": "Манипулирование протоколом",
    "Network Reconnaissance": "Разведка сети",
    "Network Boundary Bridging": "Преодоление сетевых границ",
    "Port Scanning": "Сканирование портов",
    "Fingerprinting": "Снятие отпечатков",
    "Footprinting": "Сбор следов (Footprinting)",
    "OS Fingerprinting": "Определение ОС",
    "Reverse Engineering": "Обратная разработка",
    "Malicious Software": "Вредоносное ПО",
    "Malicious Files": "Вредоносные файлы",
    "Malicious Extension": "Вредоносное расширение",
    "Malicious Hardware": "Вредоносное оборудование",
    "Malicious Logic": "Вредоносная логика",
    "Malware": "Вредоносное ПО",
    "Malicious": "Вредоносный",
    "Cryptanalysis": "Криптоанализ",
    "Encryption Brute Forcing": "Взлом шифрования перебором",
    "Encryption": "Шифрование",
    "Cryptographic": "Криптографический",
    "Cache Poisoning": "Отравление кэша",
    "DNS Spoofing": "Подмена DNS",
    "DNS Rebinding": "Перепривязка DNS",
    "DNS Cache Poisoning": "Отравление кэша DNS",
    "ARP Spoofing": "Подмена ARP",
    "ARP Cache Poisoning": "Отравление ARP-кэша",
    "BGP Route": "Маршрут BGP",
    "IP Spoofing": "Подмена IP-адреса",
    "Spoofing": "Подмена",
    "Tampering": "Фальсификация",
    "Fuzzing": "Фаззинг",
    "Fuzzing for application": "Фаззинг приложения",
    "Flooding": "Затопление",
    "Resource Depletion": "Истощение ресурсов",
    "Resource Injection": "Внедрение ресурсов",
    "Resource Leak": "Утечка ресурсов",
    "Resource Location": "Определение местоположения ресурса",
    "File Manipulation": "Манипулирование файлами",
    "File Discovery": "Обнаружение файлов",
    "Path Traversal": "Обход пути (Path Traversal)",
    "Directory Traversal": "Обход директорий",
    "Directory Indexing": "Индексация директорий",
    "Forced Browsing": "Принудительный просмотр",
    "Configuration Abuse": "Злоупотребление конфигурацией",
    "Configuration Manipulation": "Манипулирование конфигурацией",
    "Supply Chain": "Цепочка поставок",
    "Hardware Fault Injection": "Внедрение аппаратных сбоев",
    "Hardware Integrity Attack": "Атака на целостность оборудования",
    "Hardware Component Substitution": "Подмена аппаратного компонента",
    "Hardware Component": "Аппаратный компонент",
    "Firmware Modification": "Модификация прошивки",
    "Physical Access": "Физический доступ",
    "Physical Theft": "Физическая кража",
    "Physical Security": "Физическая безопасность",
    "Side Channel Attack": "Атака по побочному каналу",
    "Timing Attack": "Атака по времени",
    "Power Analysis": "Анализ энергопотребления",
    "Electromagnetic": "Электромагнитный",
    "Fault Injection": "Внедрение сбоев",
    "Race Condition": "Состояние гонки",
    "Integer Overflow": "Целочисленное переполнение",
    "Format String": "Форматная строка",
    "Format String Injection": "Внедрение форматной строки",
    "Heap Overflow": "Переполнение кучи",
    "Stack Overflow": "Переполнение стека",
    "Use After Free": "Использование после освобождения",
    "Double Free": "Двойное освобождение",
    "Null Pointer Dereference": "Разыменование нулевого указателя",
    "Null Byte Injection": "Внедрение нулевого байта",
    "Memory Corruption": "Повреждение памяти",
    "Type Confusion": "Путаница типов",
    "Deserialization": "Десериализация",
    "Object Injection": "Внедрение объекта",
    "Template Injection": "Внедрение шаблона",
    "Expression Language Injection": "Внедрение языка выражений",
    "Header Injection": "Внедрение заголовков",
    "HTTP Response Splitting": "Разделение HTTP-ответа",
    "HTTP Response Smuggling": "Контрабанда HTTP-ответа",
    "HTTP Request Smuggling": "Контрабанда HTTP-запроса",
    "Request Smuggling": "Контрабанда запросов",
    "Response Splitting": "Разделение ответа",
    "URL Manipulation": "Манипулирование URL",
    "URL Encoding": "Кодирование URL",
    "Parameter Injection": "Внедрение параметров",
    "Parameter Tampering": "Фальсификация параметров",
    "Cookie Manipulation": "Манипулирование cookie",
    "Script Injection": "Внедрение скрипта",
    "CSS Injection": "Внедрение CSS",
    "Clickjacking": "Кликджекинг",
    "Content Spoofing": "Подмена содержимого",
    "Functionality Misuse": "Злоупотребление функциональностью",
    "Functionality Not Properly Constrained": "Недостаточное ограничение функциональности",
    "API Manipulation": "Манипулирование API",
    "API Abuse": "Злоупотребление API",
    "Sniffing": "Перехват (Sniffing)",
    "Wiretapping": "Прослушка",
    "Replay Attack": "Атака воспроизведения",
    "Reflection Attack": "Атака отражения",
    "Relay Attack": "Атака ретрансляции",
    "WiFi": "Wi-Fi",
    "Account Lockout": "Блокировка учётной записи",
    "Inducing Account Lockout": "Принудительная блокировка учётной записи",
    "Accessing Functionality": "Доступ к функциональности",
    "Alternative IP Address Encodings": "Альтернативное кодирование IP-адресов",
    "Blue Boxing": "Атака Blue Box",
    "Argument Injection": "Внедрение аргументов",
    "Web Server Misclassification": "Ошибочная классификация веб-сервера",
    "Environment Variable": "Переменная окружения",
    "Client-side Injection": "Внедрение на стороне клиента",
    "Embedding Scripts within Scripts": "Встраивание скриптов в скрипты",
    "Choosing Message Identifier": "Выбор идентификатора сообщения",
    "Subverting Environment Variable Values": "Подмена значений переменных окружения",
    "Ghost Character Sequences": "Призрачные символьные последовательности",
    "Leveraging": "Использование",
    "Leveraging Race Conditions": "Использование состояний гонки",
    "Exploiting": "Эксплуатация",
    "Exploitation": "Эксплуатация",
    "Manipulating": "Манипулирование",
    "Manipulation": "Манипулирование",
    "Subverting": "Подрыв",
    "Abusing": "Злоупотребление",
    "Abuse": "Злоупотребление",
    "Bypassing": "Обход",
    "Bypass": "Обход",
    "Injection": "Внедрение",
    "Overflow": "Переполнение",
    "Scanning": "Сканирование",
    "Probing": "Зондирование",
    "Harvesting": "Сбор",
    "Stealing": "Кража",
    "Interception": "Перехват",
    "Modification": "Модификация",
    "Disruption": "Нарушение работы",
    "Destruction": "Уничтожение",
    "Impersonation": "Подмена личности",
    "Masquerading": "Маскировка",
    "Escalation": "Повышение",
    "Evasion": "Обход обнаружения",
    "Exfiltration": "Утечка данных",
    "Embedding": "Встраивание",
    "Inducing": "Провоцирование",
    "Forcing": "Принуждение",
    "Corrupting": "Повреждение",
    "Degrading": "Деградация",
    "Overriding": "Переопределение",
    "Overreading": "Избыточное чтение",
    "Overflowing": "Переполнение",
    "Removing": "Удаление",
    "Installing": "Установка",
    "Install": "Установка",
    "Disabling": "Отключение",
    "Hiding": "Сокрытие",
    "Using": "Использование",
    "Reusing": "Повторное использование",
    "Leveraging": "Использование",
    "Collecting": "Сбор",
    "Targeting": "Нацеливание на",
    "Accessing": "Доступ к",
    "Altering": "Изменение",
    "via": "через",
    "through": "через",
    "against": "против",
    "in an": "в",
    "in a": "в",
    "with": "с",
    "from": "из",
    "Local Command-Line Utilities": "локальных утилит командной строки",
    "Environment Variables": "переменных окружения",
    "API Call": "вызове API",
    "Non-Script Elements": "нескриптовых элементов",
    "Sensitive Data Exposure": "Раскрытие конфиденциальных данных",
    "Functionality Discovery": "Обнаружение функциональности",
    "Trust Exploitation": "Эксплуатация доверия",
    "Log Injection": "Внедрение в журналы",
    "Log Manipulation": "Манипулирование журналами",
    "Audit Log": "Журнал аудита",
}


def translate(name):
    """Переводит название CAPEC на русский используя словарь."""
    result = name
    # Сортируем по длине (длинные фразы первыми)
    for eng, rus in sorted(TRANSLATIONS.items(), key=lambda x: -len(x[0])):
        if eng in result:
            result = result.replace(eng, rus)
    return result


def main():
    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()

    # Добавляем колонку name_ru если нет
    try:
        c.execute("ALTER TABLE capec_entries ADD COLUMN name_ru TEXT")
        conn.commit()
        print("Колонка name_ru добавлена")
    except Exception:
        print("Колонка name_ru уже существует")

    # Переводим все записи
    c.execute("SELECT capec_id, name FROM capec_entries ORDER BY capec_id")
    entries = c.fetchall()

    translated_count = 0
    for capec_id, name in entries:
        ru = translate(name)
        if ru != name:
            c.execute("UPDATE capec_entries SET name_ru = ? WHERE capec_id = ?", (ru, capec_id))
            translated_count += 1

    conn.commit()

    # Статистика
    c.execute("SELECT COUNT(*) FROM capec_entries WHERE name_ru IS NOT NULL")
    has_ru = c.fetchone()[0]
    c.execute("SELECT COUNT(*) FROM capec_entries WHERE name_ru IS NULL")
    no_ru = c.fetchone()[0]

    print(f"\nПереведено: {has_ru} из {len(entries)}")
    print(f"Без перевода (оставлены на английском): {no_ru}")

    # Примеры
    print("\n=== Примеры переводов ===")
    c.execute("SELECT capec_id, name, name_ru FROM capec_entries WHERE name_ru IS NOT NULL ORDER BY capec_id LIMIT 25")
    for r in c.fetchall():
        print(f"  CAPEC-{r[0]}: {r[2]}")

    print("\n=== Без перевода ===")
    c.execute("SELECT capec_id, name FROM capec_entries WHERE name_ru IS NULL ORDER BY capec_id LIMIT 10")
    for r in c.fetchall():
        print(f"  CAPEC-{r[0]}: {r[1]}")

    conn.close()


if __name__ == "__main__":
    main()
