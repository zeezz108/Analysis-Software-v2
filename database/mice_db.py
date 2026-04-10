"""
Модуль базы данных мышей (Mice Database)

Содержит класс MiceDatabase для работы с базой моделей мышей.
Поддерживает:
- Подключение к SQLite базе
- Поиск моделей по названию
- Кэширование подключения (синглтон)
"""

import os
import re
import sqlite3
from typing import List

# Базовая папка (где лежит этот файл)
BASE_DIR = os.path.dirname(os.path.abspath(__file__))


class MiceDatabase:
    """
    Синглтон для работы с базой данных мышей.

    Предоставляет методы для получения списка моделей мышей
    из базы данных mice.db.

    Пример использования:
        db = MiceDatabase()
        mice = db.get_all_mice()
        gaming_mice = db.get_all_mice(search="gaming")
    """

    _instance = None
    _connection = None
    _table_name = None

    def __new__(cls):
        """Синглтон — всегда возвращает один экземпляр."""
        if cls._instance is None:
            cls._instance = super().__new__(cls)
        return cls._instance

    def __init__(self, db_path: str = None):
        """
        Инициализация подключения к базе данных.

        Args:
            db_path: Путь к файлу базы данных (по умолчанию mice.db)

        Raises:
            FileNotFoundError: Если файл базы данных не найден
            Exception: Если в базе нет таблиц или отсутствует колонка model_name
        """
        # Если уже подключены, ничего не делаем
        if self._connection is not None:
            return

        # Определяем путь к базе данных
        if db_path is None:
            db_path = os.path.join(BASE_DIR, "mice.db")

        # Проверяем существование файла
        if not os.path.exists(db_path):
            raise FileNotFoundError(f"❌ mice.db не найден: {db_path}")

        print(f"[MICE] Подключение к: {db_path}")

        # Подключаемся к базе
        self._connection = sqlite3.connect(db_path, check_same_thread=False)
        self._connection.row_factory = sqlite3.Row

        # Определяем имя таблицы
        self._determine_table_name()

    def _determine_table_name(self) -> None:
        """
        Определяет имя таблицы в базе данных.

        Raises:
            Exception: Если в базе нет таблиц или отсутствует колонка model_name
        """
        cursor = self._connection.cursor()

        # Получаем список всех таблиц
        cursor.execute("SELECT name FROM sqlite_master WHERE type='table';")
        tables = cursor.fetchall()

        if not tables:
            raise Exception("В mice.db нет таблиц")

        # Берём первую таблицу
        self._table_name = tables[0][0]
        print(f"[MICE] Таблица: {self._table_name}")

        # Валидация имени таблицы (только буквы, цифры, подчёркивание)
        if not re.match(r'^[A-Za-z0-9_]+$', self._table_name):
            raise Exception(f"Недопустимое имя таблицы: {self._table_name}")

        # Проверяем наличие колонки model_name
        cursor.execute(f"PRAGMA table_info({self._table_name})")
        columns = [col[1] for col in cursor.fetchall()]

        if 'model_name' not in columns:
            raise Exception(f"Нет колонки model_name в {self._table_name}")

    def get_all_mice(self, search: str = "") -> List[str]:
        """
        Возвращает список всех моделей мышей (с фильтрацией по поиску).

        Args:
            search: Поисковая строка (опционально)

        Returns:
            Список названий моделей мышей

        Example:
            >>> db = MiceDatabase()
            >>> all_mice = db.get_all_mice()
            >>> logitech_mice = db.get_all_mice(search="Logitech")
        """
        query = f"SELECT model_name FROM {self._table_name}"
        params = []

        # Добавляем поиск, если указан
        if search:
            query += " WHERE model_name LIKE ?"
            params = [f"%{search}%"]

        # Сортируем по алфавиту
        query += " ORDER BY model_name"

        cursor = self._connection.cursor()
        cursor.execute(query, params)

        return [row['model_name'] for row in cursor.fetchall()]

    def get_mice_count(self) -> int:
        """
        Возвращает количество записей в базе.

        Returns:
            Количество моделей мышей
        """
        cursor = self._connection.cursor()
        cursor.execute(f"SELECT COUNT(*) as count FROM {self._table_name}")
        row = cursor.fetchone()
        return row['count'] if row else 0

    def search_mice_by_brand(self, brand: str) -> List[str]:
        """
        Ищет мыши по бренду.

        Args:
            brand: Название бренда (например, "Logitech", "Razer")

        Returns:
            Список моделей указанного бренда
        """
        return self.get_all_mice(search=brand)

    def close(self) -> None:
        """Закрывает соединение с базой данных."""
        if self._connection:
            self._connection.close()
            self._connection = None
            self._table_name = None
            print("[MICE] Соединение закрыто")

    def __enter__(self):
        """Поддержка контекстного менеджера."""
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        """Закрывает соединение при выходе из контекста."""
        self.close()


# Пример использования при импорте модуля
if __name__ == "__main__":
    # Тестовый запуск
    try:
        db = MiceDatabase()
        print(f"Найдено мышей: {db.get_mice_count()}")

        # Показываем первые 5 моделей
        all_mice = db.get_all_mice()
        print("Первые 5 моделей:")
        for mouse in all_mice[:5]:
            print(f"  - {mouse}")

        db.close()
    except FileNotFoundError as e:
        print(f"Ошибка: {e}")
    except Exception as e:
        print(f"Неожиданная ошибка: {e}")