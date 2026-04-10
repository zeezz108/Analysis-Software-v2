"""
Модуль кэширования данных из базы данных (синглтон)

Обеспечивает:
- Единый источник данных для всех компонентов приложения
- Ленивую загрузку данных (только когда нужны)
- Значительное ускорение работы за счёт кэширования
- Предотвращение многократных обращений к БД
"""

from typing import Any, Callable, Dict


class DataCache:
    """
    Синглтон для кэширования данных из БД.

    Используется для хранения списков компонентов (процессоры, видеокарты, ОС и т.д.),
    чтобы не загружать их каждый раз заново при открытии диалогов.

    Пример использования:
        cache = DataCache()
        processors = cache.get("processors", lambda: db.get_processors())
    """

    _instance = None
    _data: Dict[str, Any] = {}
    _loaded: bool = False

    def __new__(cls) -> 'DataCache':
        """
        Реализация синглтона — всегда возвращает один и тот же экземпляр.
        """
        if cls._instance is None:
            cls._instance = super().__new__(cls)
        return cls._instance

    def get(self, key: str, loader_func: Callable[[], Any]) -> Any:
        """
        Получает данные из кэша или загружает их с помощью loader_func.

        Args:
            key: Ключ для кэша (например, "ARM_processor")
            loader_func: Функция, которая загружает данные, если их нет в кэше

        Returns:
            Загруженные данные (обычно список строк)
        """
        if key not in self._data:
            self._data[key] = loader_func()
        return self._data[key]

    def set(self, key: str, value: Any) -> None:
        """
        Принудительно устанавливает значение в кэш.

        Args:
            key: Ключ для кэша
            value: Значение для сохранения
        """
        self._data[key] = value

    def clear(self) -> None:
        """
        Полностью очищает кэш.
        Используется при необходимости принудительного обновления данных.
        """
        self._data.clear()
        self._loaded = False

    def is_loaded(self) -> bool:
        """
        Проверяет, были ли уже загружены данные в кэш.

        Returns:
            True если данные загружены, False если кэш пуст
        """
        return self._loaded

    def set_loaded(self) -> None:
        """
        Устанавливает флаг, что данные загружены.
        Вызывается после завершения асинхронной загрузки всех данных.
        """
        self._loaded = True

    def has_key(self, key: str) -> bool:
        """
        Проверяет наличие ключа в кэше.

        Args:
            key: Ключ для проверки

        Returns:
            True если ключ существует, иначе False
        """
        return key in self._data

    def get_keys(self) -> list:
        """
        Возвращает список всех ключей в кэше.

        Returns:
            Список ключей
        """
        return list(self._data.keys())

    def remove(self, key: str) -> None:
        """
        Удаляет конкретный ключ из кэша.

        Args:
            key: Ключ для удаления
        """
        if key in self._data:
            del self._data[key]

    def __contains__(self, key: str) -> bool:
        """
        Поддержка оператора 'in'.

        Example:
            if "some_key" in cache:
                data = cache["some_key"]
        """
        return key in self._data

    def __getitem__(self, key: str) -> Any:
        """
        Поддержка доступа через квадратные скобки.

        Example:
            data = cache["some_key"]
        """
        return self._data.get(key)

    def __setitem__(self, key: str, value: Any) -> None:
        """
        Поддержка присваивания через квадратные скобки.

        Example:
            cache["some_key"] = some_data
        """
        self._data[key] = value


# Для удобства создаём глобальный экземпляр
_default_cache = None


def get_cache() -> DataCache:
    """
    Возвращает глобальный экземпляр кэша.
    Удобная функция-обёртка для доступа к синглтону.

    Returns:
        Экземпляр DataCache
    """
    global _default_cache
    if _default_cache is None:
        _default_cache = DataCache()
    return _default_cache