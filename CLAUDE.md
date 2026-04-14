# Инструкция для Claude Code — Analysis-Software-v2

## Проект

**Автоматизированная система построения цифровых карт безопасности** — desktop-приложение (Python 3.13 + Tkinter + CustomTkinter) для построения топологии сети с анализом уязвимостей CVE.

## Техстек

- Python 3.13, CustomTkinter, Pillow, reportlab, python-docx
- SQLite3: `database/cve_database_v2.db` (344K CVE, NVD NIST)
- Шрифт UI: **Segoe UI** (не Arial!)

## Архитектура

- `main.py` — точка входа, splash с queue (Python 3.13 safe)
- `views/canvas_view.py` — главное окно, sidebar-аккордеон, холст с сеткой
- `views/osi_canvas_view.py` — схема ЭМВОС (двойная палитра dark/light)
- `models/osi_decomposition.py` — декомпозиция узла по 10 уровням (7 ЭМВОС + 3 ФСТЭК)
- `models/zone.py` — Zone, Board (с to_dict/load_from_dict для сохранения)
- `models/node.py` — Node, NetworkPort, VirtualMachine
- `dialogs/security_passport_dialog.py` — паспорт безопасности (на NodeDecomposition)
- `dialogs/node_dialog.py` — создание/редактирование узлов
- `config/presets.py` — пресеты конфигураций (АРМ, Маршрутизатор, Сервер)
- `database/cve_db.py` — CVEDatabase (SQL запросы к NVD)
- `utils/cpe_utils.py` — extract_cpe_components (30+ вендоров, version-фильтрация)
- `utils/theme.py` — палитра light/dark, color(), c()

## CVE-поиск (архитектура)

```
Компонент → extract_cpe_components() → {vendor, product, version}
  → get_cves_for_component(vendor, product, version) [LIMIT 200]
    → fallback без version → fallback без product
```

- CVE ищутся только для hardware/software/peripheral (не для протоколов)
- Кеш в `node.properties["security_passport_cache"]`
- Схема ЭМВОС читает из кеша паспорта

## Текущая версия: v2.1.2 (коммит 343e348)

## Правила работы

- Общение на русском языке
- Инкрементальный подход: каждый шаг показывать и подтверждать
- Релизы/коммиты только по явной просьбе
- Python 3.13: всегда оборачивать after() в try/except, использовать queue для фоновых потоков
- Промты лежат в `Promts/` (PDF) — в .gitignore
- БД CVE в .gitignore (345 MB)

## Известные проблемы

- Python 3.13 `deletecommand` crash — косметический, не критичный
- LIMIT 200 на CVE-запросы — умышленное ограничение скорости
- smart_search_cves существует но не используется в паспорте (тяжёлый)