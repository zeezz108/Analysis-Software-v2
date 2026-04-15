"""
Модуль модели файервола (Firewall)

Содержит классы:
- FirewallRule: Правило файервола (модель Source → Destination, аналог Cisco ACL)
- FirewallManager: Менеджер правил файервола для узла
"""

from dataclasses import dataclass, field
from typing import List, Dict, Any, Optional
from datetime import datetime

from utils.generators import uid


class FirewallRule:
    """
    Класс для представления одного правила файервола.

    Модель Source → Destination (аналог Cisco ACL):
    - source_address: IP/подсеть источника трафика или "any"
    - destination_address: IP/подсеть назначения трафика или "any"
    - interface: port_id интерфейса узла, к которому привязано правило, или "all"
    - source_ports: порты источника (TCP/UDP)
    - destination_ports: порты назначения (TCP/UDP)
    - action: разрешить/блокировать
    - protocol: TCP/UDP/ICMP/любой
    """

    def __init__(
            self,
            rule_id: Optional[str] = None,
            name: str = "",
            action: str = "allow",
            protocol: str = "any",
            source_address: str = "any",
            destination_address: str = "any",
            interface: str = "all",
            source_ports: str = "",
            destination_ports: str = "",
            enabled: bool = True,
            description: str = ""
    ):
        """
        Инициализация правила файервола.

        Args:
            rule_id: Уникальный идентификатор (генерируется автоматически)
            name: Название правила
            action: Действие ("allow" - разрешить, "block" - блокировать)
            protocol: Протокол ("any", "tcp", "udp", "icmp")
            source_address: IP/подсеть источника или "any"
            destination_address: IP/подсеть назначения или "any"
            interface: port_id интерфейса или "all" (все интерфейсы)
            source_ports: Порты источника (например, "80,443" или "5000-5010")
            destination_ports: Порты назначения
            enabled: Включено ли правило
            description: Описание правила
        """
        self.id = rule_id or uid()
        self.name = name
        self.action = action
        self.protocol = protocol
        self.source_address = source_address
        self.destination_address = destination_address
        self.interface = interface
        self.source_ports = source_ports
        self.destination_ports = destination_ports
        self.enabled = enabled
        self.description = description
        self.created = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        self.modified = self.created

    def to_dict(self) -> Dict[str, Any]:
        """
        Сериализует правило в словарь.

        Returns:
            Словарь с данными правила
        """
        return {
            "id": self.id,
            "name": self.name,
            "action": self.action,
            "protocol": self.protocol,
            "source_address": self.source_address,
            "destination_address": self.destination_address,
            "interface": self.interface,
            "source_ports": self.source_ports,
            "destination_ports": self.destination_ports,
            "enabled": self.enabled,
            "description": self.description,
            "created": self.created,
            "modified": self.modified
        }

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> 'FirewallRule':
        """
        Восстанавливает правило из словаря.

        Поддерживает оба формата:
        - Новый (source_address/destination_address)
        - Старый (direction/local_addresses/remote_addresses) — конвертируется автоматически

        Args:
            data: Словарь с данными правила

        Returns:
            Экземпляр FirewallRule
        """
        rule = cls()
        rule.id = data.get("id", uid())
        rule.name = data.get("name", "")
        rule.action = data.get("action", "allow")
        rule.protocol = data.get("protocol", "any")
        rule.enabled = data.get("enabled", True)
        rule.description = data.get("description", "")
        rule.created = data.get("created", datetime.now().strftime("%Y-%m-%d %H:%M:%S"))
        rule.modified = data.get("modified", rule.created)

        if "source_address" in data:
            # Новый формат — используем напрямую
            rule.source_address = data.get("source_address", "any")
            rule.destination_address = data.get("destination_address", "any")
            rule.interface = data.get("interface", "all")
            rule.source_ports = data.get("source_ports", "")
            rule.destination_ports = data.get("destination_ports", "")
        elif "direction" in data:
            # Старый формат — конвертируем
            direction = data.get("direction", "in")
            local_addr = data.get("local_addresses", "any") or "any"
            remote_addr = data.get("remote_addresses", "any") or "any"

            if direction == "in":
                # Входящий: remote → local  =>  source=remote, destination=local
                rule.source_address = remote_addr
                rule.destination_address = local_addr
            else:
                # Исходящий: local → remote  =>  source=local, destination=remote
                rule.source_address = local_addr
                rule.destination_address = remote_addr

            rule.interface = "all"
            rule.source_ports = data.get("local_ports", "") if direction == "out" else data.get("remote_ports", "")
            rule.destination_ports = data.get("remote_ports", "") if direction == "out" else data.get("local_ports", "")
        else:
            # Минимальные данные
            rule.source_address = "any"
            rule.destination_address = "any"
            rule.interface = "all"
            rule.source_ports = ""
            rule.destination_ports = ""

        return rule

    def clone(self) -> 'FirewallRule':
        """
        Создаёт копию правила.

        Returns:
            Новый экземпляр FirewallRule
        """
        return FirewallRule(
            name=f"Копия {self.name}",
            action=self.action,
            protocol=self.protocol,
            source_address=self.source_address,
            destination_address=self.destination_address,
            interface=self.interface,
            source_ports=self.source_ports,
            destination_ports=self.destination_ports,
            enabled=self.enabled,
            description=f"Копия: {self.description}"
        )

    def get_display_name(self) -> str:
        """
        Возвращает отображаемое имя правила.

        Returns:
            Строка для отображения в UI
        """
        if self.name:
            return self.name

        # Генерируем имя на основе параметров
        src = self.source_address if self.source_address != "any" else "*"
        dst = self.destination_address if self.destination_address != "any" else "*"
        action_str = "разрешение" if self.action == "allow" else "блокирование"

        parts = [f"{src} -> {dst}"]

        if self.protocol != "any":
            parts.append(self.protocol.upper())

        if self.destination_ports:
            parts.append(f"порт {self.destination_ports}")

        parts.append(f"[{action_str}]")

        return " ".join(parts)

    def __str__(self) -> str:
        """Строковое представление правила."""
        return self.get_display_name()

    def __repr__(self) -> str:
        """Представление для отладки."""
        return (f"FirewallRule(name={self.name}, "
                f"src={self.source_address}, dst={self.destination_address}, "
                f"action={self.action})")


class FirewallManager:
    """
    Менеджер правил файервола для узла.

    Управляет списком правил, профилями сети и состоянием файервола.

    Attributes:
        node_id: ID узла, которому принадлежит файервол
        rules: Список правил
        profiles: Профили сети (domain, private, public)
        firewall_enabled: Включён ли файервол
        notification_enabled: Показывать ли уведомления о блокировках
    """

    def __init__(self, node_id: str):
        """
        Инициализация менеджера файервола.

        Args:
            node_id: ID узла
        """
        self.node_id = node_id
        self.rules: List[FirewallRule] = []
        self.profiles: Dict[str, bool] = {
            "domain": True,  # Доменный профиль
            "private": True,  # Частный профиль
            "public": True  # Публичный профиль
        }
        self.firewall_enabled: bool = True
        self.notification_enabled: bool = True

    def add_rule(self, rule: FirewallRule) -> FirewallRule:
        """
        Добавляет правило в конец списка.

        Args:
            rule: Правило для добавления

        Returns:
            Добавленное правило
        """
        self.rules.append(rule)
        return rule

    def insert_rule(self, index: int, rule: FirewallRule) -> FirewallRule:
        """
        Вставляет правило на указанную позицию.

        Args:
            index: Позиция для вставки
            rule: Правило для вставки

        Returns:
            Вставленное правило
        """
        self.rules.insert(index, rule)
        return rule

    def remove_rule(self, rule_id: str) -> None:
        """
        Удаляет правило по ID.

        Args:
            rule_id: ID правила для удаления
        """
        self.rules = [r for r in self.rules if r.id != rule_id]

    def get_rule(self, rule_id: str) -> Optional[FirewallRule]:
        """
        Возвращает правило по ID.

        Args:
            rule_id: ID правила

        Returns:
            Правило или None, если не найдено
        """
        for rule in self.rules:
            if rule.id == rule_id:
                return rule
        return None

    def update_rule(self, rule_id: str, **kwargs) -> bool:
        """
        Обновляет поля правила.

        Args:
            rule_id: ID правила для обновления
            **kwargs: Поля и новые значения для обновления

        Returns:
            True если обновление успешно, False если правило не найдено
        """
        for rule in self.rules:
            if rule.id == rule_id:
                for key, value in kwargs.items():
                    if hasattr(rule, key):
                        setattr(rule, key, value)
                rule.modified = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
                return True
        return False

    def toggle_rule(self, rule_id: str) -> Optional[bool]:
        """
        Включает/выключает правило.

        Args:
            rule_id: ID правила

        Returns:
            Новое состояние правила (True/False) или None если правило не найдено
        """
        for rule in self.rules:
            if rule.id == rule_id:
                rule.enabled = not rule.enabled
                rule.modified = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
                return rule.enabled
        return None

    def move_rule_up(self, rule_id: str) -> bool:
        """
        Перемещает правило вверх (повышает приоритет).

        Args:
            rule_id: ID перемещаемого правила

        Returns:
            True если перемещение успешно
        """
        for i, rule in enumerate(self.rules):
            if rule.id == rule_id and i > 0:
                self.rules[i], self.rules[i - 1] = self.rules[i - 1], self.rules[i]
                return True
        return False

    def move_rule_down(self, rule_id: str) -> bool:
        """
        Перемещает правило вниз (понижает приоритет).

        Args:
            rule_id: ID перемещаемого правила

        Returns:
            True если перемещение успешно
        """
        for i, rule in enumerate(self.rules):
            if rule.id == rule_id and i < len(self.rules) - 1:
                self.rules[i], self.rules[i + 1] = self.rules[i + 1], self.rules[i]
                return True
        return False

    def get_enabled_rules(self) -> List[FirewallRule]:
        """
        Возвращает только включённые правила.

        Returns:
            Список включённых правил
        """
        return [r for r in self.rules if r.enabled]

    def get_rules_by_action(self, action: str) -> List[FirewallRule]:
        """
        Возвращает правила по действию.

        Args:
            action: Действие ("allow" или "block")

        Returns:
            Список правил с указанным действием
        """
        return [r for r in self.rules if r.action == action]

    def get_rules_by_protocol(self, protocol: str) -> List[FirewallRule]:
        """
        Возвращает правила по протоколу.

        Args:
            protocol: Протокол ("any", "tcp", "udp", "icmp")

        Returns:
            Список правил с указанным протоколом
        """
        return [r for r in self.rules if r.protocol == protocol]

    def clear_rules(self) -> None:
        """Удаляет все правила."""
        self.rules.clear()

    def get_statistics(self) -> Dict[str, int]:
        """
        Возвращает статистику по правилам.

        Returns:
            Словарь со статистикой
        """
        stats = {
            "total": len(self.rules),
            "enabled": len(self.get_enabled_rules()),
            "disabled": len(self.rules) - len(self.get_enabled_rules()),
            "allow": len(self.get_rules_by_action("allow")),
            "block": len(self.get_rules_by_action("block"))
        }
        return stats

    def set_profile(self, profile: str, enabled: bool) -> None:
        """
        Устанавливает состояние профиля сети.

        Args:
            profile: Имя профиля ("domain", "private", "public")
            enabled: Включён ли профиль
        """
        if profile in self.profiles:
            self.profiles[profile] = enabled

    def is_profile_enabled(self, profile: str) -> bool:
        """
        Проверяет, включён ли профиль.

        Args:
            profile: Имя профиля

        Returns:
            True если профиль включён
        """
        return self.profiles.get(profile, False)

    def to_dict(self) -> Dict[str, Any]:
        """
        Сериализует менеджер в словарь.

        Returns:
            Словарь с данными менеджера
        """
        return {
            "node_id": self.node_id,
            "rules": [rule.to_dict() for rule in self.rules],
            "profiles": self.profiles.copy(),
            "firewall_enabled": self.firewall_enabled,
            "notification_enabled": self.notification_enabled
        }

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> 'FirewallManager':
        """
        Восстанавливает менеджер из словаря.

        Args:
            data: Словарь с данными менеджера

        Returns:
            Экземпляр FirewallManager
        """
        manager = cls(data.get("node_id", ""))
        manager.rules = [FirewallRule.from_dict(r) for r in data.get("rules", [])]
        manager.profiles = data.get("profiles", {"domain": True, "private": True, "public": True})
        manager.firewall_enabled = data.get("firewall_enabled", True)
        manager.notification_enabled = data.get("notification_enabled", True)
        return manager


# Константы для действий
ACTION_ALLOW = "allow"
ACTION_BLOCK = "block"
ACTIONS = [ACTION_ALLOW, ACTION_BLOCK]

# Константы для протоколов
PROTOCOL_ANY = "any"
PROTOCOL_TCP = "tcp"
PROTOCOL_UDP = "udp"
PROTOCOL_ICMP = "icmp"
PROTOCOLS = [PROTOCOL_ANY, PROTOCOL_TCP, PROTOCOL_UDP, PROTOCOL_ICMP]

# Константы для профилей
PROFILE_DOMAIN = "domain"
PROFILE_PRIVATE = "private"
PROFILE_PUBLIC = "public"
PROFILES = [PROFILE_DOMAIN, PROFILE_PRIVATE, PROFILE_PUBLIC]

# Отображения для UI
ACTION_DISPLAY = {
    ACTION_ALLOW: "Разрешить",
    ACTION_BLOCK: "Блокировать"
}

PROTOCOL_DISPLAY = {
    PROTOCOL_ANY: "Любой",
    PROTOCOL_TCP: "TCP",
    PROTOCOL_UDP: "UDP",
    PROTOCOL_ICMP: "ICMP"
}

PROFILE_DISPLAY = {
    PROFILE_DOMAIN: "Домен",
    PROFILE_PRIVATE: "Частная",
    PROFILE_PUBLIC: "Публичная"
}
