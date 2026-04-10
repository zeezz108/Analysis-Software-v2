"""
Модуль матрицы связности сети

Хранит информацию о том, какие узлы могут взаимодействовать на сетевом уровне.
"""

from dataclasses import dataclass, field
from typing import Dict, List, Optional, Set, Tuple
from enum import Enum

from models.node import Node

class ConnectivityStatus(Enum):
    """Статус связности между узлами."""
    DIRECT = "direct"  # Прямое соединение (в одной подсети)
    ROUTED = "routed"  # Через маршрутизатор
    VPN = "vpn"  # Через VPN
    BLOCKED = "blocked"  # Заблокировано файерволом
    NONE = "none"  # Нет соединения


@dataclass
class ConnectionPath:
    """Путь соединения между двумя узлами."""
    source_id: str
    target_id: str
    status: ConnectivityStatus
    path_nodes: List[str] = field(default_factory=list)  # Список ID узлов по пути
    interface: str = ""  # Через какой интерфейс
    reason: str = ""  # Причина (если blocked)


class ConnectivityMatrix:
    """
    Матрица связности сети.

    Хранит для каждой пары узлов информацию о возможности взаимодействия.
    """

    def __init__(self, board):
        self.board = board
        self.matrix: Dict[Tuple[str, str], ConnectionPath] = {}
        self._build_matrix()

    def _build_matrix(self):
        """Строит матрицу связности на основе всех данных."""
        nodes = self.board.nodes
        node_ids = [n.id for n in nodes]

        # Инициализируем матрицу
        for src in node_ids:
            for dst in node_ids:
                if src != dst:
                    key = (src, dst)
                    self.matrix[key] = ConnectionPath(
                        source_id=src,
                        target_id=dst,
                        status=ConnectivityStatus.NONE
                    )

        # 1. Проверяем прямые физические соединения с совместимыми IP
        self._check_direct_connections()

        # 2. Проверяем маршрутизацию
        self._check_routed_connections()

        # 3. Проверяем VPN соединения
        self._check_vpn_connections()

        # 4. Проверяем файерволы
        self._check_firewall_blocks()

    def _check_direct_connections(self):
        """Проверяет прямые физические соединения."""
        for link in self.board.links:
            # Получаем порты, участвующие в соединении
            if link.is_wifi:
                # Wi-Fi соединение
                if link.a.id == link.wifi_ap_node_id:
                    ap_node = link.a
                    client_node = link.b
                elif link.b.id == link.wifi_ap_node_id:
                    ap_node = link.b
                    client_node = link.a
                else:
                    continue

                # Находим IP портов
                ap_ip = self._get_port_ip(ap_node, link.wifi_ap_port_id)
                client_ip = self._get_port_ip(client_node, link.wifi_client_port_id)

                if self._are_ips_compatible(ap_ip, client_ip):
                    self._set_connection(ap_node.id, client_node.id, ConnectivityStatus.DIRECT)
            else:
                # P2P соединение
                port_a_id = link.ports_connected.get("a")
                port_b_id = link.ports_connected.get("b")

                if port_a_id and port_b_id:
                    ip_a = self._get_port_ip(link.a, port_a_id)
                    ip_b = self._get_port_ip(link.b, port_b_id)

                    if self._are_ips_compatible(ip_a, ip_b):
                        self._set_connection(link.a.id, link.b.id, ConnectivityStatus.DIRECT)

    def _check_routed_connections(self):
        """Проверяет соединения через маршрутизацию с учётом таблиц маршрутизации."""

        for src in self.board.nodes:
            for dst in self.board.nodes:
                if src.id == dst.id:
                    continue

                # 1. Уже есть прямое соединение?
                if self._has_direct_connection(src.id, dst.id):
                    continue

                # 2. Может ли src достичь dst по своей таблице маршрутизации?
                if self._can_reach_via_routing_table(src, dst):
                    continue

                # 3. Если нет таблицы, но есть маршрутизатор между подсетями
                self._check_router_based_connection(src, dst)

    def _has_direct_connection(self, src_id: str, dst_id: str) -> bool:
        """Проверяет, есть ли уже прямое соединение между узлами."""
        key = (src_id, dst_id)
        if key in self.matrix:
            return self.matrix[key].status == ConnectivityStatus.DIRECT
        return False

    def _can_reach_via_routing_table(self, src: Node, dst: Node) -> bool:
        """Проверяет, может ли src достичь dst по своей таблице маршрутизации."""

        if not hasattr(src, 'routing_table') or not src.routing_table:
            return False

        dst_ip = self._get_node_ip(dst)
        if not dst_ip:
            return False

        dst_addr = dst_ip.split('/')[0]

        for route_data in src.routing_table:
            from models.route import Route
            route = Route.from_dict(route_data)

            # Проверяем, принадлежит ли dst сети назначения
            if self._is_ip_in_network(dst_addr, route.destination, route.netmask):
                # Нашли маршрут!
                gateway = route.gateway

                if gateway == "0.0.0.0":
                    # Прямое подключение
                    self._set_connection(src.id, dst.id, ConnectivityStatus.DIRECT)
                else:
                    # Идём через шлюз
                    gateway_node = self._find_node_by_ip(gateway)
                    if gateway_node:
                        self._set_connection(
                            src.id, dst.id,
                            ConnectivityStatus.ROUTED,
                            path_nodes=[src.id, gateway_node.id, dst.id],
                            reason=f"через шлюз {gateway}"
                        )
                return True

        return False

    def _check_router_based_connection(self, src: Node, dst: Node):
        """Проверяет соединение через маршрутизатор (если у src нет таблицы)."""

        src_ip = self._get_node_ip(src)
        dst_ip = self._get_node_ip(dst)

        if not src_ip or not dst_ip:
            return

        src_network = self._get_ip_network(src_ip)
        dst_network = self._get_ip_network(dst_ip)

        # Если в одной сети, но нет прямого соединения — не соединяются
        if src_network == dst_network:
            return

        # Ищем маршрутизатор, который знает обе сети
        for router in self.board.nodes:
            if router.type != "Router":
                continue

            router_networks = self._get_all_node_networks(router)

            if src_network in router_networks and dst_network in router_networks:
                # Проверяем, есть ли у маршрутизатора маршруты
                if self._router_has_routes(router, src_network, dst_network):
                    self._set_connection(
                        src.id, dst.id,
                        ConnectivityStatus.ROUTED,
                        path_nodes=[src.id, router.id, dst.id],
                        reason=f"через маршрутизатор {router.name}"
                    )
                break

    def _router_has_routes(self, router: Node, src_network: str, dst_network: str) -> bool:
        """Проверяет, есть ли у маршрутизатора маршруты для обеих сетей."""

        if not hasattr(router, 'routing_table') or not router.routing_table:
            # Если нет таблицы, считаем что маршрутизатор работает по умолчанию
            return True

        has_src_route = False
        has_dst_route = False

        for route_data in router.routing_table:
            from models.route import Route
            route = Route.from_dict(route_data)

            # Проверяем, знает ли маршрутизатор src_network
            if route.destination == src_network or route.destination == "0.0.0.0":
                has_src_route = True

            # Проверяем, знает ли маршрутизатор dst_network
            if route.destination == dst_network or route.destination == "0.0.0.0":
                has_dst_route = True

        return has_src_route and has_dst_route

    def _find_node_by_ip(self, ip: str) -> Optional[Node]:
        """Находит узел по IP-адресу."""
        for node in self.board.nodes:
            node_ip = self._get_node_ip(node)
            if node_ip and node_ip.split('/')[0] == ip:
                return node
        return None

    def _get_ip_network(self, ip_with_mask: str) -> str:
        """Возвращает сеть IP-адреса."""
        if not ip_with_mask:
            return ""
        from utils.network_utils import calculate_network
        parts = ip_with_mask.split('/')
        ip = parts[0]
        if len(parts) < 2 or not parts[1]:
            return ""
        mask = parts[1]
        return calculate_network(ip, mask)

    def _get_all_node_networks(self, node: Node) -> List[str]:
        """Возвращает все сети, к которым подключён узел."""
        networks = []
        for port in node.ports:
            ip = port.get("ip_address", "")
            mask = port.get("subnet_mask", "")
            if ip and mask:
                network = self._get_ip_network(f"{ip}/{mask}")
                if network:
                    networks.append(network)
        return networks

    def _check_vpn_connections(self):
        """Проверяет VPN соединения."""
        for node in self.board.nodes:
            if node.vpn_client_enabled and node.vpn_client_peer_id:
                # Клиент подключён к серверу
                server = self.board.find_node(node.vpn_client_peer_id)
                if server and server.vpn_server_enabled:
                    # Проверяем совпадение параметров
                    client_ip = node.vpn_client_tunnel_ip.split('/')[0] if node.vpn_client_tunnel_ip else ""
                    server_ips = [ip.split('/')[0] for ip in (server.vpn_server_tunnel_ips or []) if ip]

                    if client_ip in server_ips:
                        self._set_connection(
                            node.id, server.id,
                            ConnectivityStatus.VPN,
                            reason=f"VPN туннель: {client_ip} -> {server_ips}"
                        )

    def _check_firewall_blocks(self):
        """Проверяет, не блокирует ли файервол соединения."""
        for src in self.board.nodes:
            if not src.firewall_enabled:
                continue

            # Проверяем правила файервола
            firewall_data = src.properties.get("firewall", {})
            rules = firewall_data.get("rules", [])

            for rule in rules:
                if not rule.get("enabled", True):
                    continue

                if rule.get("action") == "block":
                    # Блокирующее правило
                    direction = rule.get("direction", "in")
                    remote_network = rule.get("remote_addresses", "any")

                    for dst in self.board.nodes:
                        if dst.id == src.id:
                            continue

                        dst_ip = self._get_node_ip(dst)
                        if not dst_ip:
                            continue
                        if remote_network == "any":
                            match = True
                        elif '/' in remote_network:
                            net_parts = remote_network.split('/')
                            match = self._is_ip_in_network(dst_ip, net_parts[0], net_parts[1])
                        else:
                            match = self._is_ip_in_network(dst_ip, remote_network, "32")
                        if match:
                            key = (src.id, dst.id)
                            if key in self.matrix and self.matrix[key].status != ConnectivityStatus.NONE:
                                self.matrix[key].status = ConnectivityStatus.BLOCKED
                                self.matrix[key].reason = f"Заблокировано правилом: {rule.get('name', 'без имени')}"

    def _get_port_ip(self, node, port_id: str) -> Optional[str]:
        """Возвращает IP адрес порта."""
        for port in node.ports:
            if port.get("port_id") == port_id:
                ip = port.get("ip_address", "")
                mask = port.get("subnet_mask", "")
                if ip and mask:
                    return f"{ip}/{mask}"
                return ip if ip else None
        return None

    def _get_node_ip(self, node) -> Optional[str]:
        """Возвращает первый IP адрес узла."""
        for port in node.ports:
            ip = port.get("ip_address", "")
            if ip:
                mask = port.get("subnet_mask", "")
                return f"{ip}/{mask}" if mask else ip
        return None

    def _are_ips_compatible(self, ip1: Optional[str], ip2: Optional[str]) -> bool:
        """Проверяет, совместимы ли два IP (в одной подсети)."""
        if not ip1 or not ip2:
            return False

        from utils.network_utils import calculate_network

        # Парсим IP и маску
        ip1_parts = ip1.split('/')
        ip2_parts = ip2.split('/')

        ip1_addr = ip1_parts[0]
        ip1_mask = ip1_parts[1] if len(ip1_parts) > 1 else "24"

        ip2_addr = ip2_parts[0]
        ip2_mask = ip2_parts[1] if len(ip2_parts) > 1 else "24"

        # Если маски разные, используем более строгую
        # В реальности нужно проверять обе стороны, но упростим

        net1 = calculate_network(ip1_addr, ip1_mask)
        net2 = calculate_network(ip2_addr, ip2_mask)

        return net1 == net2

    def _is_ip_in_network(self, ip_with_mask: str, network: str, netmask: str) -> bool:
        """Проверяет, принадлежит ли IP указанной сети."""
        if not ip_with_mask or not network:
            return False

        ip = ip_with_mask.split('/')[0]

        from utils.network_utils import is_ip_in_network
        return is_ip_in_network(ip, network, netmask)

    def _set_connection(self, src_id: str, dst_id: str, status: ConnectivityStatus,
                        path_nodes: List[str] = None, reason: str = ""):
        """Устанавливает соединение в матрице."""
        key = (src_id, dst_id)
        if key in self.matrix:
            # Не перезаписываем более высокий приоритет
            current = self.matrix[key].status
            priority = {ConnectivityStatus.DIRECT: 4, ConnectivityStatus.VPN: 3,
                        ConnectivityStatus.ROUTED: 2, ConnectivityStatus.BLOCKED: 1,
                        ConnectivityStatus.NONE: 0}

            if priority.get(status, 0) > priority.get(current, 0):
                self.matrix[key] = ConnectionPath(
                    source_id=src_id,
                    target_id=dst_id,
                    status=status,
                    path_nodes=path_nodes or [src_id, dst_id],
                    reason=reason
                )

    def can_communicate(self, node1_id: str, node2_id: str) -> Tuple[bool, ConnectivityStatus, str]:
        """Проверяет, могут ли два узла взаимодействовать."""
        key = (node1_id, node2_id)
        if key in self.matrix:
            conn = self.matrix[key]
            return (conn.status != ConnectivityStatus.NONE and conn.status != ConnectivityStatus.BLOCKED,
                    conn.status, conn.reason)

        # Проверяем обратное направление
        key_rev = (node2_id, node1_id)
        if key_rev in self.matrix:
            conn = self.matrix[key_rev]
            return (conn.status != ConnectivityStatus.NONE and conn.status != ConnectivityStatus.BLOCKED,
                    conn.status, conn.reason)

        return False, ConnectivityStatus.NONE, ""

    def get_reachable_nodes(self, node_id: str) -> List[str]:
        """Возвращает список узлов, достижимых из данного."""
        reachable = []
        for (src, dst), conn in self.matrix.items():
            if src == node_id and conn.status not in [ConnectivityStatus.NONE, ConnectivityStatus.BLOCKED]:
                reachable.append(dst)
        return reachable

    def get_connectivity_report(self) -> str:
        """Возвращает текстовый отчёт о связности."""
        report = []
        report.append("=" * 60)
        report.append("ОТЧЁТ О СЕТЕВОЙ СВЯЗНОСТИ")
        report.append("=" * 60)

        nodes_dict = {n.id: n.name for n in self.board.nodes}

        for (src, dst), conn in self.matrix.items():
            if conn.status != ConnectivityStatus.NONE:
                src_name = nodes_dict.get(src, src)
                dst_name = nodes_dict.get(dst, dst)

                status_text = {
                    ConnectivityStatus.DIRECT: "✅ ПРЯМОЕ",
                    ConnectivityStatus.ROUTED: "🔄 МАРШРУТ",
                    ConnectivityStatus.VPN: "🔒 VPN",
                    ConnectivityStatus.BLOCKED: "⛔ ЗАБЛОКИРОВАНО"
                }.get(conn.status, "❓ НЕТ")

                report.append(f"{src_name} -> {dst_name}: {status_text}")
                if conn.reason:
                    report.append(f"   Причина: {conn.reason}")

        report.append("=" * 60)
        return "\n".join(report)

    def to_dict(self) -> Dict:
        """Сериализует матрицу в словарь."""
        result = {}
        for (src, dst), conn in self.matrix.items():
            result[f"{src}|{dst}"] = {
                "status": conn.status.value,
                "path_nodes": conn.path_nodes,
                "reason": conn.reason
            }
        return result