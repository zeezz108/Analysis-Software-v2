"""
Модуль диалогов управления виртуальными машинами

Содержит классы:
- VMManagementDialog: Главное окно управления ВМ
- VMCreationDialog: Диалог создания/редактирования ВМ
"""

import tkinter as tk
from tkinter import ttk, messagebox
import customtkinter as ctk
import threading
from typing import Optional, List, Dict, Any

from models.node import Node, VirtualMachine
from utils.theme import center_window
from database.cve_db import CVEDatabase
from utils.cache import DataCache
from utils.validators import validate_ip, validate_mac, validate_mask
from utils.generators import uid, generate_test_ip, generate_test_mac, generate_test_mask


class VMManagementDialog:
    """Главное окно для управления виртуальными машинами на сервере."""

    def __init__(self, parent, server_node: Node):
        self.parent = parent
        self.server_node = server_node
        self.dialog = ctk.CTkToplevel(parent)
        self.dialog.title(f"Управление ВМ на сервере: {server_node.name}")
        self.dialog.geometry("950x650")
        self.dialog.transient(parent)
        # grab_set убран

        self.create_widgets()
        self.center_window()
        self.refresh_vm_list()

    def center_window(self):
        self.dialog.update_idletasks()
        # Get the geometry size that was set
        geo = self.dialog.geometry()
        # Parse "WxH+X+Y" or "WxH"
        size_part = geo.split('+')[0]
        if 'x' in size_part:
            width = int(size_part.split('x')[0])
            height = int(size_part.split('x')[1])
        else:
            width = self.dialog.winfo_reqwidth()
            height = self.dialog.winfo_reqheight()
        center_window(self.dialog, width, height)

    def create_widgets(self):
        main_frame = ctk.CTkFrame(self.dialog, fg_color="transparent")
        main_frame.pack(fill=tk.BOTH, expand=True, padx=15, pady=15)

        # Верхняя панель с информацией
        info_frame = ctk.CTkFrame(main_frame, fg_color="transparent")
        info_frame.pack(fill=tk.X, pady=(0, 10))

        ctk.CTkLabel(
            info_frame, text=f"🔌 Физических портов: {self.server_node.physical_port_count}",
            font=("Segoe UI", 12)
        ).pack(side=tk.LEFT, padx=10, pady=5)

        ctk.CTkLabel(
            info_frame, text=f"🖥️ ВМ: {len(self.server_node.virtual_machines)}",
            font=("Segoe UI", 12)
        ).pack(side=tk.LEFT, padx=10, pady=5)

        # Панель кнопок
        btn_frame = ctk.CTkFrame(main_frame, fg_color="transparent")
        btn_frame.pack(fill=tk.X, pady=(0, 10))

        ctk.CTkButton(btn_frame, text="➕ Создать ВМ", command=self.create_vm, width=120, height=32).pack(side=tk.LEFT,
                                                                                                         padx=5)
        ctk.CTkButton(btn_frame, text="✏️ Редактировать", command=self.edit_vm, width=120, height=32).pack(side=tk.LEFT,
                                                                                                           padx=5)
        ctk.CTkButton(btn_frame, text="🗑️ Удалить", command=self.delete_vm, width=100, height=32,
                      fg_color="#F44336").pack(side=tk.LEFT, padx=5)

        # Таблица ВМ
        table_frame = ctk.CTkFrame(main_frame, fg_color="transparent")
        table_frame.pack(fill=tk.BOTH, expand=True)

        columns = ("Имя ВМ", "ОС", "Кол-во портов", "ПО")

        style = ttk.Style()
        if ctk.get_appearance_mode() == "Dark":
            style.theme_use("clam")
            style.configure("Treeview", background="#2b2b2b", foreground="white", fieldbackground="#2b2b2b")
            style.configure("Treeview.Heading", background="#3b3b3b", foreground="white")
        else:
            style.theme_use("clam")
            style.configure("Treeview", background="white", foreground="black", fieldbackground="white")
            style.configure("Treeview.Heading", background="#f0f0f0", foreground="black")

        vsb = ttk.Scrollbar(table_frame, orient="vertical")
        vsb.pack(side=tk.RIGHT, fill=tk.Y)

        self.tree = ttk.Treeview(table_frame, columns=columns, show="headings", yscrollcommand=vsb.set, height=20)
        vsb.config(command=self.tree.yview)

        col_widths = [200, 250, 100, 200]
        for col, width in zip(columns, col_widths):
            self.tree.heading(col, text=col)
            self.tree.column(col, width=width, anchor="w")

        self.tree.pack(fill=tk.BOTH, expand=True)
        self.tree.bind("<Double-Button-1>", lambda e: self.edit_vm())

        # Кнопка закрытия
        ctk.CTkButton(main_frame, text="Закрыть", command=self.dialog.destroy, width=100, height=35).pack(pady=(10, 0))

    def refresh_vm_list(self):
        """Обновляет список ВМ в таблице."""
        for item in self.tree.get_children():
            self.tree.delete(item)

        for vm_data in self.server_node.virtual_machines:
            vm = VirtualMachine.from_dict(vm_data)
            sw_count = len(vm.software)
            sw_text = f"{sw_count} прил." if sw_count > 0 else "—"
            self.tree.insert("", tk.END, values=(
                vm.name,
                vm.os[:40] + "..." if len(vm.os) > 40 else vm.os,
                len(vm.ports),
                sw_text
            ), iid=vm.vm_id)

    def get_selected_vm_id(self) -> Optional[str]:
        selection = self.tree.selection()
        return selection[0] if selection else None

    def get_selected_vm(self) -> Optional[VirtualMachine]:
        vm_id = self.get_selected_vm_id()
        if vm_id:
            for vm_data in self.server_node.virtual_machines:
                if vm_data.get("vm_id") == vm_id:
                    return VirtualMachine.from_dict(vm_data)
        return None

    def create_vm(self):
        dialog = VMCreationDialog(self.dialog, self.server_node)
        self.dialog.wait_window(dialog.dialog)
        if dialog.result:
            self.server_node.virtual_machines.append(dialog.result.to_dict())
            self.refresh_vm_list()

    def edit_vm(self):
        vm = self.get_selected_vm()
        if not vm:
            messagebox.showwarning("Предупреждение", "Выберите ВМ для редактирования!")
            return

        dialog = VMCreationDialog(self.dialog, self.server_node, vm)
        self.dialog.wait_window(dialog.dialog)
        if dialog.result:
            for i, vm_data in enumerate(self.server_node.virtual_machines):
                if vm_data.get("vm_id") == dialog.result.vm_id:
                    self.server_node.virtual_machines[i] = dialog.result.to_dict()
                    break
            self.refresh_vm_list()

    def delete_vm(self):
        vm = self.get_selected_vm()
        if not vm:
            messagebox.showwarning("Предупреждение", "Выберите ВМ для удаления!")
            return

        if messagebox.askyesno("Удаление ВМ", f"Удалить виртуальную машину '{vm.name}'?"):
            self.server_node.virtual_machines = [
                vm_data for vm_data in self.server_node.virtual_machines
                if vm_data.get("vm_id") != vm.vm_id
            ]
            self.refresh_vm_list()


class VMCreationDialog:
    """Окно для создания или редактирования виртуальной машины."""

    def __init__(self, parent, server_node: Node, vm_to_edit: Optional[VirtualMachine] = None):
        self.parent = parent
        self.server_node = server_node
        self.vm = vm_to_edit
        self.result = None
        self.port_vars = {}
        self.db = None
        self.cached_data = {}
        self.cache = DataCache()

        self.dialog = ctk.CTkToplevel(parent)
        self.dialog.title("Редактирование ВМ" if vm_to_edit else "Создание новой ВМ")
        self.dialog.geometry("850x750")
        self.dialog.transient(parent)
        # grab_set убран

        self.show_loading_screen()
        self.dialog.after(100, self.load_data_async)

    def center_window(self):
        self.dialog.update_idletasks()
        # Get the geometry size that was set
        geo = self.dialog.geometry()
        # Parse "WxH+X+Y" or "WxH"
        size_part = geo.split('+')[0]
        if 'x' in size_part:
            width = int(size_part.split('x')[0])
            height = int(size_part.split('x')[1])
        else:
            width = self.dialog.winfo_reqwidth()
            height = self.dialog.winfo_reqheight()
        center_window(self.dialog, width, height)

    def show_loading_screen(self):
        temp_frame = ctk.CTkFrame(self.dialog)
        frame_color = temp_frame.cget("fg_color")
        temp_frame.destroy()
        self.dialog.configure(fg_color=frame_color)

        self.loading_frame = ctk.CTkFrame(self.dialog, fg_color=frame_color)
        self.loading_frame.pack(fill=tk.BOTH, expand=True)

        content_frame = ctk.CTkFrame(self.loading_frame, fg_color="transparent")
        content_frame.pack(expand=True)

        ctk.CTkLabel(content_frame, text="Загрузка списков ОС и ПО...", font=("Segoe UI", 18, "bold")).pack(pady=(0, 20))

        self.animation_label = ctk.CTkLabel(content_frame, text="⏳", font=("Segoe UI", 48, "bold"), text_color="#2196F3")
        self.animation_label.pack(pady=20)

        self.status_label = ctk.CTkLabel(content_frame, text="Подключение к базе данных CVE...", font=("Segoe UI", 12),
                                         text_color="gray")
        self.status_label.pack(pady=(0, 20))

        self.progress = ctk.CTkProgressBar(content_frame, width=400)
        self.progress.pack(pady=10)
        self.progress.set(0)

        self.loading_active = True
        self.animate_loading(0)

    def animate_loading(self, idx):
        if self.loading_active:
            chars = ["⏳", "⌛", "⏳", "⌛"]
            colors = ["#2196F3", "#FF9800", "#4CAF50", "#F44336"]
            try:
                if hasattr(self, 'animation_label') and self.animation_label.winfo_exists():
                    self.animation_label.configure(text=chars[idx % len(chars)], text_color=colors[idx % len(colors)])
                    self.dialog.after(100, lambda: self.animate_loading(idx + 1))
            except (tk.TclError, AttributeError):
                pass

    def load_data_async(self):
        def load_thread():
            try:
                self.dialog.after(0, lambda: self.status_label.configure(text="Подключение к БД..."))
                self.db = CVEDatabase()

                self.dialog.after(0, lambda: self.progress.set(0.3))
                self.dialog.after(0, lambda: self.status_label.configure(text="Загрузка операционных систем..."))

                # Загружаем данные через кэш
                def load_server_os():
                    return self.db.get_server_operating_systems()

                def load_windows_server():
                    return self.db.get_windows_server_versions()

                def load_linux_server():
                    return self.db.get_linux_server_versions()

                def load_app_software():
                    return self.db.get_application_software()

                self.cached_data["server_os"] = self.cache.get("vm_server_os", load_server_os)

                self.dialog.after(0, lambda: self.progress.set(0.6))
                self.dialog.after(0, lambda: self.status_label.configure(text="Загрузка Windows Server..."))

                self.cached_data["windows_server"] = self.cache.get("vm_windows_server", load_windows_server)

                self.dialog.after(0, lambda: self.progress.set(0.8))
                self.dialog.after(0, lambda: self.status_label.configure(text="Загрузка Linux..."))

                self.cached_data["linux_server"] = self.cache.get("vm_linux_server", load_linux_server)
                self.cached_data["app_software"] = self.cache.get("vm_app_software", load_app_software)

                # Объединяем все ОС
                all_os = []
                all_os.extend(self.cached_data.get("server_os", []))
                all_os.extend(self.cached_data.get("windows_server", []))
                all_os.extend(self.cached_data.get("linux_server", []))

                seen = set()
                self.cached_data["all_os"] = []
                for item in all_os:
                    if item not in seen:
                        seen.add(item)
                        self.cached_data["all_os"].append(item)

                self.dialog.after(0, lambda: self.progress.set(1.0))
                self.dialog.after(0, self.finish_loading)

            except Exception as e:
                self.dialog.after(0, lambda: self.show_load_error(str(e)))

        thread = threading.Thread(target=load_thread, daemon=True)
        thread.start()

    def finish_loading(self):
        self.loading_active = False
        try:
            if hasattr(self, 'loading_frame') and self.loading_frame.winfo_exists():
                self.loading_frame.destroy()
        except:
            pass
        try:
            if self.dialog.winfo_exists():
                self.create_widgets()
        except Exception as e:
            print(f"Ошибка: {e}")

    def show_load_error(self, error_msg):
        self.loading_active = False
        messagebox.showerror("Ошибка загрузки", f"Не удалось загрузить данные:\n{error_msg}")
        try:
            if self.dialog.winfo_exists():
                self.dialog.destroy()
        except:
            pass

    def create_widgets(self):
        main_frame = ctk.CTkFrame(self.dialog)
        main_frame.pack(fill=tk.BOTH, expand=True, padx=15, pady=15)

        # Имя ВМ
        name_frame = ctk.CTkFrame(main_frame)
        name_frame.pack(fill=tk.X, pady=(0, 10))

        ctk.CTkLabel(name_frame, text="Имя виртуальной машины:", font=("Segoe UI", 13, "bold")).pack(anchor=tk.W, padx=5,
                                                                                                  pady=(5, 0))
        self.name_var = tk.StringVar(value=self.vm.name if self.vm else "")
        ctk.CTkEntry(name_frame, textvariable=self.name_var, placeholder_text="Например: Web Server 01",
                     height=35).pack(fill=tk.X, padx=5, pady=(0, 5))

        # Вкладки
        self.notebook = ctk.CTkTabview(main_frame)
        self.notebook.pack(fill=tk.BOTH, expand=True, pady=(0, 10))

        # Определяем тип виртуализации
        is_container = False
        if hasattr(self.server_node, 'properties') and 'virtualization_type' in self.server_node.properties:
            is_container = (self.server_node.properties['virtualization_type'] == "container")

        # Вкладка ОС (только для гипервизоров)
        if not is_container:
            self.notebook.add("Операционная система")
            os_frame = self.notebook.tab("Операционная система")
            self.create_os_selector(os_frame)

        # Вкладка ПО
        self.notebook.add("Прикладное ПО")
        app_frame = self.notebook.tab("Прикладное ПО")
        self.create_app_selector(app_frame)

        # Вкладка сети
        self.notebook.add("Сетевые интерфейсы")
        network_frame = self.notebook.tab("Сетевые интерфейсы")
        self.create_network_tab(network_frame)

        # Кнопки
        btn_frame = ctk.CTkFrame(main_frame, fg_color="transparent")
        btn_frame.pack(fill=tk.X, pady=(10, 0))

        ctk.CTkButton(btn_frame, text="💾 Сохранить ВМ", command=self.save_vm, fg_color="#4CAF50", width=120, height=38,
                      font=("Segoe UI", 13, "bold")).pack(side=tk.RIGHT, padx=5)
        ctk.CTkButton(btn_frame, text="✕ Отмена", command=self.dialog.destroy, fg_color="#CD3333", width=100,
                      height=38).pack(side=tk.RIGHT, padx=5)

        self.center_window()

    def create_os_selector(self, parent):
        """Создаёт селектор для выбора ОС."""
        frame = ctk.CTkFrame(parent)
        frame.pack(fill=tk.BOTH, expand=True, padx=10, pady=10)

        ctk.CTkLabel(frame, text="Выберите операционную систему:", font=("Segoe UI", 13, "bold")).pack(anchor=tk.W,
                                                                                                    pady=(0, 10))

        items = self.cached_data.get("all_os", [])
        if not items:
            items = ["Нет данных в БД"]

        self.os_var = tk.StringVar(value=self.vm.os if self.vm else "")

        # Поиск
        search_frame = ctk.CTkFrame(frame, fg_color="transparent")
        search_frame.pack(fill=tk.X, pady=(0, 10))

        search_var = tk.StringVar()
        ctk.CTkEntry(search_frame, textvariable=search_var, placeholder_text="🔍 Поиск ОС...", height=32).pack(
            side=tk.LEFT, fill=tk.X, expand=True)

        count_label = ctk.CTkLabel(search_frame, text=f"({len(items)})", font=("Segoe UI", 10), text_color="gray")
        count_label.pack(side=tk.RIGHT, padx=(5, 0))

        # Список
        list_frame = ctk.CTkFrame(frame)
        list_frame.pack(fill=tk.BOTH, expand=True)

        self.os_listbox = tk.Listbox(
            list_frame, bg="#2b2b2b" if ctk.get_appearance_mode() == "Dark" else "white",
            fg="white" if ctk.get_appearance_mode() == "Dark" else "black",
            font=("Segoe UI", 10), height=15, selectmode=tk.SINGLE
        )

        scrollbar = ctk.CTkScrollbar(list_frame, command=self.os_listbox.yview)
        scrollbar.pack(side=tk.RIGHT, fill=tk.Y)
        self.os_listbox.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
        self.os_listbox.configure(yscrollcommand=scrollbar.set)

        for item in items:
            self.os_listbox.insert(tk.END, item)

        if self.vm and self.vm.os:
            for i, item in enumerate(items):
                if item == self.vm.os:
                    self.os_listbox.selection_set(i)
                    self.os_listbox.see(i)
                    break

        def filter_list(*args):
            search_text = search_var.get().lower()
            self.os_listbox.delete(0, tk.END)
            if search_text:
                filtered = [item for item in items if search_text in item.lower()]
                for item in filtered:
                    self.os_listbox.insert(tk.END, item)
                count_label.configure(text=f"({len(filtered)}/{len(items)})", text_color="blue")
            else:
                for item in items:
                    self.os_listbox.insert(tk.END, item)
                count_label.configure(text=f"({len(items)})", text_color="gray")

        search_var.trace('w', filter_list)

        def on_select(event):
            selection = self.os_listbox.curselection()
            if selection:
                self.os_var.set(self.os_listbox.get(selection[0]))
                selected_label.configure(text=f"✓ {self.os_var.get()}", text_color="green")

        self.os_listbox.bind('<<ListboxSelect>>', on_select)

        selected_frame = ctk.CTkFrame(frame, fg_color="transparent")
        selected_frame.pack(fill=tk.X, pady=(10, 0))

        ctk.CTkLabel(selected_frame, text="Выбрано:", font=("Segoe UI", 11, "bold")).pack(side=tk.LEFT, padx=(0, 5))
        selected_label = ctk.CTkLabel(selected_frame, text=self.vm.os if self.vm and self.vm.os else "не выбрано",
                                      text_color="green" if self.vm and self.vm.os else "gray")
        selected_label.pack(side=tk.LEFT)

        if self.vm and self.vm.os:
            ctk.CTkButton(selected_frame, text="✕ Очистить", command=lambda: [self.os_var.set(""),
                                                                              selected_label.configure(
                                                                                  text="не выбрано", text_color="gray"),
                                                                              self.os_listbox.selection_clear(0,
                                                                                                              tk.END)],
                          width=80, height=28).pack(side=tk.RIGHT)

    def create_app_selector(self, parent):
        """Создаёт селектор для выбора прикладного ПО."""
        frame = ctk.CTkFrame(parent)
        frame.pack(fill=tk.BOTH, expand=True, padx=10, pady=10)

        ctk.CTkLabel(frame, text="Выберите прикладное ПО (можно несколько):", font=("Segoe UI", 13, "bold")).pack(
            anchor=tk.W, pady=(0, 10))

        items = self.cached_data.get("app_software", [])
        if not items:
            items = ["Нет данных в БД"]

        self.app_var = tk.StringVar()
        if self.vm and self.vm.software:
            self.app_var.set("|".join(self.vm.software))

        # Левая колонка
        left_frame = ctk.CTkFrame(frame)
        left_frame.pack(side=tk.LEFT, fill=tk.BOTH, expand=True, padx=(0, 5))

        ctk.CTkLabel(left_frame, text="Доступные приложения:", font=("Segoe UI", 12, "bold")).pack(anchor=tk.W,
                                                                                                pady=(0, 5))

        search_frame = ctk.CTkFrame(left_frame, fg_color="transparent")
        search_frame.pack(fill=tk.X, pady=(0, 5))

        search_var = tk.StringVar()
        ctk.CTkEntry(search_frame, textvariable=search_var, placeholder_text="🔍 Поиск...", height=32).pack(side=tk.LEFT,
                                                                                                           fill=tk.X,
                                                                                                           expand=True)

        count_label = ctk.CTkLabel(search_frame, text=f"({len(items)})", font=("Segoe UI", 10), text_color="gray")
        count_label.pack(side=tk.RIGHT, padx=(5, 0))

        list_frame = ctk.CTkFrame(left_frame)
        list_frame.pack(fill=tk.BOTH, expand=True)

        self.app_listbox = tk.Listbox(
            list_frame, bg="#2b2b2b" if ctk.get_appearance_mode() == "Dark" else "white",
            fg="white" if ctk.get_appearance_mode() == "Dark" else "black",
            font=("Segoe UI", 10), height=15, selectmode=tk.MULTIPLE
        )

        scrollbar = ctk.CTkScrollbar(list_frame, command=self.app_listbox.yview)
        scrollbar.pack(side=tk.RIGHT, fill=tk.Y)
        self.app_listbox.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
        self.app_listbox.configure(yscrollcommand=scrollbar.set)

        for item in items:
            self.app_listbox.insert(tk.END, item)

        # Правая колонка
        right_frame = ctk.CTkFrame(frame)
        right_frame.pack(side=tk.RIGHT, fill=tk.BOTH, expand=True, padx=(5, 0))

        ctk.CTkLabel(right_frame, text="Выбранные приложения:", font=("Segoe UI", 12, "bold")).pack(anchor=tk.W,
                                                                                                 pady=(0, 5))

        self.selected_listbox = tk.Listbox(
            right_frame, bg="#2b2b2b" if ctk.get_appearance_mode() == "Dark" else "white",
            fg="white" if ctk.get_appearance_mode() == "Dark" else "black",
            font=("Segoe UI", 10), height=15
        )

        scrollbar2 = ctk.CTkScrollbar(right_frame, command=self.selected_listbox.yview)
        scrollbar2.pack(side=tk.RIGHT, fill=tk.Y)
        self.selected_listbox.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
        self.selected_listbox.configure(yscrollcommand=scrollbar2.set)

        selected_items = []
        if self.vm and self.vm.software:
            selected_items = self.vm.software.copy()
            for item in selected_items:
                self.selected_listbox.insert(tk.END, item)

        def filter_list(*args):
            search_text = search_var.get().lower()
            self.app_listbox.delete(0, tk.END)
            if search_text:
                filtered = [item for item in items if search_text in item.lower()]
                for item in filtered:
                    self.app_listbox.insert(tk.END, item)
                count_label.configure(text=f"({len(filtered)}/{len(items)})", text_color="blue")
            else:
                for item in items:
                    self.app_listbox.insert(tk.END, item)
                count_label.configure(text=f"({len(items)})", text_color="gray")

        search_var.trace('w', filter_list)

        def add_selected():
            selection = self.app_listbox.curselection()
            added = False
            for idx in selection:
                item = self.app_listbox.get(idx)
                if item not in selected_items:
                    selected_items.append(item)
                    self.selected_listbox.insert(tk.END, item)
                    added = True
            if added:
                self.app_var.set("|".join(selected_items))
                status_label.configure(text=f"✅ Выбрано: {len(selected_items)}", text_color="green")

        def remove_selected():
            selection = self.selected_listbox.curselection()
            if not selection:
                return
            for idx in sorted(selection, reverse=True):
                item = self.selected_listbox.get(idx)
                if item in selected_items:
                    selected_items.remove(item)
                self.selected_listbox.delete(idx)
            self.app_var.set("|".join(selected_items))
            if selected_items:
                status_label.configure(text=f"✅ Выбрано: {len(selected_items)}", text_color="green")
            else:
                status_label.configure(text="Выбрано: 0", text_color="gray")

        btn_frame = ctk.CTkFrame(frame, fg_color="transparent")
        btn_frame.pack(fill=tk.X, pady=(10, 0))

        ctk.CTkButton(btn_frame, text="▶ Добавить", command=add_selected, width=100, height=32).pack(side=tk.LEFT,
                                                                                                     padx=5)
        ctk.CTkButton(btn_frame, text="◀ Удалить", command=remove_selected, width=100, height=32,
                      fg_color="#F44336").pack(side=tk.LEFT, padx=5)

        status_frame = ctk.CTkFrame(frame, fg_color="transparent")
        status_frame.pack(fill=tk.X, pady=(5, 0))

        status_label = ctk.CTkLabel(status_frame,
                                    text=f"✅ Выбрано: {len(selected_items)}" if selected_items else "Выбрано: 0",
                                    text_color="green" if selected_items else "gray")
        status_label.pack(side=tk.LEFT)

    def create_network_tab(self, parent):
        """Создаёт вкладку с сетевыми интерфейсами (промт 8 №10)."""
        section_bg = "#F5F5F5" if ctk.get_appearance_mode() == "Light" else "#2B2B2B"
        border_clr = "#CCCCCC" if ctk.get_appearance_mode() == "Light" else "#3D3D3D"

        frame = ctk.CTkFrame(parent, fg_color=section_bg,
                              border_width=1, border_color=border_clr, corner_radius=8)
        frame.pack(fill=tk.BOTH, expand=True, padx=10, pady=10)

        title_frame = ctk.CTkFrame(frame, fg_color="transparent")
        title_frame.pack(fill=tk.X, pady=(0, 10))

        ctk.CTkLabel(title_frame, text="🌐 Сетевые интерфейсы", font=("Segoe UI", 14, "bold")).pack(side=tk.LEFT)
        ctk.CTkButton(title_frame, text="➕ Добавить интерфейс", command=self.add_vm_port, width=150, height=32).pack(
            side=tk.RIGHT)
        ctk.CTkButton(title_frame, text="🧪 Тестовые данные", command=self.fill_test_data, width=130, height=32).pack(
            side=tk.RIGHT, padx=5)

        # Контейнер с прокруткой
        ports_container = ctk.CTkFrame(frame, fg_color="transparent")
        ports_container.pack(fill=tk.BOTH, expand=True, pady=5)

        canvas = tk.Canvas(ports_container, highlightthickness=0, bg=self._get_canvas_bg_color())
        scrollbar = ttk.Scrollbar(ports_container, orient="vertical", command=canvas.yview)
        scrollable_frame = ctk.CTkFrame(canvas, fg_color=section_bg)

        scrollable_frame.bind("<Configure>", lambda e: canvas.configure(scrollregion=canvas.bbox("all")))
        canvas.create_window((0, 0), window=scrollable_frame, anchor="nw")
        canvas.configure(yscrollcommand=scrollbar.set)

        self.ports_list_frame = scrollable_frame
        self.display_ports()

        canvas.pack(side="left", fill="both", expand=True)
        scrollbar.pack(side="right", fill="y")

        info_frame = ctk.CTkFrame(frame, fg_color="transparent")
        info_frame.pack(fill=tk.X, pady=(5, 0))
        ctk.CTkLabel(info_frame, text="📌 MAC-адрес обязателен для каждого интерфейса", font=("Segoe UI", 10),
                     text_color="gray").pack(side=tk.LEFT)

    def _get_canvas_bg_color(self):
        return "#2b2b2b" if ctk.get_appearance_mode() == "Dark" else "#ffffff"

    def display_ports(self):
        for widget in self.ports_list_frame.winfo_children():
            widget.destroy()
        self.port_vars = {}

        ports = self.vm.ports.copy() if self.vm and self.vm.ports else []
        if not ports:
            ports = [self.create_default_vm_port(1)]

        for port in ports:
            self.create_port_widget(port)

    def create_default_vm_port(self, number: int) -> Dict:
        return {
            "port_id": f"vm_eth_{number}",
            "name": f"eth{number}",
            "mac_address": "",
            "ip_address": "",
            "subnet_mask": ""
        }

    def create_port_widget(self, port: Dict):
        frame = ctk.CTkFrame(self.ports_list_frame, fg_color="transparent")
        frame.pack(fill=tk.X, pady=2, padx=2)

        ctk.CTkLabel(frame, text=f"{port['name']}:", width=50, anchor=tk.W).pack(side=tk.LEFT, padx=2)

        mac_var = tk.StringVar(value=port.get("mac_address", ""))
        ip_var = tk.StringVar(value=port.get("ip_address", ""))
        mask_var = tk.StringVar(value=port.get("subnet_mask", ""))

        self.port_vars[port["port_id"]] = {"name": port["name"], "mac": mac_var, "ip": ip_var, "mask": mask_var}

        ctk.CTkEntry(frame, textvariable=mac_var, width=130, placeholder_text="MAC-адрес").pack(side=tk.LEFT, padx=2)
        ctk.CTkEntry(frame, textvariable=ip_var, width=120, placeholder_text="IP-адрес").pack(side=tk.LEFT, padx=2)
        ctk.CTkLabel(frame, text="/", font=("Segoe UI", 12, "bold")).pack(side=tk.LEFT)
        ctk.CTkEntry(frame, textvariable=mask_var, width=60, placeholder_text="маска").pack(side=tk.LEFT, padx=2)

        ctk.CTkButton(frame, text="✕", width=30, command=lambda pid=port["port_id"]: self.remove_vm_port(pid)).pack(
            side=tk.RIGHT, padx=5)

    def add_vm_port(self):
        existing_numbers = []
        for vars_dict in self.port_vars.values():
            name = vars_dict["name"]
            if name.startswith("eth"):
                try:
                    num = int(name[3:])
                    existing_numbers.append(num)
                except:
                    pass
        next_num = max(existing_numbers) + 1 if existing_numbers else 1

        new_port = {
            "port_id": f"vm_eth_{next_num}",
            "name": f"eth{next_num}",
            "mac_address": "",
            "ip_address": "",
            "subnet_mask": ""
        }
        self.create_port_widget(new_port)

    def remove_vm_port(self, port_id: str):
        if port_id in self.port_vars:
            del self.port_vars[port_id]
            self.display_ports()

    def fill_test_data(self):
        for vars_dict in self.port_vars.values():
            vars_dict["mac"].set(generate_test_mac())
            vars_dict["ip"].set(generate_test_ip())
            vars_dict["mask"].set(generate_test_mask())

    def validate_ports(self, ports: List[Dict]) -> bool:
        for port in ports:
            if not port["mac_address"]:
                messagebox.showerror("Ошибка", f"Для порта {port['name']} необходимо указать MAC-адрес!")
                return False
            if not validate_mac(port["mac_address"]):
                messagebox.showerror("Ошибка", f"Неверный MAC для {port['name']}!\nФормат: 00:11:22:33:44:55")
                return False
            if port["ip_address"] and not validate_ip(port["ip_address"]):
                messagebox.showerror("Ошибка", f"Неверный IP для {port['name']}!\nФормат: 192.168.1.1")
                return False
            if port["subnet_mask"] and not validate_mask(port["subnet_mask"]):
                messagebox.showerror("Ошибка", f"Неверная маска для {port['name']}!\nФормат: число от 0 до 32")
                return False
            if port["ip_address"] and not port["subnet_mask"]:
                messagebox.showerror("Ошибка", f"Для порта {port['name']} указан IP, но нет маски!")
                return False
        return True

    def save_vm(self):
        name = self.name_var.get().strip()
        if not name:
            messagebox.showerror("Ошибка", "Введите имя виртуальной машины!")
            return

        is_container = False
        if hasattr(self.server_node, 'properties') and 'virtualization_type' in self.server_node.properties:
            is_container = (self.server_node.properties['virtualization_type'] == "container")

        os_name = ""
        if not is_container and hasattr(self, 'os_var'):
            os_name = self.os_var.get().strip()

        software_list = []
        if hasattr(self, 'app_var'):
            app_value = self.app_var.get().strip()
            if app_value and '|' in app_value:
                software_list = [s.strip() for s in app_value.split('|') if s.strip()]
            elif app_value:
                software_list = [app_value]

        ports = []
        for port_id, vars_dict in self.port_vars.items():
            port = {
                "port_id": port_id,
                "name": vars_dict["name"],
                "mac_address": vars_dict["mac"].get().strip(),
                "ip_address": vars_dict["ip"].get().strip(),
                "subnet_mask": vars_dict["mask"].get().strip()
            }
            ports.append(port)

        if not self.validate_ports(ports):
            return

        if self.vm:
            vm = self.vm
            vm.name = name
            vm.os = os_name
            vm.software = software_list
            vm.ports = ports
        else:
            vm = VirtualMachine(
                vm_id=uid(),
                name=name,
                os=os_name,
                software=software_list,
                ports=ports
            )

        self.result = vm
        self.dialog.destroy()