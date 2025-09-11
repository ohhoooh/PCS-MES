import tkinter as tk
from tkinter import ttk, messagebox, scrolledtext
import socket
import time
import threading
from datetime import datetime
from config import *
from serial_comm import SerialCommunicator
from mes_client import MESClient


class MESQuerySystem:
    """MES查询系统主界面"""

    def __init__(self, root):
        self.root = root
        self.serial_comm = SerialCommunicator()
        self.mes_client = MESClient(self.serial_comm)

        # 变量初始化
        self.com_var = tk.StringVar()
        self.baud_var = tk.StringVar(value=DEFAULT_BAUDRATE)
        self.data_bits_var = tk.StringVar(value=DEFAULT_DATA_BITS)
        self.stop_bits_var = tk.StringVar(value=DEFAULT_STOP_BITS)
        self.parity_var = tk.StringVar(value=DEFAULT_PARITY)
        self.sn_var = tk.StringVar()
        self.query_result_var = tk.StringVar(value="未查询")
        self.intranet_status_var = tk.StringVar(value="未连接")
        self.is_connected = False

        # 初始化界面
        self.init_ui()

        # 启动后台检测线程
        self.start_detection_thread()
        self.update_port_list()

    def init_ui(self):
        """初始化用户界面"""
        self.root.title(WINDOW_TITLE)
        self.root.geometry(WINDOW_SIZE)
        self.root.minsize(*WINDOW_MIN_SIZE.split('x'))

        # 配置网格权重
        self.root.grid_rowconfigure(3, weight=1)
        self.root.grid_columnconfigure(0, weight=1)

        # 1. 串口配置区
        self.create_serial_frame()

        # 2. 网络状态区
        self.create_network_frame()

        # 3. 操作区
        self.create_operation_frame()

        # 4. 详细信息区
        self.create_details_frame()

        # 5. 日志显示区
        self.create_log_frame()

        # 初始化日志
        self.add_log("系统启动完成，等待串口连接...")

    def create_serial_frame(self):
        """创建串口配置区域"""
        frame_serial = ttk.LabelFrame(self.root, text="串口配置")
        frame_serial.grid(row=0, column=0, padx=10, pady=5, sticky="we")

        # 串口号选择
        ttk.Label(frame_serial, text="串口号：").grid(row=0, column=0, padx=5, pady=5)
        self.com_combobox = ttk.Combobox(frame_serial, textvariable=self.com_var, width=10)
        self.com_combobox.grid(row=0, column=1, padx=5, pady=5)

        # 波特率选择
        ttk.Label(frame_serial, text="波特率：").grid(row=0, column=2, padx=5, pady=5)
        ttk.OptionMenu(frame_serial, self.baud_var, "9600", "1200", "2400", "4800", "9600", "115200").grid(row=0,
                                                                                                           column=3,
                                                                                                           padx=5,
                                                                                                           pady=5)

        # 数据位选择
        ttk.Label(frame_serial, text="数据位：").grid(row=0, column=4, padx=5, pady=5)
        ttk.OptionMenu(frame_serial, self.data_bits_var, "8", "5", "6", "7", "8").grid(row=0, column=5, padx=5, pady=5)

        # 停止位选择
        ttk.Label(frame_serial, text="停止位：").grid(row=0, column=6, padx=5, pady=5)
        ttk.OptionMenu(frame_serial, self.stop_bits_var, "1", "1", "1.5", "2").grid(row=0, column=7, padx=5, pady=5)

        # 校验位选择
        ttk.Label(frame_serial, text="校验位：").grid(row=0, column=8, padx=5, pady=5)
        ttk.OptionMenu(frame_serial, self.parity_var, "无校验", "无校验", "奇校验", "偶校验").grid(row=0, column=9,
                                                                                                   padx=5, pady=5)

        # 串口控制按钮
        self.open_btn = ttk.Button(frame_serial, text="打开串口", command=self.open_serial)
        self.open_btn.grid(row=0, column=10, padx=5, pady=5)
        self.close_btn = ttk.Button(frame_serial, text="关闭串口", state=tk.DISABLED, command=self.close_serial)
        self.close_btn.grid(row=0, column=11, padx=5, pady=5)

    def create_network_frame(self):
        """创建网络状态区域"""
        frame_network = ttk.LabelFrame(self.root, text="网络状态")
        frame_network.grid(row=1, column=0, padx=10, pady=5, sticky="we")

        # 内网连接状态
        ttk.Label(frame_network, text="服务器状态：").grid(row=0, column=0, padx=5, pady=5)
        ttk.Label(frame_network, textvariable=self.intranet_status_var, foreground="red").grid(row=0, column=1, padx=5,
                                                                                               pady=5)

    def create_operation_frame(self):
        """创建操作区域"""
        frame_operation = ttk.LabelFrame(self.root, text="SN操作")
        frame_operation.grid(row=2, column=0, padx=10, pady=5, sticky="we")

        # SN码输入
        ttk.Label(frame_operation, text="SN码：").grid(row=0, column=0, padx=5, pady=5)
        sn_entry = ttk.Entry(frame_operation, textvariable=self.sn_var, width=25)
        sn_entry.grid(row=0, column=1, padx=5, pady=5)
        sn_entry.bind('<Return>', lambda event: self.query_mes_record())  # 回车查询

        # 查询按钮
        self.query_btn = ttk.Button(frame_operation, text="查询MES老化记录", command=self.query_mes_record,
                                    state=tk.DISABLED)
        self.query_btn.grid(row=0, column=2, padx=5, pady=5)

        # 检号过站按钮
        self.pass_btn = ttk.Button(frame_operation, text="检号过站", command=self.perform_check_pass, state=tk.DISABLED)
        self.pass_btn.grid(row=0, column=3, padx=5, pady=5)

        # 查询结果
        ttk.Label(frame_operation, text="查询结果：").grid(row=0, column=4, padx=5, pady=5)
        ttk.Label(frame_operation, textvariable=self.query_result_var, font=("Arial", 10, "bold")).grid(row=0, column=5,
                                                                                                        padx=5, pady=5)

    def create_details_frame(self):
        """创建详细信息区域"""
        frame_details = ttk.LabelFrame(self.root, text="检测记录详情")
        frame_details.grid(row=3, column=0, padx=10, pady=5, sticky="nsew")

        self.details_text = scrolledtext.ScrolledText(frame_details, wrap=tk.WORD, font=("SimHei", 10), height=8)
        self.details_text.grid(row=0, column=0, sticky="nsew")
        self.details_text.config(state=tk.DISABLED)

        frame_details.grid_rowconfigure(0, weight=1)
        frame_details.grid_columnconfigure(0, weight=1)

    def create_log_frame(self):
        """创建日志显示区域"""
        frame_log = ttk.LabelFrame(self.root, text="系统日志")
        frame_log.grid(row=4, column=0, padx=10, pady=5, sticky="nsew")

        self.log_text = scrolledtext.ScrolledText(frame_log, wrap=tk.WORD, font=("SimHei", 9), height=8)
        self.log_text.grid(row=0, column=0, sticky="nsew")
        self.log_text.config(state=tk.DISABLED)

        frame_log.grid_rowconfigure(0, weight=1)
        frame_log.grid_columnconfigure(0, weight=1)

    def add_log(self, message):
        """添加日志信息"""
        self.log_text.config(state=tk.NORMAL)
        timestamp = datetime.now().strftime("%H:%M:%S")
        self.log_text.insert(tk.END, f"[{timestamp}] {message}\n")
        self.log_text.see(tk.END)  # 滚动到最后
        self.log_text.config(state=tk.DISABLED)

    def update_details(self, details):
        """更新详细信息"""
        self.details_text.config(state=tk.NORMAL)
        self.details_text.delete(1.0, tk.END)
        self.details_text.insert(tk.END, details)
        self.details_text.config(state=tk.DISABLED)

    def update_port_list(self):
        """更新串口列表"""
        try:
            port_list = self.serial_comm.get_available_ports()
            self.com_combobox['values'] = port_list
            if port_list and port_list[0] != "无可用串口" and not self.com_var.get():
                self.com_var.set(port_list[0])
                self.add_log(f"串口列表更新: {', '.join(port_list)}")
        except Exception as e:
            self.add_log(f"更新串口列表失败: {str(e)}")

        # 定时更新
        self.root.after(1000, self.update_port_list)

    def check_intranet_connection(self):
        """检查内网连接"""
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
                s.settimeout(2)
                result = s.connect_ex((INTRANET_TEST_IP, INTRANET_TEST_PORT))
                return result == 0
        except Exception as e:
            self.add_log(f"网络检测错误: {str(e)}")
            return False

    def start_detection_thread(self):
        """启动后台检测线程"""

        def detection_loop():
            while True:
                # 检测内网连接
                is_connected = self.check_intranet_connection()

                # 更新连接状态
                if is_connected != self.is_connected:
                    self.is_connected = is_connected
                    if is_connected:
                        self.intranet_status_var.set("已连接")
                        self.root.after(0, lambda: self.add_log("已连接到服务器"))
                    else:
                        self.intranet_status_var.set("未连接")
                        self.root.after(0, lambda: self.add_log("未连接到服务器"))

                time.sleep(3)  # 每3秒检测一次

        # 启动线程
        thread = threading.Thread(target=detection_loop, daemon=True)
        thread.start()

    def open_serial(self):
        """打开串口"""
        try:
            port = self.com_var.get()
            if not port or port == "无可用串口":
                messagebox.showwarning("警告", "请选择有效的串口号")
                return

            # 打开串口
            success = self.serial_comm.open_serial(
                port=port,
                baudrate=self.baud_var.get(),
                data_bits=self.data_bits_var.get(),
                stop_bits=self.stop_bits_var.get(),
                parity=self.parity_var.get()
            )

            if success:
                self.add_log(f"串口 {port} 已打开")
                self.open_btn.config(state=tk.DISABLED)
                self.close_btn.config(state=tk.NORMAL)
                self.query_btn.config(state=tk.NORMAL)
        except Exception as e:
            self.add_log(f"打开串口失败: {str(e)}")
            messagebox.showerror("错误", f"打开串口失败: {str(e)}")

    def close_serial(self):
        """关闭串口"""
        try:
            self.serial_comm.close_serial()
            self.add_log(f"串口 {self.com_var.get()} 已关闭")
            self.close_btn.config(state=tk.DISABLED)
            self.open_btn.config(state=tk.NORMAL)
            self.query_btn.config(state=tk.DISABLED)
            self.pass_btn.config(state=tk.DISABLED)
        except Exception as e:
            self.add_log(f"关闭串口失败: {str(e)}")
            messagebox.showerror("错误", f"关闭串口失败: {str(e)}")

    def query_mes_record(self):
        """查询MES记录"""
        sn = self.sn_var.get().strip()
        if not sn:
            messagebox.showwarning("警告", "请输入SN码")
            return

        if not self.is_connected:
            messagebox.showwarning("警告", "未连接到服务器，请检查网络")
            return

        self.add_log(f"开始查询SN: {sn} 的老化检测记录")
        self.query_btn.config(state=tk.DISABLED)
        self.query_result_var.set("查询中...")
        self.update_details("查询中，请稍候...")

        # 在新线程中执行查询
        def perform_query():
            try:
                result, details = self.mes_client.query_aging_record(sn)

                # 更新UI
                self.root.after(0, lambda: self.query_result_var.set(result))
                self.root.after(0, lambda: self.update_details(details))
                self.root.after(0, lambda: self.add_log(f"查询完成: {result}"))

                # 根据结果启用/禁用过站按钮
                if result == "检测合格":
                    self.root.after(0, lambda: self.pass_btn.config(state=tk.NORMAL))
                else:
                    self.root.after(0, lambda: self.pass_btn.config(state=tk.DISABLED))

            except Exception as e:
                error_msg = f"查询失败: {str(e)}"
                self.root.after(0, lambda: self.add_log(error_msg))
                self.root.after(0, lambda: self.query_result_var.set("查询失败"))
                self.root.after(0, lambda: self.update_details(error_msg))
                self.root.after(0, lambda: self.pass_btn.config(state=tk.DISABLED))
            finally:
                self.root.after(0, lambda: self.query_btn.config(state=tk.NORMAL))

        # 启动查询线程
        thread = threading.Thread(target=perform_query, daemon=True)
        thread.start()

    def perform_check_pass(self):
        """执行检号过站"""
        sn = self.sn_var.get().strip()
        if not sn:
            messagebox.showwarning("警告", "请输入SN码")
            return

        if not self.is_connected:
            messagebox.showwarning("警告", "未连接到服务器，请检查网络")
            return

        # 确认操作
        if not messagebox.askyesno("确认", f"确定要对SN: {sn} 执行检号过站吗？"):
            return

        self.add_log(f"开始对SN: {sn} 执行检号过站")
        self.pass_btn.config(state=tk.DISABLED)

        # 在新线程中执行过站操作
        def perform_pass():
            try:
                success, message = self.mes_client.perform_check_pass(sn)

                if success:
                    self.root.after(0, lambda: messagebox.showinfo("成功", message))
                    self.root.after(0, lambda: self.add_log(message))
                else:
                    self.root.after(0, lambda: messagebox.showerror("失败", message))
                    self.root.after(0, lambda: self.add_log(message))
                    self.root.after(0, lambda: self.pass_btn.config(state=tk.NORMAL))

            except Exception as e:
                error_msg = f"过站操作失败: {str(e)}"
                self.root.after(0, lambda: self.add_log(error_msg))
                self.root.after(0, lambda: messagebox.showerror("失败", error_msg))
                self.root.after(0, lambda: self.pass_btn.config(state=tk.NORMAL))

        # 启动过站线程
        thread = threading.Thread(target=perform_pass, daemon=True)
        thread.start()
