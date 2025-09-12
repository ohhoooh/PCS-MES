import tkinter as tk
from tkinter import ttk, messagebox
import threading
import time
from config import *


class MESQuerySystem:
    """MES查询系统主界面"""

    def __init__(self, root, serial_comm, mes_client):
        self.root = root
        self.root.title("MES-PCS 通信系统")
        self.root.geometry("1000x600")
        self.root.grid_columnconfigure(0, weight=1)
        self.root.grid_rowconfigure(3, weight=1)

        # 实例引用
        self.serial_comm = serial_comm
        self.mes_client = mes_client

        # 状态变量
        self.is_connected = False
        self.sn_var = tk.StringVar()
        self.slave_addr_var = tk.StringVar(value="1")
        self.query_result_var = tk.StringVar()
        self.log_text = None
        self.details_text = None

        # 初始化界面
        self.init_ui()

        # 启动网络检测线程
        self.start_detection_thread()

    def init_ui(self):
        """初始化界面组件"""
        self.create_serial_frame()
        self.create_network_frame()
        self.create_operation_frame()  # 整合后的操作区域
        self.create_log_frame()
        self.create_details_frame()

    def create_serial_frame(self):
        """创建串口配置区域"""
        frame_serial = ttk.LabelFrame(self.root, text="串口配置")
        frame_serial.grid(row=0, column=0, padx=10, pady=5, sticky="we")

        # 串口号选择
        ttk.Label(frame_serial, text="串口号：").grid(row=0, column=0, padx=5, pady=5)
        self.com_var = tk.StringVar()
        self.com_combobox = ttk.Combobox(frame_serial, textvariable=self.com_var, width=10)
        self.com_combobox['values'] = self.serial_comm.get_available_ports()
        self.com_combobox.grid(row=0, column=1, padx=5, pady=5)

        # 波特率选择
        ttk.Label(frame_serial, text="波特率：").grid(row=0, column=2, padx=5, pady=5)
        self.baud_var = tk.StringVar(value=DEFAULT_BAUDRATE)
        self.baud_combobox = ttk.Combobox(frame_serial, textvariable=self.baud_var, width=10)
        self.baud_combobox['values'] = ["9600", "19200", "38400", "57600", "115200"]
        self.baud_combobox.grid(row=0, column=3, padx=5, pady=5)

        # 串口控制按钮
        self.open_btn = ttk.Button(frame_serial, text="打开串口", command=self.open_serial)
        self.open_btn.grid(row=0, column=4, padx=5, pady=5)

        self.close_btn = ttk.Button(frame_serial, text="关闭串口", command=self.close_serial, state=tk.DISABLED)
        self.close_btn.grid(row=0, column=5, padx=5, pady=5)

        # 刷新串口按钮
        self.refresh_btn = ttk.Button(frame_serial, text="刷新串口", command=self.refresh_ports)
        self.refresh_btn.grid(row=0, column=6, padx=5, pady=5)

    def create_network_frame(self):
        """创建网络状态区域"""
        frame_network = ttk.LabelFrame(self.root, text="网络状态")
        frame_network.grid(row=1, column=0, padx=10, pady=5, sticky="we")

        self.network_status_var = tk.StringVar(value="未检测")
        ttk.Label(frame_network, text="服务器连接：").grid(row=0, column=0, padx=5, pady=5)
        ttk.Label(frame_network, textvariable=self.network_status_var, font=("Arial", 10, "bold")).grid(row=0, column=1,
                                                                                                        padx=5, pady=5)

        ttk.Label(frame_network, text=f"服务器地址：{INTRANET_TEST_IP}:{INTRANET_TEST_PORT}").grid(row=0, column=2,
                                                                                                  padx=5, pady=5)

    def create_operation_frame(self):
        """创建整合后的操作区域（共用SN码输入）"""
        frame_operation = ttk.LabelFrame(self.root, text="SN码操作区")
        frame_operation.grid(row=2, column=0, padx=10, pady=5, sticky="we")
        frame_operation.grid_columnconfigure(5, weight=1)  # 让结果区域自适应

        # SN码输入（共用）
        ttk.Label(frame_operation, text="SN码：").grid(row=0, column=0, padx=5, pady=5)
        self.sn_entry = ttk.Entry(frame_operation, textvariable=self.sn_var, width=25)
        self.sn_entry.grid(row=0, column=1, padx=5, pady=5)
        self.sn_entry.bind('<Return>', lambda event: self.perform_check_pass())

        # 从机地址输入
        ttk.Label(frame_operation, text="从机地址（1-31）：").grid(row=0, column=2, padx=5, pady=5)
        self.slave_addr_entry = ttk.Entry(frame_operation, textvariable=self.slave_addr_var, width=10)
        self.slave_addr_entry.grid(row=0, column=3, padx=5, pady=5)

        # 操作按钮
        self.pass_btn = ttk.Button(frame_operation, text="检号过站", command=self.perform_check_pass, state=tk.DISABLED)
        self.pass_btn.grid(row=0, column=4, padx=5, pady=5)

        self.write_btn = ttk.Button(frame_operation, text="发送写码指令", command=self.perform_write_sn,
                                    state=tk.DISABLED)
        self.write_btn.grid(row=0, column=5, padx=5, pady=5)

        self.version_btn = ttk.Button(frame_operation, text="查询软件版本", command=self.perform_version_query,
                                      state=tk.DISABLED)
        self.version_btn.grid(row=0, column=6, padx=5, pady=5)

        # 操作结果显示
        ttk.Label(frame_operation, text="操作结果：").grid(row=0, column=7, padx=5, pady=5)
        ttk.Label(frame_operation, textvariable=self.query_result_var, font=("Arial", 10, "bold")).grid(row=0, column=8,
                                                                                                        padx=5, pady=5,
                                                                                                        sticky="w")

    def create_log_frame(self):
        """创建日志显示区域"""
        frame_log = ttk.LabelFrame(self.root, text="系统日志")
        frame_log.grid(row=3, column=0, padx=10, pady=5, sticky="nsew")
        frame_log.grid_rowconfigure(0, weight=1)
        frame_log.grid_columnconfigure(0, weight=1)

        # 日志文本框
        self.log_text = tk.Text(frame_log, height=10, wrap=tk.WORD)
        self.log_text.grid(row=0, column=0, sticky="nsew")
        self.log_text.config(state=tk.DISABLED)

        # 滚动条
        scrollbar = ttk.Scrollbar(frame_log, command=self.log_text.yview)
        scrollbar.grid(row=0, column=1, sticky="ns")
        self.log_text['yscrollcommand'] = scrollbar.set

    def create_details_frame(self):
        """创建详情显示区域"""
        frame_details = ttk.LabelFrame(self.root, text="检测记录详情")
        frame_details.grid(row=4, column=0, padx=10, pady=5, sticky="nsew")
        frame_details.grid_rowconfigure(0, weight=1)
        frame_details.grid_columnconfigure(0, weight=1)

        # 详情文本框
        self.details_text = tk.Text(frame_details, height=6, wrap=tk.WORD)
        self.details_text.grid(row=0, column=0, sticky="nsew")
        self.details_text.config(state=tk.DISABLED)

        # 滚动条
        scrollbar = ttk.Scrollbar(frame_details, command=self.details_text.yview)
        scrollbar.grid(row=0, column=1, sticky="ns")
        self.details_text['yscrollcommand'] = scrollbar.set

    def refresh_ports(self):
        """刷新可用串口列表"""
        ports = self.serial_comm.get_available_ports()
        self.com_combobox['values'] = ports
        if ports:
            self.com_var.set(ports[0])
        self.add_log("已刷新串口列表")

    def open_serial(self):
        """打开串口"""
        try:
            port = self.com_var.get()
            baudrate = int(self.baud_var.get())

            if not port:
                messagebox.showwarning("警告", "请选择串口号")
                return

            success, msg = self.serial_comm.open_serial(port, baudrate)
            self.add_log(msg)

            if success:
                self.open_btn.config(state=tk.DISABLED)
                self.close_btn.config(state=tk.NORMAL)
                self.pass_btn.config(state=tk.NORMAL)
                self.write_btn.config(state=tk.NORMAL)
                self.version_btn.config(state=tk.NORMAL)

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
            self.pass_btn.config(state=tk.DISABLED)
            self.write_btn.config(state=tk.DISABLED)
            self.version_btn.config(state=tk.DISABLED)

        except Exception as e:
            self.add_log(f"关闭串口失败: {str(e)}")

    def add_log(self, message):
        """添加日志信息"""
        if not self.log_text:
            return

        timestamp = time.strftime("%H:%M:%S")
        log_entry = f"[{timestamp}] {message}\n"

        self.log_text.config(state=tk.NORMAL)
        self.log_text.insert(tk.END, log_entry)
        self.log_text.see(tk.END)  # 滚动到最新条目
        self.log_text.config(state=tk.DISABLED)

    def update_details(self, content):
        """更新详情区域内容"""
        if not self.details_text:
            return

        self.details_text.config(state=tk.NORMAL)
        self.details_text.delete(1.0, tk.END)
        self.details_text.insert(tk.END, content)
        self.details_text.config(state=tk.DISABLED)

    def start_detection_thread(self):
        """启动网络检测线程"""

        def _detection_loop():
            while True:
                # 模拟网络检测（实际项目中应替换为真实检测逻辑）
                time.sleep(3)
                self.is_connected = True  # 这里简化为始终连接成功
                status = "正常" if self.is_connected else "断开"
                self.network_status_var.set(status)

        thread = threading.Thread(target=_detection_loop, daemon=True)
        thread.start()

    def perform_check_pass(self):
        """执行检号过站操作"""
        sn_code = self.sn_var.get().strip()
        if not sn_code:
            messagebox.showwarning("警告", "请输入SN码")
            return

        self.pass_btn.config(state=tk.DISABLED)
        self.add_log(f"开始执行检号过站，SN：{sn_code}")
        self.query_result_var.set("处理中...")

        def _thread_func():
            success, msg = self.mes_client.perform_check_pass(sn_code)
            self.root.after(0, lambda: self.query_result_var.set("成功" if success else "失败"))
            self.root.after(0, lambda: self.add_log(f"检号过站结果：{msg}"))
            self.root.after(0, lambda: self.pass_btn.config(state=tk.NORMAL))
            self.root.after(0, lambda: self.update_details(msg))

            if not success:
                self.root.after(0, lambda: messagebox.showerror("操作失败", msg))

        threading.Thread(target=_thread_func, daemon=True).start()

    def perform_write_sn(self):
        """执行写码操作"""
        # 获取并验证输入
        slave_addr_str = self.slave_addr_var.get().strip()
        sn_code = self.sn_var.get().strip()

        if not slave_addr_str.isdigit():
            messagebox.showwarning("警告", "从机地址必须是数字（1-31）")
            return

        slave_addr = int(slave_addr_str)
        if not (1 <= slave_addr <= 31):
            messagebox.showwarning("警告", "从机地址必须在1-31之间")
            return

        if not sn_code:
            messagebox.showwarning("警告", "请输入SN码")
            return

        if not (1 <= len(sn_code) <= 24):
            messagebox.showwarning("警告", "SN码长度必须在1-24字符之间")
            return

        # 执行操作
        self.write_btn.config(state=tk.DISABLED)
        self.add_log(f"开始向从机（地址：{slave_addr}）发送写码指令，SN：{sn_code}")
        self.query_result_var.set("写码中...")

        def _thread_func():
            success, msg = self.mes_client.write_sn_code(slave_addr, sn_code)
            self.root.after(0, lambda: self.query_result_var.set("写码成功" if success else "写码失败"))
            self.root.after(0, lambda: self.add_log(f"写码结果：{msg}"))
            self.root.after(0, lambda: self.write_btn.config(state=tk.NORMAL))
            self.root.after(0, lambda: self.update_details(msg))

            if not success:
                self.root.after(0, lambda: messagebox.showerror("写码失败", msg))

        threading.Thread(target=_thread_func, daemon=True).start()

    def perform_version_query(self):
        """执行软件版本查询"""
        # 获取并验证输入
        slave_addr_str = self.slave_addr_var.get().strip()
        if not slave_addr_str.isdigit():
            messagebox.showwarning("警告", "从机地址必须是数字（1-31）")
            return

        slave_addr = int(slave_addr_str)
        if not (1 <= slave_addr <= 31):
            messagebox.showwarning("警告", "从机地址必须在1-31之间")
            return

        # 执行操作
        self.version_btn.config(state=tk.DISABLED)
        self.add_log(f"开始向从机（地址：{slave_addr}）发送版本查询指令")
        self.query_result_var.set("查询中...")
        self.update_details("版本查询中，请稍候...")

        def _thread_func():
            success, version_info = self.mes_client.query_version_info(slave_addr)
            self.root.after(0, lambda: self.version_btn.config(state=tk.NORMAL))
            self.root.after(0, lambda: self.update_details(version_info))
            self.root.after(0, lambda: self.add_log(f"版本查询完成：{version_info.split(chr(10))[0]}"))

            if success:
                self.root.after(0, lambda: self.query_result_var.set("查询成功"))
            else:
                self.root.after(0, lambda: self.query_result_var.set("查询失败"))
                self.root.after(0, lambda: messagebox.showerror("版本查询失败", version_info))

        threading.Thread(target=_thread_func, daemon=True).start()
