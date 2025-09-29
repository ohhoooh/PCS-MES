import tkinter as tk
from tkinter import ttk, messagebox
import threading
import time
import socket
from config import *


class MESQuerySystem:
    """MES查询系统主界面"""

    def __init__(self, root, serial_comm, mes_client,config_manager):
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
        self.network_status_var = tk.StringVar(value="未检测")  # 网络状态变量
        self.local_ip_var = tk.StringVar(value="获取中...")      # 本地IP显示变量

        # 内网检测配置
        self.detection_interval = 10  # 检测间隔（秒）
        self.timeout = 2  # 连接超时时间（秒）
        # 公司内网IP段配置（根据实际情况修改）
        self.company_subnets = [
            "10.10.",  # 公司内网主要网段
            "192.168.1.",  # 公司内网次要网段
            "172.16."  # 公司内网其他网段
        ]
        # 公司内网特定服务器列表（根据实际情况添加）
        self.intranet_servers = [
            (INTRANET_TEST_IP, INTRANET_TEST_PORT),  # 配置文件中的服务器
            ("10.10.30.1", 80),  # 公司内网网关
            ("10.10.20.5", 443)  # 公司内部Web服务器
        ]
        # 公司内网DNS域名（根据实际情况修改）
        self.intranet_domains = [
            "internal.company.com",
            "mes-server.local"
        ]
        self.config_manager = config_manager
        self.api_ip_var = tk.StringVar()

        # 初始化界面
        self.init_ui()
        self.load_saved_settings()

        #图标设置
        root.iconbitmap('test.ico')

    def init_ui(self):
        """初始化界面组件"""
        self.create_serial_frame()
        self.create_network_frame()
        self.create_operation_frame()  # 整合后的操作区域
        self.create_log_frame()
        self.create_details_frame()

    def load_saved_settings(self):
        """加载所有保存的设置并应用到界面"""
        try:
            # 加载保存的API IP
            saved_api_ip = self.config_manager.get_api_ip()
            if saved_api_ip:
                # 更新输入框
                self.api_ip_var.set(saved_api_ip)
                # 更新MES客户端
                self.mes_client.set_api_ip(saved_api_ip)
                self.add_log(f"已加载保存的API IP: {saved_api_ip}")
            else:
                self.add_log("未找到保存的API IP，使用默认值")
                default_ip = self.config_manager.default_config["api_ip"]
                self.api_ip_var.set(default_ip)
                self.mes_client.set_api_ip(default_ip)
        except Exception as e:
            self.add_log(f"加载配置时出错: {str(e)}")
            # 出错时使用默认值
            default_ip = self.config_manager.default_config["api_ip"]
            self.api_ip_var.set(default_ip)
            self.mes_client.set_api_ip(default_ip)

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
        """创建网络状态显示区域（Windows环境）"""
        frame_network = ttk.LabelFrame(self.root, text="网络状态 (Windows)")
        frame_network.grid(row=1, column=0, padx=10, pady=5, sticky="we")
        frame_network.grid_columnconfigure(5, weight=1)

        # 网络状态显示
        ttk.Label(frame_network, text="网络连接状态：").grid(row=0, column=0, padx=5, pady=5, sticky="e")
        self.api_ip_entry = ttk.Entry(frame_network, textvariable=self.api_ip_var, width=15)
        self.api_ip_entry.grid(row=0, column=6, padx=5, pady=5, sticky="w")

        # 手动检测按钮
        self.check_network_btn = ttk.Button(
            frame_network,
            text="网络检测",
            command=self.trigger_manual_detection
        )
        self.check_network_btn.grid(row=0, column=5, padx=10, pady=5,sticky="w")

        # 设置API IP按钮
        self.set_api_ip_btn = ttk.Button(
            frame_network,
            text="设置API IP",
            command=self.set_api_ip
        )
        self.set_api_ip_btn.grid(row=0, column=7, padx=10, pady=5)

        #网络状态显示
        self.network_status_label = ttk.Label(
            frame_network,
            textvariable=self.network_status_var,
            font=("Arial", 10, "bold"),
            foreground="orange"  # 初始为橙色
        )
        self.network_status_label.grid(row=0, column=1, padx=5, pady=5, sticky="w")

        # 本地IP地址显示
        ttk.Label(frame_network, text="本地IP地址：").grid(row=0, column=2, padx=5, pady=5, sticky="e")
        ttk.Label(
            frame_network,
            textvariable=self.local_ip_var,
            font=("Arial", 10)
        ).grid(row=0, column=3, padx=5, pady=5, sticky="w")

    def get_local_ip_addresses(self):
        """获取Windows系统下的本机IP地址（适配Windows环境）"""
        ip_addresses = []
        try:
            # Windows系统专用的IP获取方式
            # 创建一个临时socket连接来获取本机IP
            with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
                # 不实际连接，只是为了获取当前网络接口的IP
                s.connect(("8.8.8.8", 80))
                primary_ip = s.getsockname()[0]
                ip_addresses.append(primary_ip)

            # 获取所有网络接口的IP
            hostname = socket.gethostname()
            addrs = socket.getaddrinfo(hostname, None, socket.AF_INET)
            for addr in addrs:
                ip_addr = addr[4][0]
                if ip_addr not in ip_addresses and ip_addr != "127.0.0.1":
                    ip_addresses.append(ip_addr)

        except Exception as e:
            self.add_log(f"获取本地IP地址出错: {str(e)}")

        # 更新本地IP显示
        self.root.after(0, lambda: self.local_ip_var.set(", ".join(ip_addresses)))
        return ip_addresses

    def is_ip_in_company_subnet(self, ip):
        """检查IP是否属于公司内网网段"""
        for subnet in self.company_subnets:
            if ip.startswith(subnet):
                return True
        return False

    def check_dns_resolution(self):
        """检查能否解析公司内网域名"""
        for domain in self.intranet_domains:
            try:
                socket.gethostbyname(domain)
                return True  # 只要有一个域名能解析就返回True
            except:
                continue
        return False

    def check_server_connectivity(self):
        """检查能否连接到公司内网服务器（Windows优化版）"""
        success_count = 0
        for server in self.intranet_servers:
            try:
                with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
                    # Windows环境下的超时设置优化
                    s.settimeout(self.timeout)
                    # 尝试连接服务器
                    result = s.connect_ex(server)
                    if result == 0:
                        success_count += 1
                        # 连接成功后不必检测所有服务器，提高响应速度
                        if success_count >= 1:
                            break
            except Exception as e:
                self.add_log(f"连接服务器 {server} 出错: {str(e)}")
                continue

        return success_count > 0

    def trigger_manual_detection(self):
        """手动触发一次网络检测"""
        self.add_log("正在进行网络检测...")
        # 禁用按钮防止重复点击
        self.check_network_btn.config(state=tk.DISABLED)
        # 在新线程中执行检测
        threading.Thread(target=self._manual_detection, daemon=True).start()

    def _manual_detection(self):
        """手动检测逻辑实现"""
        # 执行检测
        detection_results = self.perform_detection()

        # 更新UI
        status_text = "正常" if self.is_connected else "断开"
        self.root.after(0, lambda s=status_text: self.network_status_var.set(s))

        color = "green" if self.is_connected else "red"
        self.root.after(0, lambda c=color: self.update_status_color(c))

        # 重新启用按钮
        self.root.after(0, lambda: self.check_network_btn.config(state=tk.NORMAL))

    def perform_detection(self):
        """执行网络检测并返回结果（提取为独立方法）"""
        detection_results = {
            "ip_check": False,
            "dns_check": False,
            "server_check": False
        }

        # 1. 检查本机IP是否属于公司内网网段
        local_ips = self.get_local_ip_addresses()
        for ip in local_ips:
            if self.is_ip_in_company_subnet(ip):
                detection_results["ip_check"] = True
                break

        # 2. 检查内网DNS解析
        detection_results["dns_check"] = self.check_dns_resolution()

        # 3. 检查内网服务器连接
        detection_results["server_check"] = self.check_server_connectivity()

        # 综合判断：至少满足两项条件才认为连接到公司内网
        self.is_connected = sum(detection_results.values()) >= 2

        # 记录详细检测结果到日志
        log_msg = f"内网检测结果 - IP段: {'通过' if detection_results['ip_check'] else '失败'}, "
        log_msg += f"DNS解析: {'通过' if detection_results['dns_check'] else '失败'}, "
        log_msg += f"服务器连接: {'通过' if detection_results['server_check'] else '失败'} - "
        log_msg += f"最终状态: {'已连接' if self.is_connected else '未连接'}"
        self.add_log(log_msg)

        return detection_results

    def update_status_color(self, color):
        """更新网络状态显示的颜色"""
        self.network_status_label.configure(foreground=color)

    def start_detection_thread(self):
        """启动Windows环境下的内网检测线程"""

        def _detection_loop():
            """Windows优化版网络检测循环"""
            while True:
                # 执行检测
                self.perform_detection()

                # 更新UI显示
                status_text = "正常" if self.is_connected else "断开"
                self.root.after(0, lambda s=status_text: self.network_status_var.set(s))

                # 更新状态颜色
                color = "green" if self.is_connected else "red"
                self.root.after(0, lambda c=color: self.update_status_color(c))

                # 等待下一次检测
                time.sleep(self.detection_interval)

        # 创建并启动后台线程
        detection_thread = threading.Thread(target=_detection_loop, daemon=True)
        detection_thread.start()

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

    # 在create_log_frame方法中添加日志操作按钮
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

        # 日志操作按钮
        log_buttons_frame = ttk.Frame(frame_log)
        log_buttons_frame.grid(row=1, column=0, columnspan=2, padx=5, pady=5, sticky="e")

        self.clear_log_btn = ttk.Button(log_buttons_frame, text="清除日志", command=self.clear_log)
        self.clear_log_btn.pack(side=tk.LEFT, padx=5)

        self.save_log_btn = ttk.Button(log_buttons_frame, text="保存日志", command=self.save_log)
        self.save_log_btn.pack(side=tk.LEFT, padx=5)

    # 在create_details_frame方法中添加记录操作按钮
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

        # 记录操作按钮
        details_buttons_frame = ttk.Frame(frame_details)
        details_buttons_frame.grid(row=1, column=0, columnspan=2, padx=5, pady=5, sticky="e")

        self.clear_details_btn = ttk.Button(details_buttons_frame, text="清除记录", command=self.clear_details)
        self.clear_details_btn.pack(side=tk.LEFT, padx=5)

        self.save_details_btn = ttk.Button(details_buttons_frame, text="保存记录", command=self.save_details)
        self.save_details_btn.pack(side=tk.LEFT, padx=5)

    # 添加日志和记录操作的实现方法
    def clear_log(self):
        """清除日志内容"""
        if not self.log_text:
            return

        self.log_text.config(state=tk.NORMAL)
        self.log_text.delete(1.0, tk.END)
        self.log_text.config(state=tk.DISABLED)

    def save_log(self):
        """保存日志内容到文件"""
        if not self.log_text or not self.log_text.get(1.0, tk.END).strip():
            messagebox.showinfo("提示", "日志为空，无需保存")
            return

        from tkinter import filedialog
        import os

        # 获取当前时间作为默认文件名
        default_filename = f"log_{time.strftime('%Y%m%d_%H%M%S')}.txt"
        file_path = filedialog.asksaveasfilename(
            defaultextension=".txt",
            filetypes=[("文本文件", "*.txt"), ("所有文件", "*.*")],
            initialfile=default_filename
        )

        if file_path:
            try:
                log_content = self.log_text.get(1.0, tk.END)
                with open(file_path, "w", encoding="utf-8") as f:
                    f.write(log_content)
                self.add_log(f"日志已保存至: {file_path}")
                messagebox.showinfo("成功", f"日志已成功保存至:\n{file_path}")
            except Exception as e:
                self.add_log(f"保存日志失败: {str(e)}")
                messagebox.showerror("错误", f"保存日志失败:\n{str(e)}")

    def clear_details(self):
        """清除记录详情内容"""
        if not self.details_text:
            return

        self.details_text.config(state=tk.NORMAL)
        self.details_text.delete(1.0, tk.END)
        self.details_text.config(state=tk.DISABLED)

    def save_details(self):
        """保存记录详情到文件"""
        if not self.details_text or not self.details_text.get(1.0, tk.END).strip():
            messagebox.showinfo("提示", "记录详情为空，无需保存")
            return

        from tkinter import filedialog
        import os

        # 获取当前时间作为默认文件名
        default_filename = f"details_{time.strftime('%Y%m%d_%H%M%S')}.txt"
        file_path = filedialog.asksaveasfilename(
            defaultextension=".txt",
            filetypes=[("文本文件", "*.txt"), ("所有文件", "*.*")],
            initialfile=default_filename
        )

        if file_path:
            try:
                details_content = self.details_text.get(1.0, tk.END)
                with open(file_path, "w", encoding="utf-8") as f:
                    f.write(details_content)
                self.add_log(f"记录详情已保存至: {file_path}")
                messagebox.showinfo("成功", f"记录详情已成功保存至:\n{file_path}")
            except Exception as e:
                self.add_log(f"保存记录详情失败: {str(e)}")
                messagebox.showerror("错误", f"保存记录详情失败:\n{str(e)}")

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

    def set_api_ip(self):
        """设置并保存API接口IP地址"""
        api_ip = self.api_ip_var.get().strip()
        if not api_ip:
            messagebox.showwarning("警告", "请输入API接口IP地址")
            return

        # 验证IP地址格式
        import re
        ip_pattern = r'^((25[0-5]|2[0-4]\d|[01]?\d\d?)\.){3}(25[0-5]|2[0-4]\d|[01]?\d\d?)$'
        if not re.match(ip_pattern, api_ip):
            messagebox.showwarning("警告", "请输入有效的IP地址（格式如: 192.168.1.1）")
            return

        # 保存配置
        if self.config_manager.set_api_ip(api_ip):
            # 保存成功后更新MES客户端
            self.mes_client.set_api_ip(api_ip)
            self.add_log(f"已设置并保存API接口IP: {api_ip}")
            messagebox.showinfo("成功", f"API接口IP已设置为: {api_ip}\n下次启动将自动使用此IP")
        else:
            self.add_log(f"保存API接口IP失败: {api_ip}")
            messagebox.showwarning("警告", f"保存API接口IP失败，请检查文件权限")

    # 在gui.py中修改perform_check_pass方法
    def perform_check_pass(self):
        """执行检号过站操作（仅API接口，不使用串口）"""
        sn_code = self.sn_var.get().strip()
        user_no = "1001"

        # 验证SN码
        if not sn_code:
            messagebox.showwarning("警告", "请输入SN码")
            return
        if not (1 <= len(sn_code) <= 24):
            messagebox.showwarning("警告", "SN码长度必须在1-24字符之间")
            return

        # 执行操作
        self.pass_btn.config(state=tk.DISABLED)
        self.add_log(f"开始执行检号过站，SN：{sn_code}，员工号：{user_no}")
        self.query_result_var.set("处理中...")

        def _thread_func():
            # 调用MES客户端的API接口方法（无串口操作）
            success, msg = self.mes_client.perform_check_pass(sn_code, user_no)

            # 更新UI
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


def perform_check_pass(self):
    """执行检号过站操作（仅API接口，不使用串口）"""
    sn_code = self.sn_var.get().strip()
    user_no = "1001"  # 实际应用中应从员工登录信息或输入框获取

    # 验证SN码
    if not sn_code:
        messagebox.showwarning("警告", "请输入SN码")
        return
    if not (1 <= len(sn_code) <= 24):
        messagebox.showwarning("警告", "SN码长度必须在1-24字符之间")
        return

    # 执行操作
    self.pass_btn.config(state=tk.DISABLED)
    self.add_log(f"开始执行检号过站，SN：{sn_code}，员工号：{user_no}")
    self.query_result_var.set("处理中...")

    def _thread_func():
        # 调用MES客户端的API接口方法（无串口操作）
        success, msg = self.mes_client.perform_check_pass(sn_code, user_no)

        # 更新UI
        self.root.after(0, lambda: self.query_result_var.set("成功" if success else "失败"))
        self.root.after(0, lambda: self.add_log(f"检号过站结果：{msg}"))
        self.root.after(0, lambda: self.pass_btn.config(state=tk.NORMAL))
        self.root.after(0, lambda: self.update_details(msg))

        if not success:
            self.root.after(0, lambda: messagebox.showerror("操作失败", msg))

    threading.Thread(target=_thread_func, daemon=True).start()