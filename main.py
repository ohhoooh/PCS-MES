import tkinter as tk
from serial_comm import SerialCommunicator
from mes_client import MESClient
from gui import MESQuerySystem
from config_manager import ConfigManager  # 导入配置管理器


def main():
    """程序主入口"""
    # 初始化配置管理器
    config_manager = ConfigManager()

    # 从配置中获取保存的API IP
    saved_api_ip = config_manager.get_api_ip()

    # 创建串口通信实例
    serial_comm = SerialCommunicator()

    # 创建MES客户端实例，传入保存的API IP
    mes_client = MESClient(serial_comm, api_ip=saved_api_ip)

    # 创建主窗口并启动应用，同时传入配置管理器
    root = tk.Tk()

    # 创建MES客户端实例，传入日志记录方法
    def log_func(message):
        """日志记录函数"""
        if hasattr(app, 'add_log'):
            app.add_log(message)

    mes_client = MESClient(serial_comm, api_ip=saved_api_ip, logger=log_func)

    app = MESQuerySystem(root, serial_comm, mes_client, config_manager)
    root.mainloop()


if __name__ == "__main__":
    main()
