import tkinter as tk
from serial_comm import SerialCommunicator
from mes_client import MESClient
from gui import MESQuerySystem
from config import INTRANET_TEST_IP  # 导入默认IP


def main():
    """程序主入口"""
    # 创建串口通信实例
    serial_comm = SerialCommunicator()

    # 创建MES客户端实例，传入默认API IP
    mes_client = MESClient(serial_comm, api_ip=INTRANET_TEST_IP)

    # 创建主窗口并启动应用
    root = tk.Tk()
    app = MESQuerySystem(root, serial_comm, mes_client)
    root.mainloop()


if __name__ == "__main__":
    main()