import tkinter as tk
from serial_comm import SerialCommunicator
from mes_client import MESClient
from gui import MESQuerySystem


def main():
    """程序主入口"""
    # 创建串口通信实例
    serial_comm = SerialCommunicator()

    # 创建MES客户端实例
    mes_client = MESClient(serial_comm)

    # 创建主窗口并启动应用
    root = tk.Tk()
    app = MESQuerySystem(root, serial_comm, mes_client)
    root.mainloop()


if __name__ == "__main__":
    main()
