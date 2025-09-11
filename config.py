"""系统配置参数"""

# 网络配置
INTRANET_TEST_IP = "10.10.30.82"        # 内网测试IP
INTRANET_TEST_PORT = 80                 # 内网测试端口

# 串口配置
SERIAL_TIMEOUT = 5                      # 串口超时时间(秒)
DEFAULT_BAUDRATE = "9600"               # 默认波特率
DEFAULT_DATA_BITS = "8"                 # 默认数据位
DEFAULT_STOP_BITS = "1"                 # 默认停止位
DEFAULT_PARITY = "无校验"                # 默认校验位

# 串口指令格式 (根据实际协议修改)
QUERY_CMD_FORMAT = "QUERY,MES,SN={sn}\r\n"  # 查询指令格式
PASS_CMD_FORMAT = "PASS,MES,SN={sn}\r\n"    # 过站指令格式

# UI配置
WINDOW_TITLE = "MES产品老化记录查询与检号过站系统"
WINDOW_SIZE = "1200x700"
WINDOW_MIN_SIZE = "1000x600"
