"""系统配置参数"""
# 网络配置
INTRANET_TEST_IP = "10.10.30.82"  # 服务器IP
INTRANET_TEST_PORT = 80           # 服务器端口

# 串口配置
DEFAULT_BAUDRATE = "9600"         # 默认波特率
SERIAL_TIMEOUT = 5                # 串口超时时间（秒）
FRAME_HEADER = 0x7E               # 帧头
FRAME_TAIL = 0x7E                 # 帧尾

# 原有指令格式
PASS_CMD_FORMAT = "PASS,MES,SN={sn}\r\n"  # 过站命令模板

# 写码指令配置
WRITE_CODE_CMD = 0xA0          # 写码指令命令码（主机发送）
WRITE_CODE_ACK_CMD = 0xA1      # 写码应答命令码（从机返回）
MASTER_ADDRESS = 0xF4          # 写码应答中「主机固定地址」
WRITE_SUCCESS = 0x00           # 写码成功状态码
WRITE_FAILED = 0x01            # 写码失败状态码

# 版本查询配置
VERSION_QUERY_CMD = 0xA2       # 版本查询指令命令码（主机发送）
VERSION_ACK_CMD = 0xA3         # 版本应答命令码（从机返回）
DC_VERSION_LEN = 10            # DC侧版本信息长度
PFC_VERSION_LEN = 10           # PFC侧版本信息长度
