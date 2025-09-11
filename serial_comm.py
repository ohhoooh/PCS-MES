import serial
import serial.tools.list_ports
import time
from config import SERIAL_TIMEOUT
import struct

# 定义帧头、帧尾
FRAME_HEADER = 0x7E
FRAME_TAIL = 0x7E
# 定义命令代码
CMD_WRITE_SN = 0xA0     #设置指令
CMD_QUERY_AGING_RECORD = 0xA2
CMD_CHECK_PASS = 0xA3

class SerialCommunicator:
    """串口通信管理器"""

    def __init__(self):
        self.serial_obj = None
        self.is_connected = False
        self.current_ports = []

    def get_available_ports(self):
        """获取可用串口列表"""
        try:
            ports = serial.tools.list_ports.comports()
            port_list = [port.device for port in ports]
            if not port_list:
                port_list = ["无可用串口"]
            self.current_ports = port_list
            return port_list
        except Exception as e:
            raise Exception(f"获取串口列表失败: {str(e)}")

    def _get_parity_code(self, parity_text):
        """将校验位文本转换为serial库对应的代码"""
        parity_map = {
            "无校验": serial.PARITY_NONE,
            "奇校验": serial.PARITY_ODD,
            "偶校验": serial.PARITY_EVEN
        }
        return parity_map.get(parity_text, serial.PARITY_NONE)

    def _get_stop_bits(self, stop_bits_text):
        """将停止位文本转换为serial库对应的代码"""
        stop_bits_map = {
            "1": serial.STOPBITS_ONE,
            "1.5": serial.STOPBITS_ONE_POINT_FIVE,
            "2": serial.STOPBITS_TWO
        }
        return stop_bits_map.get(stop_bits_text, serial.STOPBITS_ONE)

    def open_serial(self, port, baudrate, data_bits, stop_bits, parity):
        try:
            # 关闭已打开的串口
            if self.serial_obj and self.serial_obj.is_open:
                self.serial_obj.close()
            # 配置并打开串口，根据协议设置默认参数
            self.serial_obj = serial.Serial(
                port=port,
                baudrate=9600,  # 协议规定波特率为9600Bps
                bytesize=8,  # 协议规定数据位为8
                parity=serial.PARITY_NONE,  # 协议规定奇偶校验位为无
                stopbits=serial.STOPBITS_ONE,  # 协议规定停止位为1
                timeout=SERIAL_TIMEOUT
            )
            self.is_connected = self.serial_obj.is_open
            return self.is_connected
        except Exception as e:
            raise Exception(f"打开串口失败: {str(e)}")

    def close_serial(self):
        """关闭串口"""
        try:
            if self.serial_obj and self.serial_obj.is_open:
                self.serial_obj.close()
            self.is_connected = False
        except Exception as e:
            raise Exception(f"关闭串口失败: {str(e)}")

    # serial_comm.py
    def send_command(self, command):
        if not self.is_connected or not self.serial_obj:
            raise Exception("串口未连接")
        try:
            # 构建数据帧
            data = bytearray()
            data.append(FRAME_HEADER)
            # 根据不同命令设置命令代码
            if command.startswith("QUERY,MES,SN="):
                data.append(CMD_QUERY_AGING_RECORD)
            elif command.startswith("PASS,MES,SN="):
                data.append(CMD_CHECK_PASS)
            # 假设从机地址固定为1（需根据实际情况修改）
            data.append(1)
            command_data = command.split(',')[2].encode('utf-8')
            escaped_command_data = escape_data(command_data)
            data.extend(escaped_command_data)
            crc = calculate_crc16(data[1:])
            data.append(crc >> 8)
            data.append(crc & 0xFF)
            data.append(FRAME_TAIL)

            # 发送命令
            self.serial_obj.write(data)
            # 等待并接收响应
            response = b""
            start_time = time.time()
            while time.time() - start_time < SERIAL_TIMEOUT:
                if self.serial_obj.in_waiting:
                    response += self.serial_obj.read(self.serial_obj.in_waiting)
                    # 假设响应以帧尾结尾
                    if response.endswith(bytes([FRAME_TAIL])):
                        break
                time.sleep(0.1)
            if not response:
                raise Exception("未收到响应，操作超时")
            # 解析响应
            response = response[1:-3]  # 去除帧头、CRC校验和帧尾
            unescaped_response = unescape_data(response)
            received_crc = (response[-2] << 8) + response[-1]
            calculated_crc = calculate_crc16(response[:-2])
            if received_crc != calculated_crc:
                raise Exception("CRC校验失败")
            return unescaped_response.decode('utf-8').strip()
        except Exception as e:
            raise Exception(f"串口通信失败: {str(e)}")

    # mes_client.py
    def query_aging_record(self, sn):
        if not sn:
            raise ValueError("SN码不能为空")
        if not self.serial_comm.is_connected:
            raise ConnectionError("串口未连接，请先打开串口")
        # 构建查询指令
        query_cmd = f"QUERY,MES,SN={sn}"
        # 发送查询指令并获取响应
        response = self.serial_comm.send_command(query_cmd)
        # 解析响应
        return self._parse_query_response(response, sn)

    def perform_check_pass(self, sn):
        if not sn:
            raise ValueError("SN码不能为空")
        if not self.serial_comm.is_connected:
            raise ConnectionError("串口未连接，请先打开串口")
        # 构建过站指令
        pass_cmd = f"PASS,MES,SN={sn}"
        # 发送过站指令并获取响应
        response = self.serial_comm.send_command(pass_cmd)
        # 解析响应
        if "SUCCESS" in response:
            return True, "检号过站成功"
        else:
            return False, f"过站失败: {response}"

    def _parse_query_response(self, response, sn):
        details = "产品老化检测记录:\n"
        details += f"SN码: {sn}\n"
        details += f"查询时间: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n"
        # 从响应中提取信息（根据实际协议修改）
        if "AGE=" in response:
            age_match = re.search(r"AGE=(\d+)", response)
            if age_match:
                details += f"老化时间: {age_match.group(1)} 小时\n"
        if "TEMP=" in response:
            temp_match = re.search(r"TEMP=(\d+\.\d+)", response)
            if temp_match:
                details += f"老化温度: {temp_match.group(1)} ℃\n"
        if "RESULT=" in response:
            result_match = re.search(r"RESULT=(.*?)(,|$)", response)
            if result_match:
                details += f"检测结果: {result_match.group(1)}\n"
        # 确定查询结果状态
        if "PASS" in response:
            return "检测合格", details
        elif "FAIL" in response:
            return "检测不合格", details
        else:
            return "记录未找到", "未在MES系统中找到该SN的老化检测记录"
def escape_data(data):
    escaped_data = bytearray()
    for byte in data:
        if byte == FRAME_HEADER or byte == FRAME_TAIL or byte == 0x7D:
            escaped_data.append(0x7D)
            byte ^= 0x20
        escaped_data.append(byte)
    return escaped_data
def unescape_data(data):
    unescaped_data = bytearray()
    i = 0
    while i < len(data):
        byte = data[i]
        if byte == 0x7D:
            i += 1
            byte = data[i] ^ 0x20
        unescaped_data.append(byte)
        i += 1
    return unescaped_data
def calculate_crc16(data):
    crc = 0xFFFF
    for byte in data:
        crc ^= byte << 8
        for _ in range(8):
            if crc & 0x8000:
                crc = (crc << 1) ^ 0x1021
            else:
                crc = crc << 1
            crc &= 0xFFFF
    return crc