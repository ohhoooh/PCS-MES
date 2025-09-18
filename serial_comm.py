import serial
import serial.tools.list_ports
import time
from config import *


def escape_data(data):
    """数据转义处理"""
    escaped = bytearray()
    for byte in data:
        if byte == FRAME_HEADER:
            escaped.extend([0x7D, 0x5E])
        elif byte == 0x7D:
            escaped.extend([0x7D, 0x5D])
        else:
            escaped.append(byte)
    return escaped


def unescape_data(escaped_data):
    """数据还原处理"""
    data = bytearray()
    i = 0
    while i < len(escaped_data):
        if escaped_data[i] == 0x7D and i + 1 < len(escaped_data):
            if escaped_data[i + 1] == 0x5E:
                data.append(FRAME_HEADER)
            elif escaped_data[i + 1] == 0x5D:
                data.append(0x7D)
            i += 2
        else:
            data.append(escaped_data[i])
            i += 1
    return data


def calculate_crc16(data):
    """CRC16_CCITT计算（协议标准）"""
    crc = 0
    for byte in data:
        crc ^= (byte << 8)
        for _ in range(8):
            if crc & 0x8000:
                crc = (crc << 1) ^ 0x1021
            else:
                crc = crc << 1
            crc &= 0xFFFF
    return crc


class SerialCommunicator:
    """串口通信管理器"""

    def __init__(self):
        self.serial_obj = None
        self.is_connected = False

    def get_available_ports(self):
        """获取可用串口列表"""
        ports = serial.tools.list_ports.comports()
        return [port.device for port in ports]

    def open_serial(self, port, baudrate):
        """打开串口"""
        try:
            self.serial_obj = serial.Serial(
                port=port,
                baudrate=baudrate,
                timeout=SERIAL_TIMEOUT,
                parity=serial.PARITY_NONE,
                stopbits=STOPBITS_1,
                bytesize=EIGHTBITS
            )
            self.is_connected = self.serial_obj.is_open
            return self.is_connected, f"串口 {port} 打开成功"
        except Exception as e:
            return False, f"串口打开失败: {str(e)}"

    def close_serial(self):
        """关闭串口"""
        if self.serial_obj and self.serial_obj.is_open:
            self.serial_obj.close()
        self.is_connected = False

    def send_command(self, data_area):
        """发送通用命令（原有功能）"""
        return self._send_and_receive(data_area, None)

    def send_write_code_cmd(self, slave_addr, sn_code):
        """
        发送写码指令（0xA0），将SN码直接按两位一组解析为十六进制数
        若SN码长度为奇数，在最后单独的一位后补充'0'
        若处理后不足24字节，在后面补0直到达到24字节

        参数:
            slave_addr: 从机地址（1-31）
            sn_code: SN码字符串（如"010201009800250400028"）
        """
        if not (1 <= slave_addr <= 31):
            raise ValueError(f"从机地址无效（需1-31），当前：{slave_addr}")

        # 处理SN码：移除空格
        sn_hex_clean = sn_code.replace(" ", "")  # 清除可能的空格

        # 检查长度，若为奇数则在最后单独的一位后补充'0'
        if len(sn_hex_clean) % 2 != 0:
            sn_hex_clean = sn_hex_clean[:-1] + sn_hex_clean[-1] + '0'
            # 可选：添加日志提示
            # logging.warning(f"SN码长度为奇数，已在最后一位后补充'0'，处理后为: {sn_hex_clean}")

        try:
            sn_bytes = bytes.fromhex(sn_hex_clean)  # 直接解析为十六进制字节
        except ValueError as e:
            raise ValueError(f"SN码包含无效十六进制字符：{e}")

        # 如果不足24字节，在后面补0直到达到24字节
        if len(sn_bytes) < 12:
            padding_length = 12 - len(sn_bytes)
            sn_bytes += b'\x00' * padding_length
            # 可选：添加日志提示
            # logging.info(f"SN码不足24字节，已补充{padding_length}个0，总长度变为24字节")

        # 校验SN码长度是否为24字节
        if len(sn_bytes) != 12:
            raise ValueError(f"SN码处理后长度异常，应为24字节，实际为：{len(sn_bytes)}字节")

        # 构建指令数据区
        data_area = bytearray()
        data_area.append(WRITE_CODE_CMD)  # 写入指令标识（0xA0）
        data_area.append(slave_addr)  # 从机地址
        data_area.append(len(sn_bytes))  # SN码长度（字节数），应为24
        data_area.extend(sn_bytes)  # 十六进制SN字节数据

        response = self._send_and_receive(data_area, WRITE_CODE_ACK_CMD)
        return response

    def _send_and_receive(self, data_area, expected_ack_cmd):
        """通用发送-接收逻辑"""
        if not self.is_connected or not self.serial_obj:
            raise ConnectionError("串口未连接，请先打开串口")

        try:
            # 构建完整数据帧
            escaped_data = escape_data(data_area)
            crc = calculate_crc16(data_area)
            crc_high = (crc >> 8) & 0xFF
            crc_low = crc & 0xFF

            frame = bytearray()
            frame.append(FRAME_HEADER)
            frame.extend(escaped_data)
            frame.append(crc_high)
            frame.append(crc_low)
            frame.append(FRAME_TAIL)
            print("发送帧（十六进制）：", [hex(b) for b in frame])
            # 发送指令
            time.sleep(0.03)
            self.serial_obj.write(frame)
            self.serial_obj.flush()

            # 接收应答
            response_frame = b""
            start_time = time.time()
            while time.time() - start_time < SERIAL_TIMEOUT:
                if self.serial_obj.in_waiting:
                    response_frame += self.serial_obj.read(self.serial_obj.in_waiting)
                    if response_frame.endswith(bytes([FRAME_TAIL])):
                        break
                time.sleep(0.01)
                print("接收帧（十六进制）：", [hex(b) for b in response_frame])

            if not response_frame:
                raise TimeoutError("未收到从机应答，操作超时")
            if len(response_frame) < 5:
                raise ValueError(f"应答帧长度无效：{len(response_frame)}字节")

            # 解析应答帧
            response_body = response_frame[1:-1]
            response_data_escaped = response_body[:-2]
            response_crc_high = response_body[-2]
            response_crc_low = response_body[-1]
            received_crc = (response_crc_high << 8) | response_crc_low

            response_data = unescape_data(response_data_escaped)
            calculated_crc = calculate_crc16(response_data)
            if received_crc != calculated_crc:
                raise ValueError(f"CRC校验失败（接收：0x{received_crc:04X}，计算：0x{calculated_crc:04X}）")

            # 校验应答命令码（如果指定）
            if expected_ack_cmd is not None:
                if len(response_data) < 1:
                    raise ValueError("应答数据区为空")
                actual_ack_cmd = response_data[0]
                if actual_ack_cmd != expected_ack_cmd:
                    raise ValueError(f"应答命令码不匹配（期望：0x{expected_ack_cmd:02X}，实际：0x{actual_ack_cmd:02X}）")

            return response_data[1:] if expected_ack_cmd else response_data

        except Exception as e:
            raise Exception(f"串口通信失败：{str(e)}")
