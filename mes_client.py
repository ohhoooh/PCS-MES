import re
from datetime import datetime
from config import QUERY_CMD_FORMAT, PASS_CMD_FORMAT


class MESClient:
    """MES系统客户端"""

    def __init__(self, serial_communicator):
        self.serial_comm = serial_communicator

    def query_aging_record(self, sn):
        """查询MES系统中的老化记录"""
        if not sn:
            raise ValueError("SN码不能为空")

        if not self.serial_comm.is_connected:
            raise ConnectionError("串口未连接，请先打开串口")

        # 构建查询指令
        query_cmd = QUERY_CMD_FORMAT.format(sn=sn)

        # 发送查询指令并获取响应
        response = self.serial_comm.send_command(query_cmd)

        # 解析响应
        return self._parse_query_response(response, sn)

    def perform_check_pass(self, sn):
        """执行检号过站操作"""
        if not sn:
            raise ValueError("SN码不能为空")

        if not self.serial_comm.is_connected:
            raise ConnectionError("串口未连接，请先打开串口")

        # 构建过站指令
        pass_cmd = PASS_CMD_FORMAT.format(sn=sn)

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
        # 根据实际协议解析响应数据
        # 假设响应格式为 "RESULT:状态;AGE:老化时间;TEMP:老化温度"
        parts = response.split(';')
        for part in parts:
            if part.startswith('RESULT:'):
                result = part.split(':')[1]
                if result == 'PASS':
                    details += f"检测结果: 合格\n"
                elif result == 'FAIL':
                    details += f"检测结果: 不合格\n"
            elif part.startswith('AGE:'):
                age = part.split(':')[1]
                details += f"老化时间: {age} 小时\n"
            elif part.startswith('TEMP:'):
                temp = part.split(':')[1]
                details += f"老化温度: {temp} ℃\n"
        # 确定查询结果状态
        if "PASS" in response:
            return "检测合格", details
        elif "FAIL" in response:
            return "检测不合格", details
        else:
            return "记录未找到", "未在MES系统中找到该SN的老化检测记录"