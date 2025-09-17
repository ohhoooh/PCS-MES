import datetime
import requests
import json
from config import CHECK_SN_URL, EXECUTE_SN_URL
from config import *


class MESClient:
    """MES系统客户端"""

    def __init__(self, serial_communicator):
        self.serial_comm = serial_communicator

    def check_sn_validity(self, sn_code, user_no):
        """调用1号接口检查SN号是否合法"""
        data = {"BarCode": sn_code, "UserNo": user_no}
        headers = {"Content-Type": "application/json"}
        try:
            response = requests.post(CHECK_SN_URL, data=json.dumps(data), headers=headers)
            response.raise_for_status()
            result = response.json()
            if result.get("code") == 0:
                return True, result.get("message", "SN号检查通过")
            else:
                return False, result.get("message", "SN号检查失败")
        except requests.exceptions.RequestException as e:
            return False, f"检查SN号时发生网络错误: {str(e)}"

    def upload_result_pass(self, sn_code, user_no):
        """调用2号接口上传结果过站"""
        data = {"BarCode": sn_code, "UserNo": user_no}
        headers = {"Content-Type": "application/json"}
        try:
            response = requests.post(EXECUTE_SN_URL, data=json.dumps(data), headers=headers)
            response.raise_for_status()
            result = response.json()
            if result.get("code") == 0:
                return True, result.get("message", "过站成功")
            else:
                return False, result.get("message", "过站失败")
        except requests.exceptions.RequestException as e:
            return False, f"上传过站结果时发生网络错误: {str(e)}"

    def perform_check_burn_and_pass(self, sn_code, user_no, slave_addr):
        """执行完整的检号、烧录、过站流程"""
        # 检查SN号
        check_success, check_msg = self.check_sn_validity(sn_code, user_no)
        if not check_success:
            return False, check_msg

        # 烧录
        burn_success, burn_msg = self.write_sn_code(slave_addr, sn_code)
        if not burn_success:
            return False, burn_msg

        # 上传过站结果
        pass_success, pass_msg = self.upload_result_pass(sn_code, user_no)
        if not pass_success:
            return False, pass_msg

        return True, "检号、烧录、过站全部成功"
    def perform_check_pass(self, sn_code):
        """执行检号过站操作"""
        try:
            if not sn_code or len(sn_code) > 24:
                return False, "SN码格式无效（需1-24字符）"

            # 构建过站命令数据区
            pass_cmd = PASS_CMD_FORMAT.format(sn=sn_code)
            data_area = pass_cmd.encode('utf-8')

            # 发送命令并获取响应
            response_data = self.serial_comm.send_command(data_area)
            response_str = response_data.decode('utf-8', errors='ignore').strip()

            if "SUCCESS" in response_str:
                return True, f"SN码（{sn_code}）检号过站成功"
            else:
                return False, f"检号过站失败：{response_str}"

        except Exception as e:
            return False, f"检号过站异常：{str(e)}"

    def write_sn_code(self, slave_addr, sn_code):
        """执行写码操作"""
        try:
            # 发送写码指令并获取应答
            ack_data = self.serial_comm.send_write_code_cmd(slave_addr, sn_code)

            # 解析应答
            if len(ack_data) < 2:
                raise ValueError(f"写码应答数据不完整：{len(ack_data)}字节")

            ack_master_addr = ack_data[0]
            if ack_master_addr != MASTER_ADDRESS:
                raise ValueError(f"应答主机地址不匹配（期望：0x{MASTER_ADDRESS:02X}，实际：0x{ack_master_addr:02X}）")

            status_code = ack_data[1]
            if status_code == WRITE_SUCCESS:
                return True, f"SN码（{sn_code}）写码成功（从机地址：{slave_addr}）"
            elif status_code == WRITE_FAILED:
                return False, f"SN码（{sn_code}）写码失败（从机地址：{slave_addr}）"
            else:
                return False, f"写码状态码未知（0x{status_code:02X}）"

        except Exception as e:
            return False, f"写码操作异常：{str(e)}"

    def query_version_info(self, slave_addr):
        """执行软件版本查询"""
        try:
            # 发送版本查询指令并获取应答
            ack_data = self.serial_comm.send_version_query_cmd(slave_addr)

            # 解析应答
            if len(ack_data) < (1 + DC_VERSION_LEN + PFC_VERSION_LEN):
                raise ValueError(f"版本应答数据不完整：{len(ack_data)}字节（需≥21字节）")

            ack_master_addr = ack_data[0]
            if ack_master_addr != MASTER_ADDRESS:
                raise ValueError(f"应答主机地址不匹配（期望：0x{MASTER_ADDRESS:02X}，实际：0x{ack_master_addr:02X}）")

            # 提取版本信息
            dc_version_bytes = ack_data[1:1 + DC_VERSION_LEN]
            dc_version = dc_version_bytes.decode("utf-8", errors="ignore").strip('\x00')

            pfc_version_bytes = ack_data[1 + DC_VERSION_LEN: 1 + DC_VERSION_LEN + PFC_VERSION_LEN]
            pfc_version = pfc_version_bytes.decode("utf-8", errors="ignore").strip('\x00')

            # 组装版本信息
            version_info = f"""软件版本查询结果（从机地址：{slave_addr}）
                ========================================
                DC侧版本：{dc_version if dc_version else '未获取'}
                PFC侧版本：{pfc_version if pfc_version else '未获取'}
                查询时间：{datetime.now().strftime('%Y-%m-%d %H:%M:%S')}
                ========================================"""
            return True, version_info

        except Exception as e:
            return False, f"版本查询异常：{str(e)}"

