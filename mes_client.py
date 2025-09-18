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

    def perform_check_pass(self, sn_code, user_no):
        """仅使用API接口执行检号过站操作（不涉及串口）"""
        # 1. 检查SN号合法性（调用1号接口）
        check_success, check_msg = self.check_sn_validity(sn_code, user_no)
        if not check_success:
            return False, f"SN码（{sn_code}）检号失败"

        # 2. 执行过站操作（调用2号接口）
        pass_success, pass_msg = self.upload_result_pass(sn_code, user_no)
        if not pass_success:
            return False, f"SN码（{sn_code}）过站失败"

        # 3. 操作成功
        return True, f"SN码（{sn_code}）检号过站成功：{check_msg} -> {pass_msg}"

    def write_sn_code(self, slave_addr, sn_code):
        """执行写码操作"""
        try:
            # 发送写码指令并获取应答
            ack_data = self.serial_comm.send_write_code_cmd(slave_addr, sn_code)

            # 解析应答
            if len(ack_data) < 2:
                raise ValueError(f"写码应答数据不完整：{len(ack_data)}字节")

            ack_master_addr = ack_data[0]
            if ack_master_addr != slave_addr:
                raise ValueError(f"应答主机地址不匹配（期望：0x{slave_addr:02X}，实际：0x{ack_master_addr:02X}）")

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

