import json
import os


class ConfigManager:
    """配置管理工具类，用于保存和读取应用配置"""

    def __init__(self, config_file="app_config.json"):
        """初始化配置管理器

        Args:
            config_file: 配置文件路径
        """
        self.config_file = config_file
        self.default_config = {
            "api_ip": "127.0.0.1",  # 默认API IP
            "window_position": (100, 100),  # 默认窗口位置
            "window_size": (800, 600)  # 默认窗口大小
        }
        # 确保配置文件存在
        self._ensure_config_file_exists()

    def _ensure_config_file_exists(self):
        """确保配置文件存在，如果不存在则创建并写入默认配置"""
        if not os.path.exists(self.config_file):
            self.save_config(self.default_config)

    def load_config(self):
        """加载配置文件内容

        Returns:
            配置字典，如果加载失败则返回默认配置
        """
        try:
            with open(self.config_file, 'r', encoding='utf-8') as f:
                return json.load(f)
        except (json.JSONDecodeError, IOError) as e:
            print(f"加载配置失败: {e}，使用默认配置")
            return self.default_config.copy()

    def save_config(self, config):
        """保存配置到文件

        Args:
            config: 要保存的配置字典
        """
        try:
            # 合并配置，确保所有默认键都存在
            merged_config = self.default_config.copy()
            merged_config.update(config)

            with open(self.config_file, 'w', encoding='utf-8') as f:
                json.dump(merged_config, f, ensure_ascii=False, indent=4)
            return True
        except IOError as e:
            print(f"保存配置失败: {e}")
            return False

    def get_api_ip(self):
        """获取保存的API IP地址

        Returns:
            保存的API IP地址，如果没有则返回默认值
        """
        config = self.load_config()
        return config.get("api_ip", self.default_config["api_ip"])

    def set_api_ip(self, api_ip):
        """保存API IP地址配置

        Args:
            api_ip: 要保存的API IP地址

        Returns:
            是否保存成功
        """
        config = self.load_config()
        config["api_ip"] = api_ip
        return self.save_config(config)
