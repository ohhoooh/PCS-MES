import json
import os
import sys


class ConfigManager:
    """配置管理工具类，用于保存和读取应用配置"""

    def __init__(self, config_file=None):
        """初始化配置管理器，确保使用正确的配置文件路径"""
        # 确定配置文件的正确路径
        if config_file is None:
            # 获取程序运行目录
            if getattr(sys, 'frozen', False):
                # 处理打包后的情况
                base_dir = os.path.dirname(sys.executable)
            else:
                # 处理开发环境情况
                base_dir = os.path.dirname(os.path.abspath(__file__))

            self.config_file = os.path.join(base_dir, "app_config.json")
        else:
            self.config_file = config_file

        self.default_config = {
            "api_ip": "127.0.0.1",  # 默认API IP
            "window_position": (100, 100),
            "window_size": (800, 600)
        }

        # 确保配置文件存在
        self._ensure_config_file_exists()
        print(f"配置文件路径: {self.config_file}")  # 调试用，可删除

    def _ensure_config_file_exists(self):
        """确保配置文件存在，如果不存在则创建并写入默认配置"""
        if not os.path.exists(self.config_file):
            # 尝试创建文件
            try:
                with open(self.config_file, 'w', encoding='utf-8') as f:
                    json.dump(self.default_config, f, ensure_ascii=False, indent=4)
                print(f"已创建新配置文件: {self.config_file}")
            except Exception as e:
                print(f"创建配置文件失败: {e}")

    def load_config(self):
        """加载配置文件内容"""
        try:
            if os.path.exists(self.config_file) and os.path.getsize(self.config_file) > 0:
                with open(self.config_file, 'r', encoding='utf-8') as f:
                    config = json.load(f)
                    # 确保配置完整
                    for key, value in self.default_config.items():
                        if key not in config:
                            config[key] = value
                    return config
            else:
                return self.default_config.copy()
        except Exception as e:
            print(f"加载配置失败: {e}，使用默认配置")
            return self.default_config.copy()

    def save_config(self, config):
        """保存配置到文件"""
        try:
            # 合并配置，确保所有默认键都存在
            merged_config = self.default_config.copy()
            merged_config.update(config)

            with open(self.config_file, 'w', encoding='utf-8') as f:
                json.dump(merged_config, f, ensure_ascii=False, indent=4)
            return True
        except Exception as e:
            print(f"保存配置失败: {e}")
            return False

    def get_api_ip(self):
        """获取保存的API IP地址"""
        config = self.load_config()
        return config.get("api_ip", self.default_config["api_ip"])

    def set_api_ip(self, api_ip):
        """保存API IP地址配置"""
        config = self.load_config()
        config["api_ip"] = api_ip
        return self.save_config(config)
