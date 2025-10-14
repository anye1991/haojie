import time
import os

class PentestLogger:
    def __init__(self, log_dir="./pentest_logs"):
        # 创建日志目录（按日期命名）
        self.log_date = time.strftime("%Y%m%d_%H%M%S")
        self.log_dir = f"{log_dir}/{self.log_date}"
        os.makedirs(self.log_dir, exist_ok=True)
        # 初始化日志文件
        self.main_log = open(f"{self.log_dir}/main_log.txt", "a", encoding="utf-8")
        self.http_log = open(f"{self.log_dir}/http_requests.txt", "a", encoding="utf-8")
        print(f"[日志] 日志保存目录：{self.log_dir}")

    def log_main(self, content):
        """记录主流程日志（工具调用、阶段结果）"""
        log_line = f"[{time.strftime('%H:%M:%S')}] {content}\n"
        self.main_log.write(log_line)
        self.main_log.flush()  # 实时写入，避免缓存丢失
        print(log_line.strip())

    def log_http(self, method, url, headers, data=None, response=None):
        """记录HTTP请求/响应日志"""
        log_line = f"\n[{time.strftime('%H:%M:%S')}] {method} {url}\n"
        log_line += f"Headers: {headers}\n"
        if data:
            log_line += f"Data: {data}\n"
        if response:
            log_line += f"Response Status: {response.status_code}\n"
            log_line += f"Response Content: {response.text[:200]}..."  # 截取前200字符
        self.http_log.write(log_line)
        self.http_log.flush()

    def close(self):
        """关闭日志文件"""
        self.main_log.close()
        self.http_log.close()
        print(f"[日志] 所有日志已保存至：{self.log_dir}")

# 全局实例（其他文件导入后直接使用）
logger = PentestLogger()
