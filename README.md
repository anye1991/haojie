# AI+机器人联动渗透测试框架

本框架实现了"AI智能决策+机器人自动化执行"的完整渗透测试流程，覆盖从信息收集到权限获取的全场景，支持技术型漏洞和业务逻辑漏洞的自动化探测与利用。

## 核心功能

1. **AI智能决策中枢**：
   - 基于50维漏洞特征识别23类Web漏洞
   - 动态生成WAF绕防策略和模糊测试Payload
   - 匹配漏洞专属探测与利用方案

2. **自动化渗透机器人**：
   - 全流程信息收集（端口扫描、子域枚举、敏感文件探测）
   - 技术型漏洞利用（SQL注入、RCE、文件上传等）
   - 业务逻辑漏洞探测（越权访问、支付篡改、验证码绕过）
   - 自动提权（Linux/Windows多路径提权）

3. **完整流程闭环**：
   - 实时日志记录与证据留存
   - 自动化生成渗透测试报告
   - 支持未知漏洞模糊测试

## 环境准备

### 依赖安装

1. 安装Python库：pip install -r requirements.txt
2. 安装必要工具（需提前配置好环境变量）：
   - Nmap（端口扫描）
   - sqlmap（SQL注入检测）
   - Subfinder（子域枚举）

## 使用步骤

### 1. 训练AI漏洞识别模型（首次使用需执行）
python train_ai_vuln_model.py
执行后将生成：
- `ai_vuln_model.pth`：AI模型文件
- `vuln_feature_dataset.csv`：训练数据集
- `scaler_mean.npy`/`scaler_std.npy`：数据标准化参数

### 2. 运行全流程渗透测试
# 基础扫描（仅检测漏洞）
python ai_bot_pipeline.py -u http://目标URL

# 完整渗透（含反弹Shell）
python ai_bot_pipeline.py -u http://目标URL -ip 攻击机IP -p 攻击机端口
示例：python ai_bot_pipeline.py -u http://test.dvwa.com -ip 192.168.1.100 -p 4444
## 输出文件

1. 日志文件：保存在`./pentest_logs/日期时间`目录下
   - `main_log.txt`：主流程操作日志
   - `http_requests.txt`：HTTP请求与响应记录

2. 报告文件：
   - `info_report.md`：信息收集报告
   - `ai_bot_pentest_report_目标URL.md`：全流程渗透测试报告

## 注意事项

1. 仅用于合法授权的渗透测试，禁止未授权使用
2. 复杂环境下可能需要调整Payload和探测策略
3. 可通过扩展`vuln_feature_dataset.csv`提升AI模型准确率
4. 业务逻辑漏洞探测可能需要根据目标业务定制化调整
