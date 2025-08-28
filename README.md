# AwvsAutomate
**AwvsAutomate** 是一个非官方的 Acunetix 命令行界面（CLI）工具，旨在简化大规模目标的自动化渗透测试和漏洞狩猎。在进行大型渗透测试时，它是一个宝贵的助手，能够轻松启动或停止多个 Acunetix 扫描。此外，其多功能性可以无缝集成到枚举包装器或单行命令中，通过其管道功能提供高效的控制。

![banner.png](https://github.com/N1Ch01aS/AwvsAutomate/blob/main/banner.png)

## 安装
```bash
git clone https://github.com/N1Ch01aS/AwvsAutomate.git
cd AwvsAutomate
chmod +x AwvsAutomate.py
pip3 install -r requirements.txt
```

Linux系统可能pip安装会出现“error: externally-managed-environment”

使用以下命令安装即可

```
pip3 install -r requirements.txt --break-system-packages
```

## 配置 (config.json)

在使用 **AwvsAutomate** 之前，需要在 **AwvsAutomate** 目录内设置 `config.json` 配置文件：
```json
{
    "url": "https://localhost",
    "port": 3443,
    "api_key": "API_KEY"
}
```
- **URL** 和 **PORT** 参数默认设置为 Acunetix 的默认配置，但可以根据您的 Acunetix 设置进行更改。
- 将 **API_KEY** 替换为您的 Acunetix API 密钥。密钥可从用户配置文件页面获取，地址为 `https://localhost:3443/#/profile`。

## 使用
使用帮助参数（`-h`）可以获取特定操作的详细帮助信息：
```bash
                                       __  _                 ___
          ____ ________  ______  ___  / /_(_)  __      _____/ (_)
         / __ `/ ___/ / / / __ \/ _ \/ __/ / |/_/_____/ ___/ / /
        / /_/ / /__/ /_/ / / / /  __/ /_/ />  </_____/ /__/ / /
        \__,_/\___/\__,_/_/ /_/\___/\__/_/_/|_|      \___/_/_/

                           -: By N1Ch01aS :-

    
使用 Acunetix API 启动或停止扫描

可选参数：
  -h, --help   显示此帮助信息并退出

位置参数：
  {scan,stop,list,report}
    scan       启动扫描，使用 scan -h 查看详情
    stop       停止扫描
    list       列出所有扫描
    report     生成或下载报告
```

## 扫描操作
要启动扫描，请使用 `scan` 命令：
```bash
./AwvsAutomate.py scan -h
    
使用 Acunetix API 启动扫描

可选参数：
  -h, --help            显示此帮助信息并退出
  -p, --pipe            从管道读取输入
  -d DOMAIN, --domain DOMAIN
                        要扫描的域名
  -f FILE, --file FILE  包含要扫描的 URL 列表的文件
  -t {full,high,weak,crawl,xss,sql}, --type {full,high,weak,crawl,xss,sql}
                        高危漏洞扫描、弱密码扫描、仅爬取、XSS 扫描、SQL 注入扫描、完整扫描（默认）
```

### 扫描单一目标
使用 `-d` 标志指定单一站点进行扫描：
```bash
./AwvsAutomate.py scan -d https://www.google.com
```

### 扫描多个目标
要扫描多个域名，请将域名添加到文件中，然后使用 `-f` 标志指定文件名：
```bash
./AwvsAutomate.py scan -f domains.txt
```

### 管道
支持通过 `-p` 标志从管道输入进行操作：
```bash
cat domain.txt | ./AwvsAutomate.py scan -p
```
这非常适合与其他工具结合使用。例如，可以结合 **subfinder** 和 **httpx**，将输出通过管道传递给 AwvsAutomate 进行大规模扫描：
```bash
subfinder -silent -d google.com | httpx -silent | ./AwvsAutomate.py scan -p
```

### 扫描类型
使用 `-t` 标志定义扫描类型。例如，仅检测 **SQL 注入漏洞**：
```bash
./AwvsAutomate.py scan -d https://www.google.com -t sql
```

## 停止操作
使用 `stop` 命令停止扫描，可通过 `-d` 标志指定域名，或使用 `-a` 标志停止所有正在运行的扫描：
```bash
./AwvsAutomate.py stop -h

                                       __  _                 ___
          ____ ________  ______  ___  / /_(_)  __      _____/ (_)
         / __ `/ ___/ / / / __ \/ _ \/ __/ / |/_/_____/ ___/ / /
        / /_/ / /__/ /_/ / / / /  __/ /_/ />  </_____/ /__/ / /
        \__,_/\___/\__,_/_/ /_/\___/\__/_/_/|_|      \___/_/_/

                           -: By N1Ch01aS :-

    
使用 Acunetix API 停止扫描

可选参数：
  -h, --help            显示此帮助信息并退出
  -d DOMAIN, --domain DOMAIN
                        要停止扫描的域名
  -a, --all             停止所有正在运行的扫描
```

### 示例
停止特定域名的扫描：
```bash
./AwvsAutomate.py stop -d https://www.google.com
```

停止所有扫描：
```bash
./AwvsAutomate.py stop -a
```

## 列出扫描
使用 `list` 命令查看所有扫描的详细信息，包括扫描 ID、目标、状态和开始时间：
```bash
./AwvsAutomate.py list
```

## 报告操作
使用 `report` 命令生成或下载扫描报告：
```bash
./AwvsAutomate.py report -h

                                       __  _                 ___
          ____ ________  ______  ___  / /_(_)  __      _____/ (_)
         / __ `/ ___/ / / / __ \/ _ \/ __/ / |/_/_____/ ___/ / /
        / /_/ / /__/ /_/ / / / /  __/ /_/ />  </_____/ /__/ / /
        \__,_/\___/\__,_/_/ /_/\___/\__/_/_/|_|      \___/_/_/

                           -: By N1Ch01aS :-

    
使用 Acunetix API 生成或下载报告

可选参数：
  -h, --help            显示此帮助信息并退出
  -S SCAN_ID, --scan-id SCAN_ID
                        要生成报告的扫描 ID
  -G {developer,comprehensive}, --generate {developer,comprehensive}
                        生成报告类型：developer 或 comprehensive
  -D [DOWNLOAD], --download [DOWNLOAD]
                        下载指定扫描 ID 的报告（默认：当前目录）
  -l, --list            列出所有可用报告
```

### 生成报告
为特定扫描生成报告，指定扫描 ID 和报告类型（`developer` 或 `comprehensive`）：
```bash
./AwvsAutomate.py report -S <scan_id> -G developer
```

### 下载报告
下载指定扫描 ID 的报告，可选指定输出目录：
```bash
./AwvsAutomate.py report -S <scan_id> -D /path/to/output
```

### 列出报告
查看所有可用报告，包括报告 ID、扫描 ID、报告类型、状态和下载链接：
```bash
./AwvsAutomate.py report -l
```

## 注意事项
- AwvsAutomate 仅接受带有 `http://` 或 `https://` 的域名。
- 确保 `config.json` 中的 API 密钥有效，以避免认证错误。
- 下载报告时，工具会检查报告状态，只有状态为 `completed` 的报告才能下载。

## 下载
您可以通过以下方式下载 **AwvsAutomate**：
1. **GitHub 仓库**: https://github.com/N1Ch01aS/AwvsAutomate.git
