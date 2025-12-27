#!/usr/bin/env python3
import argparse
import sys
sys.dont_write_bytecode = True

import os
import re
import mmap
import json
import hashlib
from pathlib import Path
from datetime import datetime

# 检查yara库是否安装
try:
    import yara
    HAS_YARA = True
except ImportError:
    HAS_YARA = False

class YaraForenScanner:
    def __init__(self, output_dir="forensic_report"):
        self.output_dir = Path(output_dir)
        self.output_dir.mkdir(exist_ok=True)
        
        # 初始化数据结构
        self.forensic_findings = []
        self.scan_stats = {
            'files_processed': 0,      # 找到匹配的文件数
            'total_files_scanned': 0,  # 实际扫描的文件总数
            'artifacts_found': 0,
            'start_time': datetime.now().isoformat(),
            'yara_matches': 0,
            'regex_matches': 0
        }
        
        # 加载特征库
        self.yara_rules = None
        self.custom_patterns = {}
        self.forensic_patterns = {}
        self._load_forensic_signatures()
    

    def _load_forensic_signatures(self):
        signatures_dir = Path("signatures")
        signatures_dir.mkdir(exist_ok=True)
        
        # 创建默认特征目录结构
        (signatures_dir / "yara").mkdir(exist_ok=True)
        (signatures_dir / "regex").mkdir(exist_ok=True)
        
        # 1. 加载YARA规则（如果yara库可用）
        if not HAS_YARA:
            print("[!] YARA功能不可用，跳过YARA规则加载")
            self.yara_rules = None
        else:
            yara_dir = signatures_dir / "yara"
            try:
                yara_files = list(yara_dir.glob("*.yar"))
                if yara_files:
                    self.yara_rules = yara.compile(filepaths={f.stem: str(f) for f in yara_files})
                    print(f"[+] 加载 {len(yara_files)} 个YARA规则")
                else:
                    self.yara_rules = None
            except yara.Error as e:
                print(f"[!] YARA规则加载失败: {str(e)}")
                self.yara_rules = None
            except Exception as e:
                print(f"[!] YARA目录读取错误: {str(e)}")
                self.yara_rules = None
        
        # 2. 加载自定义正则模式
        regex_dir = signatures_dir / "regex"
        try:
            for pattern_file in regex_dir.glob("*.json"):
                try:
                    with open(pattern_file, 'r', encoding='utf-8') as f:
                        patterns = json.load(f)
                        self.custom_patterns.update(patterns)
                    print(f"[*] 从 {pattern_file.name} 加载 {len(patterns)} 个正则模式")
                except Exception as e:
                    print(f"[!] 加载模式文件 {pattern_file} 失败: {str(e)}")
        except Exception as e:
            print(f"[!] 正则模式目录读取错误: {str(e)}")
        
        # 3. 加载内置默认模式
        self._load_default_patterns()
    

    def _load_default_patterns(self):
        default_patterns = {
            # 凭据和认证相关
            'credential_hashes': rb'(?i)([a-f0-9]{32}:[a-f0-9]{32}|[a-f0-9]{65}:[a-f0-9]{65}|\$NT\$[a-f0-9]{32}|\$LM\$[a-f0-9]{32}|\$DCC2\$[a-f0-9]+\$[a-f0-9]+\$[a-f0-9]+)',
            'dpapi_secrets': rb'(?i)([a-f0-9]{64}:[a-f0-9]{64}|\bDPAPI_SYSTEM\b|Microsoft\\Crypto|\\x01\\x00\\x00\\x00\\xd0\\x8c\\x9d\\xdf\\x01\\x15\\xd1\\x11\\x8c\\x7a\\x00\\xc0\\x4f\\xc2\\x97\\xeb)',
            'jwt_tokens': rb'(?i)\beyJhbGciOiJ[A-Za-z0-9-_]+\.[A-Za-z0-9-_]+\.[A-Za-z0-9-_]{20,}\b',
            'api_keys': rb'(?i)\b(?:ak_[a-z0-9]{20,32}|sk_[a-z0-9]{40,64}|[a-z0-9]{32}_[a-z0-9]{32}|[a-f0-9]{8}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{12}|gh[op]_[a-zA-Z0-9]{36}|xox[bp]-[a-zA-Z0-9-]+)\b',
            
            # 网络和通信
            'ip_addresses': rb'\b(?:(?:25[0-5]|2[0-4][0-9]|1[0-9]{2}|[1-9]?[0-9])\.){3}(?:25[0-5]|2[0-4][0-9]|1[0-9]{2}|[1-9]?[0-9])(?::(?:[1-9]|[1-9][0-9]{1,3}|[1-5][0-9]{4}|6[0-4][0-9]{3}|65[0-4][0-9]{2}|655[0-2][0-9]|6553[0-5]))?\b',
            'mac_addresses': rb'\b(?:[0-9A-Fa-f]{2}[:-]){5}[0-9A-Fa-f]{2}\b',
            'url_patterns': rb'\bhttps?://(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}(?::\d{1,5})?(?:/[\w\-\.~!$&\'()*+,;=:@%]*)*(?:\?[\w\-\.~!$&\'()*+,;=:@%/?]*)?(?:#[\w\-\.~!$&\'()*+,;=:@%/?]*)?\b',
            'email_addresses': rb'\b[A-Z0-9._%+-]+@[A-Z0-9.-]+\.[A-Z]{2,}\b',
            'domain_names': rb'\b(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,}\b',
            
            # 系统关键信息
            'registry_paths': rb'(?i)\b(?:HKLM\\|HKCU\\|HKCR\\|HKU\\|HKEY_[A-Z_]+|SAM|SECURITY|SYSTEM|SOFTWARE)\b',
            'system_processes': rb'(?i)\b(?:lsass\.exe|csrss\.exe|smss\.exe|winlogon\.exe|services\.exe)\b',
            'service_names': rb'(?i)\b(?:svchost\.exe|spoolsv\.exe|lsm\.exe|taskhost\.exe)\b',
            
            # 恶意软件特征
            'injection_apis': rb'(?i)\b(?:CreateRemoteThread|WriteProcessMemory|VirtualAllocEx|NtCreateThreadEx|QueueUserAPC)\b',
            'process_hollowing': rb'(?i)\b(?:NtUnmapViewOfSection|ZwUnmapViewOfSection|SetThreadContext)\b',
            'suspicious_cmds': rb'(?i)\b(?:powershell.*-enc|cmd.*/c|%COMSPEC%|%WINDIR%|%TEMP%|schtasks.*/create)\b',
            'obfuscated_code': rb'(?i)\b(?:eval\(|exec\(|fromCharCode|String\.fromCharCode|%u[0-9a-f]{4})\b',
            
            # 持久化机制
            'registry_persistence': rb'(?i)\b(?:Run\\\\|RunOnce\\\\|Services\\\\|Winlogon\\\\|Policies\\\\Explorer\\\\Run)\b',
            'scheduled_tasks': rb'(?i)\b(?:\\.job|TaskScheduler|SchTasks|\\.xml.*<Exec>.*<Command>)\b',
            'wmi_persistence': rb'(?i)\b(?:__FilterToConsumerBinding|EventFilter|EventConsumer|__EventFilter)\b',
            'startup_items': rb'(?i)\b(?:Start Menu\\\\Programs\\\\Startup|Common Startup|autostart)\b',
            
            # 文件系统特征
            'executable_files': rb'(?i)\b\\.(?:exe|dll|sys|scr|bat|ps1|vbs|js)(?:\\x00|\\\\|/|\\s|$)',
            'suspicious_extensions': rb'(?i)\b\\.(?:tmp|bak|old|temp|download|partial)\\.(?:exe|dll|sys)',
            'hidden_files': rb'(?i)\b(?:\\$Recycle\\.Bin|System Volume Information|\\.\\w+\\.sw[op]|\\.\\w+\\.tmp)\b',
            'temp_executables': rb'(?i)\b(?:AppData\\\\Local\\\\Temp\\\\[^\\\\]+\\.exe|TEMP\\\\[^\\\\]+\\.dll)\b',
            
            # 加密和密钥材料
            'private_keys': rb'(?i)\b-{5}BEGIN (?:RSA|DSA|EC|OPENSSH) PRIVATE KEY-{5}|-{5}BEGIN PRIVATE KEY-{5}|-{5}BEGIN ENCRYPTED PRIVATE KEY-{5}',
            'certificates': rb'(?i)\b-{5}BEGIN CERTIFICATE-{5}|\\.(?:pfx|p12|cer|crt|pem)\b',
            'pgp_keys': rb'(?i)\b-{5}BEGIN PGP|-{5}END PGP|PGP SIGNATURE',
            
            # 内存取证特定模式
            'pe_headers': rb'(?i)\bMZ[\\x00-\\xff]{58,60}PE\\0\\0|This program cannot be run in DOS mode|This program must be run under Win32',
            'process_structures': rb'(?i)\b(?:_EPROCESS|_ETHREAD|_PEB|_TEB|KPROCESS|KTHREAD)\b',
            'driver_objects': rb'(?i)\b(?:_DRIVER_OBJECT|_DEVICE_OBJECT|_IRP|IoCreateDevice)\b',
            
            # 应用程序特定数据
            'browser_data': rb'(?i)\b(?:cookie\\.sqlite|places\\.sqlite|history|login|password)\b',
            'database_files': rb'(?i)\\.(?:sqlite|mdb|accdb|db|sql)\b',
            'config_files': rb'(?i)\\.(?:config|ini|conf|xml|json|yaml|yml)(?:\\x00|\\\\|/|\\s|$)',
            
            # 网络协议特征
            'http_headers': rb'(?i)\b(?:GET /|POST /|HTTP/1\\.1|Host: |User-Agent: |Cookie: )\b',
            'dns_queries': rb'(?i)(?:\\x00\\x01|\\x00\\x1c|\\x80\\x00|\\x00\\x0f)',
            'tcp_streams': rb'(?i)(?:\\x00\\x50|\\x00\\x35|\\x01\\xbb|\\x04\\x00)',
            
            # 反调试和反分析
            'anti_debug': rb'(?i)\b(?:IsDebuggerPresent|CheckRemoteDebuggerPresent|OutputDebugString)\b',
            'vm_detection': rb'(?i)\b(?:VMware|VirtualBox|Xen|KVM|QEMU|vbox|vmware|hyper-v)\b',
            'sandbox_checks': rb'(?i)\b(?:sandbox|malware analysis|Cuckoo|JoeBox|Anubis|threatgrid)\b',
            
            # 漏洞利用特征
            'rop_gadgets': rb'(?i)(?:\\xc3[\\x00-\\xff]{0,10}){4,}',  # ROP链特征
            'shellcode_patterns': rb'(?i)(?:\\xcc\\xcc\\xcc\\xcc\\xcc\\xcc|\\x90\\x90\\x90\\x90\\x90\\x90|\\xeb\\xfe\\xeb\\xfe)',
            'exploit_strings': rb'(?i)\b(?:ms[0-9]{2,3}-[0-9]{3,4}|CVE-[0-9]{4}-[0-9]{4,5})\b',
            
            # 数据泄露特征
            'credit_cards': rb'\b(?:4[0-9]{12}(?:[0-9]{3})?|5[1-5][0-9]{14}|6(?:011|5[0-9][0-9])[0-9]{12}|3[47][0-9]{13}|3(?:0[0-5]|[68][0-9])[0-9]{11}|(?:2131|1800|35\d{3})\d{11})\b',
            'social_security': rb'\b(?!000|666|9\d{2})[0-8]\d{2}-(?!00)\d{2}-(?!0000)\d{4}\b',
            'phone_numbers': rb'\b(?:\+?1[-.\s]?)?\(?([2-9][0-8][0-9])\)?[-.\s]?([2-9][0-9]{2})[-.\s]?([0-9]{4})\b',
            
            # 其他敏感模式
            'base64_data': rb'(?i)(?:[A-Za-z0-9+/]{4}){6,}(?:[A-Za-z0-9+/]{2}==|[A-Za-z0-9+/]{3}=)?(?<![A-Za-z]{12})',
            'hex_strings': rb'(?:\b[0-9a-fA-F]{2}\s){8,}[0-9a-fA-F]{2}\b',
            'unicode_strings': rb'(?:[^\x00]\x00){16,}',
            
            # WEB攻击流量检测
            'sql_injection': rb'(?i)\b(?:union\s+select|select\s+from|insert\s+into|update\s+set|delete\s+from|drop\s+table|exec\(|xp_cmdshell|waitfor\s+delay|sleep\(\d+\)|benchmark\(\d+\))\b',
            'xss_attacks': rb'(?i)\b(?:<script>|javascript:|onerror=|onload=|onmouseover=|alert\(|document\.cookie|window\.location|eval\(|String\.fromCharCode)\b',
            'path_traversal': rb'(?i)\b(?:\.\./|\.\.\\|\.\.%2f|\.\.%5c|\.\.%255c|\.\.%252f|/etc/passwd|/windows/win\.ini|C:\\windows\\system32)\b',
            'command_injection': rb'(?i)(?:;\s*(?:ls|cat|whoami|id|pwd|ifconfig|ipconfig|netstat|ps|bash|sh|cmd|powershell)\b|`(?:ls|cat|whoami|id|pwd|ifconfig|ipconfig|netstat|ps|bash|sh|cmd|powershell)[^`]{0,30}`|\$\((?:ls|cat|whoami|id|pwd|ifconfig|ipconfig|netstat|ps|bash|sh|cmd|powershell)[^)]{0,30}\))',
            
            # WEB木马特征
            'antsword_webshell': rb'(?i)\b(?:antsword|as_.*key|@ini_set.*display_errors|@set_time_limit\(0\)|eval\(base64_decode|eval\(gzuncompress|eval\(gzinflate)\b',
            'godzilla_webshell': rb'(?i)\b(?:godzilla|gz_.*key|pass.*TheKing|@error_reporting\(0\)|@ini_set\(.*0\)|eval\(.*POST|assert\(.*POST)\b',
            'behinder_webshell': rb'(?i)\b(?:behinder|bypass.*disable|@ini_set\(.*0\)|base64_decode.*eval|gzuncompress.*eval)\b',
            'china_chopper': rb'(?i)\b(?:china.*chopper|chopper|@eval\(.*_POST|eval\(request\(|execute\(request\(\))\b',
            
            # 常见木马流量特征
            'reverse_shell': rb'(?i)\b(?:bash.*-i|nc.*-e|telnet.*/bin/sh|python.*-c.*import.*socket|perl.*-e.*use.*Socket|php.*-r.*fsockopen)\b',
            'bind_shell': rb'(?i)\b(?:nc.*-l.*-p|ncat.*-l.*-p|socat.*TCP-LISTEN|busybox.*telnetd)\b',
            'meterpreter': rb'(?i)\b(?:metsrv|meterpreter|stdapi|priv|extapi|migrate)\b',
            'cobalt_strike': rb'(?i)\b(?:beacon|jquery-\d\.\d\.\d\.min\.js|\./\./\./\./\./\./\./\./\./\./\./\./\./\./\./\./\.)\b',
            
            # 加密特征流量
            'encrypted_cmdline': rb'(?i)\b(?:openssl.*(?:enc|aes|des|rc4)|gpg.*(?:--encrypt|--symmetric)|bcrypt.*-e|ccrypt.*-e|7z.*-p|rar.*-p|zip.*-P|aescrypt|truecrypt|veracrypt|bitlocker|encfs|cryptsetup|dm-crypt|luks|pkcs|aes-(?:128|192|256)|des-(?:ede3|ede)|blowfish|twofish|serpent|cast5|rc4|rc2|idea|seed\b|camellia|chacha20|salsa20|poly1305)\b',
            'encrypted_key_formats': rb'(?i)(?:-----BEGIN (?:RSA|DSA|EC|OPENSSH) (?:PRIVATE|PUBLIC) KEY-----|-----BEGIN (?:ENCRYPTED|RSA ENCRYPTED) PRIVATE KEY-----|-----BEGIN PGP (?:MESSAGE|PRIVATE KEY BLOCK)-----)',
            'encrypted_traffic': rb'(?i)(?:\\x00\\x01\\x02\\x03\\x04\\x05\\x06\\x07|\\x08\\x09\\x0a\\x0b\\x0c\\x0d\\x0e\\x0f|\\x10\\x11\\x12\\x13\\x14\\x15\\x16\\x17|\\x18\\x19\\x1a\\x1b\\x1c\\x1d\\x1e\\x1f|\\x16\\x03[\\x00-\\x03]|\\x17\\x03[\\x00-\\x03]|\\x14\\x03[\\x00-\\x03]|\bTLS_\b|\bSSL_\b|\b(?:AES|DES|3DES|RC4|Blowfish|Twofish|Serpent|CAST5|IDEA|SEED\b|Camellia|ChaCha20|Salsa20|Poly1305)_|\b(?:RSA|DSA|ECDSA|ECDH|DH|EC)_|\b(?:SHA1|SHA256|SHA384|SHA512|MD5|HMAC)_|\b(?:GCM|CCM|OCB|EAX)_|\b(?:PKCS1|PKCS5|PKCS7|PKCS8|PKCS12)\b)',
            'encrypted_packet_data': rb'(?i)(?:\\x16\\x03[\\x00-\\x03][\\x00-\\xff]{2,}|\\x17\\x03[\\x00-\\x03][\\x00-\\xff]{2,}|\b(?:TLS_|SSL_)\b|\\x00\\x01\\x02\\x03\\x04\\x05\\x06\\x07[\\x00-\\xff]{8,})',
            'ssl_tls_handshake': rb'(?i)(?:\\x16\\x03[\\x00-\\x03]|\bClientHello\b|\bServerHello\b|\bCertificate\b|\bServerKeyExchange\b|\bClientKeyExchange\b|\bFinished\b|\bChangeCipherSpec\b)',
            'tor_traffic': rb'(?i)\b(?:\\.onion|tor\\s+project|orport|dirport|bridge)\b',
            'vpn_protocols': rb'(?i)\b(?:openvpn|wireguard|ipsec|pptp|l2tp|ikev[12])\b',
            'openssl_encrypted_data': rb'(?i)(?:U2FsdGVkX[0-9A-Za-z+/]{20,}|Salted__[0-9A-Za-z+/]{20,})',
            'aes_encrypted_data': rb'(?i)\b(?:AES-[0-9]{3}-(?:CBC|ECB|CFB|OFB|CTR)|AES_(?:128|192|256)_(?:CBC|ECB|CFB|OFB|CTR))\b|\\x00{16}[\\x00-\\xff]{16,}|\b[a-f0-9]{32}:[a-f0-9]{32,64}\b',
            'des_encrypted_data': rb'(?i)\b(?:DES-(?:CBC|ECB|CFB|OFB)|3DES-(?:CBC|ECB|CFB|OFB)|DESede|TripleDES)\b|\b[a-f0-9]{16}:[a-f0-9]{16,32}\b',
            'rc4_encrypted_data': rb'(?i)\b(?:RC4|ARC4|ARCFOUR)\b|\b[a-f0-9]{40,}:[a-f0-9]{40,}\b',
            'other_encrypted_data': rb'(?i)\b(?:Blowfish|Twofish|Serpent|CAST5|IDEA|SEED\b|Camellia|ChaCha20|Salsa20|Poly1305)\b|\b[a-f0-9]{8,}:[a-f0-9]{8,}\b',

            # 渗透测试工具特征
            'metasploit_framework': rb'(?i)\b(?:msfconsole|msfvenom|msfpayload|msfencode|meterpreter|msf\\s+exploit)\b',
            'nmap_scans': rb'(?i)\b(?:nmap.*-s[STUVCXA]|nmap.*-p\\s*\\d+|nmap.*-O|nmap.*-sV|nmap.*-sC|nmap.*--script)\b',
            'burpsuite_traffic': rb'(?i)\b(?:burpsuite|burp\\s+suite|intruder|repeater|decoder|comparer|sequencer)\b',
            'sqlmap_attacks': rb'(?i)\b(?:sqlmap.*--dbs|sqlmap.*--tables|sqlmap.*--columns|sqlmap.*--dump|sqlmap.*--batch)\b',
            'nessus_scans': rb'(?i)\b(?:nessus|tenable|\\.nessus|nessuscli|nessusd)\b',
            'openvas_scans': rb'(?i)\b(?:openvas|gvm|gsad|gvmd|openvas-scanner)\b',
            'wireshark_capture': rb'(?i)\b(?:wireshark|tshark|capinfos|editcap|mergecap|text2pcap)\b',
            
            # 目录扫描和404错误特征
            'directory_bruteforce': rb'(?i)\b(?:dirb|dirbuster|gobuster|wfuzz|ffuf|dirsearch|\\.git/|\\.svn/|\\.env|wp-admin|admin\\.php)\b',
            'http_404_errors': rb'(?i)\b(?:404\\s+Not\\s+Found|HTTP/1\\.1\\s+404|Status:\\s+404|The\\s+requested\\s+URL.*was\\s+not\\s+found)\b',
            'web_scanner_signatures': rb'(?i)\b(?:acunetix|netsparker|appscan|webinspect|nikto|w3af|arachni|skipfish)\b',
            
            # 网络侦察工具
            'whois_queries': rb'(?i)\b(?:whois.*\\.[a-z]{2,}|domain.*whois|registrar.*whois)\b',
            'dns_enumeration': rb'(?i)\b(?:dnsenum|dnsrecon|fierce|subfinder|sublist3r|amass|theharvester)\b',
            'network_mappers': rb'(?i)\b(?:netdiscover|arp-scan|angry\\s+ip\\s+scanner|advanced\\s+ip\\s+scanner)\b',
            
            # 漏洞利用框架
            'exploit_frameworks': rb'(?i)\b(?:exploit-db|searchsploit|rapid7|core\\s+impact|canvas|immunity\\s+debugger)\b',
            'payload_generators': rb'(?i)\b(?:msfvenom|veil|the-backdoor-factory|shellter|unicorn)\b',
            
            # 社会工程工具
            'social_engineering': rb'(?i)\b(?:setoolkit|social-engineer-toolkit|beef|browser-exploitation)\b',
            
            # 密码攻击工具
            'password_attacks': rb'(?i)\b(?:john.*ripper|hashcat|hydra|medusa|ncrack|aircrack-ng|reaver|wpscan)\b',
            
            # 后渗透工具
            'post_exploitation': rb'(?i)\b(?:mimikatz|kiwi|sekurlsa|procdump|lsadump|pwdump|fgdump|empire|powersploit)\b',
            
            # 网络嗅探工具
            'network_sniffers': rb'(?i)\b(?:ettercap|dsniff|cain\\s+and\\s+abel|responder|bettercap)\b',
            
            # 无线攻击工具
            'wireless_attacks': rb'(?i)\b(?:airmon-ng|airodump-ng|aireplay-ng|aircrack-ng|kismet|wifite)\b',
            
            # 取证和分析工具
            'forensic_tools': rb'(?i)\b(?:volatility|sleuthkit|autopsy|ftkimager|encase|x-ways|wireshark|tshark)\b',
            
            # 反病毒规避特征
            'av_evasion': rb'(?i)\b(?:veil-evasion|shellter|the-backdoor-factory|hyperion|pecloak)\b',
            
            # 持久化工具
            'persistence_tools': rb'(?i)\b(?:psexec|wmic|schtasks|at\\s+command|sc\\s+create|reg\\s+add)\b',
            
            # 数据渗出特征
            'data_exfiltration': rb'(?i)\b(?:base64.*-d|base64.*-decode|curl.*-T|wget.*--post-file|nc.*-w|socat.*TCP)\b',
            
            # 日志清除特征
            'log_clearing': rb'(?i)\b(?:wevtutil.*cl|Clear-EventLog|echo.*>.*null|rm.*-rf|del.*/f.*/q)\b',
            
            # 时间戳操作
            'timestomp': rb'(?i)\b(?:touch.*-t|SetFileTime|timestomp|Set-ItemProperty.*LastWriteTime)\b',
            
            # 进程注入特征
            'process_injection': rb'(?i)\b(?:CreateRemoteThread|VirtualAllocEx|WriteProcessMemory|QueueUserAPC|NtCreateThreadEx)\b',
            
            # 反分析特征
            'anti_analysis': rb'(?i)\b(?:IsDebuggerPresent|CheckRemoteDebuggerPresent|OutputDebugString|rdtsc|cpuid)\b',
            
            # 虚拟机检测
            'vm_detection': rb'(?i)\b(?:VMware|VirtualBox|Xen|KVM|QEMU|vbox|vmware|hyper-v)\b',
            
            # 沙箱检测
            'sandbox_detection': rb'(?i)\b(?:sandbox|malware\\s+analysis|cuckoo|joebox|anubis|threatgrid)\b',
            
            # 调试器检测
            'debugger_detection': rb'(?i)\b(?:OllyDbg|ImmunityDebugger|WinDbg|x64dbg|IDA\\s+Pro|Process\\s+Monitor)\b',
            
            # 系统信息收集
            'system_recon': rb'(?i)\b(?:systeminfo|whoami|ipconfig|ifconfig|netstat|tasklist|ps\\s+aux|getmac)\b',
            
            # 网络连接特征
            'network_connections': rb'(?i)\b(?:netstat.*-ano|netstat.*-an|ss.*-tulpn|lsof.*-i|Get-NetTCPConnection)\b',
            
            # 服务枚举
            'service_enumeration': rb'(?i)\b(?:sc\\s+query|net\\s+start|Get-Service|service.*--status-all|chkconfig)\b',
            
            # 用户账户枚举
            'user_enumeration': rb'(?i)\b(?:net\\s+user|net\\s+localgroup|Get-LocalUser|Get-LocalGroup|who\\s+-a)\b',
            
            # 文件系统枚举
            'filesystem_enumeration': rb'(?i)\b(?:dir.*/s|ls.*-la|tree.*/f|find.*-name|Get-ChildItem.*-Recurse)\b',
            
            # 注册表操作
            'registry_operations': rb'(?i)\b(?:reg\\s+query|reg\\s+add|reg\\s+delete|reg\\s+export|Get-ItemProperty)\b',
            
            # 计划任务操作
            'scheduled_tasks_ops': rb'(?i)\b(?:schtasks.*/create|schtasks.*/query|at.*\\d{2}:\\d{2}|Get-ScheduledTask)\b',
            
            # WMI操作
            'wmi_operations': rb'(?i)\b(?:wmic.*process|wmic.*service|wmic.*share|Get-WmiObject|Get-CimInstance)\b',
            
            # PowerShell特征
            'powershell_ops': rb'(?i)\b(?:powershell.*-EncodedCommand|powershell.*-executionpolicy.*bypass|iex.*\(New-Object)\b',
            
            # 命令行混淆
            'cmd_obfuscation': rb'(?i)\b(?:cmd.*/c.*echo|set.*=&&|for.*/f.*in.*do|%\\w+%|^\\w+\\^\\w+)\b',
            
            # 环境变量操作
            'env_variable_ops': rb'(?i)\b(?:set.*=|setx.*|Get-ChildItem.*Env:|echo.*%\\w+%|$env:\\w+)\b',
            
            # 进程操作
            'process_operations': rb'(?i)\b(?:taskkill.*/f|taskkill.*/im|Stop-Process|kill.*-9|pkill.*-f)\b',
            
            # 文件操作特征
            'file_operations': rb'(?i)\b(?:copy.*/y|move.*/y|rm.*-rf|del.*/f.*/q|Remove-Item.*-Force)\b',
            
            # 权限提升特征
            'privilege_escalation': rb'(?i)(?:\brunas\s+.*/user|\bsudo\s+.*-i|\bsu\s+.*-|\bGet-System\b|\bbypassuac\b)',
            
            # 横向移动特征
            'lateral_movement': rb'(?i)\b(?:psexec.*\\\\|wmic.*/node:|schtasks.*/s|sc.*\\\\|Invoke-Command)\b',
            
            # 域渗透特征
            'domain_enumeration': rb'(?i)\b(?:net.*group.*domain|net.*user.*/domain|dsquery.*|Get-ADUser|Get-ADGroup)\b',
            
            # 黄金票据特征
            'golden_ticket': rb'(?i)\b(?:kerberos::golden|mimikatz.*golden|golden.*ticket)\b',
            
            # 白银票据特征
            'silver_ticket': rb'(?i)\b(?:kerberos::silver|mimikatz.*silver|silver.*ticket)\b',
            
            # Pass-the-Hash特征
            'pass_the_hash': rb'(?i)\b(?:sekurlsa::pth|mimikatz.*pth|psexec.*-hashes)\b',
            
            # Over-Pass-the-Hash特征
            'overpass_the_hash': rb'(?i)\b(?:sekurlsa::ekeys|kerberos::ask|asktgs)\b',
            
            # DCSync攻击特征
            'dcsync_attack': rb'(?i)\b(?:lsadump::dcsync|mimikatz.*dcsync|DSInternals)\b',
            
            # NTDS.dump提取特征
            'ntds_dump': rb'(?i)\b(?:ntdsutil.*ac.*ifm|vssadmin.*create.*shadow|diskshadow)\b',
            
            # LSASS内存转储特征
            'lsass_dump': rb'(?i)\b(?:procdump.*-ma.*lsass|sqldumper.*lsass|out-minidump.*lsass)\b',
            
            # 注册表凭据提取特征
            'registry_creds': rb'(?i)\b(?:reg.*save.*HKLM\\SAM|reg.*save.*HKLM\\SYSTEM|reg.*save.*HKLM\\SECURITY)\b',
            
            # 浏览器凭据提取特征
            'browser_creds': rb'(?i)\b(?:LaZagne.*browsers|mimikatz.*dpapi|SharpChromium)\b',
            
            # WiFi凭据提取特征
            'wifi_creds': rb'(?i)\b(?:netsh.*wlan.*show.*profile|LaZagne.*wifi|WirelessKeyView)\b',
            
            # 剪贴板监控特征
            'clipboard_monitor': rb'(?i)\b(?:Get-Clipboard|clip|xclip|xsel|pbpaste)\b',
            
            # 键盘记录特征
            'keylogger': rb'(?i)\b(?:SetWindowsHookEx|GetAsyncKeyState|keylogger|logkeys|pykeylogger)\b',
            
            # 屏幕捕获特征
            'screenshot_capture': rb'(?i)\b(?:BitBlt|PrintWindow|screenshot|greenshot|snippingtool)\b',
            
            # 麦克风捕获特征
            'microphone_capture': rb'(?i)\b(?:waveInOpen|AudioCapture|recorder|sox.*record|arecord)\b',
            
            # 摄像头捕获特征
            'webcam_capture': rb'(?i)\b(?:capCreateCaptureWindow|DirectShow|webcam|ffmpeg.*video|mplayer)\b',
            
            # 文档窃取特征
            'document_theft': rb'(?i)\b(?:\\.docx|\\.xlsx|\\.pptx|\\.pdf|\\.txt.*copy|\\.csv.*upload)\b',
            
            # 压缩文件特征
            'archive_files': rb'(?i)\b(?:\\.zip.*password|\\.rar.*-p|\\.7z.*-p|tar.*-czf|gzip.*-c)\b',
            
            # 隐写术特征
            'steganography': rb'(?i)\b(?:steghide|outguess|openstego|zsteg|stegsolve)\b',
            
            # 隧道特征
            'tunneling': rb'(?i)\b(?:ssh.*-L|ssh.*-R|plink.*-L|plink.*-R|netsh.*interface.*portproxy)\b',
            
            # 代理特征
            'proxying': rb'(?i)\b(?:proxychains|ssh.*-D|3proxy|ccproxy|squid)\b',
            
            # 域名生成算法特征
            'dga_domains': rb'(?i)\b(?:[a-z]{8,16}\\.(?:com|net|org|info|biz)|[a-z]{12,20}\\.(?:ru|cn|in|br))\b',
            
            # 快速流量特征
            'fast_flux': rb'(?i)\b(?:TTL.*\\d{1,3}.*\\d{1,3}\\.\\d{1,3}\\.\\d{1,3}\\.\\d{1,3}.*\\d{1,3}\\.\\d{1,3}\\.\\d{1,3}\\.\\d{1,3})\b',
            
            # 域名生成算法检测
            'dga_detection': rb'(?i)\b(?:[bcdfghjklmnpqrstvwxyz]{5,}[aeiou]{2,}[bcdfghjklmnpqrstvwxyz]{3,}\\.)\b',
            }
        
        # 编译正则表达式
        self.forensic_patterns = {}
        for name, pattern in default_patterns.items():
            try:
                self.forensic_patterns[name] = re.compile(pattern)
            except re.error as e:
                print(f"[-] 正则模式 {name} 编译失败: {str(e)}")
        
        # 合并自定义模式
        for name, pattern in self.custom_patterns.items():
            try:
                if isinstance(pattern, str):
                    self.forensic_patterns[name] = re.compile(pattern.encode())
                else:
                    print(f"[-] 自定义模式 {name} 格式错误")
            except re.error as e:
                print(f"[-] 自定义模式 {name} 编译失败: {str(e)}")
        
        print(f"[*] 加载 {len(self.forensic_patterns)} 个取证模式")
    

    def _should_skip_file(self, file_path):
        """判断是否应该跳过文件扫描"""
        if not os.path.isfile(file_path):
            return True
        
        basename = os.path.basename(file_path)
        
        # 跳过过小文件（可能不是内存转储或二进制文件）
        if os.path.getsize(file_path) < 512:  # 小于512字节
            return True
        
        # 检查文件是否为二进制文件（通过文件头判断）
        try:
            with open(file_path, 'rb') as f:
                header = f.read(1024)
                if not header:
                    return True
                    
                # 如果是文本文件且包含大量可打印字符，跳过
                printable_count = sum(1 for byte in header if 32 <= byte <= 126 or byte in [9, 10, 13])
                if printable_count / len(header) > 0.8:  # 80%以上是可打印字符
                    return True
        except Exception:
            return True
        
        return False

    def _safe_ascii(self, data):
        if not data:
            return ""
        return ''.join(chr(b) if 32 <= b <= 126 else '.' for b in data)
    

    def _calculate_file_hash(self, file_path):
        try:
            with open(file_path, 'rb') as f:
                return hashlib.sha256(f.read()).hexdigest()
        except Exception as e:
            print(f"[!] 计算文件哈希失败 {file_path}: {str(e)}")
            return "N/A"
    

    def _scan_with_yara(self, file_path, content):
        if not self.yara_rules:
            return []
        
        yara_findings = []
        try:
            matches = self.yara_rules.match(data=content)
            
            for match in matches:
                for string in match.strings:
                    # 获取上下文
                    context_start = max(0, string[0] - 64)
                    context_end = min(len(content), string[0] + 64)
                    context_data = content[context_start:context_end]
                    
                    finding = {
                        'rule_name': match.rule,
                        'pattern_type': 'yara',
                        'offset': f"0x{string[0]:08x}",
                        'matched_data': string[1].hex(),
                        'matched_ascii': self._safe_ascii(string[1]),
                        'context_hex': context_data.hex(),
                        'context_ascii': self._safe_ascii(context_data),
                        'file_offset': string[0]
                    }
                    
                    yara_findings.append(finding)
                    self.scan_stats['yara_matches'] += 1
            
        except yara.Error as e:
            print(f"[!] YARA扫描错误 {file_path}: {str(e)}")
        except Exception as e:
            print(f"[!] YARA扫描异常 {file_path}: {str(e)}")
        
        return yara_findings
    

    def _sanitize_for_json(self, data):
        if isinstance(data, (str, int, float, bool, type(None))):
            return data
        elif isinstance(data, dict):
            return {k: self._sanitize_for_json(v) for k, v in data.items()}
        elif isinstance(data, list):
            return [self._sanitize_for_json(item) for item in data]
        elif isinstance(data, bytes):
            return data.hex()
        else:
            return str(data)
    
    
    def _generate_categorized_reports(self, file_path, findings_by_type):
        base_filename = os.path.basename(file_path)
        file_hash = self._calculate_file_hash(file_path)
        
        # 创建简化报告目录（与forensic_reports保持一致的目录结构）
        for pattern_type, matches in findings_by_type.items():
            if matches:  # 只有该类型有匹配时才创建目录
                simple_report_dir = Path(self.output_dir) / "search_report" / pattern_type
                simple_report_dir.mkdir(parents=True, exist_ok=True)
                simple_report_path = simple_report_dir / f"{base_filename}.txt"
                
                # 生成简化报告（追加模式）
                with open(simple_report_path, 'a', encoding='utf-8', errors='replace') as f:
                    # 如果是新文件，写入文件头
                    if os.path.getsize(simple_report_path) == 0:
                        f.write(f"文件: {base_filename}\n")
                        f.write(f"路径: {file_path}\n")
                        f.write(f"文件哈希: {file_hash}\n")
                        f.write(f"文件大小: {os.path.getsize(file_path)} bytes\n")
                        f.write(f"扫描时间: {datetime.now().isoformat()}\n\n")
                    
                    for match in matches:
                        f.write(f"匹配偏移: {match.get('offset', 'N/A')}\n")
                        f.write(f"匹配规则: {pattern_type}\n")
                        f.write(f"匹配大小: {len(match.get('matched_hex', '')) // 2 if match.get('matched_hex') else 'N/A'} bytes\n")
                        f.write(f"匹配数据(ASCII): {match.get('matched_ascii', 'N/A')}\n")
                        f.write(f"上下文(ASCII): {match.get('context_ascii', 'N/A')}\n")
                        f.write(f"匹配数据(HEX): {match.get('matched_hex', 'N/A')}\n")
                        f.write("\n")
        
        # 同时保留原有的分类报告
        for pattern_type, matches in findings_by_type.items():
            # 创建类型目录
            type_dir = Path(self.output_dir) / "forensic_reports" / pattern_type
            type_dir.mkdir(parents=True, exist_ok=True)
            
            # 使用文件名作为JSON文件名
            json_report_path = type_dir / f"{base_filename}.json"
            
            # 读取现有JSON数据
            existing_data = []
            if json_report_path.exists():
                try:
                    with open(json_report_path, 'r', encoding='utf-8') as f:
                        existing_data = json.load(f)
                        if not isinstance(existing_data, list):
                            existing_data = [existing_data]
                except:
                    existing_data = []
            
            # 添加新的匹配项到数据中
            for match in matches:
                match_report = {
                    'source_file': file_path,
                    'source_hash': file_hash,
                    'file_size': os.path.getsize(file_path),
                    'pattern_type': pattern_type,
                    'scan_time': datetime.now().isoformat(),
                    'match_details': match
                }
                existing_data.append(match_report)
            
            # 写入更新后的JSON数据（追加模式）
            try:
                with open(json_report_path, 'w', encoding='utf-8') as f:
                    json.dump(self._sanitize_for_json(existing_data), f, indent=2, ensure_ascii=False)
            except IOError as e:
                print(f"[!] 写入JSON报告失败 {json_report_path}: {str(e)}")
            except Exception as e:
                print(f"[!] JSON序列化失败 {json_report_path}: {str(e)}")
    

    def _yara_scan_for_flags(self, file_path):
        """扫描单个文件寻找取证痕迹"""
        if self._should_skip_file(file_path):
            return False
        
        basename = os.path.basename(file_path)
        
        try:
            file_stats = {
                'file_path': file_path,
                'file_size': os.path.getsize(file_path),
                'sha256': self._calculate_file_hash(file_path),
                'matches': [],
                'scan_timestamp': datetime.now().isoformat()
            }
            
            findings_by_type = {}
            file_size = os.path.getsize(file_path)
            
            # 优化大文件处理：分块读取而不是整个文件映射到内存
            if file_size > 100 * 1024 * 1024:  # 大于100MB的文件
                print(f"[*] 处理大文件: {basename} ({file_size//1024//1024}MB), 使用分块扫描...")
                
                # 分块处理大文件
                chunk_size = 10 * 1024 * 1024  # 10MB chunks
                overlap = 1024 * 1024  # 1MB overlap to avoid missing matches at boundaries
                
                with open(file_path, 'rb') as f:
                    for chunk_start in range(0, file_size, chunk_size - overlap):
                        chunk_end = min(chunk_start + chunk_size, file_size)
                        chunk = f.read(chunk_end - chunk_start)
                        
                        if not chunk:
                            break
                            
                        # 1. 使用YARA规则扫描当前分块
                        yara_matches = self._scan_with_yara(file_path, chunk)
                        for match in yara_matches:
                            # 调整偏移量为全局偏移量
                            match['file_offset'] += chunk_start
                            match['offset'] = f"0x{match['file_offset']:08x}"
                            file_stats['matches'].append(match)
                            if 'yara' not in findings_by_type:
                                findings_by_type['yara'] = []
                            findings_by_type['yara'].append(match)
                        
                        # 2. 使用正则模式扫描当前分块
                        for pattern_name, pattern in self.forensic_patterns.items():
                            for match in pattern.finditer(chunk):
                                offset = match.start() + chunk_start
                                matched_data = match.group()
                                
                                # 获取上下文（限制在分块内）
                                context_start_in_chunk = max(0, match.start() - 64)
                                context_end_in_chunk = min(len(chunk), match.end() + 64)
                                context_data = chunk[context_start_in_chunk:context_end_in_chunk]
                                
                                match_info = {
                                    'pattern_type': pattern_name,
                                    'offset': f"0x{offset:08x}",
                                    'matched_hex': matched_data.hex(),
                                    'matched_ascii': self._safe_ascii(matched_data),
                                    'context_hex': context_data.hex(),
                                    'context_ascii': self._safe_ascii(context_data),
                                    'file_offset': offset
                                }
                                
                                file_stats['matches'].append(match_info)
                                self.scan_stats['regex_matches'] += 1
                                
                                if pattern_name not in findings_by_type:
                                    findings_by_type[pattern_name] = []
                                findings_by_type[pattern_name].append(match_info)
            
            else:
                # 小文件使用内存映射
                with open(file_path, 'rb') as f:
                    with mmap.mmap(f.fileno(), 0, access=mmap.ACCESS_READ) as mm:
                        content = mm
                        
                        # 1. 使用YARA规则扫描
                        yara_matches = self._scan_with_yara(file_path, content)
                        for match in yara_matches:
                            file_stats['matches'].append(match)
                            if 'yara' not in findings_by_type:
                                findings_by_type['yara'] = []
                            findings_by_type['yara'].append(match)
                        
                        # 2. 使用正则模式扫描
                        for pattern_name, pattern in self.forensic_patterns.items():
                            for match in pattern.finditer(content):
                                offset = match.start()
                                matched_data = match.group()
                                
                                # 获取上下文
                                context_start = max(0, offset - 64)
                                context_end = min(len(content), offset + 64)
                                context_data = content[context_start:context_end]
                                
                                match_info = {
                                    'pattern_type': pattern_name,
                                    'offset': f"0x{offset:08x}",
                                    'matched_hex': matched_data.hex(),
                                    'matched_ascii': self._safe_ascii(matched_data),
                                    'context_hex': context_data.hex(),
                                    'context_ascii': self._safe_ascii(context_data),
                                    'file_offset': offset
                                }
                                
                                file_stats['matches'].append(match_info)
                                self.scan_stats['regex_matches'] += 1
                                
                                if pattern_name not in findings_by_type:
                                    findings_by_type[pattern_name] = []
                                findings_by_type[pattern_name].append(match_info)
            
            if file_stats['matches']:
                self.forensic_findings.append(file_stats)
                self.scan_stats['artifacts_found'] += len(file_stats['matches'])
                
                # 按匹配类型生成分类报告
                self._generate_categorized_reports(file_path, findings_by_type)
                
                print(f"[+] {basename}: 发现 {len(file_stats['matches'])} 个取证痕迹  {file_path}")
                return True
            else:
                print(f"[-] {basename}: 未发现可疑痕迹")
                return False
                
        except PermissionError as e:
            print(f"[!] 权限不足 {file_path}: {str(e)}")
            return False
        except OSError as e:
            print(f"[!] 系统错误 {file_path}: {str(e)}")
            return False
        except Exception as e:
            print(f"[!] 扫描 {file_path} 失败: {str(e)}")
            return False
    
    def scan_directory(self, directory_path):
        if not os.path.isdir(directory_path):
            print(f"[!] {directory_path} 不是有效目录")
            return False
        
        print(f"[*] 开始内存取证扫描: {directory_path}")
        print(f"[*] 开始时间: {self.scan_stats['start_time']}")
        print(f"[*] 加载特征: {len(self.forensic_patterns)} 个正则模式 + {'有' if self.yara_rules else '无'} YARA规则")
        
        # 首先收集所有需要扫描的文件
        files_to_scan = []
        skip_dirs = ['forensic_report', 'yara_scan', 'search_report']
        
        for root, dirs, files in os.walk(directory_path):
            # 跳过报告目录
            if any(skip_dir in root for skip_dir in skip_dirs):
                continue
                
            for file in files:
                file_path = os.path.join(root, file)
                # 在收集阶段就进行文件过滤，避免后续重复检查
                if self._should_skip_file(file_path):
                    continue
                files_to_scan.append(file_path)
        
        total_files = len(files_to_scan)
        file_count = 0
        processed_count = 0
        
        if total_files == 0:
            print(f"[!] 没有找到需要扫描的文件")
            return False
            
        print(f"[*] 找到 {total_files} 个需要扫描的文件")
        
        # 扫描文件
        for file_path in files_to_scan:
            processed_count += 1
            self.scan_stats['total_files_scanned'] += 1
            
            # 显示进度
            if processed_count % 10 == 0 or processed_count == total_files:
                progress = (processed_count / total_files) * 100
                print(f"[*] 进度: {processed_count}/{total_files} ({progress:.1f}%)")
            
            if self._yara_scan_for_flags(file_path):
                file_count += 1
        
        # 更新files_processed统计为找到匹配的文件数
        self.scan_stats['files_processed'] = file_count
        
        # 生成总结报告
        self._generate_summary_report()
        
        print(f"[+] 扫描完成! 扫描 {self.scan_stats['total_files_scanned']} 个文件, 其中 {file_count} 个文件发现痕迹, 共发现 {self.scan_stats['artifacts_found']} 个痕迹")
        
        # 生成HTML报告
        self._generate_html_report()
        
        return True
    
    def _generate_summary_report(self):
        summary = {
            'scan_summary': {
                'start_time': self.scan_stats['start_time'],
                'end_time': datetime.now().isoformat(),
                'duration': str(datetime.now() - datetime.fromisoformat(self.scan_stats['start_time'])),
                'total_files_scanned': self.scan_stats['total_files_scanned'],
                'files_with_artifacts': len(self.forensic_findings),
                'total_artifacts': self.scan_stats['artifacts_found'],
                'yara_matches': self.scan_stats['yara_matches'],
                'regex_matches': self.scan_stats['regex_matches']
            },
            'file_summary': [
                {
                    'file': finding['file_path'],
                    'artifacts': len(finding['matches']),
                    'sha256': finding['sha256']
                } for finding in self.forensic_findings
            ]
        }
        
        summary_path = self.output_dir / "scan_summary.json"
        try:
            with open(summary_path, 'w', encoding='utf-8') as f:
                json.dump(summary, f, indent=2, ensure_ascii=False)
            print(f"[*] 总结报告已保存: {summary_path}")
        except Exception as e:
            print(f"[!] 生成总结报告失败: {str(e)}")

    def _generate_html_report(self):
        html_report_path = self.output_dir / "forensic_report.html"
        
        try:
            with open(html_report_path, 'w', encoding='utf-8') as f:
                f.write("""<!DOCTYPE html>
<html lang="zh-CN">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>内存取证分析报告</title>
    <style>
        body { font-family: Arial, sans-serif; margin: 20px; background-color: #f5f5f5; }
        .container { max-width: 1200px; margin: 0 auto; background: white; padding: 20px; border-radius: 8px; box-shadow: 0 2px 10px rgba(0,0,0,0.1); }
        h1 { color: #2c3e50; text-align: center; }
        .summary { background: #ecf0f1; padding: 15px; border-radius: 5px; margin-bottom: 20px; }
        .file-list { margin-top: 20px; }
        .file-item { background: #fff; border: 1px solid #ddd; border-radius: 5px; padding: 15px; margin-bottom: 10px; cursor: pointer; transition: background-color 0.3s; }
        .file-item:hover { background-color: #f8f9fa; }
        .file-details { display: none; background: #f8f9fa; padding: 15px; border-radius: 5px; margin-top: 10px; }
        .match-item { background: #fff; border: 1px solid #eee; padding: 10px; margin: 5px 0; border-radius: 3px; }
        .hex-data { font-family: monospace; background: #f1f1f1; padding: 5px; border-radius: 3px; }
        .timestamp { color: #7f8c8d; font-size: 0.9em; }
        .badge { display: inline-block; padding: 3px 8px; border-radius: 12px; font-size: 0.8em; margin-right: 5px; }
        .badge-yara { background: #3498db; color: white; }
        .badge-regex { background: #e74c3c; color: white; }
        .stats-grid { display: grid; grid-template-columns: repeat(auto-fit, minmax(200px, 1fr)); gap: 15px; margin: 20px 0; }
        .stat-card { background: white; padding: 15px; border-radius: 5px; text-align: center; box-shadow: 0 2px 5px rgba(0,0,0,0.1); }
        .stat-number { font-size: 2em; font-weight: bold; color: #2c3e50; }
        .stat-label { color: #7f8c8d; }
    </style>
</head>
<body>
    <div class="container">
        <h1>🔍 内存取证分析报告</h1>
        
        <div class="summary">
            <h2>扫描摘要</h2>
            <div class="stats-grid">
                <div class="stat-card">
                    <div class="stat-number">""" + str(self.scan_stats['total_files_scanned']) + """</div>
                    <div class="stat-label">扫描文件总数</div>
                </div>
                <div class="stat-card">
                    <div class="stat-number">""" + str(self.scan_stats['files_processed']) + """</div>
                    <div class="stat-label">发现痕迹文件数</div>
                </div>
                <div class="stat-card">
                    <div class="stat-number">""" + str(self.scan_stats['artifacts_found']) + """</div>
                    <div class="stat-label">发现痕迹总数</div>
                </div>
                <div class="stat-card">
                    <div class="stat-number">""" + str(self.scan_stats['yara_matches']) + """</div>
                    <div class="stat-label">YARA匹配</div>
                </div>
                <div class="stat-card">
                    <div class="stat-number">""" + str(self.scan_stats['regex_matches']) + """</div>
                    <div class="stat-label">正则匹配</div>
                </div>
            </div>
            <p><strong>开始时间:</strong> """ + self.scan_stats['start_time'] + """</p>
            <p><strong>结束时间:</strong> """ + datetime.now().isoformat() + """</p>
        </div>

        <h2>文件分析结果</h2>
        <div class="file-list">
""")
                
                # 添加文件详情
                for i, finding in enumerate(self.forensic_findings):
                    file_path = finding['file_path']
                    basename = os.path.basename(file_path)
                    # 使用唯一标识符避免文件名重复导致的ID冲突
                    file_id = f"file_{i}_{basename.replace('.', '_')}"
                    f.write(f"""
            <div class="file-item" onclick="toggleDetails('{file_id}')">
                <strong>{basename}</strong>
                <span class="badge">{len(finding['matches'])} 个匹配</span>
                <span class="timestamp">大小: {finding['file_size']} bytes</span>
            </div>
            <div id="{file_id}" class="file-details">
                <p><strong>文件路径:</strong> {file_path}</p>
                <p><strong>SHA256:</strong> {finding['sha256']}</p>
                <h3>匹配详情:</h3>
""")
                    
                    for match in finding['matches']:
                        badge_class = 'badge-yara' if match.get('pattern_type') == 'yara' else 'badge-regex'
                        f.write(f"""
                <div class="match-item">
                    <span class="{badge_class}">{match.get('pattern_type', 'N/A')}</span>
                    <strong>偏移: {match.get('offset', 'N/A')}</strong>
                    <br>规则: {match.get('rule_name', match.get('pattern_type', 'N/A'))}
                    <br>匹配数据: <span class="hex-data">{match.get('matched_ascii', 'N/A')}</span>
                    <br>上下文: <span class="hex-data">{match.get('context_ascii', 'N/A')}</span>
                </div>
""")
                    
                    f.write("""
            </div>
""")
                
                f.write("""
        </div>
    </div>

    <script>
        function toggleDetails(id) {
            const element = document.getElementById(id);
            element.style.display = element.style.display === 'none' ? 'block' : 'none';
        }
        
        // 默认全部不打开文件详情
        document.addEventListener('DOMContentLoaded', function() {
            const details = document.querySelectorAll('.file-details');
            details.forEach(detail => {
                detail.style.display = 'none';
            });
        });
    </script>
</body>
</html>""")
            
            print(f"[+] HTML报告已生成: {html_report_path}")
            
        except Exception as e:
            print(f"[-] 生成HTML报告失败: {str(e)}")


def _yara_deep_scan(self, file_path=None):
    try:
        # 支持 args.dump_dir or automator.output_dir 模式
        scanner = YaraForenScanner(output_dir=f"{file_path}/yara_scan")
        scanner.scan_directory(file_path)
        return True
    except Exception as e:
        print(f"[!] YARA扫描失败: {str(e)}")
        return False


if __name__ == "__main__":
    parser = argparse.ArgumentParser(
        description="Frolaxify 扫描取证工具 - 使用YARA规则进行扫描",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        add_help=False
    )

    parser.add_argument("-h", "--help", action="help", default=argparse.SUPPRESS, help="显示帮助信息并退出")

    parser.add_argument("-S", "--scan-dir", help="扫描目录路径")

    args = parser.parse_args()

    scanner = YaraForenScanner()
    scanner.scan_directory(args.scan_dir)
