#!/usr/bin/env python3
import sys
sys.dont_write_bytecode = True


def _pattern(self):
        # CTF正则（优先级高 最后一个正则不要加|）
        pattern = ( 
            r'(?i)\b('
            r'ctf(?:\w+)?|'
            r'ctf(?:\d+)?|'
            r'ctf(?:\{[^}]*)?|'
            r'ctf(?:\d+\.\w+)?|'
            r'f[1li!|][a4@][g9](?:\w+)?|'
            r'f[1li!|][a4@][g9](?:\d+)?|'
            r'f[1li!|][a4@][g9](?:\{[^}]*)?|'
            r'f[1li!|][a4@][g9](?:\d+\.\w+)?|'
            r'p[@a4]ss(?:word|phrase|w0rd|wd)?|'
            r'pwd|'
            r'Bitlocker|'
            r'notepad|'
            r'mspaint|'
            r'StikyNot'
            r')\b'
        )

        return pattern



def _exclude_patterns(self):
        # 常用地址排除匹配的正则表达式模式
        exclude_patterns = [
            # 常见的系统文件扩展名
            r'(?i)\.dll',      # DLL文件
            r'(?i)\.db',       # 数据库文件
            r'(?i)\.evtx',     # Windows事件日志文件
            r'(?i)\.edb',      # Windows可扩展存储引擎数据库文件
            r'(?i)\.dir',      # Windows目录文件
            r'(?i)\.gthr',      # Windows Gatherer文件
            r'(?i)\.wid',      # Windows索引数据文件
            r'(?i)\.pyd',      # Python扩展模块文件
            r'(?i)\.sdf',      # SQL Server Compact数据库文件
            r'(?i)\.dat',      # 通用数据文件
            r'(?i)\.sys',      # Windows系统文件
            r'(?i)\.lnk',      # Windows系统文件
            r'(?i)\.Crwl',      # Windows爬虫文件
            r'(?i)\.automaticDestinations-ms',      # Windows跳转列表文件
            r'(?i)\.thumbcache', # 缩略图缓存文件
            r'(?i)thumbcache',  # 缩略图缓存（无点号）
        ]
        
        return exclude_patterns



def _common_address_patterns(self):
        # 常用地址正则表达式模式
        common_address_patterns = [
                
            # CTF文件
            r'(?i)\b(ctf(?:\{[^}]*)?)\b',
            r'(?i)\b(ctf(?:\d+\.\w+)?)\b',
            r'(?i)\b(f[1li!|][a4@][g9](?:\{[^}]*)?)\b',
            r'(?i)\b(f[1li!|][a4@][g9](?:\d+\.\w+)?)\b',
            r'(?i)\b(p[@a4]ss(?:word|phrase|w0rd|wd)?)\b',
            r'(?i)\b(pwd)\b',

            # 虚拟磁盘镜像
            r'(?i)\.vhd',
            r'(?i)\.dd',
            r'(?i)\.vmdk',
            r'(?i)\.qcow2',
            r'(?i)\.mem',
            r'(?i)\.vdi',
            r'(?i)\.raw',
            r'(?i)\.vhdx',
            r'(?i)\.img',
            r'(?i)\.dmg',
            r'(?i)\.gho',
            r'(?i)\.tib',
            r'(?i)\.pbf',
            r'(?i)\.ami',
            r'(?i)\.ova',
            r'(?i)\.ovf',
            r'(?i)\.ab',
            r'(?i)\.ipsw',
            r'(?i)\.nrg',
            r'(?i)\.bin',
            r'(?i)\.cue',
            r'(?i)\.dsk',
            r'(?i)\.iso',

            # 回收站路径正则表达式
            r'(?i)\\?\$Recycle\.Bin',  # Windows回收站
            r'(?i)\.local/share/Trash',  # Linux 回收站
            r'(?i)\.Trash',  # macOS回收站

            # Windows 系统路径
            r'(?i)Desktop',  # 桌面文件
            # r'(?i)System Volume Information',  # 系统卷信息
            # r'(?i)ProtectedPrefix',  # 受保护的前缀目录
            r'(?i)Start Menu',  # 开始菜单
            r'(?i)NamedPipe',  # 命名管道
            r'(?i)Mailslot',  # 邮件槽
            # r'(?i)HarddiskVolume',  # 硬盘卷
            # r'(?i)Device\\',  # 设备路径
            r'(?i)Program Files',  # 程序文件
            r'(?i)ProgramData',  # 程序数据
            r'(?i)Users\\',  # 用户目录
            r'(?i)AppData\\',  # 应用程序数据
            r'(?i)Temp\\',  # 临时文件
            r'(?i)Temporary Internet Files',  # 临时互联网文件
            r'(?i)Recycle\.Bin',  # 回收站
            # r'(?i)pagefile\.sys',  # 页面文件
            # r'(?i)hiberfil\.sys',  # 休眠文件
            # r'(?i)swapfile\.sys',  # 交换文件
            # r'(?i)Windows\\System32',  # 系统文件
            # r'(?i)Windows\\SysWOW64',  # 32位系统文件


            # 浏览器敏感信息文件 (Windows)
            r'(?i)Cookies',  # 浏览器Cookie文件
            r'(?i)History',  # 浏览历史
            r'(?i)WebCache',  # 网页缓存
            r'(?i)Login Data',  # 登录数据
            r'(?i)Bookmarks',  # 书签
            r'(?i)Favicons',  # 网站图标
            r'(?i)Shortcuts',  # 快捷方式
            r'(?i)Top Sites',  # 常用网站
            r'(?i)Visited Links',  # 访问过的链接
            r'(?i)Current Session',  # 当前会话
            r'(?i)Current Tabs',  # 当前标签页
            r'(?i)Last Session',  # 上次会话
            r'(?i)Last Tabs',  # 上次标签页
            r'(?i)Preferences',  # 偏好设置
            r'(?i)Secure Preferences',  # 安全偏好设置
            r'(?i)Local Storage',  # 本地存储
            r'(?i)Extension Rules',  # 扩展规则
            r'(?i)Extension State',  # 扩展状态
            r'(?i)Trusted Vault',  # 信任保险库
            

            # 浏览器相关路径
            r'(?i)Google\\Chrome',  # Chrome浏览器
            r'(?i)Microsoft\\Edge',  # Edge浏览器
            r'(?i)Mozilla\\Firefox',  # Firefox浏览器
            r'(?i)Opera Software',  # Opera浏览器
            r'(?i)BraveSoftware',  # Brave浏览器
            r'(?i)Vivaldi',  # Vivaldi浏览器
            r'(?i)Safari',  # Safari浏览器
            r'(?i)User Data',  # 用户数据目录
            r'(?i)Default\\',  # 默认配置文件
            r'(?i)Profile\\',  # 用户配置文件
            

            # Linux 系统路径
            r'(?i)/home/',  # 用户主目录
            r'(?i)/root/',  # root用户目录
            r'(?i)/etc/',  # 配置文件目录
            r'(?i)/var/',  # 可变数据目录
            r'(?i)/tmp/',  # 临时文件目录
            r'(?i)/usr/',  # 用户程序目录
            r'(?i)/bin/',  # 基本命令目录
            # r'(?i)/sbin/',  # 系统命令目录
            # r'(?i)/lib/',  # 库文件目录
            r'(?i)/opt/',  # 可选软件目录
            r'(?i)/proc/',  # 进程信息目录
            # r'(?i)/sys/',  # 系统信息目录
            # r'(?i)/dev/',  # 设备文件目录
            # r'(?i)/mnt/',  # 挂载点目录
            r'(?i)/media/',  # 可移动媒体目录
            r'(?i)/boot/',  # 启动文件目录
            r'(?i)/lost\+found',  # 文件系统恢复目录
            r'(?i)\.bash_history',  # bash历史记录
            r'(?i)\.ssh/',  # SSH配置目录
            r'(?i)\.config/',  # 用户配置目录
            r'(?i)\.cache/',  # 缓存目录
            r'(?i)\.local/',  # 本地数据目录
            
            # 命令历史文件
            r'(?i)\.bash_history',  # Bash命令历史文件
            r'(?i)\.zsh_history',   # Zsh命令历史文件
            r'(?i)\.history',       # 通用历史文件
            r'(?i)\.sh_history',    # Shell历史文件
            r'(?i)/etc/passwd',     # 用户账户文件
            r'(?i)/etc/shadow',     # 影子密码文件
            r'(?i)/var/log/auth',   # 认证日志
            r'(?i)/var/log/secure', # 安全日志
            r'(?i)/var/log/messages', # 系统消息日志
            r'(?i)/var/log/syslog', # 系统日志
            r'(?i)/var/log/mysql',  # MySQL日志
            r'(?i)/var/log/mariadb', # MariaDB日志
            r'(?i)/var/log/apache2', # Apache日志
            r'(?i)/var/log/nginx',  # Nginx日志
            r'(?i)/var/log/cron',   # 定时任务日志
            r'(?i)/var/log/lastlog', # 最后登录日志
            r'(?i)/var/log/wtmp',   # 登录记录文件
            r'(?i)/var/log/btmp',   # 失败登录记录
            r'(?i)/var/run/utmp',   # 当前登录用户
            r'(?i)/proc/\d+/cmdline', # 进程命令行参数
            r'(?i)/proc/\d+/environ', # 进程环境变量

            # Linux浏览器配置文件
            r'(?i)\.mozilla',  # Firefox配置
            r'(?i)\.config/google-chrome',  # Chrome配置
            r'(?i)\.config/chromium',  # Chromium配置
            r'(?i)\.config/microsoft-edge',  # Edge配置
            r'(?i)\.config/opera',  # Opera配置
            r'(?i)\.config/brave',  # Brave配置
            r'(?i)\.config/vivaldi',  # Vivaldi配置
            r'(?i)\.cache/mozilla',  # Firefox缓存
            r'(?i)\.cache/google-chrome',  # Chrome缓存
            r'(?i)\.cache/chromium',  # Chromium缓存
            

            # WEB网站中间件配置
            r'(?i)\\inetpub\\',  # IIS
            r'(?i)\\wwwroot\\',  # Web根目录
            r'(?i)web\.config',  # ASP.NET配置
            r'(?i)applicationHost\.config',  # IIS主机配置
            r'(?i)\\apache\\',  # Apache
            r'(?i)\\httpd\\',  # HTTP服务器
            r'(?i)\.htaccess',  # Apache配置
            r'(?i)httpd\.conf',  # Apache主配置
            r'(?i)\\nginx\\',  # Nginx
            r'(?i)nginx\.conf',  # Nginx配置
            r'(?i)\\tomcat\\',  # Tomcat
            r'(?i)\\apache-tomcat\\',  # Apache Tomcat
            r'(?i)server\.xml',  # Tomcat服务器配置
            r'(?i)\\php\\',  # PHP
            r'(?i)php\.ini',  # PHP配置
            r'(?i)php-fpm\.conf',  # PHP-FPM配置
            r'(?i)\\node_modules\\',  # Node.js模块
            r'(?i)package\.json',  # Node.js包配置
            r'(?i)\.env',  # 环境变量配置
            

            # 远程控制软件
            r'(?i)\\ToDesk\\',  # ToDesk
            r'(?i)ToDesk\.exe',  # ToDesk主程序
            r'(?i)ToDesk\.ini',  # ToDesk配置
            r'(?i)\\Sunlogin\\',  # 向日葵
            r'(?i)SunloginClient\.exe',  # 向日葵客户端
            r'(?i)Sunlogin\.ini',  # 向日葵配置
            r'(?i)\\TeamViewer\\',  # TeamViewer
            r'(?i)TeamViewer\.exe',  # TeamViewer主程序
            r'(?i)TeamViewer\.ini',  # TeamViewer配置
            r'(?i)\\AnyDesk\\',  # AnyDesk
            r'(?i)AnyDesk\.exe',  # AnyDesk主程序
            r'(?i)anydesk\.conf',  # AnyDesk配置
            r'(?i)\\mstsc\.exe',  # 远程桌面
            r'(?i)\.rdp',  # RDP连接文件
            r'(?i)Remote Desktop\\',  # 远程桌面
            

            # 数据库软件
            r'(?i)\\MySQL\\',  # MySQL
            r'(?i)\\PostgreSQL\\',  # PostgreSQL
            r'(?i)\\Oracle\\',  # Oracle
            r'(?i)\\SQL Server\\',  # SQL Server
            r'(?i)\\MongoDB\\',  # MongoDB
            r'(?i)\\Redis\\',  # Redis
            r'(?i)\\SQLite\\',  # SQLite
            r'(?i)\\MariaDB\\',  # MariaDB
            r'(?i)\\Cassandra\\',  # Cassandra
            r'(?i)\\CouchDB\\',  # CouchDB
            r'(?i)\\Neo4j\\',  # Neo4j
            r'(?i)\\InfluxDB\\',  # InfluxDB
            r'(?i)\\Elasticsearch\\',  # Elasticsearch
            r'(?i)\\Kibana\\',  # Kibana
            r'(?i)\\Logstash\\',  # Logstash
            r'(?i)\.mdf',  # SQL Server数据文件
            r'(?i)\.ldf',  # SQL Server日志文件
            r'(?i)\.frm',  # MySQL表结构文件
            r'(?i)\.db',  # 数据库文件
            r'(?i)\.sqlite',  # SQLite数据库
            r'(?i)\.sqlite3',  # SQLite3数据库
            r'(?i)\.myd',  # MySQL数据文件
            r'(?i)\.myi',  # MySQL索引文件
            r'(?i)\.ibd',  # InnoDB数据文件
            r'(?i)\.dbf',  # dBASE数据库文件
            r'(?i)\.accdb',  # Access数据库
            r'(?i)\.mdb',  # Access数据库
            

            # 压缩包和归档文件
            r'(?i)\.zip',  # ZIP压缩包
            r'(?i)\.rar',  # RAR压缩包
            r'(?i)\.7z',  # 7-Zip压缩包
            r'(?i)\.tar',  # TAR归档
            r'(?i)\.gz',  # GZIP压缩
            r'(?i)\.bz2',  # Bzip2压缩
            r'(?i)\.xz',  # XZ压缩
            r'(?i)\.zst',  # Zstandard压缩
            r'(?i)\.lzh',  # LZH压缩
            r'(?i)\.arj',  # ARJ压缩
            r'(?i)\.cab',  # CAB压缩
            r'(?i)\.deb',  # Debian包
            r'(?i)\.rpm',  # RPM包
            r'(?i)\.swp',  # 备份文件
            r'(?i)\.swo',  # 备份文件
            r'(?i)\.php~', # 备份文件
            r'(?i)\.bak',  # 备份文件
            r'(?i)\.old',  # 备份文件
            # r'(?i)\.exe',  # 可执行文件
            # r'(?i)\.msi',  # Windows安装包
            # r'(?i)\.dmg',  # macOS磁盘映像
            # r'(?i)\.pkg',  # macOS安装包
            # r'(?i)\.apk',  # Android应用包
            # r'(?i)\.ipa',  # iOS应用包
            # r'(?i)\.iso',  # ISO光盘映像
            # r'(?i)\.img',  # 磁盘映像
            # r'(?i)\.bin',  # 二进制文件
            # r'(?i)\.cue',  # CUE文件
            # r'(?i)\.nrg',  # Nero映像
            # r'(?i)\.mdf',  # Alcohol 120%映像
            # r'(?i)\.mds',  # Alcohol 120%映像描述
            # r'(?i)\.daa',  # PowerISO映像
            # r'(?i)\.uif',  # MagicISO映像
            # r'(?i)\.isz',  # 压缩ISO映像
            # r'(?i)\.cso',  # 压缩ISO映像
            # r'(?i)\.ecm',  # 错误代码模型压缩
            # r'(?i)\.par',  # PAR恢复文件
            # r'(?i)\.par2',  # PAR2恢复文件
            # r'(?i)\.sfv',  # 简单文件验证
            # r'(?i)\.md5',  # MD5校验和
            # r'(?i)\.sha1',  # SHA1校验和
            # r'(?i)\.sha256',  # SHA256校验和
            # r'(?i)\.sha512',  # SHA512校验和
            # r'(?i)\.crc',  # CRC校验和
            r'(?i)\.sfx',  # 自解压压缩包
            r'(?i)\.001',  # 分卷压缩文件
            r'(?i)\.002',  # 分卷压缩文件
            r'(?i)\.part',  # 分卷压缩文件
            r'(?i)\.split',  # 分割文件
            r'(?i)\.archive',  # 归档文件
            r'(?i)\.backup',  # 备份文件
            r'(?i)\.bak',  # 备份文件
            r'(?i)\.old',  # 旧文件
            # r'(?i)\.temp',  # 临时文件
            # r'(?i)\.tmp',  # 临时文件
            # r'(?i)\.download',  # 下载文件
            # r'(?i)\.partial',  # 部分下载文件
            # r'(?i)\.crdownload',  # Chrome下载文件
            # r'(?i)\.!ut',  # uTorrent下载文件
            # r'(?i)\.!qb',  # qBittorrent下载文件
            # r'(?i)\.torrent',  # 种子文件
            # r'(?i)\.magnet',  # 磁力链接文件
            # r'(?i)\.ed2k',  # eDonkey链接文件
            # r'(?i)\.p2p',  # P2P文件
            # r'(?i)\.emule',  # eMule文件
            # r'(?i)\.amule',  # aMule文件
            # r'(?i)\.bittorrent',  # BitTorrent文件
            # r'(?i)\.utorrent',  # uTorrent文件
            # r'(?i)\.qbittorrent',  # qBittorrent文件
            # r'(?i)\.transmission',  # Transmission文件
            # r'(?i)\.deluge',  # Deluge文件
            # r'(?i)\.rtorrent',  # rTorrent文件
            # r'(?i)\.aria2',  # aria2文件
            # r'(?i)\.jdownloader',  # JDownloader文件
            # r'(?i)\.idm',  # Internet Download Manager文件
            # r'(?i)\.fdm',  # Free Download Manager文件
            # r'(?i)\.orbit',  # Orbit Downloader文件
            # r'(?i)\.flashget',  # 快车文件
            # r'(?i)\.xunlei',  # 迅雷文件
            # r'(?i)\.thunder',  # 迅雷文件
            # r'(?i)\.qqdl',  # QQ旋风文件
            # r'(?i)\.hash',  # 哈希文件
            # r'(?i)\.checksum',  # 校验和文件
            # r'(?i)\.verify',  # 验证文件
            # r'(?i)\.signature',  # 签名文件
            # r'(?i)\.sig',  # 签名文件
            # r'(?i)\.asc',  # ASCII签名文件
            # r'(?i)\.gpg',  # GPG文件
            # r'(?i)\.pgp',  # PGP文件
            # r'(?i)\.key',  # 密钥文件
            # r'(?i)\.cert',  # 证书文件
            # r'(?i)\.crt',  # 证书文件
            # r'(?i)\.pem',  # PEM证书文件
            # r'(?i)\.der',  # DER证书文件
            # r'(?i)\.pfx',  # PKCS#12证书文件
            # r'(?i)\.p12',  # PKCS#12证书文件
            # r'(?i)\.keystore',  # Java密钥库
            # r'(?i)\.jks',  # Java密钥库
            # r'(?i)\.truststore',  # Java信任库
            # r'(?i)\.bks',  # Bouncy Castle密钥库
            # r'(?i)\.p7b',  # PKCS#7证书文件
            # r'(?i)\.p7c',  # PKCS#7证书文件
            # r'(?i)\.spc',  # 软件发布证书
            # r'(?i)\.cer',  # 证书文件
            # r'(?i)\.csr',  # 证书签名请求
            # r'(?i)\.crl',  # 证书吊销列表
            # r'(?i)\.ocsp',  # OCSP响应
            # r'(?i)\.pkipath',  # PKI路径
            # r'(?i)\.sst',  # Microsoft序列化证书存储
            # r'(?i)\.stl',  # Microsoft证书信任列表
            # r'(?i)\.cat',  # Microsoft目录文件
            # r'(?i)\.inf',  # 安装信息文件
            # r'(?i)\.ins',  # 安装脚本
            # r'(?i)\.iss',  # Inno Setup脚本
            # r'(?i)\.nsi',  # NSIS脚本
            # r'(?i)\.nsh',  # NSIS头文件
            # r'(?i)\.wxs',  # WiX脚本
            # r'(?i)\.wxi',  # WiX包含文件
            # r'(?i)\.wxl',  # WiX本地化文件
            # r'(?i)\.msm',  # Windows合并模块
            # r'(?i)\.msp',  # Windows补丁包
            # r'(?i)\.mst',  # Windows转换文件
            # r'(?i)\.pat',  # 补丁文件
            # r'(?i)\.diff',  # 差异文件
            # r'(?i)\.patch',  # 补丁文件
            # r'(?i)\.update',  # 更新文件
            # r'(?i)\.upgrade',  # 升级文件
            # r'(?i)\.hotfix',  # 热修复文件
            # r'(?i)\.servicepack',  # 服务包文件
            # r'(?i)\.sp',  # 服务包文件
            # r'(?i)\.cumulative',  # 累积更新文件
            # r'(?i)\.security',  # 安全更新文件
            # r'(?i)\.critical',  # 关键更新文件
            # r'(?i)\.important',  # 重要更新文件
            # r'(?i)\.recommended',  # 推荐更新文件
            # r'(?i)\.optional',  # 可选更新文件
            # r'(?i)\.driver',  # 驱动程序文件
            # r'(?i)\.firmware',  # 固件文件
            # r'(?i)\.bios',  # BIOS文件
            # r'(?i)\.uefi',  # UEFI文件
            # r'(?i)\.efi',  # EFI文件
            # r'(?i)\.boot',  # 启动文件
            # r'(?i)\.mbr',  # 主引导记录
            # r'(?i)\.gpt',  # GUID分区表
            # r'(?i)\.vhd',  # 虚拟硬盘
            # r'(?i)\.vhdx',  # 虚拟硬盘
            # r'(?i)\.vmdk',  # VMware虚拟磁盘
            # r'(?i)\.vdi',  # VirtualBox虚拟磁盘
            # r'(?i)\.qcow',  # QEMU虚拟磁盘
            # r'(?i)\.qcow2',  # QEMU虚拟磁盘
            # r'(?i)\.raw',  # 原始磁盘映像
            # r'(?i)\.img',  # 磁盘映像
            # r'(?i)\.ima',  # 磁盘映像
            # r'(?i)\.dsk',  # 磁盘映像
            # r'(?i)\.flp',  # 软盘映像
            # r'(?i)\.cdr',  # CD映像
            # r'(?i)\.nrg',  # Nero映像
            # r'(?i)\.bin',  # 二进制映像
            # r'(?i)\.cue',  # CUE文件
            # r'(?i)\.mds',  # MDS文件
            # r'(?i)\.ccd',  # CloneCD映像
            # r'(?i)\.sub',  # 子通道数据
            # r'(?i)\.isz',  # 压缩ISO
            # r'(?i)\.daa',  # PowerISO
            # r'(?i)\.uif',  # MagicISO
            # r'(?i)\.b5i',  # BlindWrite
            # r'(?i)\.b5t',  # BlindWrite
            # r'(?i)\.b6i',  # BlindWrite
            # r'(?i)\.b6t',  # BlindWrite
            # r'(?i)\.bwt',  # BlindWrite
            # r'(?i)\.cdi',  # DiscJuggler
            # r'(?i)\.cif',  # Easy CD Creator
            # r'(?i)\.c2d',  # Roxio
            # r'(?i)\.dmg',  # macOS磁盘映像
            # r'(?i)\.sparseimage',  # macOS稀疏映像
            # r'(?i)\.sparsebundle',  # macOS稀疏包
            # r'(?i)\.toast',  # Roxio Toast
            # r'(?i)\.img',  # 通用映像文件
            # r'(?i)\.ima',  # 磁盘映像
            # r'(?i)\.imz',  # 压缩磁盘映像
            # r'(?i)\.vfd',  # 虚拟软盘
            # r'(?i)\.vhd',  # 虚拟硬盘
            # r'(?i)\.vhdx',  # 虚拟硬盘
            # r'(?i)\.avhd',  # 差异虚拟硬盘
            # r'(?i)\.avhdx',  # 差异虚拟硬盘
            # r'(?i)\.vmdk',  # VMware虚拟磁盘
            # r'(?i)\.vmem',  # VMware内存文件
            # r'(?i)\.vmsn',  # VMware快照
            # r'(?i)\.vmss',  # VMware挂起状态
            # r'(?i)\.vmx',  # VMware配置文件
            # r'(?i)\.nvram',  # VMware NVRAM
            # r'(?i)\.vbox',  # VirtualBox配置文件
            # r'(?i)\.vdi',  # VirtualBox虚拟磁盘
            # r'(?i)\.hdd',  # Parallels虚拟磁盘
            # r'(?i)\.pvs',  # Parallels虚拟磁盘
            # r'(?i)\.hds',  # Hyper-V虚拟磁盘
            # r'(?i)\.avhd',  # Hyper-V差异磁盘
            # r'(?i)\.vhdx',  # Hyper-V虚拟磁盘
            # r'(?i)\.vud',  # Hyper-V差异磁盘
            # r'(?i)\.vhd',  # Hyper-V虚拟磁盘
            # r'(?i)\.vmdk',  # VMware虚拟磁盘
            # r'(?i)\.vdi',  # VirtualBox虚拟磁盘
            # r'(?i)\.qcow',  # QEMU虚拟磁盘
            # r'(?i)\.qcow2',  # QEMU虚拟磁盘
            # r'(?i)\.raw',  # 原始磁盘映像
            # r'(?i)\.img',  # 磁盘映像
            # r'(?i)\.iso',  # ISO光盘映像
            # r'(?i)\.bin',  # 二进制映像
            # r'(?i)\.cue',  # CUE文件
            # r'(?i)\.mdf',  # Alcohol 120%映像
            # r'(?i)\.mds',  # Alcohol 120%映像描述
            # r'(?i)\.nrg',  # Nero映像
            # r'(?i)\.cdi',  # DiscJuggler映像
            # r'(?i)\.dmg',  # macOS磁盘映像
            # r'(?i)\.toast',  # Roxio Toast映像
            # r'(?i)\.b5i',  # BlindWrite映像
            # r'(?i)\.b6i',  # BlindWrite映像
            # r'(?i)\.daa',  # PowerISO映像
            # r'(?i)\.uif',  # MagicISO映像
            # r'(?i)\.isz',  # 压缩ISO映像
            # r'(?i)\.cso',  # 压缩ISO映像
            # r'(?i)\.ecm',  # 错误代码模型压缩
            # r'(?i)\.par',  # PAR恢复文件
            # r'(?i)\.par2',  # PAR2恢复文件
            # r'(?i)\.sfv',  # 简单文件验证
            # r'(?i)\.md5',  # MD5校验和
            # r'(?i)\.sha1',  # SHA1校验和
            # r'(?i)\.sha256',  # SHA256校验和
            # r'(?i)\.sha512',  # SHA512校验和
            

            # # 开发工具和IDE
            # r'(?i)\\Visual Studio\\',  # Visual Studio
            # r'(?i)\\JetBrains\\',  # JetBrains IDE
            # r'(?i)\\IntelliJ IDEA\\',  # IntelliJ IDEA
            # r'(?i)\\PyCharm\\',  # PyCharm
            # r'(?i)\\WebStorm\\',  # WebStorm
            # r'(?i)\\PhpStorm\\',  # PhpStorm
            # r'(?i)\\RubyMine\\',  # RubyMine
            # r'(?i)\\Android Studio\\',  # Android Studio
            # r'(?i)\\Eclipse\\',  # Eclipse
            # r'(?i)\\NetBeans\\',  # NetBeans
            # r'(?i)\\VS Code\\',  # VS Code
            # r'(?i)\\Sublime Text\\',  # Sublime Text
            # r'(?i)\\Atom\\',  # Atom
            # r'(?i)\\Notepad\+\+\\',  # Notepad++
            # r'(?i)\\Vim\\',  # Vim
            # r'(?i)\\Emacs\\',  # Emacs
            # r'(?i)\\Git\\',  # Git
            # r'(?i)\\SVN\\',  # Subversion
            # r'(?i)\\Mercurial\\',  # Mercurial
            # r'(?i)\\Docker\\',  # Docker
            # r'(?i)\\Kubernetes\\',  # Kubernetes
            # r'(?i)\\Node\.js\\',  # Node.js
            # r'(?i)\\Python\\',  # Python
            # r'(?i)\\Java\\',  # Java
            # r'(?i)\\Go\\',  # Go
            # r'(?i)\\Rust\\',  # Rust
            # r'(?i)\\Ruby\\',  # Ruby
            # r'(?i)\\PHP\\',  # PHP
            # r'(?i)\\.git\\',  # Git仓库
            # r'(?i)\\.svn\\',  # SVN仓库
            # r'(?i)\\.hg\\',  # Mercurial仓库
            
            # 图片文件
            r'(?i)\.jpg',   # JPEG图像
            r'(?i)\.jpeg',  # JPEG图像
            r'(?i)\.png',   # PNG图像
            r'(?i)\.gif',   # GIF图像
            r'(?i)\.bmp',   # BMP图像
            r'(?i)\.webp',  # WebP图像
            r'(?i)\.tiff',  # TIFF图像
            r'(?i)\.tif',   # TIFF图像
            r'(?i)\.svg',   # SVG矢量图像
            r'(?i)\.raw',   # RAW图像
            r'(?i)\.heic',  # HEIC图像
            r'(?i)\.heif',  # HEIF图像
            r'(?i)\.psd',   # Photoshop文档
            r'(?i)\.ai',    # Adobe Illustrator文档
            r'(?i)\.eps',   # EPS矢量图像
            r'(?i)\.indd',  # InDesign文档
            r'(?i)\.cr2',   # Canon RAW
            r'(?i)\.nef',   # Nikon RAW
            r'(?i)\.orf',   # Olympus RAW
            r'(?i)\.sr2',   # Sony RAW
            r'(?i)\.dng',   # Digital Negative

            # 文本文件
            r'(?i)\.txt',   # 纯文本文件
            r'(?i)\.md',    # Markdown文档
            r'(?i)\.log',   # 日志文件
            r'(?i)\.csv',   # CSV数据文件
            r'(?i)\.json',  # JSON数据文件
            r'(?i)\.xml',   # XML文档
            r'(?i)\.yaml',  # YAML配置文件
            r'(?i)\.yml',   # YAML配置文件
            r'(?i)\.ini',   # INI配置文件
            r'(?i)\.cfg',   # 配置文件
            r'(?i)\.conf',  # 配置文件
            r'(?i)\.properties',  # 属性文件
            r'(?i)\.env',   # 环境变量文件
            r'(?i)\.sh',    # Shell脚本
            r'(?i)\.bat',   # Windows批处理文件
            r'(?i)\.ps1',   # PowerShell脚本
            r'(?i)\.py',    # Python脚本
            r'(?i)\.js',    # JavaScript文件
            r'(?i)\.html',  # HTML文档
            r'(?i)\.htm',   # HTML文档
            r'(?i)\.css',   # CSS样式表
            r'(?i)\.php',   # PHP脚本
            r'(?i)\.java',  # Java源代码
            r'(?i)\.c',     # C源代码
            r'(?i)\.cpp',   # C++源代码
            r'(?i)\.h',     # C/C++头文件
            r'(?i)\.hpp',   # C++头文件
            r'(?i)\.cs',    # C#源代码
            r'(?i)\.go',    # Go源代码
            r'(?i)\.rs',    # Rust源代码
            r'(?i)\.rb',    # Ruby源代码
            r'(?i)\.pl',    # Perl脚本
            r'(?i)\.pm',    # Perl模块
            r'(?i)\.sql',   # SQL脚本
            r'(?i)\.r',     # R脚本
            r'(?i)\.m',     # MATLAB/Objective-C源代码
            r'(?i)\.swift', # Swift源代码
            r'(?i)\.kt',    # Kotlin源代码
            r'(?i)\.dart',  # Dart源代码
            r'(?i)\.ts',    # TypeScript文件
            r'(?i)\.jsx',   # React JSX文件
            r'(?i)\.tsx',   # React TypeScript文件
            r'(?i)\.vue',   # Vue.js组件
            r'(?i)\.svelte', # Svelte组件

            # 日志文件
            r'(?i)\.out',   # 输出日志
            r'(?i)\.err',   # 错误日志
            r'(?i)\.syslog', # 系统日志
            r'(?i)\.event', # 事件日志
            r'(?i)\.audit', # 审计日志
            r'(?i)\.trace', # 跟踪日志
            r'(?i)\.debug', # 调试日志
            r'(?i)\\Logs\\',  # 日志目录
            r'(?i)\\var\\log\\',  # Linux日志目录
            r'(?i)\\Windows\\Logs\\',  # Windows日志目录
            r'(?i)\\EventLogs\\',  # 事件日志目录
            r'(?i)\\AppLogs\\',  # 应用日志目录
            

            # FTP服务
            r'(?i)\\FileZilla\\',  # FileZilla
            r'(?i)\\vsftpd\\',  # vsftpd
            r'(?i)ftp\.conf',  # FTP配置
            

            # 邮件服务
            r'(?i)\\Exchange\\',  # Exchange
            r'(?i)\\postfix\\',  # Postfix
            r'(?i)\\sendmail\\',  # Sendmail
            
            
            # VPN软件
            r'(?i)\\OpenVPN\\',  # OpenVPN
            r'(?i)\.ovpn',  # OpenVPN配置
            r'(?i)\\WireGuard\\',  # WireGuard
        ]

        return common_address_patterns



def _common_process_patterns(self):
        # 常用进程正则表达式模式
        common_process_patterns = [

            # 常用进程
            r'(?i)notepad',  # 记事本
            r'(?i)mspaint',  # 画图
            r'(?i)StikyNot',  # 便签
            r'(?i)wab',     # 联系人
            r'(?i)Dumpit',  # 内存取证
            r'(?i)TrueCrypt',  # TrueCrypt
            r'(?i)MineSweeper',  # 扫雷

            # 系统工具
            r'(?i)calc',        # 计算器
            r'(?i)cmd',         # 命令提示符
            r'(?i)powershell',  # PowerShell
            r'(?i)explorer',    # 文件资源管理器
            r'(?i)svchost',     # 系统服务宿主进程
            r'(?i)taskmgr',     # 任务管理器
            r'(?i)regedit',     # 注册表编辑器
            r'(?i)services',    # 服务管理器
            r'(?i)control',     # 控制面板
            r'(?i)mmc',         # 微软管理控制台

            # 办公软件
            r'(?i)winword',     # Word
            r'(?i)excel',       # Excel
            r'(?i)powerpnt',    # PowerPoint
            r'(?i)outlook',     # Outlook
            r'(?i)acrobat',     # Adobe Acrobat
            r'(?i)foxit',       # Foxit Reader

            # 多媒体工具
            r'(?i)mspaint',     # 画图工具
            r'(?i)wmplayer',    # Windows Media Player
            r'(?i)vlc',         # VLC播放器
            r'(?i)photoshop',   # Photoshop
            r'(?i)audacity',    # Audacity音频编辑

            # # 游戏娱乐
            # r'(?i)minesweeper', # 扫雷游戏
            # r'(?i)solitaire',   # 纸牌游戏
            # r'(?i)hearts',      # 红心大战
            # r'(?i)spider',      # 蜘蛛纸牌
            # r'(?i)freecell',    # 空当接龙

            # # 安全工具
            # r'(?i)dumpit',      # 内存镜像提取工具
            # r'(?i)truecrypt',   # 磁盘加密工具
            # r'(?i)mimikatz',    # 密码提取工具
            # r'(?i)wireshark',   # 网络抓包工具
            # r'(?i)volatility',  # 内存分析工具
            # r'(?i)procdump',    # 进程转储工具
            # r'(?i)processhacker', # 进程查看工具

            # # Windows系统核心进程
            # r'(?i)system',  # 系统进程
            # r'(?i)smss',  # 会话管理器
            # r'(?i)csrss',  # 客户端服务器运行时子系统
            # r'(?i)wininit',  # Windows初始化进程
            # r'(?i)winlogon',  # Windows登录进程
            # r'(?i)services',  # 服务控制管理器
            # r'(?i)lsass',  # 本地安全认证子系统
            # r'(?i)svchost',  # 服务主机进程
            # r'(?i)spoolsv',  # 打印后台处理服务
            # r'(?i)explorer',  # Windows资源管理器
            # r'(?i)dwm',  # 桌面窗口管理器

            # # Linux系统核心进程
            # r'(?i)systemd',     # 系统和服务管理器
            # r'(?i)init',        # 初始化进程
            # r'(?i)kthreadd',    # 内核线程守护进程
            # r'(?i)ksoftirqd',   # 软中断守护进程
            # r'(?i)sshd',        # SSH服务进程
            # r'(?i)bash',        # Bash shell
            # r'(?i)sh',          # Shell
            # r'(?i)cron',        # 定时任务守护进程
            # r'(?i)syslogd',     # 系统日志守护进程
            # r'(?i)dbus-daemon', # D-Bus消息总线
            # r'(?i)NetworkManager', # 网络管理器
            # r'(?i)sshd',           # SSH连接可能包含攻击痕迹
            # r'(?i)bash',           # Shell进程包含命令执行历史
            # r'(?i)cron',           # 定时任务可能被恶意利用
            # r'(?i)systemd',        # 系统服务管理器

            # # 命令历史相关进程
            # r'(?i)bash',            # Bash shell进程
            # r'(?i)sh',              # Shell进程
            # r'(?i)zsh',             # Zsh shell进程
            # r'(?i)ssh',             # SSH客户端/服务端进程
            # r'(?i)sshd',            # SSH守护进程
            # r'(?i)last',            # 最后登录信息命令
            # r'(?i)who',             # 当前登录用户命令
            # r'(?i)w',               # 显示登录用户及活动命令
            # r'(?i)ps',              # 进程查看命令
            # r'(?i)netstat',         # 网络连接查看命令
            # r'(?i)ss',              # Socket统计命令
            # r'(?i)iptables',        # 防火墙规则命令
            # r'(?i)scp',             # 安全拷贝命令
            # r'(?i)wget',            # 文件下载命令
            # r'(?i)curl',            # 数据传输工具命令
            # r'(?i)nmap',            # 网络扫描工具命令
            # r'(?i)nc',              # Netcat网络工具命令
            # r'(?i)tcpdump',         # 网络抓包工具命令
            # r'(?i)history',         # 历史命令查看
            # r'(?i)cron',            # 定时任务守护进程
            # r'(?i)atd',             # 一次性任务守护进程
            # r'(?i)systemd',         # 系统服务管理器

            # # 安全软件进程
            # r'(?i)360',  # 360安全卫士/杀毒
            # r'(?i)360safe',  # 360安全卫士
            # r'(?i)360sd',  # 360杀毒
            # r'(?i)huorong',  # 火绒安全
            # r'(?i)sysdiag',  # 火绒安全
            # r'(?i)avast',  # Avast杀毒软件
            # r'(?i)avg',  # AVG杀毒软件
            # r'(?i)bitdefender',  # Bitdefender
            # r'(?i)kaspersky',  # 卡巴斯基
            # r'(?i)mcafee',  # McAfee
            # r'(?i)norton',  # Norton
            # r'(?i)windowsdefender',  # Windows Defender
            
            # # 浏览器进程
            # r'(?i)iexplore',    # IE浏览器
            # r'(?i)chrome',  # Chrome浏览器
            # r'(?i)firefox',  # Firefox浏览器
            # r'(?i)edge',  # Edge浏览器
            # r'(?i)opera',  # Opera浏览器
            # r'(?i)safari',      # Safari浏览器
            # r'(?i)iexplorer',  # Internet Explorer
            # r'(?i)outlook',   # Outlook
            # r'(?i)thunderbird',  # Thunderbird
            # r'(?i)skype',  # Skype
            # r'(?i)teams',  # Microsoft Teams
            # r'(?i)zoom',  # Zoom
            
            # # 远程控制进程
            # r'(?i)todesk',   # ToDesk
            # r'(?i)sunlogin',   # 向日葵
            # r'(?i)anydesk',   # AnyDesk
            # r'(?i)mstsc',    # 远程桌面
            # r'(?i)teamviewer',  # 远程控制
            # r'(?i)putty',   # SSH客户端
            # r'(?i)filezilla',   # FTP客户端
            # r'(?i)winscp',   # SFTP客户端
            
            # # 数据库软件进程
            # r'(?i)sql',   # SQL Server
            # r'(?i)mysql',  # MySQL
            # r'(?i)mysqld',  # MySQL守护进程
            # r'(?i)mysqladmin',  # MySQL管理工具
            # r'(?i)mysqldump',  # MySQL备份工具
            # r'(?i)postgres',  # PostgreSQL
            # r'(?i)postmaster',  # PostgreSQL主进程
            # r'(?i)pgadmin',  # PostgreSQL管理工具
            # r'(?i)psql',  # PostgreSQL命令行工具
            # r'(?i)oracle',  # Oracle
            # r'(?i)sqlplus',  # SQL*Plus
            # r'(?i)sqlldr',  # SQL*Loader
            # r'(?i)exp',  # Oracle导出工具
            # r'(?i)imp',  # Oracle导入工具
            # r'(?i)sql',  # SQL相关进程
            # r'(?i)sqlservr',  # SQL Server
            # r'(?i)sqlagent',  # SQL Server代理
            # r'(?i)sqlbrowser',  # SQL Server浏览器
            # r'(?i)mongodb',     # MongoDB
            # r'(?i)mongod',  # MongoDB守护进程
            # r'(?i)mongo',  # MongoDB客户端
            # r'(?i)mongos',  # MongoDB路由进程
            # r'(?i)redis',  # Redis
            # r'(?i)redis-server',  # Redis服务器
            # r'(?i)redis-cli',  # Redis命令行工具
            # r'(?i)elasticsearch',  # Elasticsearch
            # r'(?i)kibana',  # Kibana
            # r'(?i)logstash',  # Logstash
            # r'(?i)cassandra',  # Cassandra
            # r'(?i)cqlsh',  # Cassandra查询语言shell
            # r'(?i)couchdb',  # CouchDB
            # r'(?i)influxd',  # InfluxDB守护进程
            # r'(?i)influx',  # InfluxDB客户端
            # r'(?i)neo4j',  # Neo4j
            # r'(?i)cypher-shell',  # Neo4j Cypher shell
            # r'(?i)clickhouse',  # ClickHouse
            # r'(?i)clickhouse-client',  # ClickHouse客户端
            # r'(?i)cockroach',  # CockroachDB
            # r'(?i)cockroach-sql',  # CockroachDB SQL客户端
            # r'(?i)timescaledb',  # TimescaleDB
            # r'(?i)postgis',  # PostGIS
            # r'(?i)spatialite',  # SpatiaLite
            # r'(?i)sqlite',  # SQLite
            # r'(?i)sqlite3',  # SQLite3
            # r'(?i)berkeleydb',  # Berkeley DB
            # r'(?i)db2',  # IBM DB2
            # r'(?i)informix',  # Informix
            # r'(?i)sybase',  # Sybase
            # r'(?i)vertica',  # Vertica
            # r'(?i)greenplum',  # Greenplum
            # r'(?i)hadoop',  # Hadoop
            # r'(?i)hbase',  # HBase
            # r'(?i)hive',  # Hive
            # r'(?i)pig',  # Pig
            # r'(?i)spark',  # Spark
            # r'(?i)presto',  # Presto
            # r'(?i)druid',  # Druid
            # r'(?i)kudu',  # Kudu
            # r'(?i)impala',  # Impala
            # r'(?i)drill',  # Drill
            # r'(?i)phoenix',  # Phoenix
            # r'(?i)flink',  # Flink
            # r'(?i)storm',  # Storm
            # r'(?i)samza',  # Samza
            # r'(?i)beam',  # Beam
            # r'(?i)nifi',  # NiFi
            # r'(?i)kafka',  # Kafka
            # r'(?i)zookeeper',  # ZooKeeper
            # r'(?i)consul',  # Consul
            # r'(?i)etcd',  # etcd
            # r'(?i)vault',  # Vault
            # r'(?i)nomad',  # Nomad
            # r'(?i)mesos',  # Mesos
            # r'(?i)marathon',  # Marathon
            # r'(?i)chronos',  # Chronos
            # r'(?i)aurora',  # Aurora
            # r'(?i)kubernetes',  # Kubernetes
            # r'(?i)minikube',  # Minikube
            # r'(?i)kind',  # Kind
            # r'(?i)k3s',  # K3s
            # r'(?i)microk8s',  # MicroK8s
            # r'(?i)openshift',  # OpenShift
            # r'(?i)okd',  # OKD
            # r'(?i)tekton',  # Tekton
            # r'(?i)knative',  # Knative
            # r'(?i)istio',  # Istio
            # r'(?i)linkerd',  # Linkerd
            # r'(?i)envoy',  # Envoy
            # r'(?i)contour',  # Contour
            # r'(?i)traefik',  # Traefik
            
            # # WEB网站中间件配置进程
            # r'(?i)apache',  # Apache
            # r'(?i)httpd',  # HTTP服务器
            # r'(?i)nginx',  # Nginx
            # r'(?i)tomcat',  # Tomcat
            # r'(?i)jetty',  # Jetty
            # r'(?i)jboss',  # JBoss
            # r'(?i)wildfly',  # WildFly
            # r'(?i)glassfish',  # GlassFish
            # r'(?i)weblogic',  # WebLogic
            # r'(?i)websphere',  # WebSphere
            # r'(?i)iis',  # IIS
            # r'(?i)w3wp',  # IIS工作进程
            # r'(?i)php',  # PHP
            # r'(?i)php-fpm',  # PHP-FPM
            # r'(?i)node',  # Node.js
            # r'(?i)nodejs',  # Node.js
            # r'(?i)python',  # Python
            # r'(?i)ruby',  # Ruby
            # r'(?i)java',  # Java
            # r'(?i)javaw',  # Java窗口应用
            # r'(?i)docker',    # Docker容器
            
            # # 日志相关进程
            # r'(?i)log',  # 日志相关
            # r'(?i)syslog',  # 系统日志
            # r'(?i)rsyslog',  # rsyslog
            # r'(?i)syslog-ng',  # syslog-ng
            # r'(?i)journald',  # systemd日志
            # r'(?i)fluentd',  # Fluentd
            # r'(?i)logstash',  # Logstash
            # r'(?i)filebeat',  # Filebeat
            # r'(?i)metricbeat',  # Metricbeat
            # r'(?i)packetbeat',  # Packetbeat
            # r'(?i)winlogbeat',  # Winlogbeat
            # r'(?i)auditd',  # 审计守护进程
            # r'(?i)splunk',  # Splunk
            
            # # 系统工具和命令行进程
            # r'(?i)cmd',  # 命令提示符
            # r'(?i)powershell',  # PowerShell
            # r'(?i)taskmgr',  # 任务管理器
            # r'(?i)mmc',  # Microsoft管理控制台
            # r'(?i)regsvr32',  # 注册服务器
            # r'(?i)rundll32',  # 运行DLL
            
            # # 邮件客户端进程
            # r'(?i)outlook',  # Outlook
            # r'(?i)thunderbird',  # Thunderbird
            # r'(?i)postfix',  # Postfix邮件服务器
            # r'(?i)sendmail',  # Sendmail邮件服务器
            # r'(?i)exim',  # Exim邮件服务器
            # r'(?i)dovecot',  # Dovecot邮件服务器
            
            # # 压缩工具进程
            # r'(?i)bandzip',  # Bandzip
            # r'(?i)winzip',  # WinZip
            # r'(?i)winrar',  # WinRAR
            # r'(?i)7zip',  # 7-Zip
            # r'(?i)7z',  # 7-Zip
            # r'(?i)xz',  # xz压缩
            # r'(?i)tar',  # tar归档工具
            # r'(?i)gzip',  # gzip压缩
            # r'(?i)bzip2',  # bzip2压缩
            
            # # 开发工具进程
            # r'(?i)visualstudio',  # Visual Studio
            # r'(?i)vscode',  # VS Code
            # r'(?i)eclipse',  # Eclipse
            # r'(?i)intellij',  # IntelliJ IDEA
            # r'(?i)pycharm',  # PyCharm
            # r'(?i)webstorm',  # WebStorm
            # r'(?i)phpstorm',  # PhpStorm
            # r'(?i)ruby',  # Ruby
            # r'(?i)rubymine',  # RubyMine
            # r'(?i)androidstudio',  # Android Studio
            # r'(?i)sublime',  # Sublime Text
            # r'(?i)atom',  # Atom
            # r'(?i)notepad\+\+',  # Notepad++
            # r'(?i)vim',  # Vim
            # r'(?i)emacs',  # Emacs
            # r'(?i)git',  # Git
            # r'(?i)svn',  # Subversion
            # r'(?i)hg',  # Mercurial
            # r'(?i)docker',  # Docker
            # r'(?i)containerd',  # Containerd
            # r'(?i)podman',  # Podman
            # r'(?i)kubernetes',  # Kubernetes
            # r'(?i)kube',  # Kubernetes组件
            # r'(?i)minikube',  # Minikube
            # r'(?i)kind',  # Kind
            # r'(?i)terraform',  # Terraform
            # r'(?i)ansible',  # Ansible
            # r'(?i)puppet',  # Puppet
            # r'(?i)chef',  # Chef
            # r'(?i)gradle',  # Gradle
            # r'(?i)maven',  # Maven
            # r'(?i)ant',  # Ant
            # r'(?i)make',  # Make
            # r'(?i)cmake',  # CMake
            # r'(?i)ninja',  # Ninja
            # r'(?i)npm',  # npm
            # r'(?i)yarn',  # Yarn
            # r'(?i)pip',  # pip
            # r'(?i)composer',  # Composer
            # r'(?i)gem',  # RubyGems
            # r'(?i)cargo',  # Cargo
            # r'(?i)go',  # Go
            # r'(?i)rust',  # Rust
            # r'(?i)dotnet',  # .NET
            # r'(?i)mono',  # Mono
        ]

        return common_process_patterns
