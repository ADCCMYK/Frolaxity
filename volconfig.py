#!/usr/bin/env python3
import os
import sys
sys.dont_write_bytecode = True

import re
import platform




def _set_volatility(self):
        # vol环境配置(.py后缀会加上python环境配置路径)
        if platform.system() == 'Windows':
            return ['vol2', 'vol3']
        else:
            return ['vol2', 'vol3']




def _set_python_paths(self):
        # python环境配置(可以直接运行vol2.py/vol3.py这里配置为空)
        if platform.system() == 'Windows':
            return ['python2', 'python3']
        else:
            return ['python2', 'python3']




def _set_volshows(self):
        # 命令行显示配置
        if platform.system() == 'Windows':
            return ['vol2', 'vol3']
        else:
            return ['vol2', 'vol3']




# 优先正则扫描目录
def _get_priority_dirs(self):
    # 获取优先扫描目录列表
    return ['tree_report']




# 正则扫描跳过的目录
def _get_skipped_directories(self):
    # 获取需要跳过的目录列表
    return ['search_report', 'ctf_report']




# 文件树扫描跳过的目录
def _get_tree_skipped_directories(self):
    # 获取文件树扫描中需要跳过的目录列表
    return ['search_report', 'tree_report', 'extracted_files']




# 解压缩扫描跳过的目录
def _get_unzip_skipped_directories(self):
    # 获取解压缩扫描中需要跳过的目录列表
    return ['search_report', 'tree_report', 'extracted_files']




# 默认目录名称列表
def _get_default_directory_names(self):
    return ['search_report', 'ctf_report', 'tree_report', 'extracted_files']




# 默认目录前缀列表
def _get_default_file_prefixes(self):
    return ['common_addresses_', 'common_process_', 'dumps_', 'hidden_processes_']




# 默认输出插件方法
def _get_default_output_plugin(self):

    return [ 
        'mimikatz.txt', 'clipboard.txt', 'hashdump.txt', 'lsadump.txt', 'cachedump.txt', 'usbstor.txt', 
        'bitlocker.txt', 'iehistory.txt', 'editbox.txt', 'cmdscan.txt','consoles.txt', 'cmdline.txt', 
        'windows.cmdline.txt','mac.bash.Bash.txt', 'linux.lsof.Lsof.txt',
        'firefoxhistory.txt', 'chromehistory.txt', 
    ]




# 优先匹配显示数量限制 0表示无上限
def _get_priority_match_limit(self):
    return 25




# 其他匹配显示数量限制 0表示无上限
def _get_other_match_limit(self):
    return 5




# 控制台输出上下文字符数限制 0表示无上限
def _get_console_context_limit(self):
    return 1000




# 从扫描匹配结果中排除不需要显示内容
def _scan_exclude_patterns(self):
    """返回CTF扫描匹配中需要排除显示的模式列表"""
    return [
        r'(?i)\bFlags\b',
        r'(?i)\bCtfImmNotify\b',
        r'(?i)\bCtfImeSetFocus\b',
        r'(?i)\bCtfImeSetFocus\b',
        r'(?i)\bCtfImeConfigure\b',
        r'(?i)\bCtfImmGetGuidAtom\b',
        r'(?i)\bCtfImmTIMActivate\b',
        r'(?i)\bCtfImmHideToolbarWnd\b',
        r'(?i)\bCtfImeAssociateFocus\b',
        r'(?i)\bCtfImeAssociateFocus\b',
        r'(?i)\bCtfImmCoUninitialize\b',
        r'(?i)\bCtfImmIsGuidMapEnable\b',
        r'(?i)\bCtfImmIsCiceroEnabled\b',
        r'(?i)\bCtfImmGenerateMessage\b',
        r'(?i)\bCtfImeDispatchDefImeMessage\b',
        r'(?i)\bCtfImmSetCiceroStartInThread\b',
        r'(?i)\bCtfImmLeaveCoInitCountSkipMode\b',
        r'(?i)\bCtfImmEnterCoInitCountSkipMode\b',
        r'(?i)\bCtfImmIsTextFrameServiceDisabled\b',
        r'(?i)\bCtfImmSetDefaultRemoteKeyboardLayout\b',
        ]




# CTF扫描优先显示
def _scan_priority_patterns(self):
    """返回CTF扫描匹配中需要优先显示的模式列表"""
    # 这些模式用于从已扫描匹配结果中筛选重要内容进行优先显示
    return [
            r'(?i)f+[1li!|]+[a4@]+[g9]+\{[^}]*(?:\})?',
            r'(?i)f+[1li!|]+[a4@]+[g9]+[-\w]*(?:\.[^.\s]+)?',
            r'(?i)f+[1li!|]+[a4@]+[g9]+(?:\d+)?\.[^.\s]+',
            r'(?i)f+[1li!|]+[a4@]+[g9]+(?:\d+)?',
            r'(?i)ctf\{[^}]*(?:\})?',
            r'(?i)ctf[-\w]*(?:\.[^.\s]+)?',
            r'(?i)h[1li!|]+[nm]+t[-\w]*(?:\.[^.\s]+)?',
            r'(?i)h[1li!|]+[nm]+t(?:\d+)?',
            r'(?i)s[5$s]+[e3]+[c\(]+[r2]+[e3]+t[-\w]*(?:\.[^.\s]+)?',
            r'(?i)s[5$s]+[e3]+[c\(]+[r2]+[e3]+t(?:\d+)?',
        ]





# 重命名移动文件操作
def _get_file_operation_timeout(self):
    # 获取文件操作超时时间
    return 60




def _get_file_exts(self, plugins=""):
    # 文件提取重命名移动后缀
    if plugins in ['dumpfiles', '']:
        file_exts = ['.dat', '.evtx', '.vacb', '.img']
    else:
    # 进程提取重命名移动后缀
        file_exts = ['.dmp']
    
    return file_exts




def _set_extract_files(self):
       # 默认解压配置
       return ['.dat', '.dat_old']




# 支持压缩文件扩展名
def _get_archive_extensions(self):
    # 获取支持的压缩文件扩展名列表
    return ['.zip', '.rar', '.7z', '.gz', '.gzip', '.bz2', '.xz', '.tar', '.tgz', '.tbz2', '.txz', '.dat', '.dat_old']




def _is_text_file(self, file_path):
    # 根据文件扩展名判断是否为文本文件
    return file_path.lower().endswith((
        '.txt', '.log', '.ini', '.conf', '.xml', '.md', '.evtx', 
        '.json', '.yaml', '.yml', '.csv', '.html', '.htm', '.js', 
        '.css', '.php', '.py', '.java', '.c', '.cpp', '.h', '.cs', 
        '.go', '.rs', '.rb', '.pl', '.sh', '.bat', '.ps1', '.sql', 
        '.css', '.js', '.py', '.c', '.cpp', '.h', '.java',
        '.cfg', '.config', '.properties', '.env', '.gitignore', 
        '.dockerignore', '.editorconfig', '.gitattributes',
        '.gd','.tscn'
    ))




def _get_file_categories(self):
    file_extensions = {
        # 系统文件
        'dll': ['.dll', '.drv', '.ocx', '.cpl'],
        'evtx': ['.evtx', '.evt'],
        'exe': ['.exe', '.com', '.bat', '.cmd', '.msi', '.msix', '.appx'],
        
        # 存储和镜像
        'img': ['.img', '.iso', '.dmg', '.cue', '.nrg', '.mdf', '.mds', '.daa', '.uif', '.isz', '.cso', '.ecm'],
        'virtualization': ['.vhd', '.vhdx', '.vmdk', '.vdi', '.qcow', '.qcow2', '.raw', '.vfd', '.vmem', '.vmsn', '.vmss', '.vmx', '.nvram', '.vbox', '.ova', '.ovf'],
        
        # 数据和数据库
        'data': ['.dat', '.kdbx', '.psafe3', '.agilekeychain', '.opvault', '.sqlite', '.sqlite3', '.db', '.mdb', '.accdb', '.fdb', '.ldf', '.frm', '.myd', '.myi', '.ibd', '.dbf', '.sql'],
        'blockchain': ['.block', '.wallet'],
        
        # 文档和办公
        'document': ['.doc', '.docx', '.ppt', '.pptx', '.xls', '.xlsx', '.rtf', '.pdf', '.odt', '.ods', '.odp'],
        'ebook': ['.epub', '.mobi', '.azw'],
        'cad': ['.dwg', '.dxf', '.stl', '.obj'],
        'gis': ['.shp', '.kml', '.kmz', '.geojson'],
        'font': ['.ttf', '.otf', '.woff', '.woff2'],
        
        # 媒体文件
        'image': ['.jpg', '.jpeg', '.png', '.gif', '.bmp', '.webp', '.tiff', '.tif', '.ico'],
        'video': ['.mp4', '.avi', '.mov', '.mkv', '.h264', '.wmv', '.flv', '.webm', '.m4v', '.mpg', '.mpeg', '.3gp', '.rmvb', '.vob', '.ts', '.m2ts', '.asf', '.divx', '.ogv', '.f4v'],
        'audio': ['.mp3', '.wav', '.flac', '.ogg', '.mid', '.midi', '.au', '.aac', '.wma', '.m4a', '.opus', '.aif', '.aiff', '.amr', '.ape', '.ra', '.rm'],
        
        # 系统和技术文件
        'process': ['.dmp', '.bin', '.core', '.crash', '.hprof', '.heapdump'],
        'text': ['.txt', '.md', '.log', '.ini', '.conf', '.xml', '.out', '.err', '.syslog', '.event', '.audit', '.trace', '.debug'],
        'config': ['.env', '.htaccess', '.config', '.yml', '.yaml', '.json', '.properties', '.cfg', '.inf', '.reg', '.policy'],
        'certificate': ['.key', '.cert', '.crt', '.pem', '.der', '.pfx', '.p12', '.keystore', '.jks', '.truststore', '.bks', '.p7b', '.p7c', '.spc', '.cer', '.csr', '.crl', '.ocsp', '.asc', '.gpg', '.pgp', '.sig', '.signature'],
        
        # 代码和脚本
        'source': ['.c', '.cpp', '.h', '.hpp', '.java', '.cs', '.go', '.rs', '.swift', '.kt', '.scala', '.m', '.mm'],
        'script': ['.sh', '.bash', '.zsh', '.fish', '.ps1', '.vbs', '.py', '.rb', '.pl', '.lua', '.tcl'],
        'web': ['.html', '.htm', '.css', '.ts', '.php', '.jsp', '.japx', '.jsx', '.tsx', '.vue', '.svelte', '.scss', '.less', '.sass'],
        
        # 压缩和归档
        'software': ['.zip', '.rar', '.tar', '.7z', '.xz', '.zst', '.gz', '.bz2', '.lzh', '.arj', '.cab', '.deb', '.rpm', '.tar.gz', '.pkg', '.apk', '.ipa', '.par', '.par2', '.sfv', '.md5', '.sha1', '.sha256', '.sha512', '.crc', '.sfx', '.001', '.002', '.part', '.split', '.archive', '.backup', '.download', '.partial', '.crdownload', '.torrent', '.magnet', '.ed2k'],
        
        # 网络和通信
        'network': ['.pcap', '.pcapng', '.cap', '.net', '.flow', '.tcpdump', '.saz', '.har', '.nfdump', '.nfcapd'],
        'email': ['.pst', '.ost', '.eml', '.msg'],
        
        # 其他独特类别
        'git': ['.git', '.gitignore', '.gitattributes', '.gitmodules', '.gitkeep'],
        'container': ['.dockerfile'],
        'backup': ['.bak', '.old', '.temp', '.tmp', '.swp', '.swo', '.php~', '.~'],
        'unknown': []
    }
    
    return file_extensions




def _create_output_dir(self):
        # 创建输出目录
        if not os.path.exists(self.output_dir):
            os.makedirs(self.output_dir)
            print(f"[*] 创建输出目录: {self.output_dir}")
        return True




def _systeminfo(self):
        # 根据自动检测的profile设置系统类型
        if "Win" in self.profile:
            self.system_type = "windows"
        elif "Linux" in self.profile:
            self.system_type = "linux"
        elif "Mac" in self.profile:
            self.system_type = "mac"
        else:
            self.system_type = "unknown"




def _get_vol3_plugin(self, plugin_name):
        if self.system_type == "windows":
            # Windows系统映射
            if plugin_name == "dumpfiles":
                return "windows.dumpfiles"
            elif plugin_name == "memdump":
                return "windows.memmap"
        elif self.system_type == "linux":
            # Linux系统映射
            if plugin_name == "dumpfiles":
                return "linux.pagecache.InodePages"
            elif plugin_name == "memdump":
                return "linux.elfs.Elfs"
        # 其他系统或未知插件保持原样
        return plugin_name




def _check_batch_termination(self, file_path):
    
    if not os.path.exists(file_path):
        return False
                
    try:
        # 首先尝试UTF-8编码读取
        with open(file_path, "r", encoding='utf-8', errors='ignore') as f:
            content = f.read()
            
            # 检测Windows批处理终止提示
            if "终止批处理操作吗(Y/N)?" in content:
                return True
                
            # 检测Linux中断输出
            linux_interrupt_patterns = [
                r"^\^C$",  # Ctrl+C
            ]
            
            for pattern in linux_interrupt_patterns:
                if re.search(pattern, content, re.IGNORECASE | re.MULTILINE):
                    return True
        
        # 如果UTF-8读取没有找到终止提示，尝试GBK编码读取
        with open(file_path, "r", encoding='gbk', errors='ignore') as f:
            content = f.read()
            
            # 检测Windows批处理终止提示
            if "终止批处理操作吗(Y/N)?" in content:
                return True

            # 检测Linux中断输出
            linux_interrupt_patterns = [
                r"^\^C$",  # Ctrl+C
            ]
                
            # 检测Linux中断输出
            for pattern in linux_interrupt_patterns:
                if re.search(pattern, content, re.IGNORECASE | re.MULTILINE):
                    return True
                    
        return False
    except Exception as e:
        print(f"[!] 检查文件 {file_path} 失败: {e}")
    return False




def _parse_windows_profile(self, content):
    
    # 检查是否空值
    if not content:
        return False
            
    # 检查是否是Windows系统
    if "NtProductType" not in content and "Kernel Base" not in content:
        return False
    
    self.system_type = "windows"
    
    # 一次性提取所有可能的信息
    build_lab_match = re.search(r"NTBuildLab\s+([\d\.\-]+)", content)
    major_version_match = re.search(r"NtMajorVersion\s+(\d+)", content)
    minor_version_match = re.search(r"NtMinorVersion\s+(\d+)", content)
    build_number_match = re.search(r"NtBuildNumber\s+(\d+)", content)
    is_64bit_match = re.search(r"Is64Bit\s+(True|False)", content)
    product_type_match = re.search(r"NtProductType\s+(\w+)", content)
    
    # 获取所有可用信息
    build_lab = build_lab_match.group(1) if build_lab_match else None
    major = int(major_version_match.group(1)) if major_version_match else None
    minor = int(minor_version_match.group(1)) if minor_version_match else None
    build_number = int(build_number_match.group(1)) if build_number_match else None
    is_64bit = bool(is_64bit_match and is_64bit_match.group(1) == "True") if is_64bit_match else True
    product_type = product_type_match.group(1) if product_type_match else None
    
    profile_suffix = "x64" if is_64bit else "x86"
    
    # 优先级1: 使用NTBuildLab进行精确匹配
    if build_lab:
        build_lab_parts = build_lab.split('.')
        if len(build_lab_parts) >= 2:
            main_build = build_lab_parts[0]
            
            # Windows Vista
            if main_build == '6000':
                self.profile = f"VistaSP0{profile_suffix}"
            elif main_build == '6001':
                self.profile = f"VistaSP1{profile_suffix}"
            elif main_build == '6002':
                self.profile = f"VistaSP2{profile_suffix}"
            # Windows 7
            elif main_build == '7600':
                self.profile = f"Win7SP0{profile_suffix}"
            elif main_build == '7601':
                self.profile = f"Win7SP1{profile_suffix}"
            # Windows 8
            elif main_build == '9200':
                self.profile = f"Win8SP0{profile_suffix}"
            # Windows 8.1
            elif main_build == '9600':
                self.profile = f"Win8SP1{profile_suffix}"
            # Windows 10
            elif main_build == '10240':
                self.profile = f"Win10x64_10586" if is_64bit else f"Win10x86_10586"
            elif main_build == '10586':
                self.profile = f"Win10x64_10586" if is_64bit else f"Win10x86_10586"
            elif main_build == '14393':
                self.profile = f"Win10x64_14393" if is_64bit else f"Win10x86_14393"
            elif main_build == '15063':
                self.profile = f"Win10x64" if is_64bit else f"Win10x86"
            elif main_build == '16299':
                self.profile = f"Win10x64" if is_64bit else f"Win10x86"
            elif main_build == '17134':
                self.profile = f"Win10x64" if is_64bit else f"Win10x86"
            elif main_build == '17763':
                self.profile = f"Win10x64" if is_64bit else f"Win10x86"
            elif main_build == '18362':
                self.profile = f"Win10x64" if is_64bit else f"Win10x86"
            elif main_build == '19041':
                self.profile = f"Win10x64" if is_64bit else f"Win10x86"
            elif main_build == '22000':
                self.profile = f"Win10x64"
            else:
                pass

            if self.profile:
                print(f"[*] 根据NTBuildLab检测: {build_lab}, 架构: {profile_suffix}, 使用Profile: {self.profile}")
                return True
    
    # 优先级2: 使用版本号和构建号进行匹配
    if major is not None and minor is not None:
        # Windows Server检测
        if product_type and product_type in ["Server", "LanmanNt", "ServerNt"]:
            if major == 5 and minor == 2:
                if build_number and build_number >= 3790:
                    self.profile = f"Win2003SP2{profile_suffix}"
                else:
                    self.profile = f"Win2003SP1{profile_suffix}"
            elif major == 6 and minor == 0:
                if build_number and build_number >= 6002:
                    self.profile = f"Win2008SP2{profile_suffix}"
                elif build_number and build_number >= 6001:
                    self.profile = f"Win2008SP1{profile_suffix}"
                else:
                    self.profile = f"Win2008SP0{profile_suffix}"
            elif major == 6 and minor == 1:
                self.profile = f"Win2008R2SP1{profile_suffix}"
            elif major == 6 and minor == 2:
                self.profile = f"Win2012x64" if is_64bit else f"Win2012x86"
            elif major == 6 and minor == 3:
                self.profile = f"Win2012R2x64" if is_64bit else f"Win2012R2x86"
            elif major == 10:
                if build_number and build_number >= 14393:
                    self.profile = f"Win2016x64_14393" if is_64bit else f"Win2016x86_14393"
                else:
                    pass

            if self.profile:
                print(f"[*] 检测到服务器系统: NT {major}.{minor}, 架构: {profile_suffix}, 使用Profile: {self.profile}")
                return True
        
        # 客户端Windows检测
        if major == 5:
            if minor == 1:
                if build_number and build_number >= 2600:
                    self.profile = f"WinXPSP3{profile_suffix}"
                else:
                    self.profile = f"WinXPSP2{profile_suffix}"
            elif minor == 2:
                self.profile = f"Win2003SP2{profile_suffix}" if is_64bit else f"Win2003SP2x86"
        elif major == 6:
            if minor == 0:
                if build_number and build_number >= 6002:
                    self.profile = f"VistaSP2{profile_suffix}"
                elif build_number and build_number >= 6001:
                    self.profile = f"VistaSP1{profile_suffix}"
                else:
                    self.profile = f"VistaSP0{profile_suffix}"
            elif minor == 1:
                if build_number and build_number >= 7601:
                    self.profile = f"Win7SP1{profile_suffix}"
                else:
                    self.profile = f"Win7SP0{profile_suffix}"
            elif minor == 2:
                self.profile = f"Win8SP0{profile_suffix}"
            elif minor == 3:
                self.profile = f"Win8SP1{profile_suffix}"
        elif major == 10:
            if build_number:
                if build_number >= 22000:
                    self.profile = f"Win10x64"
                elif build_number >= 19041:
                    self.profile = f"Win10x64" if is_64bit else f"Win10x86"
                elif build_number >= 18362:
                    self.profile = f"Win10x64" if is_64bit else f"Win10x86"
                elif build_number >= 17763:
                    self.profile = f"Win10x64" if is_64bit else f"Win10x86"
                elif build_number >= 17134:
                    self.profile = f"Win10x64" if is_64bit else f"Win10x86"
                elif build_number >= 16299:
                    self.profile = f"Win10x64" if is_64bit else f"Win10x86"
                elif build_number >= 15063:
                    self.profile = f"Win10x64" if is_64bit else f"Win10x86"
                elif build_number >= 14393:
                    self.profile = f"Win10x64_14393" if is_64bit else f"Win10x86_14393"
                elif build_number >= 10586:
                    self.profile = f"Win10x64_10586" if is_64bit else f"Win10x86_10586"
                else:
                    self.profile = f"Win10{profile_suffix}"
            else:
                pass

        version_info = f"NT {major}.{minor}"
        if build_number:
            version_info += f" (Build {build_number})"

        if self.profile:
            print(f"[*] 根据版本号检测: {version_info}, 架构: {profile_suffix}, 使用Profile: {self.profile}")
            return True
    
    # 最后检查架构
    if is_64bit_match:
        if is_64bit:
            self.profile = "Win10x64"
            print(f"[*] 检测到64位系统，使用默认Profile: {self.profile}")
        else:
            self.profile = "Win10x86"
            print(f"[*] 检测到32位系统，使用默认Profile: {self.profile}")
        return True
    
    return False
