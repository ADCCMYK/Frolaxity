#!/usr/bin/env python3
import sys
sys.dont_write_bytecode = True

import os
import re
from pathlib import Path


def _dump_and_scan_files(self, vol_version=None, plugins="", common_address=False, scan_files=True):
    
    print(f"\n[*] 正在提取 {plugins}")
    print(f"[*] 使用版本: {vol_version}")

    
    # 初始化 filescan_output 变量
    filescan_output = None

    # 初始化常用变量
    match_found = False
    matched_pattern = None


    # 获取工作目录
    input_dir = os.path.join(self.path, "..")


    # 清空输出文件以防止多次重复
    files_to_clear = []


    # 文件提取重命名移动后缀
    if plugins in ["dumpfiles", ""]:
        file_exts = ['.dat', '.evtx', '.vacb', '.img']
    else:
    # 进程提取重命名移动后缀
        file_exts = ['.dmp']

    
    # CTF正则优先匹配
    ctf_regex = self.pattern

    # 常用地址排除正则
    exclude_patterns = self.exclude_patterns

    # 常用正则表达式模式
    common_address_patterns = self.common_address_patterns
    common_process_patterns = self.common_process_patterns


    # 常用地址提取模式使用新的输出目录
    if common_address:
        if plugins == "dumpfiles":
            version_suffix = "vol3" if vol_version == "vol3" else "vol2"
            base_dump_dir = f"{self.output_dir}/common_addresses_{version_suffix}"
        elif plugins == "memdump":
            version_suffix = "vol3" if vol_version == "vol3" else "vol2"
            base_dump_dir = f"{self.output_dir}/common_process_{version_suffix}"
    else:
        # 为不同版本创建独立的输出目录
        plugins = "memdump" if plugins == "memdump" else "dumpfiles"
        version_suffix = "vol3" if vol_version == "vol3" else "vol2"
        base_dump_dir = f"{self.output_dir}/dumps_{version_suffix}"

    
    # Linux系统清空文件
    if self.system_type == "linux" and vol_version == "vol3":
        files_to_clear.append(f"{self.output_dir}/linux.elfs.Elfs.txt")
    
    # Windows系统清空文件
    if self.system_type == "windows":
        if vol_version == "vol3":
            files_to_clear.extend([
                f"{self.output_dir}/windows.dumpfiles.txt",
                f"{self.output_dir}/windows.memmap.txt"
            ])
        else:  # Volatility 2
            files_to_clear.extend([
                f"{self.output_dir}/dumpfiles.txt",
                f"{self.output_dir}/memdump.txt"
            ])
    
    # 清空所有指定的文件
    for file_path in files_to_clear:
        if os.path.exists(file_path):
            try:
                with open(file_path, 'w') as f:
                    f.write('')  # 清空文件内容
                print(f"[+] 已清空文件以防止重复: {file_path}")
            except Exception as e:
                print(f"[!] 清空文件失败: {file_path}, 错误: {e}")


    
    # 不再预先创建所有分类目录，改为在确定文件类别时再创建
    categories = {
        'dll': ['.dll'], 
        'evtx': ['.evtx'],
        'exe': ['.exe'],
        'img': ['.img', '.iso'], 
        'process': ['.dmp', '.bin'], 
        'text': ['.txt', '.md', '.log', '.ini', '.conf', '.xml', '.out', '.err', '.syslog', '.event', '.audit', '.trace', '.debug'],
        'data': ['.dat','.kdbx', '.psafe3', '.agilekeychain', '.opvault', '.sqlite', '.sqlite3', '.db', '.mdb', '.accdb', '.fdb', '.mdf', '.ldf', '.frm', '.myd', '.myi', '.ibd', '.dbf', '.sql', '.sqlite3'],
        'image': ['.jpg', '.jpeg', '.png', '.gif', '.bmp', '.webp', '.tiff', '.tif', '.ico'],
        'video': ['.mp4', '.avi', '.mov', '.mkv', '.h264'],
        'audio': ['.mp3', '.wav', '.flac', '.ogg', '.mid', '.midi', '.au'],
        'software': ['.zip', '.rar', '.tar', '.7z', '.xz', '.zst', '.gz', '.bz2', '.lzh', '.arj', '.cab', '.deb', '.rpm', '.tar.gz', '.msi', '.dmg', '.pkg', '.apk', '.ipa', '.cue', '.nrg', '.mdf', '.mds', '.daa', '.uif', '.isz', '.cso', '.ecm', '.par', '.par2', '.sfv', '.md5', '.sha1', '.sha256', '.sha512', '.crc', '.sfx', '.001', '.002', '.part', '.split', '.archive', '.backup', '.download', '.partial', '.crdownload', '.torrent', '.magnet', '.ed2k'],
        'document': ['.doc', '.docx', '.ppt', '.pptx', '.xls', '.xlsx', '.rtf', '.pdf'],
        'network': ['.pcap', '.pcapng'],
        'config': ['.env', '.htaccess', '.config', '.yml', '.yaml', '.json', '.properties', '.cfg', '.inf', '.ini', '.reg', '.policy'],
        'certificate': ['.key', '.cert', '.crt', '.pem', '.der', '.pfx', '.p12', '.keystore', '.jks', '.truststore', '.bks', '.p7b', '.p7c', '.spc', '.cer', '.csr', '.crl', '.ocsp', '.asc', '.gpg', '.pgp', '.sig', '.signature'],
        'script': ['.sh', '.bash', '.zsh', '.fish', '.ps1', '.bat', '.cmd', '.vbs', '.js', '.py', '.rb', '.pl', '.lua', '.tcl'],
        'source': ['.c', '.cpp', '.h', '.hpp', '.java', '.cs', '.go', '.rs', '.swift', '.kt', '.scala', '.m', '.mm'],
        'web': ['.html', '.htm', '.css', '.js', '.ts', '.php', '.jsp', '.japx', '.jsx', '.tsx', '.vue', '.svelte', '.scss', '.less', '.sass'],
        'backup': ['.bak', '.old', '.temp', '.tmp', '.swp', '.swo', '.php~', '.~'],
        'virtualization': ['.vhd', '.vhdx', '.vmdk', '.vdi', '.qcow', '.qcow2', '.raw', '.vfd', '.vmem', '.vmsn', '.vmss', '.vmx', '.nvram', '.vbox'],
        'unknown': []
    }
    
    
    # 处理进程转储模式
    if plugins == "memdump":
        if vol_version == "vol3":
            if self.system_type == "windows":
                # Windows使用psxview获取进程列表
                pslist_output = f"{self.output_dir}/windows.psxview.txt"
                if not os.path.exists(pslist_output):
                    self.run_command("windows.psxview", output_file=pslist_output, vol_version=vol_version)
                    print(f"[+] 已生成进程列表文件: {pslist_output}")
                else:
                    # 检查现有文件是否包含批处理终止提示
                    if self.check_batch_termination(pslist_output):
                        print(f"[!] 检测到批处理终止提示，重新生成文件: {pslist_output}")
                        self.run_command("windows.psxview", output_file=pslist_output, vol_version=vol_version)
                    else:
                        print(f"[+] 使用现有进程列表文件: {pslist_output}")
                filescan_output = pslist_output
                
            elif self.system_type == "linux":
                # Linux合并三个进程文件
                process_files = [
                    f"{self.output_dir}/linux.pslist.txt",
                    f"{self.output_dir}/linux.psscan.txt", 
                    f"{self.output_dir}/linux.pidhashtable.txt"
                ]
                
                # 检查文件是否存在，不存在则运行命令
                for i, process_file in enumerate(process_files):
                    if not os.path.exists(process_file):
                        plugin_names = ["linux.pslist", "linux.psscan", "linux.pidhashtable"]
                        self.run_command(plugin_names[i], output_file=process_file, vol_version=vol_version)
                        print(f"[*] 已生成进程文件: {process_file}")
                    else:
                        # 检查现有文件是否包含批处理终止提示
                        if self.check_batch_termination(process_file):
                            print(f"[!] 检测到批处理终止提示，重新生成文件: {process_file}")
                            plugin_names = ["linux.pslist", "linux.psscan", "linux.pidhashtable"]
                            self.run_command(plugin_names[i], output_file=process_file, vol_version=vol_version)
                            print(f"[*] 已重新生成进程文件: {process_file}")
                        else:
                            print(f"[*] 使用现有进程文件: {process_file}")

                # 合并三个文件的内容
                combined_content = ""
                for process_file in process_files:
                    if os.path.exists(process_file):
                        try:
                            with open(process_file, "r", errors='ignore') as pf:
                                content = pf.read()
                                # 添加文件分隔符和文件名标题
                                combined_content += f"\n\n{os.path.basename(process_file)}\n\n"
                                combined_content += content
                        except Exception as e:
                            print(f"[!] 读取文件 {process_file} 失败: {e}")
                
                # 创建临时合并文件
                filescan_output = f"{self.output_dir}/linux_processes_combined.txt"
                with open(filescan_output, "w", errors='ignore') as f:
                    f.write(combined_content)
                print(f"[*] 已创建合并文件: {filescan_output}")
                
            else:
                print(f"[!] 不支持的系统类型: {self.system_type}")
                return False
                
        else:  # Volatility 2
            pslist_output = f"{self.output_dir}/pslist.txt"
            if not os.path.exists(pslist_output):
                self.run_command("pslist", output_file=pslist_output, vol_version=vol_version)
                print(f"[*] 已生成进程列表文件: {pslist_output}")
            else:
                # 检查现有文件是否包含批处理终止提示
                if self.check_batch_termination(pslist_output):
                    print(f"[!] 检测到批处理终止提示，重新生成文件: {pslist_output}")
                    self.run_command("pslist", output_file=pslist_output, vol_version=vol_version)
                else:
                    print(f"[+] 使用现有进程列表文件: {pslist_output}")
            filescan_output = pslist_output
    
    else:  # dumpfiles模式
        # 检查文件是否已存在，存在则直接使用
        if vol_version == "vol3":
            if self.system_type == "windows":
                filescan_output = f"{self.output_dir}/windows.filescan.txt"
                if not os.path.exists(filescan_output):
                    self.run_command("windows.filescan", output_file=f"{self.output_dir}/windows.filescan.txt", vol_version=vol_version)
                    print(f"[*] 已生成文件扫描结果: {filescan_output}")
                else:
                    # 检查现有文件是否包含批处理终止提示
                    if self.check_batch_termination(filescan_output):
                        print(f"[!] 检测到批处理终止提示，重新生成文件: {filescan_output}")
                        self.run_command("windows.filescan", output_file=f"{self.output_dir}/windows.filescan.txt", vol_version=vol_version)
                        print(f"[*] 已重新生成文件扫描结果: {filescan_output}")
                    else:
                        print(f"[*] 使用现有文件扫描结果: {filescan_output}")
            elif self.system_type == "linux":
                filescan_output = f"{self.output_dir}/linux.pagecache.Files.txt"
                if not os.path.exists(filescan_output):
                    self.run_command("linux.pagecache.Files", output_file=f"{self.output_dir}/linux.pagecache.Files.txt", vol_version=vol_version)
                    print(f"[*] 已生成文件扫描结果: {filescan_output}")
                else:
                    # 检查现有文件是否包含批处理终止提示
                    if self.check_batch_termination(filescan_output):
                        print(f"[!] 检测到批处理终止提示，重新生成文件: {filescan_output}")
                        self.run_command("linux.pagecache.Files", output_file=f"{self.output_dir}/linux.pagecache.Files.txt", vol_version=vol_version)
                        print(f"[*] 已重新生成文件扫描结果: {filescan_output}")
                    else:
                        print(f"[*] 使用现有文件扫描结果: {filescan_output}")
        else:
            filescan_output = f"{self.output_dir}/filescan.txt"
            if not os.path.exists(filescan_output):
                self.run_command("filescan", output_file=f"{self.output_dir}/filescan.txt", vol_version=vol_version)
                print(f"[*] 已生成文件扫描结果: {filescan_output}")
            else:
                # 检查现有文件是否包含批处理终止提示
                if self.check_batch_termination(filescan_output):
                    print(f"[!] 检测到批处理终止提示，重新生成文件: {filescan_output}")
                    self.run_command("filescan", output_file=f"{self.output_dir}/filescan.txt", vol_version=vol_version)
                    print(f"[*] 已重新生成文件扫描结果: {filescan_output}")
                else:
                    print(f"[*] 使用现有文件扫描结果: {filescan_output}")

    # 检查 filescan_output 是否已正确设置
    if filescan_output is None:
        print(f"[!] 错误: 无法确定文件扫描输出路径，系统类型可能未正确识别: {self.system_type}")
        return False
    
    # 解析并提取进程
    try:
        print(f"[*] 正在从文件读取: {filescan_output}")
        with open(filescan_output, "r", errors='ignore') as f:
            # 使用集合来跟踪已处理的PID，实现去重
            seen_pids = set()
            
            for line in f:
                if not line.strip() or line.startswith(('Volatility', '#')):
                    continue
                    
                # 进程转储模式：提取PID
                if plugins == "memdump":
                    parts = line.split()
                    
                    # 跳过表头和分隔线
                    if line.startswith(('Offset(V)', 'Offset(Virtual)', '------------------')):
                        continue
                    
                    # 根据系统类型解析进程信息
                    pid = None
                    process_name = None
                    
                    if self.system_type == "windows":
                        # Windows pslist格式: Offset(V) Name PID PPID Thds Hnds Sess Wow64 Start Exit
                        # Windows psxview格式: Offset(Virtual) Name PID pslist psscan thrdscan csrss Exit Time
                        # 检查是否是有效的进程行（应该包含16进制偏移量和数字PID）
                        if len(parts) >= 3 and '0x' in parts[0] and parts[2].isdigit():
                            # 第3列是PID（从0开始计数：0=Offset, 1=Name, 2=PID）
                            pid = parts[2]
                            process_name = parts[1]  # 进程名在第2列
                    
                    elif self.system_type == "linux":
                        # 首先检查是否是详细格式的表头
                        if 'OFFSET (V)' in line and 'PID' in line and 'TID' in line and 'PPID' in line:
                            # 这是详细格式的表头行，跳过
                            continue
                        elif 'OFFSET (P)' in line and 'PID' in line and 'TID' in line and 'PPID' in line:
                            # 这是带退出状态的格式表头行，跳过
                            continue
                        elif 'OFFSET' in line and 'PID' in line and 'TID' in line and 'PPID' in line:
                            # 这是简单格式的表头行，跳过
                            continue
                        
                        # 详细格式：OFFSET (V) PID TID PPID COMM UID GID EUID EGID CREATION TIME File output
                        if len(parts) >= 11 and '0x' in parts[0] and parts[1].isdigit():
                            pid, process_name = parts[1], parts[4]  # PID在第2列，进程名在第5列
                        # 带退出状态格式：OFFSET (P) PID TID PPID COMM EXIT_STATE
                        elif len(parts) >= 6 and '0x' in parts[0] and parts[1].isdigit():
                            pid, process_name = parts[1], parts[4]  # PID在第2列，进程名在第5列
                        # 简单格式：OFFSET PID TID PPID COMM
                        elif len(parts) >= 5 and '0x' in parts[0] and parts[1].isdigit():
                            pid, process_name = parts[1], parts[4]  # PID在第2列，进程名在第5列
                        # psscan格式
                        elif len(parts) >= 4 and '0x' in parts[0]:
                            pid, process_name = parts[1], ' '.join(parts[3:])
                        # pslist/pidhashtable格式
                        elif len(parts) >= 3:
                            pid, process_name = parts[0], ' '.join(parts[2:])
                    
                    # 如果成功解析到PID，检查是否为常用进程
                    if pid and pid.isdigit():
                        # 检查是否已经处理过这个PID，避免重复提取
                        if pid in seen_pids:
                            print(f"[-] 跳过重复进程: PID={pid}, Name={process_name}")
                            continue
                        
                        # 只有在常用地址模式下才需要检查进程匹配
                        if common_address:
                            # CTF正则优先匹配
                            ctf_matched = False
                            ctf_pattern = ctf_regex  # 获取CTF正则
                            if ctf_pattern and process_name:
                                if re.search(ctf_pattern, process_name):
                                    ctf_matched = True
                                    matched_pattern = "CTF"
                            
                            # 如果CTF未匹配，则检查常用进程模式
                            if not ctf_matched:
                                # 检查进程名是否匹配常用进程模式
                                is_common_process = False

                                if process_name:
                                    for pattern in common_process_patterns:
                                        if re.search(pattern, process_name):
                                            is_common_process = True
                                            matched_pattern = pattern
                                            break
                                
                                if not is_common_process:
                                    print(f"[-] 跳过非常用进程: PID={pid}, Name={process_name}")
                                    continue
                            
                            seen_pids.add(pid)
                            dump_dir = f"{base_dump_dir}/process"
                            output_file = f"{pid}_{process_name}.dmp"
                            if ctf_matched:
                                print(f"\n[+++] 提取CTF进程: PID={pid}, Name={process_name}")
                            else:
                                print(f"\n[+] 提取常用进程: PID={pid}, Name={process_name}  {matched_pattern}")
                        else:
                            # 非常用地址模式，提取所有进程
                            seen_pids.add(pid)
                            dump_dir = f"{base_dump_dir}/process"
                            output_file = f"{pid}_{process_name}.dmp"
                            print(f"\n[+] 提取进程: PID={pid}, Name={process_name}")
                        
                        # 只在确定文件类别时才创建对应的目录
                        Path(dump_dir).mkdir(parents=True, exist_ok=True)

                        # 使用PID转储进程
                        self.run_command(
                            plugin=plugins,
                            pid=pid,
                            dump_dir=dump_dir,
                            vol_version=vol_version
                        )
                        
                        # 对于elfs.Elfs插件，使用批量重命名（因为会生成多个文件）
                        if vol_version == "vol3" and self.system_type == "linux":
                            self.rename_batch_files(
                                input_dir=input_dir,
                                dump_dir=dump_dir,
                                clean_filename=output_file,
                                file_exts=file_exts,
                                expected_offset=pid  # 对于进程转储，使用PID作为期望的偏移量
                            )
                        else:
                            # 使用重命名方法（单个文件）
                            self.rename_single_file(input_dir=input_dir if vol_version == "vol3" else dump_dir, dump_dir=dump_dir, clean_filename=output_file, file_exts=file_exts)

                else:  # dumpfiles模式
                    # 跳过filescan的表头和分隔线
                    if line.startswith(('Offset(P)', '------------------')):
                        continue
                        
                    if not line.strip():
                        continue
                        
                    parts = line.split()
                    
                    # 处理多种filescan格式
                    # 格式1: Offset(P) #Ptr #Hnd Access Name (Volatility 2/3 传统格式)
                    # 例如: "0x000000001031a050      1      1 R----- \Device\HarddiskVolume1\System Volume Information\{...}"
                    # 格式2: Offset\tName (Volatility 3 简化格式)
                    # 例如: "0x1031a050\t\System Volume Information\{...}"
                    # 格式3: linux.pagecache.Files 格式 (制表符分隔的多列)
                    # 例如: "SuperblockAddr\tMountPoint\tDevice\tInodeNum\tInodeAddr\tFileType\tInodePages\tCachedPages\tFileMode\tAccessTime\tModificationTime\tChangeTime\tFilePath\tInodeSize"
                    
                    # 首先检查是否是 linux.pagecache.Files 格式
                    if 'SuperblockAddr' in line and 'MountPoint' in line and 'InodeAddr' in line and 'FilePath' in line:
                        # 这是表头行，跳过
                        continue
                    
                    # 检查是否是 linux.pagecache.Files 的数据行（制表符分隔的多列）
                    if '\t' in line and line.count('\t') >= 13:  # 至少有13个制表符（14列）
                        parts = line.split('\t')
                        if len(parts) >= 14:
                            # linux.pagecache.Files 格式：第5列是 InodeAddr（偏移量），第13列是 FilePath（文件名）
                            offset, filename = parts[4].strip(), parts[12].strip()
                        else:
                            continue
                        
                    elif len(parts) >= 5:
                        # 格式1: 多列空格分隔
                        offset, filename = parts[0], ' '.join(parts[4:])
                    elif len(parts) == 2 and '\t' in line:
                        # 格式2: 制表符分隔的两列
                        offset, filename = parts[0], parts[1]
                    elif len(parts) >= 2:
                        # 格式3: 其他可能的格式，尝试提取偏移量和文件名
                        # 可能只有偏移量和文件名两列
                        offset, filename = parts[0], ' '.join(parts[1:])
                    else:
                        # 无法识别的格式，跳过
                        continue
                    
                    # 常用地址提取模式：检查是否匹配常用地址模式
                    if common_address:
                        # CTF正则优先匹配
                        ctf_matched = False
                        if ctf_regex:
                            if re.search(ctf_regex, line):
                                ctf_matched = True
                                match_found = True
                                matched_pattern = "CTF"
                                # 提取匹配的路径部分用于显示
                                path_match = re.search(r'[a-zA-Z]:\\.*|/.*|\\\\Device\\\\.*', line)
                                matched_path = path_match.group(0) if path_match else line.strip()
                                print(f"\n[+++] CTF匹配 '{ctf_regex}' -> {matched_path}")
                        
                        # 如果CTF匹配，跳过排除和常用地址检查
                        if not ctf_matched:
                            # 排除匹配检查：如果匹配到排除模式，跳过该行
                            excluded = False
                            if exclude_patterns:
                                for exclude_pattern in exclude_patterns:
                                    if re.search(exclude_pattern, line):
                                        # 匹配到排除模式，输出信息并跳过
                                        print(f"[-] 排除匹配 '{exclude_pattern}' -> {line.strip()}")
                                        excluded = True
                                        break
                            
                            if excluded:
                                # 跳过当前行的后续处理
                                continue
                            
                            # 在每一行开始时重置匹配状态
                            match_found = False
                            matched_pattern = None
                            
                            for addr_pattern in common_address_patterns:
                                if re.search(addr_pattern, line):
                                    match_found = True
                                    matched_pattern = addr_pattern
                                    break
                            
                            # 输出匹配的规则信息
                            if match_found:
                                # 提取匹配的路径部分用于显示 - 改进正则表达式以匹配设备路径
                                # 匹配Windows驱动器路径 (C:\...), Linux路径 (/...), 或设备路径 (\Device\...)
                                path_match = re.search(r'[a-zA-Z]:\\.*|/.*|\\\\Device\\\\.*', line)
                                matched_path = path_match.group(0) if path_match else line.strip()
                                print(f"\n[+] 匹配到常用地址规则 '{matched_pattern}' -> {matched_path}")
                            else:
                                # 如果不匹配任何常用地址模式，跳过提取
                                continue

                    # 只有在common_address模式下才需要检查匹配
                    if common_address and not match_found:
                        # 提取路径用于显示错误信息
                        path_match = re.search(r'[a-zA-Z]:\\.*|/.*|\\\\Device\\\\.*', line)
                        display_path = path_match.group(0) if path_match else line.strip()
                        print(f"[!] {display_path} 没有匹配到任何常用地址规则")
                        continue
                    
                    file_ext = os.path.splitext(filename)[1].lower()
                    file_name = os.path.basename(filename)
                    
                    # 确定文件类别
                    file_category = None
                    for category, exts in categories.items():
                        if file_ext in exts:
                            file_category = category
                            break
                    
                    # 特殊处理：如果文件名以点开头，归类到bak类别
                    if file_name.startswith('.') and file_category is None:
                        file_category = 'bak'
                    
                    # 如果无法识别文件类别，归类到unknown目录
                    if file_category is None:
                        file_category = 'unknown'
                    
                    dump_dir = f"{base_dump_dir}/{file_category}"
                    # 只在确定文件类别时才创建对应的目录
                    Path(dump_dir).mkdir(parents=True, exist_ok=True)
                    clean_filename = f"{offset}_{os.path.basename(filename.replace('\\', '/'))}"
                    self.run_command(
                        plugin=plugins,
                        offset=offset,
                        dump_dir=dump_dir,
                        vol_version=vol_version,
                    )

                    # 对于vol3，使用批量模式处理dumpfiles文件
                    self.rename_batch_files(
                        input_dir=input_dir if vol_version == "vol3" else dump_dir, 
                        dump_dir=dump_dir, 
                        clean_filename=clean_filename, 
                        file_exts=file_exts,
                        expected_offset=offset
                        )
    

    except FileNotFoundError:
        print(f"[!] 文件扫描结果不存在: {filescan_output}")
        return False


    # 扫描提取的文件（仅在scan_files为True时执行）
    if scan_files:
        print("\n[*] 正在扫描提取的文件...")
        for root, _, files in os.walk(base_dump_dir):
            for file in files:
                file_path = os.path.join(root, file)
                self.scan_for_flags(file_path)
                
                
    return True
