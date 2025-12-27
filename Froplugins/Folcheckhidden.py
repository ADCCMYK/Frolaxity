#!/usr/bin/env python3
import os
import sys
sys.dont_write_bytecode = True

from pathlib import Path


def _extract_hidden_processes(self, vol_version=None):
    print(f"\n[*] 开始提取隐藏进程，使用版本: {vol_version}")
    
    # 根据系统类型和版本确定插件名称
    if vol_version == "vol3":
        if self.system_type == "windows":
            pslist_plugin = "windows.pslist"
            psxview_plugin = "windows.psxview"
            memdump_plugin = "windows.memmap"
        elif self.system_type == "linux":
            pslist_plugin = "linux.pslist"
            psxview_plugin = "linux.psscan" 
            pidhashtable_plugin = "linux.pidhashtable"
            memdump_plugin = "linux.memmap"
        else:
            print(f"[!] 不支持的系统类型: {self.system_type}")
            return False
    else:  # Volatility 2
        pslist_plugin = "pslist"
        psxview_plugin = "psxview"
        memdump_plugin = "memdump"
    
    
    # 获取可见进程列表
    pslist_output = f"{self.output_dir}/pslist_{vol_version}.txt"
    if not os.path.exists(pslist_output):
        self.run_command(pslist_plugin, output_file=pslist_output, vol_version=vol_version)
        print(f"[*] 已生成可见进程列表: {pslist_output}")
    else:
        print(f"[*] 使用现有可见进程列表: {pslist_output}")
    
    # 获取所有进程列表
    psxview_output = f"{self.output_dir}/psxview_{vol_version}.txt"
    if not os.path.exists(psxview_output):
        self.run_command(psxview_plugin, output_file=psxview_output, vol_version=vol_version)
        print(f"[*] 已生成所有进程列表: {psxview_output}")
    else:
        print(f"[*] 使用现有所有进程列表: {psxview_output}")
    
    # 解析进程列表，找出隐藏进程
    visible_pids = set()
    all_pids = set()
    
    # 解析可见进程列表
    try:
        print(f"[*] 正在从文件读取: {pslist_output}")
        with open(pslist_output, 'r', errors='ignore') as f:
            for line in f:
                if not line.strip() or line.startswith(('Volatility', '#')):
                    continue
                    
                # 跳过表头行
                if 'OFFSET' in line and 'PID' in line and ('PPID' in line or 'TID' in line):
                    continue
                    
                parts = line.split()
                
                # 根据格式解析PID
                pid = None
                # 简单格式: OFFSET PID TID PPID COMM
                if len(parts) >= 5 and '0x' in parts[0] and parts[1].isdigit():
                    pid = parts[1]
                # 详细格式: OFFSET (V) PID TID PPID COMM UID GID EUID EGID CREATION TIME File output
                elif len(parts) >= 11 and '0x' in parts[0] and parts[2].isdigit():
                    pid = parts[2]
                # 带退出状态格式: OFFSET (P) PID TID PPID COMM EXIT_STATE
                elif len(parts) >= 6 and '0x' in parts[0] and parts[2].isdigit():
                    pid = parts[2]
                # 传统格式
                elif parts and parts[0].isdigit():
                    pid = parts[0]
                
                if pid:
                    visible_pids.add(pid)
    except FileNotFoundError:
        print(f"[!] 文件不存在: {pslist_output}")
        return False
    
    # 解析所有进程列表（包括隐藏的）
    try:
        print(f"[*] 正在从文件读取: {psxview_output}")
        with open(psxview_output, 'r', errors='ignore') as f:
            for line in f:
                if not line.strip() or line.startswith(('Volatility', '#')):
                    continue
                    
                # 跳过表头行
                if 'OFFSET' in line and 'PID' in line and ('PPID' in line or 'TID' in line):
                    continue
                    
                parts = line.split()
                
                # 根据Volatility版本和系统类型解析PID
                pid = None
                if self.system_type == "windows":
                    if vol_version == "vol3":
                        # Windows Vol3格式: Offset PID PPID Threads Handles Session Name
                        if len(parts) >= 6 and '0x' in parts[0] and parts[1].isdigit():
                            pid = parts[1]
                    else:  # Volatility 2
                        # Windows Vol2格式: Offset(V) PID PPID Threads Handles Time Name
                        if len(parts) >= 6 and '0x' in parts[0] and parts[1].isdigit():
                            pid = parts[1]
                elif self.system_type == "linux":
                    if vol_version == "vol3":
                        # Linux Vol3格式支持多种格式
                        # 简单格式: OFFSET PID TID PPID COMM
                        if len(parts) >= 5 and '0x' in parts[0] and parts[1].isdigit():
                            pid = parts[1]
                        # 详细格式: OFFSET (V) PID TID PPID COMM UID GID EUID EGID CREATION TIME File output
                        elif len(parts) >= 11 and '0x' in parts[0] and parts[2].isdigit():
                            pid = parts[2]
                        # 带退出状态格式: OFFSET (P) PID TID PPID COMM EXIT_STATE
                        elif len(parts) >= 6 and '0x' in parts[0] and parts[2].isdigit():
                            pid = parts[2]
                    else:  # Volatility 2
                        # Linux Vol2格式: Offset PID PPID UID GID DTB Start Name
                        if len(parts) >= 7 and '0x' in parts[0] and parts[1].isdigit():
                            pid = parts[1]
                
                if pid:
                    all_pids.add(pid)
    except FileNotFoundError:
        print(f"[!] 文件不存在: {psxview_output}")
        return False
    
    # 对于Linux Volatility 3，还需要合并pidhashtable
    if self.system_type == "linux" and vol_version == "vol3":
        pidhashtable_output = f"{self.output_dir}/pidhashtable_{vol_version}.txt"
        if not os.path.exists(pidhashtable_output):
            self.run_command(pidhashtable_plugin, output_file=pidhashtable_output, vol_version=vol_version)
            print(f"[*] 已生成PID哈希表: {pidhashtable_output}")
        else:
            print(f"[*] 使用现有PID哈希表: {pidhashtable_output}")
        
        try:
            print(f"[*] 正在从文件读取: {pidhashtable_output}")
            with open(pidhashtable_output, 'r', errors='ignore') as f:
                for line in f:
                    if not line.strip() or line.startswith(('Volatility', '#')):
                        continue
                        
                    # 跳过表头行
                    if 'OFFSET' in line and 'PID' in line and ('PPID' in line or 'TID' in line):
                        continue
                        
                    parts = line.split()
                    
                    # 解析pidhashtable格式
                    pid = None
                    # pidhashtable格式通常为: PID PPID COMM 或其他变体
                    if len(parts) >= 3 and parts[0].isdigit():
                        pid = parts[0]  # 第一列是PID
                    elif len(parts) >= 2 and parts[0].isdigit():
                        pid = parts[0]  # 也可能是两列格式
                    
                    if pid:
                        all_pids.add(pid)
        except FileNotFoundError:
            print(f"[!] 文件不存在: {pidhashtable_output}")
    
    # 找出隐藏进程（在所有进程中但不在可见进程中的PID）
    hidden_pids = all_pids - visible_pids
    
    if not hidden_pids:
        print("[!] 未发现隐藏进程")
        return False
    
    print(f"[!] 发现 {len(hidden_pids)} 个隐藏进程: {list(hidden_pids)}")

    # 创建隐藏进程输出目录（修正版本判断逻辑）
    if vol_version == "vol3":
        hidden_dir = f"{self.output_dir}/hidden_processes_vol3"
    else:
        hidden_dir = f"{self.output_dir}/hidden_processes_vol2"
    
    Path(hidden_dir).mkdir(exist_ok=True)
    
    # 提取隐藏进程内存
    for pid in hidden_pids:
        dump_file = f"{hidden_dir}/hidden_{self.system_type}_{pid}.dmp"
        self.run_command(
            memdump_plugin,
            pid=pid,
            dump_dir=hidden_dir,
            vol_version=vol_version
        )
        print(f"[*] 已提取隐藏进程 PID {pid} -> {hidden_dir}")
    
    return True
