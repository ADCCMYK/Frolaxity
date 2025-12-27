#!/usr/bin/env python3
import sys
sys.dont_write_bytecode = True

import re
import subprocess

def _handle_symbol_download(self, process, cmd_exec, output_file, file_mode, plugin, first_stderr_line):
    """
    处理符号下载和进度显示
    
    Args:
        process: subprocess.Popen对象
        cmd_exec: 要执行的命令
        output_file: 输出文件路径
        file_mode: 文件写入模式
        plugin: 插件名称
        first_stderr_line: 第一行stderr输出
    
    Returns:
        bool: 命令执行是否成功
    """
    # 符号下载模式匹配模式（方法失败会卡死 建议单独运行一次vol3 加载符号表）
    symbol_download_patterns = [
        r'^Progress:\s+\d+\.\d+\s+Reading file http://msdl\.microsoft\.com/download/symbols/',
        r'^Progress:\s+\d+\.\d+\s+PDB scanning finished',
        r'^Progress:\s+\d+\.\d+\s+'
    ]
    
    # 检查第一行是否匹配符号下载模式
    is_symbol_download = False
    for pattern in symbol_download_patterns:
        if re.match(pattern, first_stderr_line):
            is_symbol_download = True
            break
    
    if not is_symbol_download:
        return False
    
    # 检测到符号下载或进度输出，进入进度显示循环
    
    # 打印第一行进度（完整输出）
    print(f"[*] {first_stderr_line.strip()}", end='', flush=True)
    
    # 继续读取剩余进度，同时确保stdout被正确写入文件
    while True:
        stderr_line = process.stderr.readline()
        if not stderr_line and process.poll() is not None:
            break
        
        # 如果是进度行，直接完整打印
        is_progress_line = False
        for pattern in symbol_download_patterns:
            if re.match(pattern, stderr_line):
                is_progress_line = True
                break
        
        if is_progress_line:
            print(f"\r[*] {stderr_line.strip()}", end='', flush=True)
    
    # 等待进程完成，确保所有输出都被处理
    process.wait()
    print("\r", end='', flush=True)  # 清除进度显示
    
    # 检查进程是否成功完成
    if process.returncode == 0:
        print(f"[+] Volatility 3符号下载完成，命令执行成功 -> {output_file}")
        return True
    else:
        print(f"[+] Volatility 3符号下载完成，重新执行 {plugin} 命令...")
        
        # 重新执行命令（不显示符号下载过程），保持相同的文件模式
        with open(output_file, file_mode) as f:
            subprocess.run(cmd_exec, shell=True, stdout=f, stderr=subprocess.DEVNULL)
        return True
