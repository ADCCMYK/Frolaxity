#!/usr/bin/env python3
import sys
sys.dont_write_bytecode = True

import os
import re
from pathlib import Path


# 扫描多个目录
def _scan_for_flags(self, file_path, depth=100, scanned_dirs=None, is_top_level=True, search_dir=None):
    
    # 初始化已扫描目录集合
    if scanned_dirs is None:
        scanned_dirs = set()

    # 初始化生成扫描目录 
    if search_dir is None:
        default_dirs = self.get_default_directory_names
        search_dir = default_dirs[0] if default_dirs else "search_report"
    
    flag_report_dir = f"{self.output_dir}/{search_dir}"
    Path(flag_report_dir).mkdir(exist_ok=True)

    # 如果是目录，处理目录内容
    if os.path.isdir(file_path):
        # 获取目录绝对路径并检查是否已扫描
        abs_path = os.path.abspath(file_path)
        if abs_path in scanned_dirs:
            print(f"[!] 目录已扫描，跳过: {file_path}")
            return True
        scanned_dirs.add(abs_path)
        
        basename = os.path.basename(file_path)
                
        # 跳过需要跳过的目录（通过volconfig.py配置）
        skipped_directories = self.get_skipped_directories
        if basename in skipped_directories:
            return True
        
        # 防止递归深度过大
        if depth < 0:
            print(f"[!] 递归深度过大，跳过: {file_path}")
            return True
        
        print(f"[*] 扫描目录: {file_path}")
        
        # 收集目录下的所有文件和子目录
        txt_files = []  # txt文件优先
        other_text_files = []  # 其他文本文件
        other_files = []  # 其他文件
        subdirs = []  # 子目录
        
        try:
            for entry in os.listdir(file_path):
                full_path = os.path.join(file_path, entry)
                
                # 检查路径是否有效
                if not os.path.exists(full_path):
                    print(f"[!] 路径不存在: {full_path}")
                    continue
                
                # 跳过扫描报告文件
                if entry.lower().endswith(('_matches.txt', '_report.txt', '_scan.txt')):
                    print(f"[*] 跳过扫描报告文件: {entry}")
                    continue
                
                # 如果是目录，先收集，稍后递归处理
                if os.path.isdir(full_path):
                    subdirs.append(full_path)
                    continue
                                
                # 根据文件类型分类
                if entry.lower().endswith('.txt'):
                    txt_files.append(full_path)
                elif self.is_text_file(full_path):
                    other_text_files.append(full_path)
                else:
                    other_files.append(full_path)
            
            # 扫描txt文件
            if txt_files:
                print(f"[*] 处理txt文件 {len(txt_files)}个")
                for full_path in txt_files:
                    print(f"[*] 扫描文件: {os.path.basename(full_path)}")
                    self.scan_single_file(full_path)
            
            # 扫描其他文本文件
            if other_text_files:
                print(f"[*] 处理其他文本文件 {len(other_text_files)}个")
                for full_path in other_text_files:
                    print(f"[*] 扫描文件: {os.path.basename(full_path)}")
                    self.scan_single_file(full_path)
            
            # 扫描优先目录
            priority_dir_list = self.get_priority_dirs

            # 子目录分为优先目录和其他目录
            priority_subdirs = []
            other_subdirs = []
            for subdir in subdirs:
                basename = os.path.basename(subdir)
                if basename in priority_dir_list:
                    priority_subdirs.append(subdir)
                else:
                    other_subdirs.append(subdir)
            
            # 优先目录扫描
            if priority_subdirs:
                print(f"[*] 扫描优先目录{priority_dir_list} ({len(priority_subdirs)}个)")
                for priority_dir in priority_subdirs:
                    self.scan_for_flags(priority_dir, depth - 1, scanned_dirs, is_top_level=False)
            
            # 处理其他文件
            if other_files:
                print(f"[*] 处理其他文件 {len(other_files)}个")
                for full_path in other_files:
                    print(f"[*] 扫描文件: {os.path.basename(full_path)}")
                    self.scan_single_file(full_path)
            
            # 最后处理其他子目录
            if other_subdirs:
                print(f"[*] 处理其他子目录 {len(other_subdirs)}个")
                for subdir in other_subdirs:
                    self.scan_for_flags(subdir, depth - 1, scanned_dirs, is_top_level=False)
        
        except PermissionError:
            print(f"[!] 权限不足，跳过目录: {file_path}")
            return False
        except Exception as e:
            print(f"[!] 扫描目录 {file_path} 时出错: {str(e)}")
            return False
        
        # 如果是最顶层调用，在所有递归扫描结束后生成CTF扫描正则报告
        if is_top_level and hasattr(self, 'ctf_scan_matches') and self.ctf_scan_matches:
            self.generate_ctf_scan_report(self.ctf_scan_matches)
            
        return True
            
    # 检查是否为扫描报告文件
    file_name = os.path.basename(file_path)
    if file_name.lower().endswith(('_matches.txt', '_report.txt', '_scan.txt')):
        print(f"[*] 跳过扫描报告文件: {file_name}")
        return True
    
    return self.scan_single_file(file_path)



# 扫描单个文件
def _scan_single_file(self, file_path, search_dir=None):

    # 使用配置的目录名
    if search_dir is None:
        default_dirs = self.get_default_directory_names
        search_dir = default_dirs[0] if default_dirs else "search_report"

    try:
        with open(file_path, "r", encoding='utf-8', errors='ignore') as f:
            content = f.read()
            flags = set()
            
            # 使用实例方法判断是否为文本文件
            is_text_file = self.is_text_file(file_path)
            
            # 获取排除模式
            exclude_patterns = self.scan_exclude_patterns
            
            for match in re.finditer(self.pattern, content):
                matched_text = match.group(0)
                
                # 检查是否匹配排除模式
                should_exclude = False
                for exclude_pattern in exclude_patterns:
                    if re.search(exclude_pattern, matched_text, re.IGNORECASE):
                        should_exclude = True
                        break
                
                if should_exclude:
                    continue
                
                if is_text_file:
                    # 文本文件模式：获取整行内容
                    line_start = content.rfind('\n', 0, match.start()) + 1
                    line_end = content.find('\n', match.end())
                    if line_end == -1:
                        line_end = len(content)
                    context = content[line_start:line_end].strip()

                else:
                    # 二进制文件模式：获取上下文片段
                    start = max(0, match.start() - 100)
                    end = min(len(content), match.end() + 100)
                    context = content[start:end].replace('\n', ' ').strip()
                
                flags.add((matched_text, context))
            
            if flags:
                # 记录到flags_found（保持兼容性）
                self.flags_found.append({
                    'source': os.path.basename(file_path),
                    'matches': [{'text': text, 'context': ctx} for text, ctx in flags],
                    'full_content_sample': content[:1000]
                })
                
                # 记录到ctf_scan_matches（用于生成报告）
                if not hasattr(self, 'ctf_scan_matches'):
                    self.ctf_scan_matches = []
                
                self.ctf_scan_matches.append({
                    'source': os.path.basename(file_path),
                    'file_path': file_path,
                    'matches': [{'text': text, 'context': ctx, 'pattern': 'ctf扫描正则'} for text, ctx in flags]
                })
                
                # 直接生成简化报告
                flag_report_dir = f"{self.output_dir}/{search_dir}"
                report_path = f"{flag_report_dir}/{os.path.basename(file_path)}.txt"
                with open(report_path, "w", encoding='utf-8') as f:
                    f.write(f"文件: {os.path.basename(file_path)}\n")
                    f.write(f"路径: {file_path}\n")
                    for text, ctx in flags:
                        f.write(f"匹配: {text}\n上下文: {ctx}\n\n")
                        
                print(f"[+] {os.path.basename(file_path)} 匹配完成 -> {report_path}")
            else:
                print(f"[-] {os.path.basename(file_path)} 未匹配到任何内容")
    
        return True
    except Exception as e:
        print(f"[!] 扫描 {file_path} 时出错: {str(e)}")
        return False
