#!/usr/bin/env python3
import sys
sys.dont_write_bytecode = True

import os
import re
from pathlib import Path


# CTF方向
def _scan_for_flags(self, file_path):

    # 如果是目录，先尝试解压dat文件，然后递归扫描目录内容
    if os.path.isdir(file_path):
        basename = os.path.basename(file_path)
                
        if basename == 'search_report':
            return True
        
        
        print(f"[*] 扫描目录: {file_path}")
        for entry in os.listdir(file_path):
            full_path = os.path.join(file_path, entry)
            # 检查路径是否有效
            if not os.path.exists(full_path):
                print(f"[!] 路径不存在: {full_path}")
                continue
            print(f"[*] 扫描文件: {full_path}")
            self.scan_for_flags(full_path)
        return True
            
    # 如果是文件，进行扫描
    try:
        with open(file_path, "r", encoding='utf-8', errors='ignore') as f:
            content = f.read()
            flags = set()
            
            # 根据文件扩展名判断扫描模式
            is_text_file = file_path.lower().endswith((
                    '.txt', '.log', '.ini', '.conf', '.xml', '.md', '.evtx', 
                    '.json', '.yaml', '.yml', '.csv', '.html', '.htm', '.js', 
                    '.css', '.php', '.py', '.java', '.c', '.cpp', '.h', '.cs', 
                    '.go', '.rs', '.rb', '.pl', '.sh', '.bat', '.ps1', '.sql', 
                    '.css', '.js', '.py', '.c', '.cpp', '.h', '.java',
                    '.cfg', '.config', '.properties', '.env', '.gitignore', 
                    '.dockerignore', '.editorconfig', '.gitattributes',
                    '.gd','.tscn'
                    ))
            
            for match in re.finditer(self.pattern, content):
                matched_text = match.group(0)
                
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
                self.flags_found.append({
                    'source': os.path.basename(file_path),
                    'matches': [{'text': text, 'context': ctx} for text, ctx in flags],
                    'full_content_sample': content[:1000]
                })
                
                # 直接生成简化报告
                flag_report_dir = f"{self.output_dir}/search_report"
                Path(flag_report_dir).mkdir(exist_ok=True)
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
