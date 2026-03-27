#!/usr/bin/env python3
import sys
sys.dont_write_bytecode = True

import os
import time
import re




def _sort_matches_priority(self, matches_list, text_field='vol_file_path'):
    """根据优先模式对匹配列表进行排序
    
    Args:
        matches_list: 匹配记录列表
        text_field: 用于匹配优先模式的字段名
        
    Returns:
        tuple: (priority_matches, other_matches) 优先匹配和其他匹配
    """
    priority_patterns = self.scan_priority_patterns
    priority_matches = []
    other_matches = []
    
    for match in matches_list:
        text = match.get(text_field, '')
        
        # 检查是否匹配优先模式
        is_priority = False
        for pattern in priority_patterns:
            if re.search(pattern, text):
                is_priority = True
                break
        
        if is_priority:
            priority_matches.append(match)
        else:
            other_matches.append(match)
    
    return priority_matches, other_matches


def _apply_match_limits(self, priority_matches, other_matches):
    """应用匹配显示数量限制
    
    Args:
        priority_matches: 优先匹配列表
        other_matches: 其他匹配列表
        
    Returns:
        tuple: (limited_priority_matches, limited_other_matches) 限制后的匹配列表
    """
    
    priority_limit = self.get_priority_match_limit
    
    other_limit = self.get_other_match_limit
    
    # 应用优先匹配限制
    if priority_limit > 0:
        limited_priority_matches = priority_matches[:priority_limit]
    else:
        limited_priority_matches = priority_matches
    
    # 应用其他匹配限制
    if other_limit > 0:
        limited_other_matches = other_matches[:other_limit]
    else:
        limited_other_matches = other_matches
    
    return limited_priority_matches, limited_other_matches



def _print_default_plugins(self):
    """输出默认插件方法文件内容"""
    try:
        plugin_files = self.get_default_output_plugin
        if not plugin_files:
            return
        
        output_dir = getattr(self, 'output_dir', '.')
        for plugin_file in plugin_files:
            file_path = os.path.join(output_dir, plugin_file)
            if os.path.exists(file_path) and os.path.getsize(file_path) > 0:
                print(f"\n\n[*] {plugin_file}")
                try:
                    with open(file_path, "r", encoding='utf-8', errors='ignore') as f:
                        content = f.read().strip()
                        if content:
                            print(f"""{content}\n""")
                        else:
                            print("\n")
                except Exception as e:
                    pass
            else:
                pass

    except Exception as e:
        print(f"[!] 默认输出插件方法失败: {e}")


def _write_match_to_file(f, match, match_type="匹配", index=1):
    """将匹配记录写入文件
    
    Args:
        f: 文件对象
        match: 匹配记录字典
        match_type: 匹配类型（如"优先匹配"、"匹配"）
        index: 匹配序号
    """
    # 获取实际路径并转换为绝对路径
    actual_path = match.get('actual_path', 'N/A')
    if actual_path != 'N/A' and not os.path.isabs(actual_path):
        actual_path = os.path.abspath(actual_path)
    
    f.write(f"  {match_type} {index}\n")
    f.write(f"匹配行: {match.get('vol_file_path', 'N/A')}\n")
    f.write(f"实际路径: {actual_path}\n")
    
    # 文件匹配特有字段
    if 'offset' in match:
        f.write(f"偏移地址: {match.get('offset', 'N/A')}\n")
    
    # 进程匹配特有字段
    if 'pid' in match:
        f.write(f"进程PID: {match.get('pid', 'N/A')}\n")
    
    if 'process_name' in match:
        f.write(f"进程名称: {match.get('process_name', 'N/A')}\n")
    
    f.write(f"\n")


def _group_matches_path(scan_results):
    """按路径对扫描结果进行分组
    
    Args:
        scan_results: 扫描结果列表
        
    Returns:
        dict: 按路径分组的扫描结果
    """
    path_groups = {}
    for result in scan_results:
        file_path = result.get('file_path', 'unknown')
        source = result.get('source', 'unknown')
        matches = result.get('matches', [])
        
        if file_path == 'unknown' or file_path == 'N/A':
            dir_path = 'unknown'
        else:
            # 转换为绝对路径并获取目录
            if not os.path.isabs(file_path):
                file_path = os.path.abspath(file_path)
            dir_path = os.path.dirname(file_path)
        
        if dir_path not in path_groups:
            path_groups[dir_path] = []
        
        path_groups[dir_path].append({
            'file_path': file_path,
            'source': source,
            'matches': matches
        })
    
    return path_groups



def _generate_ctf_files_report(self, vol_version=None):
    """生成CTF文件提取正则匹配报告"""
    try:
        # 确保输出目录存在
        os.makedirs(self.output_dir, exist_ok=True)
        
        # 创建ctf_reports子目录
        default_dirs = self.get_default_directory_names
        ctf_report_dir_name = default_dirs[1] if len(default_dirs) > 1 else "ctf_report"
        ctf_reports_dir = os.path.join(self.output_dir, ctf_report_dir_name)
        os.makedirs(ctf_reports_dir, exist_ok=True)
        
        # 根据版本信息创建报告文件名
        version_suffix = ""
        if vol_version:
            if "vol2" in vol_version or "volatility2" in vol_version:
                version_suffix = "_vol2"
            elif "vol3" in vol_version or "volatility3" in vol_version:
                version_suffix = "_vol3"
        
        report_file = os.path.join(ctf_reports_dir, f"ctf_files_matches{version_suffix}.txt")
        timestamp = time.strftime("%Y-%m-%d %H:%M:%S")
        
        with open(report_file, "w", encoding='utf-8') as f:

            # 检查是否有匹配记录
            if not hasattr(self, 'ctf_files_matches') or not self.ctf_files_matches:
                f.write(f"")
                return True


            f.write(f"生成时间: {timestamp}\n")
            f.write(f"内存文件: {os.path.basename(self.mem_file)}\n")
            f.write(f"输出目录: {os.path.abspath(self.output_dir)}\n")
            f.write(f"Volatility版本: {vol_version if vol_version else 'unknown'}\n")
            

            # 对匹配进行排序
            priority_matches, other_matches = _sort_matches_priority(self, self.ctf_files_matches)
            
            # 应用显示限制
            priority_matches, other_matches = _apply_match_limits(self, priority_matches, other_matches)
            sorted_matches = priority_matches + other_matches
            
            
            # 如果有优先匹配，先显示优先匹配
            if priority_matches:
                for i, match in enumerate(priority_matches, 1):
                    _write_match_to_file(f, match, "#", i)
            
            # 显示其他匹配
            if other_matches:
                for i, match in enumerate(other_matches, len(priority_matches) + 1):
                    _write_match_to_file(f, match, "#", i)

        return True
        
    except Exception as e:
        print(f"\n\n[!] 生成CTF文件提取正则报告失败: {e}")
        return False


def _generate_ctf_process_report(self, vol_version=None):
    """生成CTF进程提取正则匹配报告"""
    try:
        # 确保输出目录存在
        os.makedirs(self.output_dir, exist_ok=True)
        
        # 创建ctf_reports子目录
        default_dirs = self.get_default_directory_names
        ctf_report_dir_name = default_dirs[1] if len(default_dirs) > 1 else "ctf_report"
        ctf_reports_dir = os.path.join(self.output_dir, ctf_report_dir_name)
        os.makedirs(ctf_reports_dir, exist_ok=True)
        
        # 根据版本信息创建报告文件名
        version_suffix = ""
        if vol_version:
            if "vol2" in vol_version or "volatility2" in vol_version:
                version_suffix = "_vol2"
            elif "vol3" in vol_version or "volatility3" in vol_version:
                version_suffix = "_vol3"
        
        report_file = os.path.join(ctf_reports_dir, f"ctf_process_matches{version_suffix}.txt")
        timestamp = time.strftime("%Y-%m-%d %H:%M:%S")
        
        with open(report_file, "w", encoding='utf-8') as f:

            # 检查是否有匹配记录
            if not hasattr(self, 'ctf_process_matches') or not self.ctf_process_matches:
                f.write(f"")
                return True


            f.write(f"生成时间: {timestamp}\n")
            f.write(f"内存文件: {os.path.basename(self.mem_file)}\n")
            f.write(f"输出目录: {os.path.abspath(self.output_dir)}\n")
            f.write(f"Volatility版本: {vol_version if vol_version else 'unknown'}\n")
            

            # 对匹配进行排序
            priority_matches, other_matches = _sort_matches_priority(self, self.ctf_process_matches)
            # 应用显示限制
            priority_matches, other_matches = _apply_match_limits(self, priority_matches, other_matches)
            sorted_matches = priority_matches + other_matches
            
            
            # 如果有优先匹配，先显示优先匹配
            if priority_matches:
                for i, match in enumerate(priority_matches, 1):
                    _write_match_to_file(f, match, "#", i)
            
            # 显示其他匹配
            if other_matches:
                for i, match in enumerate(other_matches, len(priority_matches) + 1):
                    _write_match_to_file(f, match, "#", i)

        return True
        
    except Exception as e:
        print(f"\n\n[!] 生成CTF进程提取正则报告失败: {e}")
        return False


def _generate_ctf_scan_report(self, scan_results, report_dir=None):
    """生成CTF扫描正则匹配报告"""
    try:
        # 确保输出目录存在
        os.makedirs(self.output_dir, exist_ok=True)
        
        # 如果report_dir为None，使用默认值
        if report_dir is None:
            default_dirs = self.get_default_directory_names
            report_dir = default_dirs[1] if len(default_dirs) > 1 else "ctf_report"
        
        # 创建ctf_reports子目录
        ctf_reports_dir = os.path.join(self.output_dir, report_dir)
        os.makedirs(ctf_reports_dir, exist_ok=True)
        
        # 创建报告文件
        report_file = os.path.join(ctf_reports_dir, "ctf_scans_matches.txt")
        timestamp = time.strftime("%Y-%m-%d %H:%M:%S")
        
        with open(report_file, "w", encoding='utf-8') as f:

            if not scan_results:
                f.write(f"")
                return True

            f.write(f"生成时间: {timestamp}\n")
            f.write(f"内存文件: {os.path.basename(self.mem_file)}\n")
            f.write(f"输出目录: {os.path.abspath(self.output_dir)}\n")
            

            # 按路径分组
            path_groups = _group_matches_path(scan_results)
            
            # 处理每个组的匹配
            processed_groups = {}
            for dir_path, file_list in path_groups.items():
                processed_groups[dir_path] = []
                
                for file_info in file_list:
                    source = file_info['source']
                    matches = file_info['matches']
                    file_path = file_info['file_path']
                    
                    # 对匹配进行排序
                    priority_matches, other_matches = _sort_matches_priority(self, matches, text_field='text')

                    # 应用显示限制
                    priority_matches, other_matches = _apply_match_limits(self, priority_matches, other_matches)
                    
                    # 合并匹配：优先匹配在前，其他匹配在后
                    sorted_matches = priority_matches + other_matches
                    
                    processed_groups[dir_path].append({
                        'file_path': file_path,
                        'source': source,
                        'matches': sorted_matches,
                        'total_matches': len(matches),
                        'priority_count': len(priority_matches)
                    })
            
            
            for dir_path, file_list in processed_groups.items():
                if dir_path == 'unknown':
                    f.write(f"\n[未知路径]")
                else:
                    f.write(f"\n{dir_path}")
                
                for file_info in file_list:
                    source = file_info['source']
                    matches = file_info['matches']
                    file_path = file_info['file_path']
                    total_matches = file_info['total_matches']
                    priority_count = file_info['priority_count']
                    
                    # 显示文件信息
                    display_text = f"  {file_path}" if file_path != 'unknown' and file_path != 'N/A' else f"  {source}"
                    if priority_count > 0:
                        f.write(f"{display_text} \n")
                    else:
                        f.write(f"{display_text} \n")
                    
                    # 显示匹配（优先匹配显示全部，其他匹配显示限制数量）
                    if priority_count > 0:
                        for j, match in enumerate(matches[:priority_count], 1):
                            text = match.get('text', '')
                            context = match.get('context', '')
                            if context:
                                f.write(f"       #{j}:  {text}           {context}\n")
                            else:
                                f.write(f"       #{j}:  {text}\n")
                    
                    # 显示其他匹配（如果有的话）
                    if len(matches) > priority_count:
                        other_start = priority_count
                        for j, match in enumerate(matches[other_start:], priority_count + 1):
                            text = match.get('text', '')
                            context = match.get('context', '')
                            if context:
                                f.write(f"       #{j}:  {text}           {context}\n")
                            else:
                                f.write(f"       #{j}:  {text}\n")
                    
                    f.write(f"\n")

        return True
        
    except Exception as e:
        print(f"\n\n[!] 生成CTF扫描正则报告失败: {e}")
        return False



def _record_ctf_files_match(self, vol_file_path, actual_path, offset=None, vol_version=None):
    """记录CTF文件提取正则匹配"""
    if not hasattr(self, 'ctf_files_matches'):
        self.ctf_files_matches = []
    
    match_record = {
        'vol_file_path': vol_file_path,
        'actual_path': actual_path,
        'offset': offset,
        'pattern': 'files_patterns',
        'vol_version': vol_version
    }
    
    self.ctf_files_matches.append(match_record)
    return True



def _record_ctf_process_match(self, vol_file_path, actual_path, pid=None, process_name=None, vol_version=None):
    """记录CTF进程提取正则匹配"""
    if not hasattr(self, 'ctf_process_matches'):
        self.ctf_process_matches = []
    
    match_record = {
        'vol_file_path': vol_file_path,
        'actual_path': actual_path,
        'pid': pid,
        'process_name': process_name,
        'pattern': 'process_patterns',
        'vol_version': vol_version
    }
    
    self.ctf_process_matches.append(match_record)
    return True



def _group_matches_version(self, matches_list, version_key='vol_version'):
    """按版本分组匹配记录"""
    vol2_matches = []
    vol3_matches = []
    other_matches = []
    
    for match in matches_list:
        version = match.get(version_key, '')
        if version == 'vol2':
            vol2_matches.append(match)
        elif version == 'vol3':
            vol3_matches.append(match)
        else:
            other_matches.append(match)
    
    return vol2_matches, vol3_matches, other_matches



def _print_match_group(self, matches, title_prefix, field_mappings):
    """打印一组匹配记录"""
    if not matches:
        return
    
    print(f"\n{title_prefix} 共 {len(matches)} 个:")
    for i, match in enumerate(matches, 1):
        print(f"   #{i}")
        for field_name, display_name in field_mappings.items():
            value = match.get(field_name, 'N/A')
            print(f"    {display_name}: {value}")



def _print_ctf_matches_console(self):
    """输出CTF匹配内容到控制台"""

    # 辅助函数：打印匹配组
    def _print_sorted_match_group(matches_list, title_prefix, field_mappings, text_field='vol_file_path'):
        if not matches_list:
            return
        
        # 对匹配进行排序
        priority_matches, other_matches = _sort_matches_priority(self, matches_list, text_field)
        # 应用显示限制
        priority_matches, other_matches = _apply_match_limits(self, priority_matches, other_matches)
        
        # 输出标题
        print(f"\n\n[*] {title_prefix}\n\n")
        
        # 输出优先匹配
        if priority_matches:
            for i, match in enumerate(priority_matches, 1):
                print(f"   #{i}")
                for field_name, display_name in field_mappings.items():
                    value = match.get(field_name, 'N/A')
                    print(f"    {display_name}: {value}")
        
        # 输出其他匹配
        if other_matches:
            start_index = len(priority_matches) + 1 if priority_matches else 1
            for i, match in enumerate(other_matches, start_index):
                print(f"   #{i}")
                for field_name, display_name in field_mappings.items():
                    value = match.get(field_name, 'N/A')
                    print(f"    {display_name}: {value}")
    
    # 文件提取匹配
    if hasattr(self, 'ctf_files_matches') and self.ctf_files_matches:
        vol2_files, vol3_files, other_files = self.group_matches_version(self.ctf_files_matches)
        
        files_field_mappings = {
            'vol_file_path': '匹配行',
            'actual_path': '实际路径',
            'offset': '偏移地址'
        }
        
        if vol2_files:
            _print_sorted_match_group(vol2_files, '[CTF文件提取正则匹配]', files_field_mappings)
        
        if vol3_files:
            _print_sorted_match_group(vol3_files, '[CTF文件提取正则匹配]', files_field_mappings)
        
        if other_files:
            _print_sorted_match_group(other_files, '[CTF文件提取正则匹配]', files_field_mappings)
    else:
        print("\n\n[-] [CTF文件提取正则匹配] 没有匹配记录\n\n")
    
    # 进程提取匹配
    if hasattr(self, 'ctf_process_matches') and self.ctf_process_matches:
        vol2_process, vol3_process, other_process = self.group_matches_version(self.ctf_process_matches)
        
        process_field_mappings = {
            'vol_file_path': '匹配行',
            'actual_path': '实际路径',
            'pid': '进程PID',
            'process_name': '进程名称'
        }
        
        if vol2_process:
            _print_sorted_match_group(vol2_process, '[CTF进程提取正则匹配]', process_field_mappings)
        
        if vol3_process:
            _print_sorted_match_group(vol3_process, '[CTF进程提取正则匹配]', process_field_mappings)
        
        if other_process:
            _print_sorted_match_group(other_process, '[CTF进程提取正则匹配]', process_field_mappings)
    else:
        print("\n\n[-] [CTF进程提取正则匹配] 没有匹配记录\n\n")
    
    
    # CTF扫描匹配
    if hasattr(self, 'ctf_scan_matches') and self.ctf_scan_matches:

        # 输出标题
        print("\n\n[*] [CTF扫描正则匹配]\n\n")

        scans_bool = False

        # 按路径分组
        path_groups = _group_matches_path(self.ctf_scan_matches)
        
        # 处理每个组的匹配
        processed_groups = {}
        for dir_path, file_list in path_groups.items():
            processed_groups[dir_path] = []
            
            for file_info in file_list:
                source = file_info['source']
                matches = file_info['matches']
                file_path = file_info['file_path']
                
                # 对匹配进行排序
                priority_matches, other_matches = _sort_matches_priority(self, matches, text_field='text')

                # 应用显示限制
                priority_matches, other_matches = _apply_match_limits(self, priority_matches, other_matches)
                
                # 合并匹配：优先匹配在前，其他匹配在后
                sorted_matches = priority_matches + other_matches
                
                processed_groups[dir_path].append({
                    'file_path': file_path,
                    'source': source,
                    'matches': sorted_matches,
                    'total_matches': len(matches),
                    'priority_count': len(priority_matches)
                })


        for dir_path, file_list in processed_groups.items():

            if dir_path == 'unknown':
                if scans_bool:
                    print(f"\n\n\n\n[-] [未知路径]")
                else:
                    print(f"[-] [未知路径]")

            else:
                if scans_bool:
                    print(f"\n\n\n\n[+] {dir_path}")
                else:
                    print(f"[+] {dir_path}")

            if not scans_bool:
                scans_bool = True
            

            for file_info in file_list:
                source = file_info['source']
                matches = file_info['matches']
                file_path = file_info['file_path']
                total_matches = file_info['total_matches']
                priority_count = file_info['priority_count']
                
                # 显示文件信息
                if file_path != 'unknown' and file_path != 'N/A':
                    rel_path = os.path.relpath(file_path, dir_path) if dir_path != 'unknown' else file_path
                    display_text = rel_path
                else:
                    display_text = source
                

                if priority_count > 0:
                    print(f"  \n\n[+] {display_text}  ")
                else:
                    print(f"  \n\n[-] {display_text}  ")
                
                # 获取上下文限制
                context_limit = self.get_console_context_limit
                
                # 显示优先匹配
                if priority_count > 0:
                    for j, match in enumerate(matches[:priority_count], 1):
                        text = match.get('text', '')
                        context = match.get('context', '')
                        if context:
                            print(f"      #{j}:  {text}         {context[:context_limit]}")
                        else:
                            print(f"      #{j}:  {text}")
                
                # 显示其他匹配
                if len(matches) > priority_count:
                    other_start = priority_count
                    for j, match in enumerate(matches[other_start:], priority_count + 1):
                        text = match.get('text', '')
                        context = match.get('context', '')
                        if context:
                            print(f"      #{j}:  {text}         {context[:context_limit]}")
                        else:
                            print(f"      #{j}:  {text}")
    else:
        print("\n[-] [CTF扫描正则匹配] 没有匹配记录\n")
        
    return True



def _print_ctf_matches_paths(self):

    # 检查并输出报告文件路径
    try:

        # 创建ctf_reports子目录
        default_dirs = self.get_default_directory_names
        ctf_report_dir_name = default_dirs[1] if len(default_dirs) > 1 else "ctf_report"
        ctf_reports_dir = os.path.join(self.output_dir, ctf_report_dir_name)
        os.makedirs(ctf_reports_dir, exist_ok=True)

        
        # 检查CTF扫描正则报告
        scan_report_file = os.path.join(ctf_reports_dir, "ctf_scans_matches.txt")
        if os.path.exists(scan_report_file) and os.path.getsize(scan_report_file) > 0:
            print(f"\n[*] CTF扫描正则报告: {scan_report_file}")
        
        # 检查CTF文件提取正则报告
        file_report_patterns = [
            os.path.join(ctf_reports_dir, "ctf_files_matches_vol2.txt"),
            os.path.join(ctf_reports_dir, "ctf_files_matches_vol3.txt"),
            os.path.join(ctf_reports_dir, "ctf_files_matches.txt")
        ]
        
        for file_report in file_report_patterns:
            if os.path.exists(file_report) and os.path.getsize(file_report) > 0:
                print(f"[*] CTF文件提取正则报告: {file_report}")
                break
        
        # 检查CTF进程提取正则报告
        process_report_patterns = [
            os.path.join(ctf_reports_dir, "ctf_process_matches_vol2.txt"),
            os.path.join(ctf_reports_dir, "ctf_process_matches_vol3.txt"),
            os.path.join(ctf_reports_dir, "ctf_process_matches.txt")
        ]
        
        for process_report in process_report_patterns:
            if os.path.exists(process_report) and os.path.getsize(process_report) > 0:
                print(f"[*] CTF进程提取正则报告: {process_report}")
                break
                
    except Exception as e:
        pass
