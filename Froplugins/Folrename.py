#!/usr/bin/env python3
import sys
sys.dont_write_bytecode = True

import re
import shutil
import os
import time


def _rename_single_file(self, input_dir, dump_dir, clean_filename, file_exts):
    """
    时间处理单个文件重命名
    Args:
        input_dir: 输入目录
        dump_dir: 输出目录
        clean_filename: 目标文件名
        file_exts: 文件后缀数组
    Returns:
        str: 最终的文件路径，如果重命名失败返回None
    """
    # 等待完成文件提取
    time.sleep(0.6)  # 等待0.6秒确保文件已生成
    
    # 检查输入目录是否存在
    if not os.path.exists(input_dir):
        print(f"[!] 输入目录不存在: {input_dir}")
        return None
    
    # 获取输入目录中的所有文件
    files = os.listdir(input_dir)
    if not files:
        print(f"[!] 输入目录为空: {input_dir}")
        return None
    
    # 如果有指定文件后缀数组，过滤匹配的文件
    if file_exts:
        # 确保后缀以点开头
        file_exts = [ext if ext.startswith('.') else f'.{ext}' for ext in file_exts]
        matched_files = []
        for f in files:
            file_ext = os.path.splitext(f)[1].lower()
            if file_ext in file_exts:
                matched_files.append(f)
        
        if not matched_files:
            print(f"[!] 输入目录 {input_dir} 中没有匹配后缀 {file_exts} 的文件")
            return None
        
        # 使用匹配的文件列表
        files = matched_files
    else:
        print(f"[!]请指定匹配 {file_exts} 后缀列表")
        return None

    try:
        # 假设最后一个文件是最新生成的（使用过滤后的文件列表）
        latest_file = max([os.path.join(input_dir, f) for f in files], key=os.path.getctime)
        
        # 检查文件创建时间是否在1分钟内
        current_time = time.time()
        file_creation_time = os.path.getctime(latest_file)
        time_diff = current_time - file_creation_time
        
        if time_diff > 60:  # 1分钟
            print(f"[!] 跳过文件 {os.path.basename(latest_file)}: 创建时间超过1分钟 ({int(time_diff)}秒)")
            return None
        
        # 构建目标文件名
        target_file = os.path.join(dump_dir, clean_filename)
        
        # 如果目标文件已存在，添加序号
        if os.path.exists(target_file):
            base_name, ext = os.path.splitext(clean_filename)
            counter = 1
            while os.path.exists(os.path.join(dump_dir, f"{base_name}_{counter}{ext}")):
                counter += 1
            target_file = os.path.join(dump_dir, f"{base_name}_{counter}{ext}")
        
        # 确保目标目录存在
        os.makedirs(dump_dir, exist_ok=True)
        
        # 如果输入目录和目标目录不同，需要移动文件
        if input_dir != dump_dir:
            # 移动文件到目标目录
            shutil.move(latest_file, target_file)
            print(f"[+] 移动并重命名文件: {os.path.basename(latest_file)} -> {os.path.basename(target_file)}")
        else:
            # 重命名文件（在同一目录内）
            os.rename(latest_file, target_file)
            print(f"[+] 重命名文件: {os.path.basename(latest_file)} -> {os.path.basename(target_file)}")
        
        return target_file
        
    except Exception as e:
        print(f"[!] 文件操作失败: {e}")
        return None



def _rename_batch_files(self, input_dir, dump_dir, clean_filename, file_exts, expected_offset):
    """
    处理批量文件重命名
    Args:
        input_dir: 输入目录
        dump_dir: 输出目录
        clean_filename: 目标文件名
        file_exts: 文件后缀数组
        expected_offset: 期望的偏移量
    Returns:
        int: 处理的文件数量
    """
    # 检查输入目录是否存在
    if not os.path.exists(input_dir):
        print(f"[!] 输入目录不存在: {input_dir}")
        return 0
    
    # 构建正则表达式模式来匹配各种Volatility生成的文件格式
    # 格式1: file.{offset}.{address}.{type}.{original_filename}.{ext} (dumpfiles)
    # 格式2: file.None.{address}.{ext} (dumpfiles)
    # 格式3: pid.{PID}.{process_name}.{hex_offset}.{ext} (elfs.Elfs)
    
    # 确保扩展名不包含前面的点号
    clean_exts = [ext.replace('.', '') for ext in file_exts]
    ext_pattern = '|'.join(clean_exts)
    
    # 第一种模式：file.{offset}.{address}.{type}.{original_filename}.{ext}
    pattern1 = f"file\\.{expected_offset}\\.0x[0-9a-f]+\\..*\\.({ext_pattern})$"
    
    # 第二种模式：file.None.{address}.{ext}
    pattern2 = f"file\\.None\\.0x[0-9a-f]+\\.({ext_pattern})$"
    
    # 第三种模式：pid.{PID}.{process_name}.{hex_offset}.{ext} (elfs.Elfs格式)
    pattern3 = f"pid\\.\\d+\\.\\w+\\.0x[0-9a-f]+\\.({ext_pattern})$"
    
    # 组合所有模式
    pattern = f"({pattern1})|({pattern2})|({pattern3})"
    
    
    # 查找所有匹配的文件
    matched_files = []
    for filename in os.listdir(input_dir):
        if re.match(pattern, filename):
            matched_files.append(filename)
    
    if not matched_files:
        return 0
    
    # 批量处理所有匹配的文件
    processed_count = 0
    for filename in matched_files:
        try:
            # 检查文件创建时间是否在1分钟内
            source_path = os.path.join(input_dir, filename)
            current_time = time.time()
            file_creation_time = os.path.getctime(source_path)
            time_diff = current_time - file_creation_time
            
            if time_diff > 60:  # 1分钟
                print(f"[!] 跳过文件 {filename}: 创建时间超过1分钟 ({int(time_diff)}秒)")
                continue
            
            # 检测文件名格式
            parts = filename.split('.')
            
            # 检测文件名格式并处理
            if filename.startswith('pid.') and len(parts) >= 5:
                # 格式3: pid.{PID}.{process_name}.{hex_offset}.{ext} (elfs.Elfs格式)
                # 例如: pid.1.systemd.0x7fa9d6944000.dmp
                pid = parts[1]  # PID
                process_name = parts[2]  # 进程名
                hex_offset = parts[3]  # 十六进制偏移量             
                
                # 从elfs.Elfs.txt文件中提取对应的库文件名（内联实现）
                lib_name = None
                elfs_output_file = f"{self.output_dir}/linux.elfs.Elfs.txt"
                
                if os.path.exists(elfs_output_file):
                    try:
                        with open(elfs_output_file, 'r', errors='ignore') as f:
                            for line in f:
                                if not line.strip() or line.startswith(('Volatility', 'PID', '---')):
                                    continue
                                
                                line_parts = line.split('\t')
                                if len(line_parts) >= 6:
                                    file_pid = line_parts[0].strip()
                                    start_offset = line_parts[2].strip()
                                    file_path = line_parts[4].strip()
                                    output_file = line_parts[5].strip()
                                    
                                    # 检查PID和偏移量是否匹配
                                    if file_pid == pid and hex_offset in output_file:
                                        # 检查文件路径是否为[vdso]，如果是则保持原文件名
                                        if file_path == '[vdso]':
                                            target_name = filename  # 保持原文件名
                                            break
                                        else:
                                            # 从文件路径中提取库文件名
                                            lib_name = os.path.basename(file_path)
                                            break
                    except Exception as e:
                        print(f"[!] 读取elfs.Elfs.txt文件失败: {e}")
                
                # 如果找到库文件名且不是[vdso]，使用库文件名
                if lib_name:
                    target_name = f"{pid}_{process_name}_{lib_name}.{parts[-1]}"
                else:
                    # 如果无法提取库名或保持原文件名，使用偏移量作为后备
                    target_name = f"{pid}_{process_name}_{hex_offset}.{parts[-1]}"
            elif parts[1] == expected_offset:
                # 格式1: file.{offset}.{address}.{type}.{original_filename}.{ext}
                if len(parts) >= 6:
                    # 提取映射类型和原始文件名
                    # 例如：file.0x14c144e0.0xfa8010252b50.DataSectionObject.thumbcache_256.db.dat
                    # 映射类型：DataSectionObject (第3部分)
                    # 原始文件名：thumbcache_256.db (第4部分到倒数第2部分)
                    mapping_type = parts[3]  # 映射类型
                    original_name = '.'.join(parts[4:-1])  # 原始文件名
                    target_name = f"{expected_offset}_{mapping_type}_{original_name}"
                else:
                    # 格式不完整，使用默认名称（包含映射类型）
                    mapping_type = parts[3] if len(parts) > 3 else "Unknown"
                    target_name = f"{expected_offset}_{mapping_type}_{filename}"
            else:
                # 格式2: file.None.{address}.{ext}
                # clean_filename已经包含了expected_offset（格式：{offset}_{filename}）
                # 所以只需要添加映射类型标识，避免重复offset
                target_name = f"{clean_filename}"
            
            # 如果目标文件已存在，添加序号
            base_target = os.path.join(dump_dir, target_name)
            if os.path.exists(base_target):
                base, ext = os.path.splitext(target_name)
                counter = 1
                while os.path.exists(os.path.join(dump_dir, f"{base}_{counter}{ext}")):
                    counter += 1
                target_name = f"{base}_{counter}{ext}"
            
            # 确保目标目录存在
            os.makedirs(dump_dir, exist_ok=True)
            
            # 构建源路径和目标路径
            source_path = os.path.join(input_dir, filename)
            target_path = os.path.join(dump_dir, target_name)
            
            # 如果输入目录和目标目录不同，需要移动文件
            if input_dir != dump_dir:
                # 移动文件到目标目录
                shutil.move(source_path, target_path)
                print(f"[+] 移动并重命名文件: {filename} -> {target_name}")
            else:
                # 重命名文件（在同一目录内）
                os.rename(source_path, target_path)
                print(f"[+] 重命名文件: {filename} -> {target_name}")
            
            processed_count += 1
            
        except Exception as e:
            print(f"[!] 文件操作失败: {e}")
            continue
    
    return processed_count
