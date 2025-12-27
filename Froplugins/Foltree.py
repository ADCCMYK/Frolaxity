#!/usr/bin/env python3
import os
import sys
sys.dont_write_bytecode = True

import zipfile
import tarfile
import datetime
from pathlib import Path


try:
    import pyzipper
    HAS_PYZIPPER = True
except ImportError:
    HAS_PYZIPPER = False

try:
    import py7zr
    HAS_PY7ZR = True
except ImportError:
    HAS_PY7ZR = False

try:
    import rarfile
    HAS_RARFILE = True
except ImportError:
    HAS_RARFILE = False


# 检测压缩包类型
def detect_archive_type(file_path):
    try:
        with open(file_path, 'rb') as f:
            header = f.read(10)
        
        signatures = {
            b'PK': 'zip',
            b'Rar!': 'rar', 
            b'\x1f\x8b': 'gzip',
            b'BZh': 'bzip2',
            b'\xfd7zXZ': 'xz',
            b'ustar': 'tar'
        }
        
        for sig, archive_type in signatures.items():
            if header.startswith(sig):
                return archive_type
        
        # 备用：通过扩展名判断
        ext_map = {
            '.zip': 'zip', '.rar': 'rar', '.7z': '7z',
            '.gz': 'gzip', '.dat': 'gzip', '.dat_old': 'gzip',
            '.tgz': 'gzip','.bz2': 'bzip2', '.tbz2': 'bzip2',
            '.xz': 'xz', '.txz': 'xz','.tar': 'tar'
        }
        ext = Path(file_path).suffix.lower()
        return ext_map.get(ext, 'unknown')
        
    except:
        return 'unknown'


# 精确计算字符串在终端中的显示宽度
def get_display_width(text):
    width = 0
    for char in text:
        # 中文字符及全角字符占用2个宽度
        if ('\u4e00' <= char <= '\u9fff' or  # 中文字符
            char in '，。！？；：""（）【】《》｛｝「」『』【】'):
            width += 2
        else:
            width += 1
    return width


# 获取加密信息（支持多种压缩格式）
def get_encryption_info(file_info, archive_type):
    if hasattr(file_info, 'is_dir') and file_info.is_dir():
        return "目录"
    
    # ZIP格式加密检测
    if archive_type == 'zip' and hasattr(file_info, 'flag_bits'):
        if file_info.flag_bits & 0x1:  # 加密标志
            encryption_method = file_info.flag_bits & 0x6
            if encryption_method == 0:
                return "ZipCrypto"
            elif encryption_method == 2:
                return "AES加密"
            return "未知加密"
    
    # RAR格式加密检测
    elif archive_type == 'rar' and HAS_RARFILE:
        if hasattr(file_info, 'needs_password') and file_info.needs_password():
            return "AES加密"
    
    # 7Z格式加密检测
    elif archive_type == '7z' and HAS_PY7ZR:
        if hasattr(file_info, 'encrypted') and file_info.encrypted:
            return "AES加密"
    
    # 其他格式默认未加密
    return "未加密"


# 获取整个压缩包的加密算法
def get_encryption_algorithm(archive_path, archive_type):
    try:
        if archive_type == 'zip':
            if HAS_PYZIPPER:
                try:
                    with pyzipper.AESZipFile(archive_path, 'r') as archive:
                        encrypted_files = [fi for fi in archive.infolist() if fi.flag_bits & 0x1]
                except:
                    with zipfile.ZipFile(archive_path, 'r') as archive:
                        encrypted_files = [fi for fi in archive.infolist() if fi.flag_bits & 0x1]
            else:
                with zipfile.ZipFile(archive_path, 'r') as archive:
                    encrypted_files = [fi for fi in archive.infolist() if fi.flag_bits & 0x1]
            
            if not encrypted_files:
                return "未加密"
            
            algorithms = set()
            for file_info in encrypted_files:
                encryption_method = file_info.flag_bits & 0x6
                if encryption_method == 0:
                    algorithms.add("ZipCrypto")
                elif encryption_method == 2:
                    algorithms.add("AES加密")
                else:
                    algorithms.add("未知加密算法")
            
            return "混合加密" if len(algorithms) > 1 else list(algorithms)[0]
        
        elif archive_type == 'rar' and HAS_RARFILE:
            try:
                with rarfile.RarFile(archive_path, 'r') as archive:
                    encrypted_files = [fi for fi in archive.infolist() if hasattr(fi, 'needs_password') and fi.needs_password()]
                    if not encrypted_files:
                        return "未加密"
                    return "AES加密"  # RAR通常使用AES加密
            except:
                return "未知加密算法"
        
        elif archive_type == '7z' and HAS_PY7ZR:
            try:
                with py7zr.SevenZipFile(archive_path, 'r', password=None) as archive:
                    file_list = archive.list()
                    encrypted_files = [fi for fi in file_list if hasattr(fi, 'encrypted') and fi.encrypted]
                    if not encrypted_files:
                        return "未加密"
                    return "AES加密"  # 7Z通常使用AES加密
            except:
                return "未知加密算法"
        
        # 对于不支持加密的格式
        elif archive_type in ['gzip', 'bzip2', 'xz', 'tar']:
            return "未加密"
        
        else:
            return "未知格式"
            
    except:
        return "未知加密算法"


# 通用树形结构写入函数
def write_tree_structure(f, file_list, get_encryption_func, archive_type):
    """通用树形结构写入函数"""

    for file_info in file_list:
        encryption = get_encryption_func(file_info, archive_type)
        filename = file_info.filename
        
        filename_width = get_display_width(filename)
        padding_length = max(1, 80 - filename_width)
        
        if hasattr(file_info, 'is_dir') and file_info.is_dir():
            f.write(f"{filename}{' ' * padding_length}      [目录]\n")
        else:
            if hasattr(file_info, 'file_size'):
                size = f"{file_info.file_size:,} bytes"
                f.write(f"{filename}{' ' * padding_length}[{encryption}] ({size})\n")
            elif hasattr(file_info, 'compressed'):
                size = f"{file_info.compressed:,} bytes"
                f.write(f"{filename}{' ' * padding_length}[{encryption}] ({size})\n")
            else:
                f.write(f"{filename}{' ' * padding_length}[{encryption}]\n")


def _analyze_archive_structure(self, directory_path, output_dir="tree_reports", max_depth=1000, parent_tree=None, parent_archive=None, is_top_level=True):
    """
    递归扫描目录并分析压缩包结构，生成详细报告
    
    Args:
        directory_path: 要扫描的目录路径
        output_dir: 输出目录
        max_depth: 最大递归深度
        parent_tree: 父级目录树列表（用于递归时汇总结果）
        archive_paths_param: 压缩包路径列表（用于递归时汇总结果）
        is_top_level: 是否为最顶层调用（用于控制报告生成）
    """
    
    if max_depth <= 0:
        print(f"[!] 达到最大递归{max_depth}深度，停止扫描: {directory_path}")
        return (parent_tree or [], parent_archive or [])
    
    # 只在第一次调用时构建完整路径，避免递归时重复拼接
    # 如果 output_dir 不是绝对路径，则将其构建在要扫描的目录下
    if is_top_level and not os.path.isabs(output_dir):
        output_dir = f"{directory_path}\\{output_dir}"

    # 支持的压缩文件扩展名
    archive_extensions = ['.zip', '.rar', '.7z', '.gz', '.gzip', '.bz2', '.xz', '.tar', '.tgz', '.tbz2', '.txz']
    
    # 生成报告文件名
    archive_name = os.path.basename(directory_path)
    
    # 收集所有找到的压缩包路径（使用传入的参数或创建新列表）
    archive_paths = parent_archive or []
    
    # 记录目录结构的列表（使用传入的参数或创建新列表）
    directory_tree = parent_tree or []
    
    # 如果是目录，递归扫描
    print(f"[*] 开始扫描目录: {directory_path}")
    for entry in os.listdir(directory_path):
        full_path = os.path.join(directory_path, entry)

        if not os.path.exists(full_path):
            continue
        
        # 跳过特定目录
        basename = os.path.basename(full_path)
        if basename in ['search_report', 'tree_reports', 'extracted_files']:
            continue
        
        # 记录目录结构信息
        if os.path.isdir(full_path):
            directory_tree.append(f"{full_path}               [目录]")
            # 递归扫描子目录，传递当前的目录树和压缩包路径，保持 is_top_level 为 False
            result = self.analyze_archive_structure(full_path, output_dir, max_depth - 1, directory_tree, archive_paths, False)
            directory_tree, archive_paths = result  # 更新目录树和压缩包路径
        elif os.path.isfile(full_path):
            file_size = os.path.getsize(full_path)
            directory_tree.append(f"{full_path} {file_size:,} bytes [文件]")
            
            # 检查文件后缀是否为压缩文件
            file_ext = os.path.splitext(full_path)[1].lower()
            if file_ext in archive_extensions:
                print(f"[*] 找到压缩文件: {full_path}")
                
                # 添加到压缩包路径列表
                archive_paths.append(full_path)
                
                # 为每个压缩包生成单独的文件树报告（写入模式）
                archive_basename = os.path.basename(full_path)
                archive_tree_file = os.path.join(output_dir, f"{archive_basename}_tree.txt")
                self.analyze_single_archive(full_path, archive_tree_file)

    # 只在最顶层调用时生成总的目录树报告
    if is_top_level and directory_tree:
        # 确保输出目录存在
        if not os.path.exists(output_dir):
            os.makedirs(output_dir)
            print(f"[*] 创建文件树目录: {output_dir}")
            
        tree_file = os.path.join(output_dir, f"{archive_name}_complete_directory_tree.txt")
        try:
            with open(tree_file, 'w', encoding='utf-8') as f:
                f.write(f"完整目录结构报告 - 扫描时间: {datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n")
                f.write(f"扫描目录: {directory_path}\n")
                f.write(f"找到文件和目录总数: {len(directory_tree)}\n\n")
                
                for item in directory_tree:
                    f.write(f"{item}\n")
                
            print(f"[*] 完整目录结构报告已保存至: {tree_file}")
        except Exception as e:
            print(f"[!] 保存完整目录结构报告失败: {e}")

    # 生成压缩包路径列表（只在最顶层调用时）
    if is_top_level and archive_paths:
        # 确保输出目录存在
        if not os.path.exists(output_dir):
            os.makedirs(output_dir)
            print(f"[*] 创建文件树目录: {output_dir}")
            
        archive_list_file = os.path.join(output_dir, f"{archive_name}_archive_list.txt")
        try:
            with open(archive_list_file, 'w', encoding='utf-8') as f:
                f.write(f"压缩包路径列表 - 扫描时间: {datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n")
                f.write(f"扫描目录: {directory_path}\n")
                f.write(f"找到压缩包数量: {len(archive_paths)}\n\n")
                
                for i, path in enumerate(archive_paths, 1):
                    f.write(f"{i}. {path}\n")
                
            print(f"[*] 压缩包路径列表已保存至: {archive_list_file}")
        except Exception as e:
            print(f"[!] 保存压缩包路径列表失败: {e}")

    return (directory_tree, archive_paths)


def _analyze_single_archive(self, archive_path, report_file):
    """分析单个压缩文件"""
    
    # 创建输出目录（报告文件的父目录）
    report_dir = os.path.dirname(report_file)

    if report_dir and not os.path.exists(report_dir):
        os.makedirs(report_dir)
        print(f"[*] 创建文件树目录: {report_dir}")

    archive_type = detect_archive_type(archive_path)
    
    try:
        with open(report_file, 'w', encoding='utf-8') as f:
            file_encrypted = get_encryption_algorithm(archive_path, archive_type)

            f.write("压缩包结构分析报告\n")
            f.write(f"文件路径: {archive_path}\n")
            f.write(f"文件大小: {os.path.getsize(archive_path):,} bytes\n")
            f.write(f"压缩类型: {archive_type.upper()}\n")
            f.write(f"加密算法: {file_encrypted}\n")
            f.write(f"分析时间: {datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n\n")
            
            # 根据不同类型进行处理
            if archive_type == 'zip':
                # 使用pyzipper处理AES加密的ZIP文件（如果可用）
                if HAS_PYZIPPER:
                    try:
                        # 尝试使用空密码打开AES加密的ZIP文件
                        with pyzipper.AESZipFile(archive_path, 'r') as archive:
                            file_list = archive.infolist()
                            encrypted_count = sum(1 for fi in file_list if fi.flag_bits & 0x1)
                            
                            f.write(f"文件总数: {len(file_list)}\n")
                            f.write(f"加密文件: {encrypted_count}\n\n")
                            
                            # 使用通用树形结构写入函数
                            write_tree_structure(f, file_list, get_encryption_info, 'zip')
                    except pyzipper.zipfile.BadZipFile:
                        # 回退到标准zipfile处理
                        with zipfile.ZipFile(archive_path, 'r') as archive:
                            file_list = archive.infolist()
                            encrypted_count = sum(1 for fi in file_list if fi.flag_bits & 0x1)
                            
                            f.write(f"文件总数: {len(file_list)}\n")
                            f.write(f"加密文件: {encrypted_count}\n\n")
                            
                            # 使用通用树形结构写入函数
                            write_tree_structure(f, file_list, get_encryption_info, 'zip')
                    except Exception as e:
                        f.write(f"AES加密ZIP文件需要密码（仅尝试空密码）: {e}\n")
                        f.write("无法分析加密的ZIP文件内容\n")
                else:
                    # 使用标准zipfile处理
                    with zipfile.ZipFile(archive_path, 'r') as archive:
                        file_list = archive.infolist()
                        encrypted_count = sum(1 for fi in file_list if fi.flag_bits & 0x1)
                        
                        f.write(f"文件总数: {len(file_list)}\n")
                        f.write(f"加密文件: {encrypted_count}\n\n")
                        
                        # 使用通用树形结构写入函数
                        write_tree_structure(f, file_list, get_encryption_info, 'zip')
            
            elif archive_type == 'rar':
                if HAS_RARFILE:
                    try:
                        # 尝试使用空密码打开RAR文件
                        with rarfile.RarFile(archive_path, 'r') as archive:
                            file_list = archive.infolist()
                            f.write(f"文件总数: {len(file_list)}\n\n")
                            
                            # 使用通用树形结构写入函数
                            write_tree_structure(f, file_list, get_encryption_info, 'rar')
                    
                    except rarfile.NeedFirstVolume:
                        f.write("需要多卷RAR文件的第一个卷\n")
                    except rarfile.BadRarFile:
                        f.write("损坏的RAR文件\n")
                    except rarfile.PasswordRequired:
                        f.write("RAR文件需要密码（仅尝试空密码）\n")
                        f.write("无法分析加密的RAR文件内容\n")
            
            elif archive_type == 'gzip':
                # GZIP单文件压缩格式处理
                file_size = os.path.getsize(archive_path)
                f.write(f"文件类型: GZIP单文件压缩\n")
                f.write(f"压缩文件大小: {file_size:,} bytes\n\n")
                
                # 模拟单文件树形结构
                filename = os.path.basename(archive_path).replace('.gz', '')
                filename_width = get_display_width(filename)
                padding_length = max(1, 80 - filename_width)
                f.write(f"{filename}{' ' * padding_length}[未加密] ({file_size:,} bytes)\n")
                
                f.write("GZIP格式特性: 单文件压缩，不支持加密和多文件\n")
            
            elif archive_type == '7z':
                if HAS_PY7ZR:
                    try:
                        # 尝试使用空密码打开7Z文件
                        with py7zr.SevenZipFile(archive_path, 'r', password=None) as archive:
                            file_list = archive.list()
                            encrypted_count = sum(1 for fi in file_list if fi.encrypted)
                            
                            f.write(f"文件总数: {len(file_list)}\n")
                            f.write(f"加密文件: {encrypted_count}\n\n")
                            
                            # 使用通用树形结构写入函数
                            write_tree_structure(f, file_list, get_encryption_info, '7z')
                    
                    except py7zr.PasswordRequired:
                        f.write("7Z文件需要密码（仅尝试空密码）\n")
                        f.write("无法分析加密的7Z文件内容\n")
            
            elif archive_type == 'tar':
                # TAR格式处理
                try:
                    with tarfile.open(archive_path, 'r') as archive:
                        file_list = archive.getmembers()
                        f.write(f"文件总数: {len(file_list)}\n\n")
                        
                        # 使用通用树形结构写入函数
                        write_tree_structure(f, file_list, get_encryption_info, 'tar')
                
                except Exception as e:
                    f.write(f"TAR文件处理错误: {e}\n")
            
            elif archive_type == 'bzip2':
                # BZIP2单文件压缩格式处理
                file_size = os.path.getsize(archive_path)
                f.write(f"文件类型: BZIP2单文件压缩\n")
                f.write(f"压缩文件大小: {file_size:,} bytes\n\n")
                
                # 模拟单文件树形结构
                filename = os.path.basename(archive_path).replace('.bz2', '')
                filename_width = get_display_width(filename)
                padding_length = max(1, 80 - filename_width)
                f.write(f"{filename}{' ' * padding_length}[未加密] ({file_size:,} bytes)\n")
                
                f.write("BZIP2格式特性: 单文件压缩，不支持加密\n")
            
            elif archive_type == 'xz':
                # XZ压缩格式
                file_size = os.path.getsize(archive_path)
                f.write(f"文件类型: XZ压缩\n")
                f.write(f"压缩文件大小: {file_size:,} bytes\n\n")

                # 模拟单文件树形结构
                filename = os.path.basename(archive_path).replace('.xz', '')
                filename_width = get_display_width(filename)
                padding_length = max(1, 80 - filename_width)
                f.write(f"{filename}{' ' * padding_length}[未加密] ({file_size:,} bytes)\n")

                f.write("XZ格式特性: 通常用于单文件压缩，支持LZMA2压缩算法\n")
            
            else:
                f.write(f"不支持的文件格式: {archive_type}\n")
                # 重新读取文件头用于显示
                try:
                    with open(archive_path, 'rb') as f_header:
                        file_header = f_header.read(10)
                    f.write(f"检测到的文件头: {file_header.hex()}\n")
                except:
                    f.write("检测到的文件头: 未知\n")
        
        print(f"[*] 分析完成！报告已保存至: {report_file}")
            
    except Exception as e:
        print(f"[!] 分析失败: {e}")
        return False

    return True
