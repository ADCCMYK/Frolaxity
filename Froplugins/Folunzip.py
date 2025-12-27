#!/usr/bin/env python3
import os
import sys
sys.dont_write_bytecode = True

import zipfile
import tarfile
import gzip
import shutil


try:
    import pyzipper
    HAS_PYZIPPER = True
except ImportError:
    HAS_PYZIPPER = False


try:
    import rarfile
    HAS_RARFILE = True
except ImportError:
    HAS_RARFILE = False


def _safe_extract_path(filename):
    """
    安全处理文件名，防止目录穿越
    处理 '..' 等危险路径成分，将连续两个点（..）替换为下划线
    """
    if not filename:
        return filename
    
    # 统一路径分隔符为 /
    filename = filename.replace('\\', '/')
    
    # 分割路径组成部分
    parts = []
    for part in filename.split('/'):
        # 跳过空部分和当前目录标记
        if not part or part == '.':
            continue
        # 处理上级目录（两个连续点）
        if part == '..':
            if parts:
                parts.pop()
            continue
        # 将以点开头的部分（如隐藏文件）的点替换为下划线
        if part.startswith('.'):
            part = '_' + part[1:] if len(part) > 1 else '_'
        # 将部分中的连续两个点（..）替换为两个下划线
        if '..' in part:
            part = part.replace('..', '__')
        parts.append(part)
    
    # 重新组合路径
    safe_path = '/'.join(parts)
    
    # 如果是Windows风格路径（如C:），恢复冒号
    if len(safe_path) >= 2 and safe_path[1] == ':':
        safe_path = safe_path[0] + ':' + safe_path[2:]
    
    return safe_path


def _safe_extract_zip(zip_ref, extract_dir):
    """安全提取ZIP文件，防止目录穿越"""
    for file_info in zip_ref.filelist:
        # 获取安全文件名
        safe_name = _safe_extract_path(file_info.filename)
        if not safe_name:
            continue
            
        target_path = os.path.join(extract_dir, safe_name)
        
        # 如果是目录，创建目录
        if file_info.is_dir():
            os.makedirs(target_path, exist_ok=True)
        else:
            # 确保父目录存在
            os.makedirs(os.path.dirname(target_path), exist_ok=True)
            
            # 提取文件
            with zip_ref.open(file_info) as source:
                with open(target_path, 'wb') as target:
                    shutil.copyfileobj(source, target)
    
    return [f.filename for f in zip_ref.filelist if not f.is_dir()]


def _safe_extract_tar(tar_ref, extract_dir):
    """安全提取TAR文件，防止目录穿越"""
    extracted_files = []
    for member in tar_ref.getmembers():
        # 获取安全文件名
        safe_name = _safe_extract_path(member.name)
        if not safe_name:
            continue
            
        # 更新成员名称
        member.name = safe_name
        target_path = os.path.join(extract_dir, safe_name)
        
        # 提取成员
        tar_ref.extract(member, extract_dir)
        
        if not member.isdir():
            extracted_files.append(member.name)
    
    return extracted_files


def _safe_extract_rar(rar_ref, extract_dir):
    """安全提取RAR文件，防止目录穿越"""
    extracted_files = []
    
    # 首先创建所有需要的目录
    for member in rar_ref.infolist():
        safe_name = _safe_extract_path(member.filename)
        if not safe_name:
            continue
            
        target_path = os.path.join(extract_dir, safe_name)
        
        # 如果是目录，创建目录
        if member.isdir():
            os.makedirs(target_path, exist_ok=True)
    
    # 然后提取文件
    for member in rar_ref.infolist():
        # 获取安全文件名
        safe_name = _safe_extract_path(member.filename)
        if not safe_name:
            continue
            
        # 跳过目录，因为已经在上面创建了
        if member.isdir():
            continue
            
        target_path = os.path.join(extract_dir, safe_name)
        
        # 确保父目录存在（再次检查）
        os.makedirs(os.path.dirname(target_path), exist_ok=True)
        
        try:
            # 读取文件内容
            file_data = rar_ref.read(member)
            # 写入文件
            with open(target_path, 'wb') as f:
                f.write(file_data)
            
            extracted_files.append(safe_name)
        except Exception as e:
            # 如果读取失败（例如加密文件），回退到原始提取方法
            try:
                rar_ref.extract(member, extract_dir)
                # 重命名提取的文件（如果原始文件名与安全名称不同）
                original_extracted = os.path.join(extract_dir, member.filename)
                if os.path.exists(original_extracted) and member.filename != safe_name:
                    # 如果目标已存在，先删除
                    if os.path.exists(target_path):
                        if os.path.isdir(target_path):
                            shutil.rmtree(target_path)

                    os.rename(original_extracted, target_path)
                
                extracted_files.append(safe_name)
            except Exception as e2:
                print(f"    -> 提取RAR文件失败 {safe_name}: {e2}")
    
    return extracted_files





def _search_and_extract_dat_files(self, directory_path, extensions=None, extract_dir="extracted_files"):
    """
    递归搜索目录中的所有指定后缀文件并尝试多种解压方法
    
    Args:
        directory_path: 要搜索的目录路径
        extensions: 文件后缀数组，默认为 ['.dat', '.dat_old']
        extract_dir: 解压文件的目录命名
    """
    
    # 只在第一次调用时构建完整路径，避免递归时重复拼接
    if not extract_dir.startswith(self.output_dir):
        extract_dir = f"{self.output_dir}\\{extract_dir}"
        
    # 设置默认后缀
    if extensions is None:
        extensions = self.set_extract_files()
    
    
    # 检查路径是否存在
    if not os.path.exists(directory_path):
        print(f"[!] 路径不存在: {directory_path}")
        return False
    
    # 如果是目录，递归扫描目录内容
    if os.path.isdir(directory_path):
        basename = os.path.basename(directory_path)
        
        if basename in ['search_report', 'tree_reports', 'extracted_files']:
            return False
        
        print(f"[*] 扫描目录: {directory_path}")
        for entry in os.listdir(directory_path):
            full_path = os.path.join(directory_path, entry)
            
            # 检查路径是否有效
            if not os.path.exists(full_path):
                continue
            
            
            # 如果是目录，递归调用
            if os.path.isdir(full_path):
                self.search_and_extract_dat_files(full_path, extensions, extract_dir)
            # 如果是文件，检查后缀并尝试多种解压方法
            elif os.path.isfile(full_path):
                # 检查文件后缀
                file_ext = os.path.splitext(full_path)[1].lower()
                if file_ext in extensions:

                    # 创建解压目录
                    if not os.path.exists(extract_dir):
                        os.makedirs(extract_dir)
                        print(f"[*] 创建解压目录: {extract_dir}")
                    
                    print(f"[+] 找到目标文件: {full_path}")

                    
                    is_dat_file = file_ext in ['.dat', '.dat_old']  # 检测是否为.dat或.dat_old文件
                    
                    # 尝试多种解压方法
                    extracted = False

                    # 方法1: 尝试作为zip文件解压（支持传统加密和AES加密）
                    if not extracted and not is_dat_file:
                        try:
                            # 首先尝试标准zipfile库（传统加密）
                            with zipfile.ZipFile(full_path, 'r') as zip_ref:
                                # 检查zip文件是否有效
                                if not zip_ref.filelist:
                                    print(f"    -> ZIP文件为空或无效")
                                    raise zipfile.BadZipFile("Empty ZIP file")
                                
                                # 检查是否有加密文件（使用flag_bits判断，避免is_encrypted属性错误）
                                encrypted_files = [f for f in zip_ref.filelist if f.flag_bits & 0x1]
                                
                                if encrypted_files:
                                    # 尝试空密码
                                    zip_ref.setpassword(b'')
                                # 使用安全提取函数
                                extracted_files = _safe_extract_zip(zip_ref, extract_dir)
                                if extracted_files:
                                    if encrypted_files:
                                        print(f"    -> 解压加密ZIP文件（空密码），包含文件: {', '.join(extracted_files)}")
                                    else:
                                        print(f"    -> 解压未加密ZIP文件，包含文件: {', '.join(extracted_files)}")
                                else:
                                    if encrypted_files:
                                        print(f"    -> 解压加密ZIP文件（空密码）")
                                    else:
                                        print(f"    -> 解压未加密ZIP文件")
                            extracted = True

                        except (zipfile.BadZipFile, RuntimeError) as e:
                            if 'Bad password' in str(e) or 'password' in str(e).lower():
                                # 密码错误，继续尝试AES加密（如果pyzipper可用）
                                if HAS_PYZIPPER:
                                    try:
                                        with pyzipper.AESZipFile(full_path, 'r') as zip_ref:
                                            # 检查是否有加密文件（使用flag_bits判断，避免is_encrypted属性错误）
                                            encrypted_files = [f for f in zip_ref.filelist if f.flag_bits & 0x1]
                                            
                                            if encrypted_files:
                                                # 尝试空密码
                                                zip_ref.setpassword(b'')
                                            # 使用安全提取函数
                                            extracted_files = _safe_extract_zip(zip_ref, extract_dir)
                                            if extracted_files:
                                                if encrypted_files:
                                                    print(f"    -> 解压AES加密ZIP文件（空密码），包含文件: {', '.join(extracted_files)}")
                                                else:
                                                    print(f"    -> 解压未加密ZIP文件，包含文件: {', '.join(extracted_files)}")
                                            else:
                                                if encrypted_files:
                                                    print(f"    -> 解压AES加密ZIP文件（空密码）")
                                                else:
                                                    print(f"    -> 解压未加密ZIP文件")
                                        extracted = True

                                    except (pyzipper.BadZipFile, RuntimeError) as e2:
                                        if 'Bad password' in str(e2) or 'password' in str(e2).lower():
                                            print(f"    -> ZIP文件需要密码（非空密码）")
                                        else:
                                            print(f"    -> AES ZIP解压失败: {e2}")
                                    except Exception as e2:
                                        print(f"    -> AES ZIP解压失败: {e2}")
                            else:
                                print(f"    -> ZIP解压失败: {e}")
                        except Exception as e:
                            print(f"    -> ZIP解压失败: {e}")
                    
                    # 方法2: 尝试作为tar文件解压
                    if not extracted and not is_dat_file:
                        try:
                            with tarfile.open(full_path, 'r:*') as tar_ref:
                                # 使用安全提取函数
                                extracted_files = _safe_extract_tar(tar_ref, extract_dir)
                                if extracted_files:
                                    print(f"    -> 解压tar文件，包含文件: {', '.join(extracted_files)}")
                                else:
                                    print(f"    -> 解压tar文件")
                            extracted = True

                        except (tarfile.ReadError, tarfile.CompressionError):
                            pass  # 不是tar文件，继续尝试其他方法
                        except Exception as e:
                            print(f"    -> tar解压失败: {e}")
                    
                
                    # 方法3: 尝试作为rar文件解压
                    if not extracted and not is_dat_file:
                        if HAS_RARFILE:
                            try:
                                # 尝试使用空密码打开RAR文件（新版本API）
                                with rarfile.RarFile(full_path, 'r', password=b'') as archive:
                                    # 使用安全提取函数
                                    extracted_files = _safe_extract_rar(archive, extract_dir)
                                    if extracted_files:
                                        print(f"    -> 解压RAR文件，包含文件: {', '.join(extracted_files)}")
                                    else:
                                        print(f"    -> 解压RAR文件")
                                extracted = True
                            except TypeError as e:
                                if 'password' in str(e):
                                    # 旧版本rarfile不支持password参数，回退到setpassword方法
                                    try:
                                        with rarfile.RarFile(full_path, 'r') as archive:
                                            archive.setpassword(b'')
                                            extracted_files = _safe_extract_rar(archive, extract_dir)
                                            if extracted_files:
                                                print(f"    -> 解压RAR文件，包含文件: {', '.join(extracted_files)}")
                                            else:
                                                print(f"    -> 解压RAR文件")
                                        extracted = True
                                    except rarfile.NeedFirstVolume:
                                        print(f"    -> 需要多卷RAR文件的第一个卷")
                                    except rarfile.BadRarFile:
                                        pass  # 不是RAR文件，继续尝试其他方法
                                    except rarfile.PasswordRequired:
                                        print(f"    -> RAR文件需要密码（非空密码）")
                                    except Exception as e2:
                                        print(f"    -> RAR解压失败: {e2}")
                                else:
                                    print(f"    -> RAR解压失败: {e}")
                            except rarfile.NeedFirstVolume:
                                print(f"    -> 需要多卷RAR文件的第一个卷")
                            except rarfile.BadRarFile:
                                pass  # 不是RAR文件，继续尝试其他方法
                            except rarfile.PasswordRequired:
                                print(f"    -> RAR文件需要密码（非空密码）")
                            except Exception as e:
                                print(f"    -> RAR解压失败: {e}")
                    
                    
                    # 方法4: 尝试作为gzip文件解压
                    if not extracted:
                        try:
                            # 处理输出文件名：去掉压缩后缀
                            original_name = os.path.basename(full_path)
                            if original_name.endswith('.dat_old'):
                                output_name = original_name[:-8]  # 去掉.dat_old
                            elif original_name.endswith('.dat'):
                                output_name = original_name[:-4]  # 去掉.dat
                            elif original_name.endswith('.gz'):
                                output_name = original_name[:-3]  # 去掉.gz
                            elif original_name.endswith('.bz2'):
                                output_name = original_name[:-4]  # 去掉.bz2
                            elif original_name.endswith('.xz'):
                                output_name = original_name[:-3]  # 去掉.xz
                            elif original_name.endswith('.zst'):
                                output_name = original_name[:-4]  # 去掉.zst
                            else:
                                output_name = original_name
                            
                            output_path = os.path.join(extract_dir, output_name)
                            
                            with gzip.open(full_path, 'rb') as f_in:
                                with open(output_path, 'wb') as f_out:
                                    shutil.copyfileobj(f_in, f_out)
                            # 列出解压出的文件
                            extracted_files = [os.path.basename(output_path)]
                            if extracted_files:
                                print(f"    -> 成功作为gzip文件解压，包含文件: {', '.join(extracted_files)}")
                            else:
                                print(f"    -> 成功作为gzip文件解压")
                            extracted = True

                        except (OSError, gzip.BadGzipFile):
                            pass  # 不是gzip文件，继续尝试其他方法
                        except Exception as e:
                            print(f"    -> gzip解压失败: {e}")
                    # 如果所有解压方法都失败，检查文件类型并提供信息
                    if not extracted:
                            print(f"    -> 解压失败，文件可能需要密码或已损坏")
                        


    return True
