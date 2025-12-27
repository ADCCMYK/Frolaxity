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



def _set_extract_files(self):
       # 默认解压配置
       return ['.dat', '.dat_old']



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
