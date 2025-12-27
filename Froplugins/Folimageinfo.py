#!/usr/bin/env python3
import sys
sys.dont_write_bytecode = True

import os
import re
import subprocess

def _imageinfo(self):
    
    if self.profile:
        return True

    if not self.create_dir:
        self.create_output_dir()
        self.create_dir = True

    imageinfo_path = f"{self.output_dir}/imageinfo.txt"
    windows_info_path = f"{self.output_dir}/windows.info.txt"
    linux_banners_path = f"{self.output_dir}/linux.banners.txt"
    mac_bash_path = f"{self.output_dir}/mac_bash.txt"

    # 1. 首先尝试从缓存文件读取
    cache_files = [
        (imageinfo_path, "Suggested Profile(s)", r"Suggested Profile\(s\) : (.*?)\n", "Volatility 2"),
        (windows_info_path, "NtProductType", None, "Volatility 3 Windows"),
        (linux_banners_path, "Linux version", r"Linux version (\d+\.\d+\.\d+)", "Linux"),
        (mac_bash_path, "bash", None, "Mac")
    ]
    
    for file_path, keyword, regex_pattern, system_type in cache_files:
        try:
            if os.path.exists(file_path):
                # 检查现有文件是否包含批处理终止提示
                if self.check_batch_termination(file_path):
                    print(f"[!] 检测到批处理终止提示，跳过文件读取: {file_path}")
                    continue
                    
                with open(file_path, "r") as f:
                    content = f.read()
                    if keyword in content:
                        if system_type == "Volatility 2":
                            match = re.search(regex_pattern, content)
                            if match:
                                profiles = match.group(1)
                                if "No suggestion" in profiles and "Instantiated with" in profiles:
                                    instantiated_match = re.search(r"Instantiated with (\w+)", profiles)
                                    self.profile = instantiated_match.group(1) if instantiated_match else "Win7SP1x64"
                                else:
                                    self.profile = profiles.split(",")[0].strip()
                                self.systeminfo()
                                print(f"[*] 从imageinfo.txt读取到{system_type} profile: {self.profile}")
                                return True
                        elif system_type == "Linux":
                            self.system_type = "linux"
                            self.profile = "Linux"
                            self.vol2_available = False
                            match = re.search(regex_pattern, content)
                            if match:
                                kernel_version = match.group(1)
                                print(f"[*] 从linux.banners.txt读取到{system_type}系统，内核版本: {kernel_version}")
                            else:
                                print(f"[*] 从linux.banners.txt读取到{system_type}系统")
                            return True
                        elif system_type == "Mac":
                            self.system_type = "mac"
                            self.profile = "Mac"
                            self.vol2_available = False
                            print(f"[*] 从缓存文件读取到{system_type}系统")
                            return True
                        elif system_type == "Volatility 3 Windows":
                            if self._parse_windows_profile(content):
                                self.systeminfo()
                                print(f"[*] 从windows.info.txt文件读取到{system_type} profile: {self.profile}")
                                return True
        except:
            continue

    # 2. 优先尝试Volatility 3的windows.info
    if self.vol3_available:
        print(f"[*] 尝试Volatility 3 windows.info检测Windows系统...")
        try:
            cmd = f"{self.vol3_path} -f {self.mem_file} windows.info"
            result = subprocess.run(cmd, shell=True, capture_output=True, text=True, timeout=30)
            
            # 检查是否有有效输出，即使返回码不为0
            if "NtProductType" in result.stdout or "Kernel Base" in result.stdout:
                if self._parse_windows_profile(result.stdout):
                    with open(windows_info_path, "w") as f:
                        f.write(result.stdout)
                    self.systeminfo()
                    print(f"[*] Volatility 3检测成功: {self.profile}")
                    return True
            elif "Unsatisfied requirement" in result.stderr and "symbol_table_name" in result.stderr:
                print(f"[!] 不是Windows系统，继续检测其他系统类型...")
            else:
                print(f"[!] Volatility 3执行失败: {result.stderr}")
        except subprocess.TimeoutExpired:
            print("[!] Volatility 3执行超时")
        except Exception as e:
            print(f"[!] Volatility 3检测失败: {str(e)}")

    # 3. 尝试Volatility 3的banners.Banners
    if self.vol3_available:
        print(f"[*] 尝试Volatility 3 banners.Banners检测Linux系统...")
        try:
            cmd = f"{self.vol3_path} -f {self.mem_file} banners.Banners"
            result = subprocess.run(cmd, shell=True, capture_output=True, text=True, timeout=30)
            
            # 检查是否有有效输出，即使返回码不为0
            if ("Linux version" in result.stdout and "Offset" in result.stdout and 
                len(result.stdout.strip().split('\n')) > 2):
                self.system_type = "linux"
                self.profile = "Linux"
                self.vol2_available = False
                linux_match = re.search(r"Linux version (\d+\.\d+\.\d+)", result.stdout)
                if linux_match:
                    kernel_version = linux_match.group(1)
                    print(f"[*] 检测到Linux系统，内核版本: {kernel_version}")
                else:
                    print(f"[*] 检测到Linux系统")
                with open(linux_banners_path, "w") as f:
                    f.write(result.stdout)
                return True
            elif "Unsatisfied requirement" in result.stderr and "symbol_table_name" in result.stderr:
                print(f"[!] 不是Linux系统，继续检测其他系统类型...")
            else:
                print(f"[!] banners.Banners执行失败: {result.stderr}")
        except subprocess.TimeoutExpired:
            print("[!] banners.Banners执行超时")
        except Exception as e:
            print(f"[!] banners.Banners检测失败: {str(e)}")

    # 4. 尝试Volatility 3的mac.bash.Bash
    if self.vol3_available:
        print(f"[*] 尝试Volatility 3 mac.bash.Bash检测Mac系统...")
        try:
            cmd = f"{self.vol3_path} -f {self.mem_file} mac.bash.Bash"
            result = subprocess.run(cmd, shell=True, capture_output=True, text=True, timeout=30)
            
            # 检查是否有有效输出，即使返回码不为0
            if "CommandTime" in result.stdout.lower():
                self.system_type = "mac"
                self.profile = "Mac"
                self.vol2_available = False
                print(f"[*] 检测到Mac系统")
                with open(mac_bash_path, "w") as f:
                    f.write(result.stdout)
                return True
            elif "Unsatisfied requirement" in result.stderr and "symbol_table_name" in result.stderr:
                print(f"[!] 不是Mac系统，继续检测其他系统类型...")
            else:
                print(f"[!] mac.bash.Bash执行失败: {result.stderr}")
        except subprocess.TimeoutExpired:
            print("[!] mac.bash.Bash执行超时")
        except Exception as e:
            print(f"[!] mac.bash.Bash检测失败: {str(e)}")

    # 5. 最后尝试Volatility 2的imageinfo
    print(f"[*] 最后尝试Volatility 2 imageinfo...")
    try:
        cmd = f"{self.vol2_path} -f {self.mem_file} imageinfo"
        result = subprocess.run(cmd, shell=True, capture_output=True, text=True, timeout=60)
        
        if result.returncode == 0 and "Suggested Profile(s)" in result.stdout:
            match = re.search(r"Suggested Profile\(s\) : (.*?)\n", result.stdout)
            if match:
                profiles = match.group(1)
                if "No suggestion" in profiles and "Instantiated with" in profiles:
                    instantiated_match = re.search(r"Instantiated with (\w+)", profiles)
                    self.profile = instantiated_match.group(1) if instantiated_match else "Win7SP1x64"
                else:
                    self.profile = profiles.split(",")[0].strip()
                with open(imageinfo_path, "w") as f:
                    f.write(result.stdout)
                self.systeminfo()
                print(f"[*] Volatility 2检测成功: {self.profile}")
                return True
        else:
            print(f"[!] Volatility 2执行失败或未找到有效信息")
    except subprocess.TimeoutExpired:
        print("[!] Volatility 2执行超时")
    except Exception as e:
        print(f"[!] Volatility 2检测失败: {str(e)}")

    # 6. 所有检测都失败
    print("[!] 无法确定内存镜像类型，可能符号表有问题")
    print("[!] 请手动指定--profile参数或检查内存文件完整性")
    print("[!] 将使用通用插件进行分析")
    self.system_type = "unknown"
    self.profile = "Generic"
    return True
