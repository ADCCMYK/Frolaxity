#!/usr/bin/env python3
import sys
sys.dont_write_bytecode = True

import re
import subprocess


def _check_environment(self):
    
        # 检查环境是否已经检查过，避免重复执行
        if self.environment_checked:
            return True
            
        # 重置可用性状态
        self.vol2_available = False
        self.vol3_available = False
        self.vol2_needs_python = False
        self.vol3_needs_python = False
        self.python2_available = False
        self.python3_available = False

        # 先检查Python解释器是否可用
        try:
            result = subprocess.run(f"{self.python2_path} --version", shell=True,
                                capture_output=True, text=True, timeout=3)
            if result.returncode == 0:
                self.python2_available = True
        except:
            self.python2_available = False

        try:
            result = subprocess.run(f"{self.python3_path} --version", shell=True,
                                capture_output=True, text=True, timeout=3)
            if result.returncode == 0:
                self.python3_available = True
        except:
            self.python3_available = False

        # 检查vol2 - 首先检查是否为.py文件，如果是则直接使用Python运行
        vol2_is_py = self.vol2_path.endswith('.py')
        
        try:
            if vol2_is_py and self.python2_available:
                # 对于.py文件，直接使用Python运行
                result = subprocess.run(f"{self.python2_path} {self.vol2_path} --help", shell=True,
                                    capture_output=True, text=True, timeout=5)
                if result.returncode == 0 or "Volatility Foundation" in result.stderr:
                    self.vol2_available = True
                    self.vol2_needs_python = True
                    self.vol2_path = f"{self.python2_path} {self.vol2_path}"
            else:
                # 尝试直接运行
                result = subprocess.run(f"{self.vol2_path} --help", shell=True, 
                                    capture_output=True, text=True, timeout=5)
                if result.returncode == 0 or "Volatility Foundation" in result.stderr:
                    self.vol2_available = True
                elif self.python2_available:
                    # 尝试使用python2运行
                    result_py = subprocess.run(f"{self.python2_path} {self.vol2_path} --help", shell=True,
                                            capture_output=True, text=True, timeout=5)
                    if result_py.returncode == 0 or "Volatility Foundation" in result_py.stderr:
                        self.vol2_available = True
                        self.vol2_needs_python = True
                        self.vol2_path = f"{self.python2_path} {self.vol2_path}"

        except Exception as e:
            print(f"[!] Volatility 2 检查失败: {str(e)}")

        # 检查vol3 - 首先检查是否为.py文件，如果是则直接使用Python运行
        vol3_is_py = self.vol3_path.endswith('.py')
        
        try:
            if vol3_is_py and self.python3_available:
                # 对于.py文件，直接使用Python运行
                result = subprocess.run(f"{self.python3_path} {self.vol3_path} --help", shell=True,
                                    capture_output=True, text=True, timeout=5)
                if result.returncode == 0 or "Volatility 3 Framework" in result.stdout:
                    self.vol3_available = True
                    self.vol3_needs_python = True
                    self.vol3_path = f"{self.python3_path} {self.vol3_path}"
            else:
                # 尝试直接运行
                result = subprocess.run(f"{self.vol3_path} --help", shell=True, 
                                    capture_output=True, text=True, timeout=5)
                if result.returncode == 0 or "Volatility 3 Framework" in result.stdout:
                    self.vol3_available = True
                elif self.python3_available:
                    # 尝试使用python3运行
                    result_py = subprocess.run(f"{self.python3_path} {self.vol3_path} --help", shell=True,
                                            capture_output=True, text=True, timeout=5)
                    if result_py.returncode == 0 or "Volatility 3 Framework" in result_py.stdout:
                        self.vol3_available = True
                        self.vol3_needs_python = True
                        self.vol3_path = f"{self.python3_path} {self.vol3_path}"

        except Exception as e:
            print(f"[!] Volatility 3 检查失败: {str(e)}")

        # 总结检查结果
        if self.vol2_available and self.vol3_available:
            mode_info = ""
            if self.vol2_needs_python:
                mode_info += f" {self.python2_path}"
            if self.vol3_needs_python:
                mode_info += f" {self.python3_path}"
            print(f"[*] 环境检查通过: {self.vol2_path}、{self.vol3_path}{mode_info}")
            self.environment_checked = True
            return True
        
        elif self.vol2_available:
            mode_info = f" {self.python2_path}执行" if self.vol2_needs_python else ""
            print(f"[!] 环境检查警告: 只有{self.vol2_path}{mode_info}可用")
            self.environment_checked = True
            return True
        
        elif self.vol3_available:
            mode_info = f" {self.python3_path}" if self.vol3_needs_python else ""
            print(f"[!] 环境检查警告: 只有{self.vol3_path}{mode_info}可用")
            self.environment_checked = True
            return True
        
        else:
            print(f"[!] 环境检查失败, 请确保Volatility工具和python环境和volconfig.py已正确配置")
            print(f"[*] Volatility 2 路径: {self.vol2_path} {'可用' if self.vol2_available else '不可用'}")
            print(f"[*] Volatility 3 路径: {self.vol3_path} {'可用' if self.vol3_available else '不可用'}")
            print(f"[*] Python 2 路径: {self.python2_path} {'可用' if self.python2_available else '不可用'}")
            print(f"[*] Python 3 路径: {self.python3_path} {'可用' if self.python3_available else '不可用'}")            
            return False
