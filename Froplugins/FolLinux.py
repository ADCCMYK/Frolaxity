#!/usr/bin/env python3
# -*- coding: utf-8 -*-
import sys
sys.dont_write_bytecode = True

import subprocess
from pathlib import Path


def _linux_pagecache(self):

    # 如果用户没有手动指定profile，尝试自动检测
    if not self.profile:
        if not self.imageinfo():
            return False

    # 检查Volatility 3可用性
    if not self.vol3_available:
        print(f"[!] Linux页面缓存恢复需要Volatility 3支持")
        return False
    
    vol_version = self.vol3_available

    # 检查系统类型是否为Linux
    if self.system_type != "linux":
        print(f"[!] 当前系统类型为 {self.system_type}，Linux页面缓存恢复仅支持Linux系统")
        return False
    
    try:
        # 直接调用run_command
        success = self.run_command(plugin="linux.pagecache.RecoverFs", vol_version="vol3")
        
        if success:
            print(f"[+] Linux页面缓存恢复成功")                                        
            return True
        else:
            print(f"[-] Linux页面缓存恢复失败")
            return False
            
    except subprocess.TimeoutExpired:
        print(f"[-] Linux页面缓存恢复超时")
        return False
    except Exception as e:
        print(f"[-] Linux页面缓存恢复异常: {str(e)}")
        return False
