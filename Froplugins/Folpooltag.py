#!/usr/bin/env python3
import sys
sys.dont_write_bytecode = True

import os
import re
import subprocess


def _get_pooltag(self, pid):
        print(f"[*] 正在获取PID {pid}的PoolTag...")
        if not self.profile:
            if not self.imageinfo():
                print("[!] 无法确定内存镜像profile")
                return
        
        # 1. 从psxview.txt读取进程物理地址
        print("\n[*]  从psxview.txt读取进程物理地址")
        psxview_file = f"{self.output_dir}/psxview.txt"
        if not os.path.exists(psxview_file):
            print(f"[!] 未找到psxview.txt文件: {psxview_file}")
            return
            
        try:
            with open(psxview_file, "r", encoding='utf-8', errors='ignore') as f:
                for line in f:
                    if not line.strip() or "Offset(P)" in line:
                        continue
                        
                    parts = line.split()
                    if len(parts) >= 2 and parts[2].isdigit() and int(parts[2]) == pid:
                        phys_addr = parts[0]
                        print(f"[+] 找到进程物理地址: {phys_addr}")
                        break
                else:
                    print(f"[!] 未找到PID {pid}的进程信息")
                    return
                
            # 2. 进入volshell查询_OBJECT_HEADER
            print("\n[*]  查询_OBJECT_HEADER结构")
            volshell_cmds = [
                f"dt(\"_OBJECT_HEADER\", {phys_addr}-0x30, space=addrspace().base)"
            ]
            
            cmd = f"{self.vol2_path} -f {self.mem_file} --profile={self.profile} volshell"
            print(f"[*] 执行命令: {cmd}")
            print(f"[*] volshell的子命令: {'\n'.join(volshell_cmds)}")
            
            process = subprocess.Popen(cmd, shell=True, stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
            stdout, stderr = process.communicate('\n'.join(volshell_cmds))
            print(f"[*] _OBJECT_HEADER查询结果: {stdout}")
            
            # 3. 解析InfoMask并计算上浮字节
            print("\n[*]  解析InfoMask并计算上浮字节")
            # 尝试两种格式匹配InfoMask值
            infomask_match = re.search(r"InfoMask\s+:\s+0x([0-9a-fA-F]+)", stdout) or \
                           re.search(r"InfoMask\s+([0-9]+)", stdout)
            if not infomask_match:
                print("[!] 无法解析InfoMask值")
                return
                
            # 获取匹配到的值
            infomask_str = infomask_match.group(1)
            if infomask_str.isdigit():
                infomask = int(infomask_str)
            else:
                infomask = int(infomask_str, 16)
                
            print(f"[+] InfoMask值: 0x{infomask:x}")
            
            # 根据InfoMask计算上浮字节
            if infomask == 0x8:  # Quota
                offset = 0x60
            elif infomask == 0x4:  # Handle
                offset = 0x50
            elif infomask == 0x2:  # Name
                offset = 0x40
            else:  # 默认情况
                offset = 0x30
                
            print(f"[+] 计算得到上浮字节: 0x{offset:x}")
            
            # 4. 查询_POOL_HEADER并转换PoolTag
            print("\n[*]  查询_POOL_HEADER结构")
            volshell_cmds = [
                f"dt(\"_POOL_HEADER\", {phys_addr}-0x{offset:x}, space=addrspace().base)"
            ]
            
            process = subprocess.Popen(cmd, shell=True, stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
            stdout, stderr = process.communicate('\n'.join(volshell_cmds))
            print(f"[*] volshell的子命令: {'\n'.join(volshell_cmds)}")
            print(f"[*] _POOL_HEADER查询结果: {stdout}")
            
            # 解析PoolTag
            pooltag_match = re.search(r"PoolTag\s+:\s+0x([0-9a-fA-F]+)", stdout) or \
                          re.search(r"PoolTag\s+([0-9]+)", stdout)
            if pooltag_match:
                pooltag_str = pooltag_match.group(1)
                if pooltag_str.isdigit():
                    # 十进制转十六进制
                    pooltag_int = int(pooltag_str)
                    pooltag_hex = f"{pooltag_int:08x}"
                else:
                    pooltag_hex = pooltag_str
                
                # 转换为小端序ASCII
                try:
                    pooltag_bytes = bytes.fromhex(pooltag_hex)
                    pooltag_ascii = pooltag_bytes[::-1].decode('ascii', errors='replace')
                    print(f"[+] 找到PoolTag: {pooltag_ascii} 原始值: 0x{pooltag_hex}, 小端序: \\x{pooltag_bytes[0]:02x}\\x{pooltag_bytes[1]:02x}\\x{pooltag_bytes[2]:02x}\\x{pooltag_bytes[3]:02x}")
                except:
                    print(f"[+] 找到PoolTag值: 0x{pooltag_hex} 小端序: \\x{pooltag_bytes[0]:02x}\\x{pooltag_bytes[1]:02x}\\x{pooltag_bytes[2]:02x}\\x{pooltag_bytes[3]:02x}")
            else:
                print("[!] 未能找到PoolTag")
                
        except Exception as e:
            print(f"[!] 获取PoolTag失败: {str(e)}")
