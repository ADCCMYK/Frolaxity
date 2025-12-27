#!/usr/bin/env python3
import sys
sys.dont_write_bytecode = True



def _run_standard_plugins(self, vol_version):
        if vol_version == "vol3":
            # 根据系统类型选择Volatility 3插件
            if self.system_type == "windows":
                # Volatility 3 Windows插件列表
                all_plugins = [
                    ("windows.info", ""),
                    ("windows.banners", ""),
                    ("windows.pslist", ""),
                    ("windows.psscan", ""),
                    ("windows.psxview", ""),
                    ("windows.envars", ""),
                    ("windows.cmdline", ""),
                    ("windows.dlllist", ""),
                    ("windows.filescan", ""),
                    ("windows.netstat", ""),
                    ("windows.registry.hivelist", ""),
                    ("windows.registry.printkey", ""),
                    ("windows.userassist", ""),
                    ("windows.shimcache", ""),
                    ("windows.systeminfo", ""),
                    ("windows.mftparser", ""),
                    ("windows.malfind", ""),
                    ("windows.timeliner", ""),
                    ("windows.iehistory", ""),
                    ("windows.netscan", ""),
                    ("windows.hashdump", ""),
                    ("windows.lsadump", ""),
                ]
                
            elif self.system_type == "linux":
                # Volatility 3 Linux插件列表
                all_plugins = [
                    ("banners.Banners", ""),
                    ("linux.bash.Bash", ""),
                    ("linux.pslist", ""),
                    ("linux.psscan", ""),
                    ("linux.lsmod", ""),
                    ("linux.boottime", ""),
                    ("linux.envars", ""),
                    ("linux.netstat", ""),
                    ("linux.ip.Addr", ""),
                    ("linux.malfind", ""),
                    ("linux.lsof", ""),
                    ("linux.pidhashtable", ""),
                    ("linux.pagecache.Files", ""),
                    ("linux.hidden_modules", ""),
                    ("linux.check_modules", ""),
                    ("linux.kmsg", ""),
                ]
                
            elif self.system_type == "mac":
                # Volatility 3 Mac插件列表
                all_plugins = [
                    ("mac.bash.Bash", ""),
                    ("mac.pslist", ""),
                    ("mac.psscan", ""),
                    ("mac.lsmod", ""),
                    ("mac.envars", ""),
                    ("mac.psaux", ""),
                    ("mac.netstat", ""),
                    ("mac.ifconfig", ""),
                    ("mac.malfind", ""),
                    ("mac.lsof", ""),
                    ("mac.check_syscall", ""),
                    ("mac.dmesg", ""),
                ]
            else:
                # Volatility 3 其他系统插件列表
                all_plugins = [
                    ("windows.info", ""),
                    ("banners.Banners", ""),
                    ("timeliner.Timeliner", ""),
                    ("regexscan.RegExScan", ""),
                ]
            
        else:
            # Volatility 2 插件列表
            all_plugins = [
                ("imageinfo", ""),
                ("verinfo", ""),
                ("pslist", ""),
                ("psscan", ""),
                ("psxview", ""),
                ("pstree", ""),
                ("envars", ""),
                ("timeliner", ""),
                ("systeminfo", ""),
                ("notepad", ""),
                ("cmdscan", ""),
                ("clipboard", "-v"),
                ("iehistory", ""),
                ("filescan", ""),
                ("mimikatz", ""),
                ("netscan", ""),
                ("dlllist", ""),
                ("ndispktscan", ""),
                ("mftparser", ""),
                ("connscan", ""),
                ("connections", ""),
                ("ldrmodules", ""),
                ("hivelist", ""),
                ("shimcache", ""),
                ("svcscan", ""),
                ("userassist", ""),
                ("usbstor", ""),
                ("voldiff", ""),
                ("malfind", ""),
                ("hashdump", ""),
                ("lsadump", ""),
                ("editbox", ""),
                ("bitlocker", ""),
                ("printkey", "-K 'SAM\\Domains\\Account\\Users\\Names'"),
                ("screenshot", f"--dump-dir={self.output_dir}/screenshots/"),
            ]
            
        # 根据线程数量动态分组
        plugin_groups = self.dynamic_group_plugins(all_plugins, self.Thread)
        
        if vol_version and vol_version.strip():
            print(f"\n[*] 正在执行{'Volatility 3' if vol_version == 'vol3' else 'Volatility 2'}标准取证插件...")
            
            # 将所有插件组合并为一个大的插件组，一次性提交
            all_plugins_flat = []
            for plugin_group in plugin_groups:
                all_plugins_flat.extend(plugin_group)
            
            # 一次性执行所有插件，线程会自动接取任务
            group_bool = True
            self.execute_plugin_group(all_plugins_flat, group_bool, self.Thread, vol_version)
        
        return True
