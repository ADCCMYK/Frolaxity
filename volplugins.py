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
                    ("windows.sessions.Sessions", ""),
                    ("windows.skeleton_key_check.Skeleton_Key_Check", ""),
                    ("windows.unhooked_system_calls.unhooked_system_calls", ""),
                    ("windows.svcdiff.SvcDiff", ""),
                    ("windows.svcscan.SvcScan", ""),
                    ("windows.registry.scheduled_tasks.ScheduledTasks", ""),
                    ("windows.registry.hivelist", ""),
                    ("windows.registry.printkey", ""),
                    ("windows.userassist", ""),
                    ("windows.shimcache", ""),
                    ("windows.systeminfo", ""),
                    ("windows.malfind", ""),
                    ("windows.netscan", ""),
                    ("windows.timeliner", ""),
                    ("windows.bitlocker.BitlockerFVEKScan", "--tags FVEc Cngb None --dislocker ."),
                    ("windows.hashdump", ""),
                    ("windows.lsadump", ""),
                ]
                
            elif self.system_type == "linux":
                # Volatility 3 Linux插件列表
                all_plugins = [
                    ("banners.Banners", ""),
                    ("linux.bash.Bash", ""),
                    ("linux.boottime", ""),
                    ("linux.pslist", ""),
                    ("linux.pstree", ""),
                    ("linux.psscan", ""),
                    ("linux.psaux", ""),
                    ("linux.lsmod", ""),
                    ("linux.lsof", ""),
                    ("linux.envars", ""),
                    ("linux.netstat", ""),
                    ("linux.sockstat", ""),
                    ("linux.ip.Addr", ""),
                    ("linux.malfind", ""),
                    ("linux.mountinfo", ""),
                    ("linux.lsof.Lsof", ""),
                    ("linux.capabilities", ""),               
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
                    ("mac.pstree", ""),
                    ("mac.psaux", ""),
                    ("mac.lsmod", ""),
                    ("mac.lsof", ""),
                    ("mac.envars", ""),
                    ("mac.netstat", ""),
                    ("mac.mount", ""),
                    ("mac.malfind", ""),
                    ("mac.ifconfig", ""),
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
                ("pslist", ""),
                ("psscan", ""),
                ("psxview", ""),
                ("pstree", ""),
                ("envars", ""),
                ("timeliner", ""),
                ("systeminfo", ""),
                ("firefoxhistory", ""),
                ("chromehistory", ""),
                ("screenshot", f"--dump-dir={self.output_dir}/screenshots/"),
                ("notepad", ""),
                ("cmdscan", ""),
                ("cmdline", ""),
                ("consoles", ""),    
                ("cachedump", ""),    
                ("bitlocker", "--dislocker ."),
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
                ("hivelist", ""),
                ("shellbags", ""),
                ("svcscan", ""),
                ("userassist", ""),
                ("usbstor", ""),
                ("voldiff", ""),
                ("malfind", ""),
                ("hashdump", ""),
                ("lsadump", ""),
                ("editbox", ""),
                ("truecryptpassphrase", ""),    
                ("printkey", "-K 'SAM\\Domains\\Account\\Users\\Names'"),
            ]
            
        # 根据线程数量动态分组
        plugin_groups = self.dynamic_group_plugins(all_plugins, self.Thread)
        
        if vol_version and vol_version.strip():
            print(f"\n[*] {'Volatility 3' if vol_version == 'vol3' else 'Volatility 2'}标准取证插件...")
            
            # 将所有插件组合并为一个大的插件组，一次性提交
            all_plugins_flat = []
            for plugin_group in plugin_groups:
                all_plugins_flat.extend(plugin_group)
            
            # 一次性执行所有插件，线程会自动接取任务
            group_bool = True
            self.execute_plugin_group(all_plugins_flat, group_bool, self.Thread, vol_version)
        
        return True
