#!/usr/bin/env python3
import sys
sys.dont_write_bytecode = True

import os
import subprocess


def _run_command(self, plugin, params="", output_file=None, pid=None, offset=None, dump_dir=None, vol_version=None):

        if not self.profile:
            if not self.imageinfo():
                raise ValueError("无法自动检测内存镜像profile")


        # 选择Volatility版本
        if vol_version == "vol3":

            vol_path = self.vol3_path
            val_show = self.vol3_show

            profile_param = ""  # Volatility 3不需要profile参数
            
            # 转换插件名称（仅对memdump和dumpfiles进行映射）
            plugin = self.get_vol3_plugin(plugin)
            
            # 构建基础命令（Volatility 3格式）
            cmd = f" -f {self.mem_file} {plugin}"
            
            # 添加PID参数（Volatility 3使用--pid）
            if pid:
                cmd += f" --pid {pid}"
            
            # 添加偏移地址参数（Volatility 3使用--physaddr）
            if offset:
                if 'linux.pagecache.InodePages' in plugin:
                    cmd += f" --inode {offset}"
                elif 'linux.pagecache.RecoverFs' in plugin:
                    cmd += f'--compression-format gz'
                else:
                    cmd += f" --physaddr {offset}"
                
            # 添加dump目录参数（Volatility 3使用--dump）
            if dump_dir:
                if 'windows.dumpfiles' in plugin:
                    cmd += f" "
                else:
                    cmd += f" --dump"
                
        else:
            vol_path = self.vol2_path
            val_show = self.vol2_show
            
            profile_param = f"--profile={self.profile}"
            
            # 构建基础命令（Volatility 2格式）
            cmd = f" -f {self.mem_file} {profile_param} {plugin}"
            
            # 添加PID参数（Volatility 2使用-p）
            if pid:
                cmd += f" -p {pid}"
            
            # 添加偏移地址参数（Volatility 2使用-Q）
            if offset:
                cmd += f" -Q {offset}"
                
            # 添加dump目录参数（Volatility 2使用-D）
            if dump_dir:
                cmd += f" -D {dump_dir}"
            
            # 添加其他参数
            cmd += f" {params}"

        output_file = output_file or f"{self.output_dir}/{plugin}.txt"

        # 美化命令显示
        cmd_show = f"{val_show}{cmd}"
        cmd_exec = f"{vol_path}{cmd}"
            
        print(f"[*] 执行命令: {cmd_show}")
        
        # 检查是否为dumpfiles或memdump插件，如果是则使用追加模式
        is_dump_plugin = plugin in ["dumpfiles", "memdump", "windows.dumpfiles", "windows.memmap", 
                                  "linux.pagecache.InodePages", "linux.elfs.Elfs"]
        
        if plugin == "banners.Banners":
            output_file = f"{self.output_dir}/linux.Banners.txt"
            
        try:
            # 根据插件类型选择写入模式
            file_mode = "a" if is_dump_plugin else "w"
            
            # 如果是追加模式且文件不存在，先创建文件
            if file_mode == "a" and not os.path.exists(output_file):
                with open(output_file, "w") as f:
                    pass  # 创建空文件
            
            with open(output_file, file_mode) as f:
                # 使用Popen来实时处理输出
                process = subprocess.Popen(cmd_exec, shell=True, stdout=f, stderr=subprocess.PIPE, text=True, bufsize=1)
                
                # 先读取一行stderr来判断是否有符号下载
                first_stderr_line = process.stderr.readline()
                
                # 直接调用符号下载处理方法，由它来判断是否为符号下载
                symbol_download_result = self.handle_symbol_download(process, cmd_exec, output_file, file_mode, plugin, first_stderr_line)
                
                if symbol_download_result is not False:
                    # 如果是符号下载或者处理完成，直接返回结果
                    return symbol_download_result
                else:
                    # 对于非符号下载的情况，需要同时处理stdout和stderr
                    # 由于stdout已经重定向到文件，我们只需要处理stderr
                    while True:
                        stderr_line = process.stderr.readline()
                        if not stderr_line and process.poll() is not None:
                            break
                        # 可以在这里处理stderr输出，如果需要的话
                
            print(f"[+] {plugin} 执行完成 -> {output_file}")
            return True
        except Exception as e:
            print(f"[-] {plugin} 执行失败: {str(e)}")
            return False
