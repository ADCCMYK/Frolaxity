#!/usr/bin/env python3
import sys
sys.dont_write_bytecode = True

import os
import time
import argparse
from pathlib import Path
from Froclass.Automator import FolatiutAutomator


def main():

    print(f"""

   ║████████╗║███████╗  ║███████╗  ║███╗      ║███████╗ ║████╗   ████╗║███╗║██████████╗║████╗    ████║
   ║██╔═════╝║██╔═══██╗║███╔═══███║║███║     ║███╔══███╗  ╚███  ███╔╝ ║███║╚═══╗███╔══╝  ╚███╗  ███╔╝
   ║███████╗ ║███████╔╝║███║   ███║║███║     ║█████████║    ╚████╔╝   ║███║    ║███║       ╚█████╔╝ 
   ║██╔════╝ ║██╔══╗██╗║███║   ███║║███║     ║███╔═╗███║  ║███  ███╗  ║███║    ║███║        ║███║  
   ║██║      ║██║  ║██║ ╚███████╔╝ ║████████╗║███║ ║███║║████║  ║████╗║███║    ║███║        ║███║   
   ╚══╝      ╚══╝  ╚══╝  ╚══════╝  ╚════════╝╚═══╝ ╚═══╝╚════╝  ╚════╝╚═══╝    ╚═══╝        ╚═══╝   
""")

    
    parser = argparse.ArgumentParser(
    formatter_class=argparse.RawTextHelpFormatter, 
    description="""

    """,
    usage="%(prog)s [options]",
    allow_abbrev=False,
    add_help=False,
    )

    parser.add_argument("-h", "--help", action="help",default=argparse.SUPPRESS,help="显示帮助信息")
    parser.add_argument("-f", "--file", required=False, help="内存镜像路径")
    parser.add_argument("-k", "--quick-mode", action="store_true", help="快速分析模式")
    parser.add_argument("-e", "--check_environment", action="store_true", help="运行工具环境检查")
    parser.add_argument("-T", "--Thread", type=int, default=10, help="插件执行线程数量")
    parser.add_argument("-D", "--dump-dir", help="指定文件目录")
    parser.add_argument("-pr","--profile", help="指定内存镜像profile")
    parser.add_argument("-Q", "--offset", help="提取指定内存偏移地址")
    parser.add_argument("-P", "--pid", type=int, help="提取指定进程PID")
    parser.add_argument("-C", "--commands-only", action="store_true", help="仅执行插件命令")
    parser.add_argument("-S", "--dump-files", action="store_true", help="仅执行文件扫描和提取")
    parser.add_argument("-U", "--dump-process", action="store_true", help="仅执行进程扫描和提取")
    parser.add_argument("-cp", "--common-processes", action="store_true", help="提取常用进程")
    parser.add_argument("-cd", "--common-address", action="store_true", help="提取常用地址")
    parser.add_argument("-g", "--pattern", action="store_true", help="使用默认正则扫描")
    parser.add_argument("-Y", "--yara-scan", action="store_true", help="使用YARA规则扫描")
    parser.add_argument("-R", "--hidden-process", action="store_true", help="分析隐藏进程")
    parser.add_argument("-L", "--linux-pagecache", action="store_true", help="文件系统压缩包")
    parser.add_argument("-pl", "--pooltag", action="store_true", help="获取进程 PID PoolTag")
    parser.add_argument("-V", "--vol3", action="store_true", help="使用Vol3版本")
    
    args = parser.parse_args()


    # 环境检查模式
    if args.check_environment:
        # 创建一个临时的automator实例用于环境检查
        automator = FolatiutAutomator("dummy_file", None, None)
        automator.check_environment()
        return
    
    

    # YARA 扫描
    if args.yara_scan:
        
        # 对于 YARA 扫描，不需要内存文件，使用特殊模式
        automator = FolatiutAutomator(args.file or "dummy_file", args.pattern, args.profile, args.Thread, args.dump_dir)

        print(f"[*] 开始 YARA 深度扫描...")
        print(f"[*] 默认提取文件： {automator.extract_file}")
        print(f"[*] 扫描文件树：{args.dump_dir or automator.output_dir}")

        #显示信息
        time.sleep(2.0)

        automator.analyze_archive_structure(args.dump_dir or automator.output_dir)
        automator.search_and_extract_dat_files(args.dump_dir or automator.output_dir)
        if automator.yara_deep_scan(args.dump_dir or automator.output_dir):
            print(f"\n[*] YARA扫描完成! 结果保存在: {args.dump_dir or automator.output_dir}/yara_scan")
        return



    # 默认 CTF 方向扫描
    elif args.pattern:
        
        # 对于自定义模式扫描，不需要内存文件，使用特殊模式
        automator = FolatiutAutomator(args.file or "dummy_file", args.pattern, args.profile, args.Thread, args.dump_dir)
        
        print(f"[*] 开始自定义模式扫描...")
        print(f"[*] 默认提取文件： {automator.extract_file}")
        print(f"[*] 扫描文件树：{args.dump_dir or automator.output_dir}")

        #显示信息
        time.sleep(2.0)

        automator.analyze_archive_structure(args.dump_dir or automator.output_dir)
        automator.search_and_extract_dat_files(args.dump_dir or automator.output_dir)
        if automator.scan_for_flags(args.dump_dir or automator.output_dir):
            automator.print_ctf_matches_console()
            automator.print_default_plugins()
            automator.print_ctf_matches_paths()
            print(f"\n[*] 正则 {args.pattern} 扫描完成 目录保存在{args.dump_dir or automator.output_dir}/search_report")
        return



        # 检查文件
    if not args.file:
        print("""\nusage: folatiuty.py [options]\nfolatiuty.py: error: the following arguments are required: -f/--file""")
        return



    # 本地文件分析模式
    automator = FolatiutAutomator(args.file, args.pattern, args.profile, args.Thread, args.dump_dir)
    


    # 开始分析
    print(f"[*] 开始分析内存镜像：{args.file}")



    # 检查环境
    if not automator.check_environment():
        return



    # 检查类型
    if args.profile:
        automator.profile = args.profile
        print(f"[+] 使用手动指定的profile: {automator.profile}")




    # 处理Linux页面缓存文件系统压缩包
    if args.linux_pagecache:
        automator.imageinfo()
        print(f"[*] 开始Linux页面缓存文件系统恢复...")
        if automator.linux_pagecache() and automator.profile:
            print(f"\n[*] Linux页面缓存文件系统恢复完成, 结果保存在当前目录!")



    # 分析提取隐藏进程
    if args.hidden_process:
        automator.imageinfo()
        if automator.vol2_available and automator.profile:
            if automator.extract_hidden_processes(vol_version="vol2"):
                print(f"\n[*] vol2隐藏进程提取完成! 结果保存在: {automator.output_dir}/hidden_processes_vol2")
        if automator.vol3_available and automator.profile:
            if automator.extract_hidden_processes(vol_version="vol3"):
                print(f"\n[*] vol3隐藏进程提取完成! 结果保存在: {automator.output_dir}/hidden_processes_vol3")
        



    # 仅执行命令模式
    if args.commands_only:
        automator.imageinfo()
        print(f"[*] 默认插件执行线程：{args.Thread}")
        if automator.vol2_available and automator.profile:
            if automator.profile and automator.run_standard_plugins(vol_version="vol2"):
                print(f"\n[*] vol2仅执行取证命令模式完成! 结果保存在: {automator.output_dir}")
        if automator.vol3_available and automator.profile:
            if automator.profile and automator.run_standard_plugins(vol_version="vol3"):
                print(f"\n[*] vol3仅执行取证命令模式完成! 结果保存在: {automator.output_dir}")




    # 提取常用地址文件
    if args.common_address:
        automator.imageinfo()
        vol_version = "vol3" if args.vol3 else "vol2"
        if automator.dump_and_scan_files(vol_version=vol_version, plugins="dumpfiles", common_address=True, quick_mode=args.quick_mode):
                default_file_prefixes = automator.get_default_file_prefixes
                prefix = default_file_prefixes[0] if default_file_prefixes else "common_addresses_"
                print(f"\n[*] {vol_version}常用地址文件提取完成! 结果保存在: {automator.output_dir}/{prefix}{vol_version}")
        



    # 提取常用进程文件
    if args.common_processes:
        automator.imageinfo()
        vol_version = "vol3" if args.vol3 else "vol2"
        if automator.dump_and_scan_files(vol_version=vol_version, plugins="memdump", common_address=True, quick_mode=args.quick_mode):
                default_file_prefixes = automator.get_default_file_prefixes
                prefix = default_file_prefixes[1] if len(default_file_prefixes) > 1 else "common_process_"
                print(f"\n[*] {vol_version}常用进程文件提取完成! 结果保存在: {automator.output_dir}/{prefix}{vol_version}")




    # 仅文件提取模式
    if args.dump_files:
        automator.imageinfo()
        vol_version = "vol3" if args.vol3 else "vol2"
        if automator.profile and automator.dump_and_scan_files(plugins="dumpfiles", vol_version=vol_version, quick_mode=args.quick_mode):
                default_file_prefixes = automator.get_default_file_prefixes
                prefix = default_file_prefixes[2] if len(default_file_prefixes) > 2 else "dumps_"
                print(f"\n[*] 文件扫描提取完成! 结果保存在: {automator.output_dir}/{prefix}{vol_version}")




    # 仅进程提取模式
    if args.dump_process:
        automator.imageinfo()
        vol_version = "vol3" if args.vol3 else "vol2"
        if automator.profile and automator.dump_and_scan_files(plugins="memdump", vol_version=vol_version, quick_mode=args.quick_mode):
                default_file_prefixes = automator.get_default_file_prefixes
                prefix = default_file_prefixes[2] if len(default_file_prefixes) > 2 else "dumps_"
                print(f"\n[*] 进程扫描提取完成! 结果保存在: {automator.output_dir}/{prefix}{vol_version}")




    # 输出CTF匹配内容到控制台
    if args.linux_pagecache or args.hidden_process or args.commands_only or args.common_address or args.common_processes or args.dump_files or args.dump_process:
        if args.linux_pagecache or args.hidden_process or args.commands_only:
            automator.scan_for_flags(args.dump_dir or automator.output_dir)

        automator.print_ctf_matches_console()
        automator.print_default_plugins()
        automator.print_ctf_matches_paths()
        return



    has_other_args = args.pid or args.offset or args.dump_dir or args.pooltag or args.pattern


    if has_other_args:
        if os.path.exists(automator.output_dir) and os.listdir(automator.output_dir):
            
            print(f"[+] 检测到已有分析结果目录 {automator.output_dir}")
            
            # 检测profile设置
            if not automator.profile:
                if not automator.imageinfo():
                    return
            
            if args.pooltag and args.pid:
                automator.get_pooltag(args.pid) 
                return
            
            if args.pid or args.offset:
                if automator.profile and "Mac" in automator.profile:
                    print('MAC系统暂不支持')
                    return

                if args.pid:
                    dump_type = "memdump"
                    target = f"{args.pid}"
                    dump_dir = args.dump_dir or f"{automator.output_dir}/memdumps"
                else:
                    dump_type = "dumpfiles" 
                    target = f"{args.offset}"
                    dump_dir = args.dump_dir or f"{automator.output_dir}/dumpfiles"
                
                # 创建输出目录
                Path(dump_dir).mkdir(exist_ok=True)

                # 执行命令
                if automator.run_command(
                    dump_type,
                    pid=args.pid if args.pid else None,
                    offset=args.offset if args.offset else None,
                    dump_dir=dump_dir,
                    output_file=f"{automator.output_dir}/{target}.txt",
                    vol_version="vol3" if args.vol3 else "vol2"
                ):
                    # 获取文件扩展名
                    file_exts = automator.get_file_exts(dump_type)
                    
                    if dump_type == "memdump":

                        clean_filename = f"pid.{args.pid}.dmp"
                        
                        # vol3使用当前目录，vol2使用dump_dir
                        input_dir_for_rename = "." if args.vol3 else dump_dir
                        
                        # 单个文件重命名
                        renamed_file = automator.rename_single_file(
                            input_dir=input_dir_for_rename,
                            dump_dir=dump_dir, 
                            clean_filename=clean_filename,
                            file_exts=file_exts
                        )
                        

                    else: 

                        normalized_offset = f"0x{int(args.offset, 16):x}" if args.offset.startswith('0x') else args.offset
                        clean_filename = f"file.{normalized_offset}.dat"
                        
                        # vol3使用当前目录，vol2使用dump_dir
                        input_dir_for_rename = "." if args.vol3 else dump_dir
                        
                        # 批量重命名
                        automator.rename_batch_files(
                            input_dir=input_dir_for_rename,
                            dump_dir=dump_dir,
                            clean_filename=clean_filename,
                            file_exts=file_exts,
                            expected_offset=normalized_offset
                        )
                        
                    return
                
                else:
                    print(f"[!] {dump_type} 执行失败")
                    return
            
            else:  
                print(f"[!] 未知参数组合")
                return
        else:
            print(f"[!] 未找到已有分析结果，将执行完整分析")


    # 无论是否有其他参数，都创建输出目录
    if not automator.create_dir:
        automator.create_output_dir()


    # 如果用户没有手动指定profile，尝试自动检测
    if not args.profile:
        if not automator.imageinfo():
            return


    # 并行执行取证命令  根据可用性选择版本
    if automator.vol2_available:
        automator.run_standard_plugins(vol_version="vol2")
    if automator.vol3_available:
        automator.run_standard_plugins(vol_version="vol3")
    

    # 文件扫描和提取  根据可用性选择版本（禁用内部扫描，由主程序统一扫描）
    if automator.vol2_available:
        # automator.dump_and_scan_files(vol_version="vol2",plugins="dumpfiles",common_address=True, scan_files=False, quick_mode=args.quick_mode)
        automator.dump_and_scan_files(vol_version="vol2",plugins="memdump",common_address=True, scan_files=False, quick_mode=args.quick_mode)
    if automator.vol3_available:
        automator.dump_and_scan_files(vol_version="vol3",plugins="dumpfiles",common_address=True, scan_files=False, quick_mode=args.quick_mode)
        # automator.dump_and_scan_files(vol_version="vol3",plugins="memdump",common_address=True, scan_files=False, quick_mode=args.quick_mode)



    # 递归扫描主目录所有文件
    print("\n[*] 开始递归扫描主目录所有文件...")
    print(f"[*] 默认提取文件： {automator.extract_file}")
    print(f"[*] 扫描文件树：{args.dump_dir or automator.output_dir}")


    time.sleep(2.0)

    automator.analyze_archive_structure(args.dump_dir or automator.output_dir)
    automator.search_and_extract_dat_files(args.dump_dir or automator.output_dir)
    if automator.scan_for_flags(args.dump_dir or automator.output_dir):
        print(f"[*] 正则 {args.pattern} 扫描完成 目录保存在{args.dump_dir or automator.output_dir}/search_report")
    
    # 输出CTF匹配内容到控制台
    automator.print_ctf_matches_console()
    automator.print_default_plugins()
    automator.print_ctf_matches_paths()
    
    print(f"\n[*] 取证完成! 所有结果保存在: {automator.output_dir}")


if __name__ == "__main__":
    main()
