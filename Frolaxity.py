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

    parser.add_argument("-h", "--help", action="help",default=argparse.SUPPRESS,help="显示帮助信息并退出")
    parser.add_argument("-f", "--file", required=False, help="内存镜像文件路径")
    parser.add_argument("-e", "--check_environment", action="store_true", help="运行工具环境检查")
    parser.add_argument("-T", "--Thread", help="插件执行线程数量(默认10)")
    parser.add_argument("-Q", "--offset", help="提取指定内存偏移地址")
    parser.add_argument("-p", "--pid", type=int, help="提取指定进程PID")
    parser.add_argument("-C", "--commands-only", action="store_true", help="仅执行插件命令")
    parser.add_argument("-S", "--dump-files", action="store_true", help="仅执行文件扫描和提取")
    parser.add_argument("-U", "--dump-process", action="store_true", help="仅执行进程扫描和提取")
    parser.add_argument("-D", "--dump-dir", help="指定文件目录")
    parser.add_argument("-pr","--profile", help="指定内存镜像profile")
    parser.add_argument("-L", "--linux-pagecache", action="store_true", help="文件系统压缩包(linux.pagecache)")
    parser.add_argument("-R", "--hidden-process", action="store_true", help="提取隐藏进程")
    parser.add_argument("-cp", "--common-processes", action="store_true", help="提取常用进程")
    parser.add_argument("-cd", "--common-address", action="store_true", help="提取常用地址")
    parser.add_argument("-pl", "--pooltag", action="store_true", help="获取进程PID的PoolTag")
    parser.add_argument("-g", "--pattern", action="store_true", help="使用默认正则扫描")
    parser.add_argument("-Y", "--yara-scan", action="store_true", help="使用YARA规则进行扫描")
    parser.add_argument("-V", "--vol3", action="store_true", help="使用Vol3版本")
    
    args = parser.parse_args()


    # 环境检查模式
    if args.check_environment:
        # 创建一个临时的automator实例用于环境检查
        automator = FolatiutAutomator("dummy_file", None, None)
        automator.check_environment()
        return
    
    

    # YARA扫描
    if args.yara_scan:
        
        # 对于YARA扫描，不需要内存文件，使用特殊模式
        automator = FolatiutAutomator(args.file or "dummy_file", args.pattern, args.profile, args.Thread, args.dump_dir)

        print(f"[*] 开始YARA深度扫描...")
        print(f"[*] 默认提取文件： {automator.extract_file}")
        print(f"[*] 扫描文件树：{args.dump_dir or automator.output_dir}")

        #显示信息
        time.sleep(2.0)

        automator.analyze_archive_structure(args.dump_dir or automator.output_dir)
        automator.search_and_extract_dat_files(args.dump_dir or automator.output_dir)
        if automator.yara_deep_scan(args.dump_dir or automator.output_dir):
            print(f"[*] YARA扫描完成! 结果保存在: {args.dump_dir or automator.output_dir}/yara_scan")
        return



    # 默认CTF方向扫描
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
            print(f"[*] 正则 {args.pattern} 扫描完成 目录保存在{args.dump_dir or automator.output_dir}/search_report")
        return



        # 检查文件
    if not args.file:
        print("""\nusage: folatiuty.py [options]\nfolatiuty.py: error: the following arguments are required: -f/--file""")
        return



    # 本地文件分析模式
    automator = FolatiutAutomator(args.file, args.pattern, args.profile, args.Thread, args.dump_dir)
    print(f"[*] 开始分析内存镜像: {args.file}")



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
        return



    # 分析提取隐藏进程
    if args.hidden_process:
        automator.imageinfo()
        if automator.vol2_available and automator.profile:
            if automator.extract_hidden_processes(vol_version="vol2"):
                print(f"\n[*] vol2隐藏进程提取完成! 结果保存在: {automator.output_dir}/hidden_processes_vol2")
        if automator.vol3_available and automator.profile:
            if automator.extract_hidden_processes(vol_version="vol3"):
                print(f"\n[*] vol3隐藏进程提取完成! 结果保存在: {automator.output_dir}/hidden_processes_vol3")
        return



    # 提取常用地址文件
    if args.common_address:
        automator.imageinfo()
        vol_version = "vol3" if args.vol3 else "vol2"
        if automator.dump_and_scan_files(vol_version=vol_version, plugins="dumpfiles", common_address=True):
                print(f"\n[*] {vol_version}常用地址文件提取完成! 结果保存在: {automator.output_dir}/common_addresses_{vol_version}")
        return



    # 提取常用地址文件
    if args.common_processes:
        automator.imageinfo()
        vol_version = "vol3" if args.vol3 else "vol2"
        if automator.dump_and_scan_files(vol_version=vol_version, plugins="memdump", common_address=True):
                print(f"\n[*] {vol_version}常用进程文件提取完成! 结果保存在: {automator.output_dir}/common_process_{vol_version}")
        return



    # 仅执行取证命令模式
    if args.commands_only:
        automator.imageinfo()
        if automator.vol2_available and automator.profile:
            if automator.profile and automator.run_standard_plugins(vol_version="vol2"):
                print(f"\n[*] vol2仅执行取证命令模式完成! 结果保存在: {automator.output_dir}")
        if automator.vol3_available and automator.profile:
            if automator.profile and automator.run_standard_plugins(vol_version="vol3"):
                print(f"\n[*] vol3仅执行取证命令模式完成! 结果保存在: {automator.output_dir}")

        return



    # 仅文件扫描模式
    if args.dump_files:
        automator.imageinfo()
        vol_version = "vol3" if args.vol3 else "vol2"
        if automator.profile and automator.dump_and_scan_files(plugins="dumpfiles", vol_version=vol_version):
                print(f"\n[*] 文件扫描提取完成! 结果保存在: {automator.output_dir}/dumps_{vol_version}")
        return



    # 仅进程提取模式
    if args.dump_process:
        automator.imageinfo()
        vol_version = "vol3" if args.vol3 else "vol2"
        if automator.profile and automator.dump_and_scan_files(plugins="memdump", vol_version=vol_version):
                print(f"\n[*] 进程扫描提取完成! 结果保存在: {automator.output_dir}/dumps_{vol_version}")
        return



    has_other_args = args.pid or args.offset or args.dump_dir or args.pooltag or args.pattern


    if has_other_args:
        if os.path.exists(automator.output_dir) and os.listdir(automator.output_dir):
            print(f"[!] 检测到已有分析结果目录 {automator.output_dir}")
            
            # 确保profile已设置
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
                automator.run_command(
                    dump_type,
                    pid=args.pid if args.pid else None,
                    offset=args.offset if args.offset else None,
                    dump_dir=dump_dir,
                    output_file=f"{automator.output_dir}/{target}.txt",
                    vol_version="vol3" if args.vol3 else "vol2"
                )
                
                print(f"[*] {dump_type} 执行完成 -> {dump_dir}")
                return
            
            else:  
                print(f"[!] 未知参数组合")
                return
        else:
            print(f"[!] 未找到已有分析结果，将执行完整分析")


    # 无论是否有其他参数，都创建输出目录（如果尚未创建）
    if not automator.create_dir:
        automator.create_output_dir()


    # 如果用户没有手动指定profile，尝试自动检测
    if not args.profile:
        if not automator.imageinfo():
            return


    # 并行执行取证命令 - 根据可用性选择版本
    if automator.vol2_available:
        automator.run_standard_plugins(vol_version="vol2")
    if automator.vol3_available:
        automator.run_standard_plugins(vol_version="vol3")
    

    # 文件扫描和提取 - 根据可用性选择版本（禁用内部扫描，由主程序统一扫描）
    if automator.vol2_available:
        # automator.dump_and_scan_files(vol_version="vol2",plugins="dumpfiles",common_address=True, scan_files=False)
        automator.dump_and_scan_files(vol_version="vol2",plugins="memdump",common_address=True, scan_files=False)
    if automator.vol3_available:
        automator.dump_and_scan_files(vol_version="vol3",plugins="dumpfiles",common_address=True, scan_files=False)
        # automator.dump_and_scan_files(vol_version="vol3",plugins="memdump",common_address=True, scan_files=False)



    # 递归扫描主目录所有文件
    print("\n[*] 开始递归扫描主目录所有文件...")
    print(f"[*] 默认提取文件： {automator.extract_file}")
    print(f"[*] 扫描文件树：{args.dump_dir or automator.output_dir}")

    #显示信息
    time.sleep(2)
    

    automator.analyze_archive_structure(args.dump_dir or automator.output_dir)
    automator.search_and_extract_dat_files(args.dump_dir or automator.output_dir)
    if automator.scan_for_flags(args.dump_dir or automator.output_dir):
        print(f"[*] 正则 {args.pattern} 扫描完成 目录保存在{args.dump_dir or automator.output_dir}/search_report")
    
    print(f"\n[*] 取证完成! 所有结果保存在: {automator.output_dir}")


if __name__ == "__main__":
    main()
