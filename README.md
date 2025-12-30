# Frolaxity 内存取证工具




## 项目简介

Frolaxity 一个基于Volatility的CTF内存取证自动化工具  文件提取、进程提取无多线程提取 默认common_address=True

Volatility 插件配置在 volplugins.py  正则配置在 Folpattern.py   默认注释vol2文件提取、vol3进程提取代码

初次运行卡住请单独运行一次vol3 加载符号表



## 功能特性

```bash

   ║████████╗║███████╗  ║███████╗  ║███╗      ║███████╗ ║████╗   ████╗║███╗║██████████╗║████╗    ████║
   ║██╔═════╝║██╔═══██╗║███╔═══███║║███║     ║███╔══███╗  ╚███  ███╔╝ ║███║╚═══╗███╔══╝  ╚███╗  ███╔╝
   ║███████╗ ║███████╔╝║███║   ███║║███║     ║█████████║    ╚████╔╝   ║███║    ║███║       ╚█████╔╝
   ║██╔════╝ ║██╔══╗██╗║███║   ███║║███║     ║███╔═╗███║  ║███  ███╗  ║███║    ║███║        ║███║
   ║██║      ║██║  ║██║ ╚███████╔╝ ║████████╗║███║ ║███║║████║  ║████╗║███║    ║███║        ║███║
   ╚══╝      ╚══╝  ╚══╝  ╚══════╝  ╚════════╝╚═══╝ ╚═══╝╚════╝  ╚════╝╚═══╝    ╚═══╝        ╚═══╝

```



```bash
options:
  -h, --help            显示帮助信息并退出
  -f, --file FILE       内存镜像文件路径
  -e, --check_environment
                        运行工具环境检查
  -T, --Thread THREAD   插件执行线程数量
  -Q, --offset OFFSET   提取指定内存偏移地址
  -p, --pid PID         提取指定进程PID
  -C, --commands-only   仅执行插件命令
  -S, --dump-files      仅执行文件扫描和提取
  -U, --dump-process    仅执行进程扫描和提取
  -D, --dump-dir DUMP_DIR
                        指定文件目录
  -pr, --profile PROFILE
                        指定内存镜像profile
  -L, --linux-pagecache
                        linux文件系统压缩包
  -R, --hidden-process  提取隐藏进程
  -cp, --common-processes
                        提取常用进程
  -cd, --common-address
                        提取常用地址
  -pl, --pooltag        获取进程PID的PoolTag
  -g, --pattern         使用默认正则扫描
  -Y, --yara-scan       使用YARA规则进行扫描
  -V, --vol3            使用Vol3版本

```



## 使用说明

```bash
使用示例:
  Frolaxity.py -f memory.img                自动分析
  Frolaxity.py -f memory.img -R             提取隐藏进程
  Frolaxity.py -f memory.img -O             提取常用地址
  Frolaxity.py -f memory.img -S             仅执行插件命令
  Frolaxity.py -f memory.img -U             仅进程提取扫描
  Frolaxity.py -f memory.img -S             仅文件提取扫描
  Frolaxity.py -f memory.img -cp            提取常用进程
  Frolaxity.py -f memory.img -cd            提取常用地址
  Frolaxity.py -f memory.img -S -V          仅执行插件命令
  Frolaxity.py -f memory.img -U -V          仅进程提取扫描
  Frolaxity.py -f memory.img -S -V          仅文件提取扫描
  Frolaxity.py -f memory.img -cp -V         提取常用进程
  Frolaxity.py -f memory.img -cd -V         提取常用地址
  Frolaxity.py -f memory.img -pr 镜像       指定内存镜像
  Frolaxity.py -f memory.img -g			     默认正则扫描
  Frolaxity.py -f memory.img -g -D 目录     扫描指定目录
  Frolaxity.py -f memory.img -Y             YARA规则扫描
  Frolaxity.py -f memory.img -p 1234 -pl    分析进程PoolTag
  Frolaxity.py -f memory.img -L             文件系统压缩包
  Frolaxity.py -f memory.img -p 1234        提取进程内存
  Frolaxity.py -f memory.img -Q 0x123456    提取指定文件
  Frolaxity.py -f memory.img -V             使用vol3版本
```



## 环境变量配置

volconfig.py
```bash
def _set_volatility(self):
        # 环境变量配置
        if platform.system() == 'Windows':
            return ['vol2路径/环境变量', 'vol3路径/环境变量']
        else:
            return ['vol.py路径/环境变量', 'vol3.py路径/环境变量']
```

```bash
def _set_python_paths(self):
        # 环境变量配置
        if platform.system() == 'Windows':
            return ['python2路径/环境变量', 'python3路径/环境变量']
        else:
            return ['python2路径/环境变量', 'pyhton3路径/环境变量']
```




## 疑难解答

1. 为什么运行python报错?

答：需要安装yara_python库 而不是yara库

2. 为什么初次运行卡住了?

答：单独运行一次vol3 加载符号表

3. 不想提取所有文件怎么办?

答：common_address=True 修改Folpattern.py

4. 不想所有版本都运行怎么办?

答：手动注释主文件-f对应版本方法




## 免责声明

1. 本工具仅用于合法授权的安全研究用途

2. 禁止将本工具用于任何非法活动

3. 使用者需自行承担使用本工具带来的所有风险

4. 开发者不对任何滥用行为负责

5. 使用本工具即表示您同意上述条款

   


## 许可证

MIT License


