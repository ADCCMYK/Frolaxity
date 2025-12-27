#!/usr/bin/env python3
import sys
sys.dont_write_bytecode = True

from queue import Queue, Empty
import threading
import time


def _dynamic_group_plugins(self, plugins, thread_count):
    if not plugins:
        return []
    
    # 计算每组插件数量
    group_size = thread_count
    
    # 将插件列表按组大小分组
    plugin_groups = []
    for i in range(0, len(plugins), group_size):
        plugin_groups.append(plugins[i:i + group_size])
    
    return plugin_groups


def _execute_plugin_group(self, plugin_group, group_bool, max_workers, vol_version):
    if not plugin_group:
        return True
        
    # 根据插件组类型调整执行策略
    if not group_bool:
        # 对于耗时插件组，使用更保守的线程策略
        adjusted_workers = max(1, max_workers // 2)  # 耗时插件使用一半线程
        return _execute_with_queue(self, plugin_group, group_bool, adjusted_workers, vol_version)
    else:
        # 对于快速和中等插件组，使用正常的队列执行
        return _execute_with_queue(self, plugin_group, group_bool, max_workers, vol_version)



def _execute_with_queue(self, plugin_group, group_name, max_workers, vol_version):
    if not plugin_group:
        return True
        
    # 使用无界队列，不限制任务提交
    task_queue = Queue()
    stop_event = threading.Event()
    completed_count = 0
    total_count = len(plugin_group)
    errors = []
    
    def worker(worker_id):
        while not stop_event.is_set():
            try:
                plugin, params = task_queue.get(timeout=1.0)
                try:
                    success = self.run_command(plugin, params, vol_version=vol_version)
                    if not success:
                        pass
                except Exception as e:
                    pass
                finally:
                    task_queue.task_done()
                    nonlocal completed_count
                    completed_count += 1
            except Empty:
                # 队列为空，继续等待
                continue
            except Exception as e:
                # 其他异常，记录并继续
                errors.append(f"线程 {worker_id} 异常: {str(e)}")
                continue
    
    # 启动工作线程
    workers = []
    worker_count = min(max_workers, len(plugin_group))  # 线程数量由-T参数决定，无固定限制
    for i in range(worker_count):
        t = threading.Thread(target=worker, name=f"Worker-{group_name}-{i}", args=(i,))
        t.daemon = True
        t.start()
        workers.append(t)
    
    # 一次性提交所有任务到队列
    try:
        for plugin, params in plugin_group:
            task_queue.put((plugin, params))
        
        # 等待所有任务完成，但不阻塞其他操作
        # 线程会自动接取下一个任务，保持线程总数不变
        task_queue.join()
        
    except Exception as e:
        errors.append(f"任务调度异常: {str(e)}")
    finally:
        # 清理资源
        stop_event.set()
        
        # 等待工作线程结束
        for t in workers:
            t.join(timeout=2.0)
    
    # 如果有错误，记录日志
    if errors:
        print(f"[!] {group_name}组执行完成，发现 {len(errors)} 个错误")
        for error in errors[:5]:  # 只显示前5个错误
            print(f"    {error}")
        if len(errors) > 5:
            print(f"    ... 还有 {len(errors) - 5} 个错误未显示")
    
    return len(errors) == 0
