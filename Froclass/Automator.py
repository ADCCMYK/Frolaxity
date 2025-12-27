#!/usr/bin/env python3
import os
import sys
sys.dont_write_bytecode = True

from volplugins import _run_standard_plugins
from Froplugins.Folimageinfo import _imageinfo
from Froplugins.Folcmdline import _run_command
from Froplugins.Folpooltag import _get_pooltag
from Froplugins.FolSearch import _scan_for_flags
from Froplugins.FolLinux import _linux_pagecache
from Froplugins.Folfilescan import _dump_and_scan_files
from Froplugins.Folenvironment import _check_environment
from Froplugins.Folsymload import _handle_symbol_download
from Froplugins.Foltree import _analyze_archive_structure, _analyze_single_archive
from Froplugins.Folunzip import _search_and_extract_dat_files
from Froplugins.Folcheckhidden import  _extract_hidden_processes
from Froplugins.Folpattern import _pattern, _exclude_patterns, _common_address_patterns, _common_process_patterns
from Froplugins.Folrename import _rename_single_file, _rename_batch_files
from Froplugins.FolThread import _dynamic_group_plugins, _execute_plugin_group,  _execute_with_queue
from volconfig  import _set_volatility, _set_volshows, _set_python_paths,  _systeminfo, _set_extract_files, _create_output_dir, _parse_windows_profile, _get_vol3_plugin, _check_batch_termination
from Froclass.YaraScanner import _yara_deep_scan


class FolatiutAutomator:
    def __init__(self, mem_file, pattern=None, profile=None, Thread=None,dump_dir=None):

        self.pattern = self.pattern()
        self.exclude_patterns = self.exclude_patterns()
        self.Thread = max(1, int(Thread)) if Thread is not None else 10
        self.path = os.path.dirname(os.path.abspath(__file__)) 
        self.mem_file = os.path.abspath(mem_file)
        base_name = os.path.splitext(os.path.basename(mem_file))[0]
        self.output_dir = dump_dir if dump_dir is not None else base_name

        self.common_address_patterns = self.common_address_patterns()
        self.common_process_patterns = self.common_process_patterns()
        
        self.extract_file = self.set_extract_files()
        vol_shows = self.set_volshows()
        vol_paths = self.set_volatility()
        python_paths = self.set_python_paths()

        self.system_type = "unknown"
        self.profile = profile
        self.dump_dir = None

        self.flags_found = []
        self.archive_paths = []
        self.directory_tree = []

        self.vol2_path = vol_paths[0]
        self.vol3_path = vol_paths[1]
        self.vol2_show = vol_shows[0]
        self.vol3_show = vol_shows[1]

        self.python2_path = python_paths[0]
        self.python3_path = python_paths[1]

        self.unzip = False
        self.create_dir = False
        self.vol_version = False
        self.vol2_available = False
        self.vol3_available = False
        self.vol2_needs_python = False
        self.vol3_needs_python = False
        self.environment_checked = False

        
    


    def pattern(self):
        return _pattern(self)




    def exclude_patterns(self):
        return _exclude_patterns(self)




    def common_address_patterns(self):
        return _common_address_patterns(self)




    def common_process_patterns(self):
        return _common_process_patterns(self)




    def check_environment(self):
        return _check_environment(self)




    def imageinfo(self):
        return _imageinfo(self)




    def systeminfo(self):
        return _systeminfo(self)




    def create_output_dir(self):
        return _create_output_dir(self)




    def set_volatility(self):
        return _set_volatility(self)
    



    def set_python_paths(self):
        return _set_python_paths(self)
    



    def set_volshows(self):
        return _set_volshows(self)
    
    


    def set_extract_files(self):
        return _set_extract_files(self)




    def _parse_windows_profile(self, content):
        return _parse_windows_profile(self, content)




    def get_vol3_plugin(self, plugin_name):
        return _get_vol3_plugin(self, plugin_name)
    



    def get_pooltag(self, pid):
        return _get_pooltag(self, pid)




    def check_batch_termination(self, file_path):
        return _check_batch_termination(self, file_path)




    def scan_for_flags(self, file_path):
        return _scan_for_flags(self, file_path)
    



    def yara_deep_scan(self, file_path):
        return _yara_deep_scan(self, file_path)
    



    def linux_pagecache(self):
        return _linux_pagecache(self)




    def run_standard_plugins(self, vol_version):
        return _run_standard_plugins(self, vol_version)
    
    
    

    def extract_hidden_processes(self, vol_version=None):
        return _extract_hidden_processes(self, vol_version)




    def dynamic_group_plugins(self, plugins, thread_count):
        return _dynamic_group_plugins(self, plugins, thread_count)
    



    def execute_plugin_group(self, plugin_group, group_bool, max_workers, vol_version):
        return _execute_plugin_group(self, plugin_group, group_bool, max_workers, vol_version)




    def execute_with_queue(self, plugin_group, group_name, max_workers, vol_version):
        return _execute_with_queue(self, plugin_group, group_name, max_workers, vol_version)




    def run_command(self, plugin, params="", output_file=None, pid=None, offset=None, dump_dir=None, vol_version=None):
        return _run_command(self, plugin, params, output_file, pid, offset, dump_dir, vol_version)




    def handle_symbol_download(self, process, cmd_exec, output_file, file_mode, plugin, first_stderr_line):
        return _handle_symbol_download(self, process, cmd_exec, output_file, file_mode, plugin, first_stderr_line)
    



    def search_and_extract_dat_files(self, directory_path, extensions=None, extract_dir="extracted_files"):
        return _search_and_extract_dat_files(self, directory_path, extensions, extract_dir)




    def dump_and_scan_files(self, vol_version=None, plugins="", common_address=False, scan_files=True):
        return _dump_and_scan_files(self, vol_version, plugins, common_address, scan_files)




    def rename_single_file(self, input_dir, dump_dir, clean_filename, file_exts):
        return _rename_single_file(self, input_dir, dump_dir, clean_filename, file_exts)




    def rename_batch_files(self, input_dir, dump_dir, clean_filename, file_exts, expected_offset):
        return _rename_batch_files(self, input_dir, dump_dir, clean_filename, file_exts, expected_offset)





    def analyze_archive_structure(self, archive_path, output_dir="tree_reports", max_depth=1000, parent_tree=None, parent_archive=None, is_top_level=True):
        return _analyze_archive_structure(self, archive_path, output_dir, max_depth, parent_tree, parent_archive, is_top_level)
    



    def analyze_single_archive(self, archive_path, report_file):
        return _analyze_single_archive(self, archive_path, report_file)
