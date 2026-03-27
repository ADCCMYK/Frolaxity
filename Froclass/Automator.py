#!/usr/bin/env python3
import os
import sys
sys.dont_write_bytecode = True

from volplugins import _run_standard_plugins
from Froplugins.Folimageinfo import _imageinfo
from Froplugins.Folcmdline import _run_command
from Froplugins.Folpooltag import _get_pooltag
from Froplugins.FolLinux import _linux_pagecache
from Froplugins.Folfilescan import _dump_and_scan_files
from Froplugins.Folenvironment import _check_environment
from Froplugins.Folsymload import _handle_symbol_download
from Froplugins.FolSearch import _scan_for_flags, _scan_single_file
from Froplugins.Foltree import _analyze_archive_structure, _analyze_single_archive
from Froplugins.Folunzip import _search_and_extract_dat_files
from Froplugins.Folcheckhidden import  _extract_hidden_processes
from Froplugins.Folpattern import _pattern, _files_patterns, _process_patterns, _exclude_patterns, _common_address_patterns, _common_process_patterns, _quick_files_patterns, _quick_process_patterns, _quick_exclude_patterns
from Froplugins.Folrename import _rename_single_file, _rename_batch_files
from Froplugins.FolThread import _dynamic_group_plugins, _execute_plugin_group,  _execute_with_queue
from Froplugins.Folreport import _generate_ctf_files_report, _generate_ctf_process_report, _generate_ctf_scan_report, _record_ctf_files_match, _record_ctf_process_match, _print_ctf_matches_console, _group_matches_version, _print_match_group, _print_default_plugins, _print_ctf_matches_paths
from volconfig  import _set_volatility, _set_volshows, _set_python_paths,  _systeminfo, _set_extract_files, _create_output_dir, _parse_windows_profile, _get_vol3_plugin, _check_batch_termination, _get_file_exts, _get_file_categories, _is_text_file, _get_priority_dirs, _scan_priority_patterns, _scan_exclude_patterns, _get_skipped_directories, _get_tree_skipped_directories, _get_unzip_skipped_directories, _get_archive_extensions, _get_file_operation_timeout, _get_priority_match_limit, _get_other_match_limit, _get_console_context_limit, _get_default_output_plugin, _get_default_directory_names, _get_default_file_prefixes
from Froclass.YaraScanner import _yara_deep_scan


class FolatiutAutomator:
    def __init__(self, mem_file, pattern=None, profile=None, Thread=None,dump_dir=None):

        self.pattern = self.pattern()
        self.files_patterns = self.files_patterns()
        self.process_patterns = self.process_patterns()

        self.mem_file = os.path.abspath(mem_file)
        self.path = os.path.dirname(os.path.abspath(__file__)) 
        base_name = os.path.splitext(os.path.basename(mem_file))[0]
        self.Thread = max(1, int(Thread)) if Thread is not None else 10
        self.output_dir = dump_dir if dump_dir is not None else base_name

        self.get_other_match_limit = self.get_other_match_limit()
        self.get_priority_match_limit = self.get_priority_match_limit()
        self.get_console_context_limit = self.get_console_context_limit()

        self.get_unzip_skipped_directories = self.get_unzip_skipped_directories()
        self.get_tree_skipped_directories = self.get_tree_skipped_directories()
        self.get_skipped_directories = self.get_skipped_directories()

        self.get_default_directory_names = self.get_default_directory_names()
        self.get_default_file_prefixes = self.get_default_file_prefixes()
        self.get_default_output_plugin = self.get_default_output_plugin()

        self.scan_priority_patterns = self.scan_priority_patterns()
        self.scan_exclude_patterns = self.scan_exclude_patterns()

        self.quick_process_patterns = self.quick_process_patterns()
        self.quick_files_patterns = self.quick_files_patterns()

        self.common_address_patterns = self.common_address_patterns()
        self.common_process_patterns = self.common_process_patterns()

        self.quick_exclude_patterns = self.quick_exclude_patterns()
        self.exclude_patterns = self.exclude_patterns()

        self.get_file_categories = self.get_file_categories()
        self.get_priority_dirs = self.get_priority_dirs()
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
        self.extracted_files = []

        self.ctf_files_matches = []
        self.ctf_process_matches = []
        self.ctf_scan_matches = []    

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




    def files_patterns(self):
        return _files_patterns(self)




    def process_patterns(self):
        return _process_patterns(self)




    def exclude_patterns(self):
        return _exclude_patterns(self)




    def common_address_patterns(self):
        return _common_address_patterns(self)




    def common_process_patterns(self):
        return _common_process_patterns(self)




    def quick_exclude_patterns(self):
        return _quick_exclude_patterns(self)





    def quick_files_patterns(self):
        return _quick_files_patterns(self)




    def quick_process_patterns(self):
        return _quick_process_patterns(self)




    def scan_priority_patterns(self):
        return _scan_priority_patterns(self)





    def scan_exclude_patterns(self):
        return _scan_exclude_patterns(self)




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




    def get_file_exts(self, plugins=""):
        return _get_file_exts(self, plugins)




    def get_file_categories(self):
        return _get_file_categories(self)




    def is_text_file(self, file_path):
        return _is_text_file(self, file_path)




    def get_priority_dirs(self):
        return _get_priority_dirs(self)




    def get_skipped_directories(self):
        return _get_skipped_directories(self)




    def get_tree_skipped_directories(self):
        return _get_tree_skipped_directories(self)




    def get_unzip_skipped_directories(self):
        return _get_unzip_skipped_directories(self)




    def get_archive_extensions(self):
        return _get_archive_extensions(self)




    def get_file_operation_timeout(self):
        return _get_file_operation_timeout(self)




    def check_batch_termination(self, file_path):
        return _check_batch_termination(self, file_path)




    def scan_for_flags(self, file_path, depth=100, scanned_dirs=None, is_top_level=True):
        return _scan_for_flags(self, file_path, depth, scanned_dirs, is_top_level)
    



    def scan_single_file(self, file_path):
        return _scan_single_file(self, file_path)




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
    



    def search_and_extract_dat_files(self, directory_path, extensions=None, extract_dir=None):
        return _search_and_extract_dat_files(self, directory_path, extensions, extract_dir)




    def dump_and_scan_files(self, vol_version=None, plugins="", common_address=False, scan_files=True, quick_mode=False):
        return _dump_and_scan_files(self, vol_version, plugins, common_address, scan_files, quick_mode)




    def rename_single_file(self, input_dir, dump_dir, clean_filename, file_exts):
        return _rename_single_file(self, input_dir, dump_dir, clean_filename, file_exts)




    def rename_batch_files(self, input_dir, dump_dir, clean_filename, file_exts, expected_offset):
        return _rename_batch_files(self, input_dir, dump_dir, clean_filename, file_exts, expected_offset)




    def analyze_archive_structure(self, archive_path, output_dir=None, max_depth=1000, parent_tree=None, parent_archive=None, is_top_level=True):
        return _analyze_archive_structure(self, archive_path, output_dir, max_depth, parent_tree, parent_archive, is_top_level)
    



    def analyze_single_archive(self, archive_path, report_file):
        return _analyze_single_archive(self, archive_path, report_file)




    def generate_ctf_files_report(self, vol_version=None):
        return _generate_ctf_files_report(self, vol_version)




    def generate_ctf_process_report(self, vol_version=None):
        return _generate_ctf_process_report(self, vol_version)




    def generate_ctf_scan_report(self, scan_results):
        return _generate_ctf_scan_report(self, scan_results)




    def record_ctf_files_match(self, vol_file_path, actual_path, offset=None, vol_version=None):
        return _record_ctf_files_match(self, vol_file_path, actual_path, offset, vol_version)




    def record_ctf_process_match(self, vol_file_path, actual_path, pid=None, process_name=None, vol_version=None):
        return _record_ctf_process_match(self, vol_file_path, actual_path, pid, process_name, vol_version)




    def group_matches_version(self, matches_list, version_key='vol_version'):
        return _group_matches_version(self, matches_list, version_key)




    def print_match_group(self, matches, title_prefix, field_mappings):
        return _print_match_group(self, matches, title_prefix, field_mappings)




    def print_ctf_matches_console(self):
        return _print_ctf_matches_console(self)    




    def print_default_plugins(self):
        return _print_default_plugins(self)
    



    def print_ctf_matches_paths(self):
        return _print_ctf_matches_paths(self)




    def get_priority_match_limit(self):
        return _get_priority_match_limit(self)




    def get_other_match_limit(self):
        return _get_other_match_limit(self)




    def get_console_context_limit(self):
        return _get_console_context_limit(self)




    def get_default_output_plugin(self):
        return _get_default_output_plugin(self)




    def get_default_directory_names(self):
        return _get_default_directory_names(self)




    def get_default_file_prefixes(self):
        return _get_default_file_prefixes(self)






