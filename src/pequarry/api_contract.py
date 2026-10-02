"""Explicit compatibility boundary for public names and structured data labels."""
import functools as _boundary_functools
import enum as _boundary_enum
import inspect as _boundary_inspect
import types as _boundary_types
from pathlib import Path as _BoundaryPath
import sys as _boundary_sys
from collections import namedtuple as _boundary_namedtuple
_MISSING = object()
ATTRIBUTE_NAMES = {'AddressSet': 'quarry_AddressSet', 'add': 'quarry_add', 'diff': 'quarry_diff', 'UnicodeStringWrapperPostProcessor': 'quarry_UnicodeStringWrapperPostProcessor', 'get_rva': 'quarry_get_rva', 'decode': 'quarry_decode', 'invalidate': 'quarry_invalidate', 'render_pascal_16': 'quarry_render_pascal_16', 'get_pascal_16_length': 'quarry_get_pascal_16_length', '__get_word_value_at_rva': 'quarry___get_word_value_at_rva', 'ask_unicode_16': 'quarry_ask_unicode_16', 'render_unicode_16': 'quarry_render_unicode_16', 'PEFormatError': 'quarry_PEFormatError', 'Dump': 'quarry_Dump', 'add_lines': 'quarry_add_lines', 'add_line': 'quarry_add_line', 'add_header': 'quarry_add_header', 'add_newline': 'quarry_add_newline', 'get_text': 'quarry_get_text', 'Structure': 'quarry_Structure', 'get_field_absolute_offset': 'quarry_get_field_absolute_offset', 'get_field_relative_offset': 'quarry_get_field_relative_offset', 'get_file_offset': 'quarry_get_file_offset', 'set_file_offset': 'quarry_set_file_offset', 'all_zeroes': 'quarry_all_zeroes', 'sizeof': 'quarry_sizeof', 'dump_dict': 'quarry_dump_dict', 'SectionStructure': 'quarry_SectionStructure', 'get_PointerToRawData_adj': 'quarry_get_PointerToRawData_adj', 'get_VirtualAddress_adj': 'quarry_get_VirtualAddress_adj', 'get_data': 'quarry_get_data', 'get_rva_from_offset': 'quarry_get_rva_from_offset', 'get_offset_from_rva': 'quarry_get_offset_from_rva', 'contains_offset': 'quarry_contains_offset', 'contains_rva': 'quarry_contains_rva', 'contains': 'quarry_contains', 'get_entropy': 'quarry_get_entropy', 'get_hash_md5': 'quarry_get_hash_md5', 'get_hash_sha1': 'quarry_get_hash_sha1', 'get_hash_sha256': 'quarry_get_hash_sha256', 'get_hash_sha512': 'quarry_get_hash_sha512', 'entropy_H': 'quarry_entropy_H', 'StructureWithBitfields': 'quarry_StructureWithBitfields', '_unpack_bitfield_attributes': 'quarry__unpack_bitfield_attributes', '_pack_bitfield_attributes': 'quarry__pack_bitfield_attributes', 'DataContainer': 'quarry_DataContainer', 'ImportDescData': 'quarry_ImportDescData', 'ImportData': 'quarry_ImportData', 'ExportDirData': 'quarry_ExportDirData', 'ExportData': 'quarry_ExportData', 'ResourceDirData': 'quarry_ResourceDirData', 'ResourceDirEntryData': 'quarry_ResourceDirEntryData', 'ResourceDataEntryData': 'quarry_ResourceDataEntryData', 'DebugData': 'quarry_DebugData', 'DynamicRelocationData': 'quarry_DynamicRelocationData', 'FunctionOverrideData': 'quarry_FunctionOverrideData', 'FunctionOverrideDynamicRelocationData': 'quarry_FunctionOverrideDynamicRelocationData', 'BddDynamicRelocationData': 'quarry_BddDynamicRelocationData', 'BaseRelocationData': 'quarry_BaseRelocationData', 'RelocationData': 'quarry_RelocationData', 'TlsData': 'quarry_TlsData', 'BoundImportDescData': 'quarry_BoundImportDescData', 'LoadConfigData': 'quarry_LoadConfigData', 'BoundImportRefData': 'quarry_BoundImportRefData', 'ExceptionsDirEntryData': 'quarry_ExceptionsDirEntryData', 'UnwindInfo': 'quarry_UnwindInfo', 'unpack_in_stages': 'quarry_unpack_in_stages', 'get_chained_function_entry': 'quarry_get_chained_function_entry', 'set_chained_function_entry': 'quarry_set_chained_function_entry', 'PrologEpilogOp': 'quarry_PrologEpilogOp', 'initialize': 'quarry_initialize', 'length_in_code_structures': 'quarry_length_in_code_structures', 'is_valid': 'quarry_is_valid', '_get_format': 'quarry__get_format', 'PrologEpilogOpPushReg': 'quarry_PrologEpilogOpPushReg', 'PrologEpilogOpAllocLarge': 'quarry_PrologEpilogOpAllocLarge', 'get_alloc_size': 'quarry_get_alloc_size', 'PrologEpilogOpAllocSmall': 'quarry_PrologEpilogOpAllocSmall', 'PrologEpilogOpSetFP': 'quarry_PrologEpilogOpSetFP', 'PrologEpilogOpSaveReg': 'quarry_PrologEpilogOpSaveReg', 'get_offset': 'quarry_get_offset', 'PrologEpilogOpSaveRegFar': 'quarry_PrologEpilogOpSaveRegFar', 'PrologEpilogOpSaveXMM': 'quarry_PrologEpilogOpSaveXMM', 'PrologEpilogOpSaveXMMFar': 'quarry_PrologEpilogOpSaveXMMFar', 'PrologEpilogOpPushFrame': 'quarry_PrologEpilogOpPushFrame', 'PrologEpilogOpEpilogMarker': 'quarry_PrologEpilogOpEpilogMarker', 'PrologEpilogOpsFactory': 'quarry_PrologEpilogOpsFactory', '_class_dict': 'quarry__class_dict', 'create': 'quarry_create', 'PE': 'quarry_PE', '_close_data': 'quarry__close_data', 'close': 'quarry_close', 'parse_rich_header': 'quarry_parse_rich_header', 'get_warnings': 'quarry_get_warnings', 'show_warnings': 'quarry_show_warnings', 'full_load': 'quarry_full_load', 'write': 'quarry_write', 'parse_sections': 'quarry_parse_sections', 'parse_data_directories': 'quarry_parse_data_directories', 'parse_exceptions_directory': 'quarry_parse_exceptions_directory', 'parse_directory_bound_imports': 'quarry_parse_directory_bound_imports', 'parse_directory_tls': 'quarry_parse_directory_tls', 'parse_directory_load_config': 'quarry_parse_directory_load_config', 'parse_dynamic_relocations': 'quarry_parse_dynamic_relocations', 'parse_function_override_data': 'quarry_parse_function_override_data', 'parse_relocations_directory': 'quarry_parse_relocations_directory', 'parse_image_base_relocation_list': 'quarry_parse_image_base_relocation_list', 'parse_relocations': 'quarry_parse_relocations', 'parse_relocations_with_format': 'quarry_parse_relocations_with_format', 'parse_debug_directory': 'quarry_parse_debug_directory', 'parse_resources_directory': 'quarry_parse_resources_directory', 'parse_resource_data_entry': 'quarry_parse_resource_data_entry', 'parse_resource_entry': 'quarry_parse_resource_entry', 'parse_version_information': 'quarry_parse_version_information', 'parse_export_directory': 'quarry_parse_export_directory', 'dword_align': 'quarry_dword_align', 'normalize_import_va': 'quarry_normalize_import_va', 'parse_delay_import_directory': 'quarry_parse_delay_import_directory', 'get_rich_header_hash': 'quarry_get_rich_header_hash', 'get_imphash': 'quarry_get_imphash', 'get_exphash': 'quarry_get_exphash', 'parse_import_directory': 'quarry_parse_import_directory', 'parse_imports': 'quarry_parse_imports', 'get_import_table': 'quarry_get_import_table', 'get_memory_mapped_image': 'quarry_get_memory_mapped_image', 'get_resources_strings': 'quarry_get_resources_strings', 'get_string_at_rva': 'quarry_get_string_at_rva', 'get_bytes_from_data': 'quarry_get_bytes_from_data', 'get_string_from_data': 'quarry_get_string_from_data', 'get_string_u_at_rva': 'quarry_get_string_u_at_rva', 'get_section_by_offset': 'quarry_get_section_by_offset', 'get_section_by_rva': 'quarry_get_section_by_rva', 'has_relocs': 'quarry_has_relocs', 'has_dynamic_relocs': 'quarry_has_dynamic_relocs', 'print_info': 'quarry_print_info', 'dump_info': 'quarry_dump_info', 'get_physical_by_rva': 'quarry_get_physical_by_rva', 'get_data_from_dword': 'quarry_get_data_from_dword', 'get_dword_from_data': 'quarry_get_dword_from_data', 'get_dword_at_rva': 'quarry_get_dword_at_rva', 'get_dword_from_offset': 'quarry_get_dword_from_offset', 'set_dword_at_rva': 'quarry_set_dword_at_rva', 'set_dword_at_offset': 'quarry_set_dword_at_offset', 'get_data_from_word': 'quarry_get_data_from_word', 'get_word_from_data': 'quarry_get_word_from_data', 'get_word_at_rva': 'quarry_get_word_at_rva', 'get_word_from_offset': 'quarry_get_word_from_offset', 'set_word_at_rva': 'quarry_set_word_at_rva', 'set_word_at_offset': 'quarry_set_word_at_offset', 'get_data_from_qword': 'quarry_get_data_from_qword', 'get_qword_from_data': 'quarry_get_qword_from_data', 'get_qword_at_rva': 'quarry_get_qword_at_rva', 'get_qword_from_offset': 'quarry_get_qword_from_offset', 'set_qword_at_rva': 'quarry_set_qword_at_rva', 'set_qword_at_offset': 'quarry_set_qword_at_offset', 'set_bytes_at_rva': 'quarry_set_bytes_at_rva', 'set_bytes_at_offset': 'quarry_set_bytes_at_offset', 'set_data_bytes': 'quarry_set_data_bytes', 'merge_modified_section_data': 'quarry_merge_modified_section_data', 'relocate_image': 'quarry_relocate_image', 'verify_checksum': 'quarry_verify_checksum', 'generate_checksum': 'quarry_generate_checksum', 'is_exe': 'quarry_is_exe', 'is_dll': 'quarry_is_dll', 'is_driver': 'quarry_is_driver', 'get_overlay_data_start_offset': 'quarry_get_overlay_data_start_offset', 'get_overlay': 'quarry_get_overlay', 'trim': 'quarry_trim', 'adjust_PointerToRawData': 'quarry_adjust_PointerToRawData', 'adjust_SectionAlignment': 'quarry_adjust_SectionAlignment', 'Accumulator': 'quarry_Accumulator', 'wrap_up': 'quarry_wrap_up', 'new_type': 'quarry_new_type', 'add_subfield': 'quarry_add_subfield', 'get_type': 'quarry_get_type', 'get_name': 'quarry_get_name', 'get_bits_left': 'quarry_get_bits_left', 'RichHeader': 'quarry_RichHeader', 'min': 'quarry_min', 'max': 'quarry_max', 'rva_ptr': 'quarry_rva_ptr', 'string': 'quarry_string', 'value': 'quarry_value', 'text': 'quarry_text', 'struct': 'quarry_struct', '_frame_register': 'quarry__frame_register', '_frame_offset': 'quarry__frame_offset', '_long_offst': 'quarry__long_offst', '_first': 'quarry__first', '_epilog_size': 'quarry__epilog_size', 'max_symbol_exports': 'quarry_max_symbol_exports', 'max_repeated_symbol': 'quarry_max_repeated_symbol', '_get_section_by_rva_last_used': 'quarry__get_section_by_rva_last_used', 'sections': 'quarry_sections', '__warnings': 'quarry___warnings', 'PE_TYPE': 'quarry_PE_TYPE', '__from_file': 'quarry___from_file', 'FileAlignment_Warning': 'quarry_FileAlignment_Warning', 'SectionAlignment_Warning': 'quarry_SectionAlignment_Warning', '__total_resource_entries_count': 'quarry___total_resource_entries_count', '__total_resource_bytes': 'quarry___total_resource_bytes', '__total_import_symbols': 'quarry___total_import_symbols', 'dynamic_relocation_format_by_symbol': 'quarry_dynamic_relocation_format_by_symbol', '__resource_size_limit_upperbounds': 'quarry___resource_size_limit_upperbounds', '__resource_size_limit_reached': 'quarry___resource_size_limit_reached', 'DOS_HEADER': 'quarry_DOS_HEADER', 'NT_HEADERS': 'quarry_NT_HEADERS', 'FILE_HEADER': 'quarry_FILE_HEADER', 'OPTIONAL_HEADER': 'quarry_OPTIONAL_HEADER', 'length': 'quarry_length', '_subfields': 'quarry__subfields', '_name': 'quarry__name', '_type': 'quarry__type', '_bits_left': 'quarry__bits_left', '_comp_fields': 'quarry__comp_fields', '_format': 'quarry__format', 'header': 'quarry_header', 'RICH_HEADER': 'quarry_RICH_HEADER', 'VS_VERSIONINFO': 'quarry_VS_VERSIONINFO', 'VS_FIXEDFILEINFO': 'quarry_VS_FIXEDFILEINFO', 'FileInfo': 'quarry_FileInfo', 'fileno': 'quarry_fileno', 'SignatureDatabase': 'quarry_SignatureDatabase', 'generate_section_signatures': 'quarry_generate_section_signatures', 'generate_ep_signature': 'quarry_generate_ep_signature', '__generate_signature': 'quarry___generate_signature', 'match': 'quarry_match', 'match_all': 'quarry_match_all', '__match': 'quarry___match', 'match_data': 'quarry_match_data', '__match_signature_tree': 'quarry___match_signature_tree', 'load': 'quarry_load', '__load': 'quarry___load', 'parse_sig': 'quarry_parse_sig', 'signature_tree_eponly_false': 'quarry_signature_tree_eponly_false', 'signature_tree_eponly_true': 'quarry_signature_tree_eponly_true', 'signature_tree_section_start': 'quarry_signature_tree_section_start', 'signature_count_eponly_false': 'quarry_signature_count_eponly_false', 'signature_count_eponly_true': 'quarry_signature_count_eponly_true', 'signature_count_section_start': 'quarry_signature_count_section_start', 'max_depth': 'quarry_max_depth', 'TestExports': 'quarry_TestExports', 'test_exports32': 'quarry_test_exports32', 'test_exports64': 'quarry_test_exports64', 'TestPEFile': 'quarry_TestPEFile', '_load_test_files': 'quarry__load_test_files', 'test_pe_image_regression_test': 'quarry_test_pe_image_regression_test', 'test_get_rich_header_hash': 'quarry_test_get_rich_header_hash', 'test_selective_loading_integrity': 'quarry_test_selective_loading_integrity', 'test_imphash': 'quarry_test_imphash', 'test_exphash': 'quarry_test_exphash', 'test_write_header_fields': 'quarry_test_write_header_fields', 'test_nt_headers_exception': 'quarry_test_nt_headers_exception', 'test_dos_header_exception_large_data': 'quarry_test_dos_header_exception_large_data', 'test_dos_header_exception_small_data': 'quarry_test_dos_header_exception_small_data', 'test_empty_file_exception': 'quarry_test_empty_file_exception', 'test_virtual_size_less_than_raw_size': 'quarry_test_virtual_size_less_than_raw_size', 'test_virtual_size_greater_than_raw_size': 'quarry_test_virtual_size_greater_than_raw_size', 'test_relocated_memory_mapped_image': 'quarry_test_relocated_memory_mapped_image', 'test_entry_point_retrieval_with_overlapping_sections': 'quarry_test_entry_point_retrieval_with_overlapping_sections', 'test_entry_point_retrieval_with_unusual_aligments': 'quarry_test_entry_point_retrieval_with_unusual_aligments', 'test_entry_point_retrieval_with_unusual_PointerToRawData_values': 'quarry_test_entry_point_retrieval_with_unusual_PointerToRawData_values', 'test_low_alignment_section_pointer_to_raw_data': 'quarry_test_low_alignment_section_pointer_to_raw_data', 'test_VS_VERSIONINFO_dword_aligment': 'quarry_test_VS_VERSIONINFO_dword_aligment', 'test_overlay_github_issue_104': 'quarry_test_overlay_github_issue_104', 'test_get_overlay_and_trimming': 'quarry_test_get_overlay_and_trimming', 'test_unable_to_read_file': 'quarry_test_unable_to_read_file', 'test_driver_check': 'quarry_test_driver_check', 'test_rebased_image': 'quarry_test_rebased_image', 'test_checksum': 'quarry_test_checksum', 'test_files': 'quarry_test_files', 'oleaut32': 'automation_names', 'ws2_32': 'winsock2_names', 'wsock32': 'winsock1_names', 'imphash_oleaut32': 'automation_hash_names', 'imphash_ws2_32': 'winsock_hash_names', 'export_test': 'test_quarry_export_test', 'pefile_test': 'test_quarry_pefile_test'}
GLOBAL_NAMES = {'imphash_format_ordinal': 'quarry_imphash_format_ordinal', 'imphash_oleaut32': 'quarry_imphash_oleaut32', 'imphash_ords': 'quarry_imphash_ords', 'ordinal_lookup': 'quarry_ordinal_lookup', 'imphash_ws2_32': 'quarry_imphash_ws2_32', 'ws2_32': 'quarry_ws2_32', 'imphash_ordinal_lookup': 'quarry_imphash_ordinal_lookup', 'format_ordinal': 'quarry_format_ordinal', 'ords': 'quarry_ords', 'wsock32': 'quarry_wsock32', 'oleaut32': 'quarry_oleaut32', 'ord_names': 'quarry_ord_names', 'MAX_DLL_LENGTH': 'quarry_MAX_DLL_LENGTH', 'two_way_dict': 'quarry_two_way_dict', 'SUBSYSTEM_TYPE': 'quarry_SUBSYSTEM_TYPE', 'Structure': 'quarry_Structure', 'fast_load': 'quarry_fast_load', 'TlsData': 'quarry_TlsData', 'IMAGE_LX_SIGNATURE': 'quarry_IMAGE_LX_SIGNATURE', 'PrologEpilogOpSaveXMMFar': 'quarry_PrologEpilogOpSaveXMMFar', 'MAX_IMPORT_SYMBOLS': 'quarry_MAX_IMPORT_SYMBOLS', 'IMAGE_ORDINAL_FLAG': 'quarry_IMAGE_ORDINAL_FLAG', 'ResourceDataEntryData': 'quarry_ResourceDataEntryData', 'image_characteristics': 'quarry_image_characteristics', 'sha512': 'quarry_sha512', 'debug_types': 'quarry_debug_types', 'section_characteristics': 'quarry_section_characteristics', 'cache_adjust_SectionAlignment': 'quarry_cache_adjust_SectionAlignment', 'lru_cache_copy': 'quarry_lru_cache_copy', 'PE': 'quarry_PE', 'allowed_filename': 'quarry_allowed_filename', 'DebugData': 'quarry_DebugData', 'LANG': 'quarry_LANG', 'IMAGE_TE_SIGNATURE': 'quarry_IMAGE_TE_SIGNATURE', 'SECTION_CHARACTERISTICS': 'quarry_SECTION_CHARACTERISTICS', 'UnwindInfo': 'quarry_UnwindInfo', 'human_readable_size': 'quarry_human_readable_size', 'UWOP_PUSH_NONVOL': 'quarry_UWOP_PUSH_NONVOL', 'UWOP_SET_FPREG': 'quarry_UWOP_SET_FPREG', 'set_flags': 'quarry_set_flags', 'lru_cache': 'quarry_lru_cache', 'Dump': 'quarry_Dump', 'registers': 'quarry_registers', 'IMAGE_DOSZM_SIGNATURE': 'quarry_IMAGE_DOSZM_SIGNATURE', 'ImportData': 'quarry_ImportData', 'MACHINE_TYPE': 'quarry_MACHINE_TYPE', 'count_zeroes': 'quarry_count_zeroes', 'relocation_types': 'quarry_relocation_types', 'UWOP_ALLOC_LARGE': 'quarry_UWOP_ALLOC_LARGE', 'os': 'quarry_os', 'ResourceDirData': 'quarry_ResourceDirData', 'DIRECTORY_ENTRY': 'quarry_DIRECTORY_ENTRY', 'SECTOR_SIZE': 'quarry_SECTOR_SIZE', 'FunctionOverrideData': 'quarry_FunctionOverrideData', 'uuid': 'quarry_uuid', 'OPTIONAL_HEADER_MAGIC_PE': 'quarry_OPTIONAL_HEADER_MAGIC_PE', 'allowed_function_name': 'quarry_allowed_function_name', 'Counter': 'quarry_Counter', 'ExceptionsDirEntryData': 'quarry_ExceptionsDirEntryData', 'PrologEpilogOpSaveRegFar': 'quarry_PrologEpilogOpSaveRegFar', 'dll_characteristics': 'quarry_dll_characteristics', 'IMAGE_NT_SIGNATURE': 'quarry_IMAGE_NT_SIGNATURE', 'mmap': 'quarry_mmap', 'string': 'quarry_string', 'machine_types': 'quarry_machine_types', 'IMAGE_NUMBEROF_DIRECTORY_ENTRIES': 'quarry_IMAGE_NUMBEROF_DIRECTORY_ENTRIES', 'PrologEpilogOpPushFrame': 'quarry_PrologEpilogOpPushFrame', 'IMAGE_ORDINAL_FLAG64': 'quarry_IMAGE_ORDINAL_FLAG64', 'EX_DLL_CHARACTERISTICS': 'quarry_EX_DLL_CHARACTERISTICS', 'PrologEpilogOpsFactory': 'quarry_PrologEpilogOpsFactory', 'unwind_info_flags': 'quarry_unwind_info_flags', 'BoundImportRefData': 'quarry_BoundImportRefData', 'power_of_two': 'quarry_power_of_two', 'math': 'quarry_math', 'UWOP_SAVE_NONVOL': 'quarry_UWOP_SAVE_NONVOL', 'IMAGE_CHARACTERISTICS': 'quarry_IMAGE_CHARACTERISTICS', 'UWOP_ALLOC_SMALL': 'quarry_UWOP_ALLOC_SMALL', 'DynamicRelocationData': 'quarry_DynamicRelocationData', 'DEBUG_TYPE': 'quarry_DEBUG_TYPE', 'md5': 'quarry_md5', 'MAX_RESOURCE_ENTRIES': 'quarry_MAX_RESOURCE_ENTRIES', 'sha1': 'quarry_sha1', 'subsystem_types': 'quarry_subsystem_types', 'PrologEpilogOpAllocSmall': 'quarry_PrologEpilogOpAllocSmall', 'is_valid_dos_filename': 'quarry_is_valid_dos_filename', 'StructureWithBitfields': 'quarry_StructureWithBitfields', 'get_sublang_name_for_lang': 'quarry_get_sublang_name_for_lang', 'sublang': 'quarry_sublang', 'ExportData': 'quarry_ExportData', 'UWOP_PUSH_MACHFRAME': 'quarry_UWOP_PUSH_MACHFRAME', 'ex_dll_characteristics': 'quarry_ex_dll_characteristics', 'parse_strings': 'quarry_parse_strings', 'IMAGE_DOS_SIGNATURE': 'quarry_IMAGE_DOS_SIGNATURE', 'IMAGE_NE_SIGNATURE': 'quarry_IMAGE_NE_SIGNATURE', 'MAX_SECTIONS': 'quarry_MAX_SECTIONS', 'ImportDescData': 'quarry_ImportDescData', 'time': 'quarry_time', 'UWOP_EPILOG': 'quarry_UWOP_EPILOG', 'OPTIONAL_HEADER_MAGIC_PE_PLUS': 'quarry_OPTIONAL_HEADER_MAGIC_PE_PLUS', 'LoadConfigData': 'quarry_LoadConfigData', 'ordlookup': 'quarry_ordlookup', 'MAX_SYMBOL_EXPORT_COUNT': 'quarry_MAX_SYMBOL_EXPORT_COUNT', 'BaseRelocationData': 'quarry_BaseRelocationData', 'RESOURCE_TYPE': 'quarry_RESOURCE_TYPE', 'set_bitfields_format': 'quarry_set_bitfields_format', 'sha256': 'quarry_sha256', 'PrologEpilogOpAllocLarge': 'quarry_PrologEpilogOpAllocLarge', 'defaultdict': 'quarry_defaultdict', 'set_format': 'quarry_set_format', 'PrologEpilogOpPushReg': 'quarry_PrologEpilogOpPushReg', 'UWOP_SAVE_NONVOL_FAR': 'quarry_UWOP_SAVE_NONVOL_FAR', 'directory_entry_types': 'quarry_directory_entry_types', 'BddDynamicRelocationData': 'quarry_BddDynamicRelocationData', 'STRUCT_SIZEOF_TYPES': 'quarry_STRUCT_SIZEOF_TYPES', 'ExportDirData': 'quarry_ExportDirData', 'main': 'quarry_main', 'DLL_CHARACTERISTICS': 'quarry_DLL_CHARACTERISTICS', 'ResourceDirEntryData': 'quarry_ResourceDirEntryData', 'SUBLANG': 'quarry_SUBLANG', 'struct': 'quarry_struct', 'resource_type': 'quarry_resource_type', 'lang': 'quarry_lang', 'UnicodeStringWrapperPostProcessor': 'quarry_UnicodeStringWrapperPostProcessor', 'codecs': 'quarry_codecs', 'wraps': 'quarry_wraps', 'PrologEpilogOp': 'quarry_PrologEpilogOp', 'PrologEpilogOpSetFP': 'quarry_PrologEpilogOpSetFP', 'MAX_SYMBOL_NAME_LENGTH': 'quarry_MAX_SYMBOL_NAME_LENGTH', 'PEFormatError': 'quarry_PEFormatError', 'RELOCATION_TYPE': 'quarry_RELOCATION_TYPE', 'is_valid_function_name': 'quarry_is_valid_function_name', 'MAX_IMPORT_NAME_LENGTH': 'quarry_MAX_IMPORT_NAME_LENGTH', 'UNWIND_INFO_FLAGS': 'quarry_UNWIND_INFO_FLAGS', 'MAX_STRING_LENGTH': 'quarry_MAX_STRING_LENGTH', 'PrologEpilogOpSaveXMM': 'quarry_PrologEpilogOpSaveXMM', 'PrologEpilogOpEpilogMarker': 'quarry_PrologEpilogOpEpilogMarker', 'RelocationData': 'quarry_RelocationData', 'retrieve_flags': 'quarry_retrieve_flags', 'BoundImportDescData': 'quarry_BoundImportDescData', 'MAX_RESOURCE_DEPTH': 'quarry_MAX_RESOURCE_DEPTH', 'REGISTERS': 'quarry_REGISTERS', 'copy': 'quarry_copy', 'UWOP_SAVE_XMM128': 'quarry_UWOP_SAVE_XMM128', 'sizeof_type': 'quarry_sizeof_type', 'PrologEpilogOpSaveReg': 'quarry_PrologEpilogOpSaveReg', 'UWOP_SAVE_XMM128_FAR': 'quarry_UWOP_SAVE_XMM128_FAR', 'DataContainer': 'quarry_DataContainer', 'MIN_VALID_FILE_ALIGNMENT': 'quarry_MIN_VALID_FILE_ALIGNMENT', 'FunctionOverrideDynamicRelocationData': 'quarry_FunctionOverrideDynamicRelocationData', 'IMAGE_LE_SIGNATURE': 'quarry_IMAGE_LE_SIGNATURE', 'AddressSet': 'quarry_AddressSet', 'SectionStructure': 'quarry_SectionStructure', 'sublang_name': 'quarry_sublang_name', 'sublang_value': 'quarry_sublang_value', 'pefile': 'quarry_pefile', 'SignatureDatabase': 'quarry_SignatureDatabase', 'is_valid': 'quarry_is_valid', 're': 'quarry_re', 'is_probably_packed': 'quarry_is_probably_packed', 'is_suspicious': 'quarry_is_suspicious', 'urllib': 'quarry_urllib', 'unhexlify': 'quarry_unhexlify', 'EXPECT_NAMES': 'quarry_EXPECT_NAMES', 'PE_32': 'quarry_PE_32', 'TestExports': 'quarry_TestExports', 'PE_64': 'quarry_PE_64', 'unittest': 'quarry_unittest', 'sys': 'quarry_sys', '_create_pe': 'quarry__create_pe', 'difflib': 'quarry_difflib', 'TestPEFile': 'quarry_TestPEFile', '_low_alignment_resource_pe': 'quarry__low_alignment_resource_pe', 'REGRESSION_TESTS_DIR': 'quarry_REGRESSION_TESTS_DIR'}
TYPE_LABELS = {'quarry_AddressSet': 'AddressSet', 'quarry_UnicodeStringWrapperPostProcessor': 'UnicodeStringWrapperPostProcessor', 'quarry_PEFormatError': 'PEFormatError', 'quarry_Dump': 'Dump', 'quarry_Structure': 'Structure', 'quarry_SectionStructure': 'SectionStructure', 'quarry_StructureWithBitfields': 'StructureWithBitfields', 'quarry_DataContainer': 'DataContainer', 'quarry_ImportDescData': 'ImportDescData', 'quarry_ImportData': 'ImportData', 'quarry_ExportDirData': 'ExportDirData', 'quarry_ExportData': 'ExportData', 'quarry_ResourceDirData': 'ResourceDirData', 'quarry_ResourceDirEntryData': 'ResourceDirEntryData', 'quarry_ResourceDataEntryData': 'ResourceDataEntryData', 'quarry_DebugData': 'DebugData', 'quarry_DynamicRelocationData': 'DynamicRelocationData', 'quarry_FunctionOverrideData': 'FunctionOverrideData', 'quarry_FunctionOverrideDynamicRelocationData': 'FunctionOverrideDynamicRelocationData', 'quarry_BddDynamicRelocationData': 'BddDynamicRelocationData', 'quarry_BaseRelocationData': 'BaseRelocationData', 'quarry_RelocationData': 'RelocationData', 'quarry_TlsData': 'TlsData', 'quarry_BoundImportDescData': 'BoundImportDescData', 'quarry_LoadConfigData': 'LoadConfigData', 'quarry_BoundImportRefData': 'BoundImportRefData', 'quarry_ExceptionsDirEntryData': 'ExceptionsDirEntryData', 'quarry_UnwindInfo': 'UnwindInfo', 'quarry_PrologEpilogOp': 'PrologEpilogOp', 'quarry_PrologEpilogOpPushReg': 'PrologEpilogOpPushReg', 'quarry_PrologEpilogOpAllocLarge': 'PrologEpilogOpAllocLarge', 'quarry_PrologEpilogOpAllocSmall': 'PrologEpilogOpAllocSmall', 'quarry_PrologEpilogOpSetFP': 'PrologEpilogOpSetFP', 'quarry_PrologEpilogOpSaveReg': 'PrologEpilogOpSaveReg', 'quarry_PrologEpilogOpSaveRegFar': 'PrologEpilogOpSaveRegFar', 'quarry_PrologEpilogOpSaveXMM': 'PrologEpilogOpSaveXMM', 'quarry_PrologEpilogOpSaveXMMFar': 'PrologEpilogOpSaveXMMFar', 'quarry_PrologEpilogOpPushFrame': 'PrologEpilogOpPushFrame', 'quarry_PrologEpilogOpEpilogMarker': 'PrologEpilogOpEpilogMarker', 'quarry_PrologEpilogOpsFactory': 'PrologEpilogOpsFactory', 'quarry_PE': 'PE', 'quarry_Accumulator': 'Accumulator', 'quarry_RichHeader': 'RichHeader', 'quarry_SignatureDatabase': 'SignatureDatabase', 'quarry_TestExports': 'TestExports', 'quarry_TestPEFile': 'TestPEFile'}

def type_label(boundary_type):
    boundary_name = getattr(boundary_type, '__name__', None)
    return TYPE_LABELS.get(boundary_name, boundary_name)

def attribute_name(boundary_owner, boundary_label):
    if isinstance(boundary_owner, _boundary_types.ModuleType):
        return getattr(boundary_owner, '__boundary_names__', {}).get(boundary_label, boundary_label)
    boundary_class = boundary_owner if isinstance(boundary_owner, type) else type(boundary_owner)
    boundary_map = getattr(boundary_class, '__boundary_names__', {})
    return boundary_map.get(boundary_label, boundary_label)

def read_attribute(boundary_owner, boundary_label, boundary_default=_MISSING):
    if boundary_label == '__name__' and isinstance(boundary_owner, type):
        return type_label(boundary_owner)
    boundary_target = attribute_name(boundary_owner, boundary_label)
    try:
        return getattr(boundary_owner, boundary_target)
    except AttributeError:
        try:
            return getattr(boundary_owner, boundary_label)
        except AttributeError:
            if boundary_default is _MISSING:
                raise
            return boundary_default

def write_attribute(boundary_owner, boundary_label, boundary_value):
    setattr(boundary_owner, attribute_name(boundary_owner, boundary_label), boundary_value)

def has_attribute(boundary_owner, boundary_label):
    try:
        read_attribute(boundary_owner, boundary_label)
        return True
    except AttributeError:
        return False

def remove_attribute(boundary_owner, boundary_label):
    delattr(boundary_owner, attribute_name(boundary_owner, boundary_label))

class AttributeBoundary:

    def __init__(boundary_self, boundary_owner):
        boundary_self.owner = boundary_owner

    def __getitem__(boundary_self, boundary_label):
        return read_attribute(boundary_self.owner, boundary_label)

    def __setitem__(boundary_self, boundary_label, boundary_value):
        write_attribute(boundary_self.owner, boundary_label, boundary_value)

    def __delitem__(boundary_self, boundary_label):
        remove_attribute(boundary_self.owner, boundary_label)

def attributes(boundary_owner):
    return AttributeBoundary(boundary_owner)

def callable_contract(boundary_parameters, boundary_label):

    def boundary_decorate(boundary_function):

        @_boundary_functools.wraps(boundary_function)
        def boundary_invoke(*boundary_values, **boundary_keywords):
            boundary_remapped = {boundary_parameters.get(boundary_key, boundary_key): boundary_value for boundary_key, boundary_value in boundary_keywords.items()}
            try:
                return boundary_function(*boundary_values, **boundary_remapped)
            except (TypeError, AttributeError, ValueError) as boundary_error:
                if boundary_error.args and isinstance(boundary_error.args[0], str):
                    boundary_message = boundary_error.args[0]
                    for boundary_new, boundary_old in TYPE_LABELS.items():
                        boundary_message = boundary_message.replace(boundary_new, boundary_old)
                    boundary_message = boundary_message.replace(boundary_function.__name__, boundary_label)
                    for boundary_old, boundary_new in boundary_parameters.items():
                        boundary_message = boundary_message.replace(boundary_new, boundary_old)
                    boundary_error.args = (boundary_message,) + boundary_error.args[1:]
                raise
        boundary_invoke.__wire_name__ = boundary_label
        boundary_signature = _boundary_inspect.signature(boundary_function)
        boundary_reverse = {value: key for key, value in boundary_parameters.items()}
        boundary_invoke.__signature__ = boundary_signature.replace(parameters=[p.replace(name=boundary_reverse.get(p.name, p.name)) for p in boundary_signature.parameters.values()])
        if _boundary_inspect.isgeneratorfunction(boundary_function):

            @_boundary_functools.wraps(boundary_function)
            def boundary_generate(*boundary_values, **boundary_keywords):
                yield from boundary_invoke(*boundary_values, **boundary_keywords)
            boundary_generate.__signature__ = boundary_invoke.__signature__
            return boundary_generate
        return boundary_invoke
    return boundary_decorate

def class_contract(boundary_label, boundary_fields):

    def boundary_decorate(boundary_class):
        boundary_mapping = {}
        for boundary_base in reversed(boundary_class.__mro__[1:]):
            boundary_mapping.update(getattr(boundary_base, '__boundary_names__', {}))
        boundary_mapping.update(boundary_fields)
        boundary_class.__boundary_names__ = boundary_mapping
        boundary_class.__wire_name__ = boundary_label
        if issubclass(boundary_class, _boundary_enum.Enum) and (not issubclass(boundary_class, _boundary_enum.Flag)) and ('_missing_' not in vars(boundary_class)):

            def boundary_missing(boundary_cls, boundary_value):
                raise ValueError(f'{boundary_value!r} is not a valid {boundary_label}')
            boundary_class._missing_ = classmethod(boundary_missing)
        for boundary_old, boundary_new in boundary_fields.items():
            if boundary_new in vars(boundary_class) and boundary_old not in vars(boundary_class):
                setattr(boundary_class, boundary_old, vars(boundary_class)[boundary_new])
        if not issubclass(boundary_class, tuple):
            boundary_setter = vars(boundary_class).get('__setattr__', object.__setattr__)
            boundary_deleter = vars(boundary_class).get('__delattr__', object.__delattr__)
            boundary_getter = vars(boundary_class).get('__getattr__')

            def boundary_store(boundary_self, boundary_key, boundary_value):
                boundary_setter(boundary_self, boundary_mapping.get(boundary_key, boundary_key), boundary_value)

            def boundary_fetch(boundary_self, boundary_key):
                boundary_key2 = boundary_mapping.get(boundary_key, boundary_key)
                if any((boundary_key2 in vars(boundary_base) for boundary_base in type(boundary_self).__mro__)):
                    return object.__getattribute__(boundary_self, boundary_key2)
                if boundary_key2 != boundary_key:
                    try:
                        return object.__getattribute__(boundary_self, boundary_key2)
                    except AttributeError:
                        pass
                if boundary_getter:
                    return boundary_getter(boundary_self, boundary_key)
                raise AttributeError(f"'{boundary_label}' object has no attribute '{boundary_key}'")

            def boundary_delete(boundary_self, boundary_key):
                boundary_deleter(boundary_self, boundary_mapping.get(boundary_key, boundary_key))
            boundary_class.__setattr__ = boundary_store
            boundary_class.__getattr__ = boundary_fetch
            boundary_class.__delattr__ = boundary_delete
        if hasattr(boundary_class, '__dataclass_fields__'):
            boundary_repr = boundary_class.__repr__

            def boundary_represent(boundary_self):
                return boundary_repr(boundary_self).replace(boundary_class.__name__ + '(', boundary_label + '(', 1)
            boundary_class.__repr__ = boundary_represent
        return boundary_class
    return boundary_decorate

def named_record(boundary_label, boundary_fields, **boundary_options):
    boundary_name = GLOBAL_NAMES.get(boundary_label, boundary_label)
    boundary_record = _boundary_namedtuple(boundary_name, boundary_fields, **boundary_options)
    boundary_repr = boundary_record.__repr__
    boundary_record.__wire_name__ = boundary_label
    boundary_record.__repr__ = lambda boundary_self: boundary_repr(boundary_self).replace(boundary_name + '(', boundary_label + '(', 1)
    return boundary_record

def module_contract(boundary_namespace, boundary_names):
    boundary_namespace['__boundary_names__'] = boundary_names
    for boundary_old, boundary_new in boundary_names.items():
        if boundary_new in boundary_namespace:
            boundary_value = boundary_namespace[boundary_new]
            if isinstance(boundary_value, type) and any((base.__module__ == 'unittest.case' for base in boundary_value.__mro__)):
                continue
            boundary_namespace.setdefault(boundary_old, boundary_namespace[boundary_new])
from collections.abc import MutableMapping as _BoundaryMapping

class NamespaceView(_BoundaryMapping):

    def __init__(boundary_self, boundary_owner):
        boundary_self.owner = boundary_owner
        boundary_self.raw = boundary_owner.__dict__
        boundary_class = boundary_owner if isinstance(boundary_owner, (type, _boundary_types.ModuleType)) else type(boundary_owner)
        boundary_self.names = getattr(boundary_class, '__boundary_names__', {})

    def __getitem__(boundary_self, boundary_key):
        return boundary_self.raw[boundary_self.names.get(boundary_key, boundary_key)]

    def __setitem__(boundary_self, boundary_key, boundary_value):
        boundary_self.raw[boundary_self.names.get(boundary_key, boundary_key)] = boundary_value

    def __delitem__(boundary_self, boundary_key):
        del boundary_self.raw[boundary_self.names.get(boundary_key, boundary_key)]

    def __iter__(boundary_self):
        boundary_reverse = {v: k for k, v in boundary_self.names.items()}
        return iter(dict.fromkeys((boundary_reverse.get(k, k) for k in boundary_self.raw)))

    def __len__(boundary_self):
        return sum((1 for _ in boundary_self))

def namespace_view(boundary_owner):
    return NamespaceView(boundary_owner)

def public_names(boundary_owner):
    boundary_class = boundary_owner if isinstance(boundary_owner, (type, _boundary_types.ModuleType)) else type(boundary_owner)
    boundary_names = getattr(boundary_class, '__boundary_names__', {})
    boundary_reverse = {v: k for k, v in boundary_names.items()}
    return sorted(set((boundary_reverse.get(k, k) for k in dir(boundary_owner))))

class NamespaceContract(_boundary_types.ModuleType):

    def __getattribute__(boundary_self, boundary_key):
        boundary_namespace = _boundary_types.ModuleType.__getattribute__(boundary_self, '__dict__')
        boundary_mapping = boundary_namespace.get('__boundary_names__', {})
        boundary_target = boundary_mapping.get(boundary_key, boundary_key)
        return _boundary_types.ModuleType.__getattribute__(boundary_self, boundary_target)

    def __setattr__(boundary_self, boundary_key, boundary_value):
        boundary_namespace = _boundary_types.ModuleType.__getattribute__(boundary_self, '__dict__')
        boundary_mapping = boundary_namespace.get('__boundary_names__', {})
        _boundary_types.ModuleType.__setattr__(boundary_self, boundary_mapping.get(boundary_key, boundary_key), boundary_value)

    def __delattr__(boundary_self, boundary_key):
        boundary_namespace = _boundary_types.ModuleType.__getattribute__(boundary_self, '__dict__')
        boundary_mapping = boundary_namespace.get('__boundary_names__', {})
        _boundary_types.ModuleType.__delattr__(boundary_self, boundary_mapping.get(boundary_key, boundary_key))
_module_initial_contract = module_contract

def module_contract(boundary_namespace, boundary_names):
    _module_initial_contract(boundary_namespace, boundary_names)
    boundary_module = _boundary_sys.modules.get(boundary_namespace.get('__name__'))
    if boundary_module is not None:
        boundary_module.__class__ = NamespaceContract
