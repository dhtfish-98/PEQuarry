#!/usr/bin/python
# Derived from pefile.py; original copyright and license retained in ORIGIN.md.
"""pefile, Portable Executable reader module

All the PE file basic structures are available with their default names as
attributes of the instance returned.

Processed elements such as the import table are made available with lowercase
names, to differentiate them from the upper case basic structure names.

pefile has been tested against many edge cases such as corrupted and malformed
PEs as well as malware, which often attempts to abuse the format way beyond its
standard use. To the best of my knowledge most of the abuse is handled
gracefully.

Copyright (c) 2005-2024 Ero Carrera <ero.carrera@gmail.com>
"""
import pequarry.api_contract as _name_boundary
__author__ = 'Ero Carrera'
__version__ = '2024.8.26'
__contact__ = 'ero.carrera@gmail.com'
import codecs as quarry_codecs
import copy as quarry_copy
import math as quarry_math
import mmap as quarry_mmap
import os as quarry_os
import string as quarry_string
import struct as quarry_struct
import time as quarry_time
import uuid as quarry_uuid
from collections import Counter as quarry_Counter, defaultdict as quarry_defaultdict
from functools import lru_cache as quarry_lru_cache, wraps as quarry_wraps
from hashlib import md5 as quarry_md5, sha1 as quarry_sha1, sha256 as quarry_sha256, sha512 as quarry_sha512
import pequarry.ordinal_catalog as quarry_ordlookup
from pequarry.bounded_io import quarry_INPUT_LIMIT, quarry_MAPPED_LIMIT, quarry_LimitError, quarry_positive_limit, quarry_read_regular, quarry_in_memory_bytes, quarry_write_regular
quarry_codecs.register_error('backslashreplace_', quarry_codecs.lookup_error('backslashreplace'))

@_name_boundary.callable_contract({'maxsize': 'quarry_maxsize_43837fc', 'typed': 'quarry_typed_2c3ac54'}, 'lru_cache_copy')
def quarry_lru_cache_copy(quarry_maxsize_43837fc=128, quarry_typed_2c3ac54=False):

    @_name_boundary.callable_contract({'f': 'quarry_f_d78c9cd'}, 'decorator')
    def quarry_decorator_e251684(quarry_f_d78c9cd):
        quarry_cached_function_0068643 = quarry_lru_cache(quarry_maxsize_43837fc, quarry_typed_2c3ac54)(quarry_f_d78c9cd)

        @quarry_wraps(quarry_f_d78c9cd)
        @_name_boundary.callable_contract({'args': 'quarry_args_85455a9', 'kwargs': 'quarry_kwargs_3fda449'}, 'wrapper')
        def quarry_wrapper_a0753f7(*quarry_args_85455a9, **quarry_kwargs_3fda449):
            return quarry_copy.copy(quarry_cached_function_0068643(*quarry_args_85455a9, **quarry_kwargs_3fda449))
        return quarry_wrapper_a0753f7
    return quarry_decorator_e251684

@quarry_lru_cache(maxsize=2048)
@_name_boundary.callable_contract({'val': 'quarry_val_49da088', 'section_alignment': 'quarry_section_alignment_af08012', 'file_alignment': 'quarry_file_alignment_ec2c7ae'}, 'cache_adjust_SectionAlignment')
def quarry_cache_adjust_SectionAlignment(quarry_val_49da088, quarry_section_alignment_af08012, quarry_file_alignment_ec2c7ae):
    if quarry_section_alignment_af08012 < 4096:
        quarry_section_alignment_af08012 = quarry_file_alignment_ec2c7ae
    if quarry_section_alignment_af08012 and quarry_val_49da088 % quarry_section_alignment_af08012:
        return quarry_val_49da088 // quarry_section_alignment_af08012 * quarry_section_alignment_af08012
    return quarry_val_49da088

@_name_boundary.callable_contract({'data': 'quarry_data_local_cfda918'}, 'count_zeroes')
def quarry_count_zeroes(quarry_data_local_cfda918):
    return quarry_data_local_cfda918.count(0)
quarry_fast_load = False
quarry_MAX_STRING_LENGTH = 1048576
quarry_MAX_IMPORT_SYMBOLS = 8192
quarry_MAX_DLL_LENGTH = 512
quarry_MAX_IMPORT_NAME_LENGTH = 512
quarry_MAX_SYMBOL_NAME_LENGTH = 512
quarry_MAX_SECTIONS = 2048
quarry_MAX_RESOURCE_ENTRIES = 32768
quarry_MAX_RESOURCE_DEPTH = 32
quarry_MAX_SYMBOL_EXPORT_COUNT = 8192
quarry_MIN_VALID_FILE_ALIGNMENT = 512
quarry_SECTOR_SIZE = 512
quarry_IMAGE_DOS_SIGNATURE = 23117
quarry_IMAGE_DOSZM_SIGNATURE = 19802
quarry_IMAGE_NT_SIGNATURE = 17744
quarry_IMAGE_NE_SIGNATURE = 17742
quarry_IMAGE_LE_SIGNATURE = 17740
quarry_IMAGE_LX_SIGNATURE = 22604
quarry_IMAGE_TE_SIGNATURE = 23126
quarry_IMAGE_NUMBEROF_DIRECTORY_ENTRIES = 16
quarry_IMAGE_ORDINAL_FLAG = 2147483648
quarry_IMAGE_ORDINAL_FLAG64 = 9223372036854775808
quarry_OPTIONAL_HEADER_MAGIC_PE = 267
quarry_OPTIONAL_HEADER_MAGIC_PE_PLUS = 523

@_name_boundary.callable_contract({'pairs': 'quarry_pairs_07e5de4'}, 'two_way_dict')
def quarry_two_way_dict(quarry_pairs_07e5de4):
    return dict([(quarry_e_7b20d41[1], quarry_e_7b20d41[0]) for quarry_e_7b20d41 in quarry_pairs_07e5de4] + quarry_pairs_07e5de4)
quarry_directory_entry_types = [('IMAGE_DIRECTORY_ENTRY_EXPORT', 0), ('IMAGE_DIRECTORY_ENTRY_IMPORT', 1), ('IMAGE_DIRECTORY_ENTRY_RESOURCE', 2), ('IMAGE_DIRECTORY_ENTRY_EXCEPTION', 3), ('IMAGE_DIRECTORY_ENTRY_SECURITY', 4), ('IMAGE_DIRECTORY_ENTRY_BASERELOC', 5), ('IMAGE_DIRECTORY_ENTRY_DEBUG', 6), ('IMAGE_DIRECTORY_ENTRY_COPYRIGHT', 7), ('IMAGE_DIRECTORY_ENTRY_GLOBALPTR', 8), ('IMAGE_DIRECTORY_ENTRY_TLS', 9), ('IMAGE_DIRECTORY_ENTRY_LOAD_CONFIG', 10), ('IMAGE_DIRECTORY_ENTRY_BOUND_IMPORT', 11), ('IMAGE_DIRECTORY_ENTRY_IAT', 12), ('IMAGE_DIRECTORY_ENTRY_DELAY_IMPORT', 13), ('IMAGE_DIRECTORY_ENTRY_COM_DESCRIPTOR', 14), ('IMAGE_DIRECTORY_ENTRY_RESERVED', 15)]
quarry_DIRECTORY_ENTRY = quarry_two_way_dict(quarry_directory_entry_types)
quarry_image_characteristics = [('IMAGE_FILE_RELOCS_STRIPPED', 1), ('IMAGE_FILE_EXECUTABLE_IMAGE', 2), ('IMAGE_FILE_LINE_NUMS_STRIPPED', 4), ('IMAGE_FILE_LOCAL_SYMS_STRIPPED', 8), ('IMAGE_FILE_AGGRESIVE_WS_TRIM', 16), ('IMAGE_FILE_LARGE_ADDRESS_AWARE', 32), ('IMAGE_FILE_16BIT_MACHINE', 64), ('IMAGE_FILE_BYTES_REVERSED_LO', 128), ('IMAGE_FILE_32BIT_MACHINE', 256), ('IMAGE_FILE_DEBUG_STRIPPED', 512), ('IMAGE_FILE_REMOVABLE_RUN_FROM_SWAP', 1024), ('IMAGE_FILE_NET_RUN_FROM_SWAP', 2048), ('IMAGE_FILE_SYSTEM', 4096), ('IMAGE_FILE_DLL', 8192), ('IMAGE_FILE_UP_SYSTEM_ONLY', 16384), ('IMAGE_FILE_BYTES_REVERSED_HI', 32768)]
quarry_IMAGE_CHARACTERISTICS = quarry_two_way_dict(quarry_image_characteristics)
quarry_section_characteristics = [('IMAGE_SCN_TYPE_REG', 0), ('IMAGE_SCN_TYPE_DSECT', 1), ('IMAGE_SCN_TYPE_NOLOAD', 2), ('IMAGE_SCN_TYPE_GROUP', 4), ('IMAGE_SCN_TYPE_NO_PAD', 8), ('IMAGE_SCN_TYPE_COPY', 16), ('IMAGE_SCN_CNT_CODE', 32), ('IMAGE_SCN_CNT_INITIALIZED_DATA', 64), ('IMAGE_SCN_CNT_UNINITIALIZED_DATA', 128), ('IMAGE_SCN_LNK_OTHER', 256), ('IMAGE_SCN_LNK_INFO', 512), ('IMAGE_SCN_LNK_OVER', 1024), ('IMAGE_SCN_LNK_REMOVE', 2048), ('IMAGE_SCN_LNK_COMDAT', 4096), ('IMAGE_SCN_MEM_PROTECTED', 16384), ('IMAGE_SCN_NO_DEFER_SPEC_EXC', 16384), ('IMAGE_SCN_GPREL', 32768), ('IMAGE_SCN_MEM_FARDATA', 32768), ('IMAGE_SCN_MEM_SYSHEAP', 65536), ('IMAGE_SCN_MEM_PURGEABLE', 131072), ('IMAGE_SCN_MEM_16BIT', 131072), ('IMAGE_SCN_MEM_LOCKED', 262144), ('IMAGE_SCN_MEM_PRELOAD', 524288), ('IMAGE_SCN_ALIGN_1BYTES', 1048576), ('IMAGE_SCN_ALIGN_2BYTES', 2097152), ('IMAGE_SCN_ALIGN_4BYTES', 3145728), ('IMAGE_SCN_ALIGN_8BYTES', 4194304), ('IMAGE_SCN_ALIGN_16BYTES', 5242880), ('IMAGE_SCN_ALIGN_32BYTES', 6291456), ('IMAGE_SCN_ALIGN_64BYTES', 7340032), ('IMAGE_SCN_ALIGN_128BYTES', 8388608), ('IMAGE_SCN_ALIGN_256BYTES', 9437184), ('IMAGE_SCN_ALIGN_512BYTES', 10485760), ('IMAGE_SCN_ALIGN_1024BYTES', 11534336), ('IMAGE_SCN_ALIGN_2048BYTES', 12582912), ('IMAGE_SCN_ALIGN_4096BYTES', 13631488), ('IMAGE_SCN_ALIGN_8192BYTES', 14680064), ('IMAGE_SCN_ALIGN_MASK', 15728640), ('IMAGE_SCN_LNK_NRELOC_OVFL', 16777216), ('IMAGE_SCN_MEM_DISCARDABLE', 33554432), ('IMAGE_SCN_MEM_NOT_CACHED', 67108864), ('IMAGE_SCN_MEM_NOT_PAGED', 134217728), ('IMAGE_SCN_MEM_SHARED', 268435456), ('IMAGE_SCN_MEM_EXECUTE', 536870912), ('IMAGE_SCN_MEM_READ', 1073741824), ('IMAGE_SCN_MEM_WRITE', 2147483648)]
quarry_SECTION_CHARACTERISTICS = quarry_two_way_dict(quarry_section_characteristics)
quarry_debug_types = [('IMAGE_DEBUG_TYPE_UNKNOWN', 0), ('IMAGE_DEBUG_TYPE_COFF', 1), ('IMAGE_DEBUG_TYPE_CODEVIEW', 2), ('IMAGE_DEBUG_TYPE_FPO', 3), ('IMAGE_DEBUG_TYPE_MISC', 4), ('IMAGE_DEBUG_TYPE_EXCEPTION', 5), ('IMAGE_DEBUG_TYPE_FIXUP', 6), ('IMAGE_DEBUG_TYPE_OMAP_TO_SRC', 7), ('IMAGE_DEBUG_TYPE_OMAP_FROM_SRC', 8), ('IMAGE_DEBUG_TYPE_BORLAND', 9), ('IMAGE_DEBUG_TYPE_RESERVED10', 10), ('IMAGE_DEBUG_TYPE_CLSID', 11), ('IMAGE_DEBUG_TYPE_VC_FEATURE', 12), ('IMAGE_DEBUG_TYPE_POGO', 13), ('IMAGE_DEBUG_TYPE_ILTCG', 14), ('IMAGE_DEBUG_TYPE_MPX', 15), ('IMAGE_DEBUG_TYPE_REPRO', 16), ('IMAGE_DEBUG_TYPE_EX_DLLCHARACTERISTICS', 20)]
quarry_DEBUG_TYPE = quarry_two_way_dict(quarry_debug_types)
quarry_subsystem_types = [('IMAGE_SUBSYSTEM_UNKNOWN', 0), ('IMAGE_SUBSYSTEM_NATIVE', 1), ('IMAGE_SUBSYSTEM_WINDOWS_GUI', 2), ('IMAGE_SUBSYSTEM_WINDOWS_CUI', 3), ('IMAGE_SUBSYSTEM_OS2_CUI', 5), ('IMAGE_SUBSYSTEM_POSIX_CUI', 7), ('IMAGE_SUBSYSTEM_NATIVE_WINDOWS', 8), ('IMAGE_SUBSYSTEM_WINDOWS_CE_GUI', 9), ('IMAGE_SUBSYSTEM_EFI_APPLICATION', 10), ('IMAGE_SUBSYSTEM_EFI_BOOT_SERVICE_DRIVER', 11), ('IMAGE_SUBSYSTEM_EFI_RUNTIME_DRIVER', 12), ('IMAGE_SUBSYSTEM_EFI_ROM', 13), ('IMAGE_SUBSYSTEM_XBOX', 14), ('IMAGE_SUBSYSTEM_WINDOWS_BOOT_APPLICATION', 16), ('IMAGE_SUBSYSTEM_XBOX_CODE_CATALOG', 17)]
quarry_SUBSYSTEM_TYPE = quarry_two_way_dict(quarry_subsystem_types)
quarry_machine_types = [('IMAGE_FILE_MACHINE_UNKNOWN', 0), ('IMAGE_FILE_MACHINE_I386', 332), ('IMAGE_FILE_MACHINE_R3000BE', 352), ('IMAGE_FILE_MACHINE_R3000', 354), ('IMAGE_FILE_MACHINE_R4000', 358), ('IMAGE_FILE_MACHINE_R10000', 360), ('IMAGE_FILE_MACHINE_WCEMIPSV2', 361), ('IMAGE_FILE_MACHINE_ALPHA', 388), ('IMAGE_FILE_MACHINE_SH3', 418), ('IMAGE_FILE_MACHINE_SH3DSP', 419), ('IMAGE_FILE_MACHINE_SH3E', 420), ('IMAGE_FILE_MACHINE_SH4', 422), ('IMAGE_FILE_MACHINE_SH5', 424), ('IMAGE_FILE_MACHINE_ARM', 448), ('IMAGE_FILE_MACHINE_THUMB', 450), ('IMAGE_FILE_MACHINE_ARMNT', 452), ('IMAGE_FILE_MACHINE_AM33', 467), ('IMAGE_FILE_MACHINE_POWERPC', 496), ('IMAGE_FILE_MACHINE_POWERPCFP', 497), ('IMAGE_FILE_MACHINE_IA64', 512), ('IMAGE_FILE_MACHINE_MIPS16', 614), ('IMAGE_FILE_MACHINE_ALPHA64', 644), ('IMAGE_FILE_MACHINE_AXP64', 644), ('IMAGE_FILE_MACHINE_MIPSFPU', 870), ('IMAGE_FILE_MACHINE_MIPSFPU16', 1126), ('IMAGE_FILE_MACHINE_TRICORE', 1312), ('IMAGE_FILE_MACHINE_CEF', 3311), ('IMAGE_FILE_MACHINE_EBC', 3772), ('IMAGE_FILE_MACHINE_RISCV32', 20530), ('IMAGE_FILE_MACHINE_RISCV64', 20580), ('IMAGE_FILE_MACHINE_RISCV128', 20776), ('IMAGE_FILE_MACHINE_LOONGARCH32', 25138), ('IMAGE_FILE_MACHINE_LOONGARCH64', 25188), ('IMAGE_FILE_MACHINE_AMD64', 34404), ('IMAGE_FILE_MACHINE_M32R', 36929), ('IMAGE_FILE_MACHINE_ARM64', 43620), ('IMAGE_FILE_MACHINE_CEE', 49390)]
quarry_MACHINE_TYPE = quarry_two_way_dict(quarry_machine_types)
quarry_relocation_types = [('IMAGE_REL_BASED_ABSOLUTE', 0), ('IMAGE_REL_BASED_HIGH', 1), ('IMAGE_REL_BASED_LOW', 2), ('IMAGE_REL_BASED_HIGHLOW', 3), ('IMAGE_REL_BASED_HIGHADJ', 4), ('IMAGE_REL_BASED_MIPS_JMPADDR', 5), ('IMAGE_REL_BASED_SECTION', 6), ('IMAGE_REL_BASED_REL', 7), ('IMAGE_REL_BASED_MIPS_JMPADDR16', 9), ('IMAGE_REL_BASED_IA64_IMM64', 9), ('IMAGE_REL_BASED_DIR64', 10), ('IMAGE_REL_BASED_HIGH3ADJ', 11)]
quarry_RELOCATION_TYPE = quarry_two_way_dict(quarry_relocation_types)
quarry_dll_characteristics = [('IMAGE_LIBRARY_PROCESS_INIT', 1), ('IMAGE_LIBRARY_PROCESS_TERM', 2), ('IMAGE_LIBRARY_THREAD_INIT', 4), ('IMAGE_LIBRARY_THREAD_TERM', 8), ('IMAGE_DLLCHARACTERISTICS_HIGH_ENTROPY_VA', 32), ('IMAGE_DLLCHARACTERISTICS_DYNAMIC_BASE', 64), ('IMAGE_DLLCHARACTERISTICS_FORCE_INTEGRITY', 128), ('IMAGE_DLLCHARACTERISTICS_NX_COMPAT', 256), ('IMAGE_DLLCHARACTERISTICS_NO_ISOLATION', 512), ('IMAGE_DLLCHARACTERISTICS_NO_SEH', 1024), ('IMAGE_DLLCHARACTERISTICS_NO_BIND', 2048), ('IMAGE_DLLCHARACTERISTICS_APPCONTAINER', 4096), ('IMAGE_DLLCHARACTERISTICS_WDM_DRIVER', 8192), ('IMAGE_DLLCHARACTERISTICS_GUARD_CF', 16384), ('IMAGE_DLLCHARACTERISTICS_TERMINAL_SERVER_AWARE', 32768)]
quarry_DLL_CHARACTERISTICS = quarry_two_way_dict(quarry_dll_characteristics)
quarry_ex_dll_characteristics = [('IMAGE_DLLCHARACTERISTICS_EX_CET_COMPAT', 1), ('IMAGE_DLLCHARACTERISTICS_EX_CET_COMPAT_STRICT_MODE', 2), ('IMAGE_DLLCHARACTERISTICS_EX_CET_SET_CONTEXT_IP_VALIDATION_RELAXED_MODE', 4), ('IMAGE_DLLCHARACTERISTICS_EX_CET_DYNAMIC_APIS_ALLOW_IN_PROC', 8), ('IMAGE_DLLCHARACTERISTICS_EX_CET_RESERVED_1', 16), ('IMAGE_DLLCHARACTERISTICS_EX_CET_RESERVED_2', 32)]
quarry_EX_DLL_CHARACTERISTICS = quarry_two_way_dict(quarry_ex_dll_characteristics)
quarry_unwind_info_flags = [('UNW_FLAG_EHANDLER', 1), ('UNW_FLAG_UHANDLER', 2), ('UNW_FLAG_CHAININFO', 4)]
quarry_UNWIND_INFO_FLAGS = quarry_two_way_dict(quarry_unwind_info_flags)
quarry_registers = [('RAX', 0), ('RCX', 1), ('RDX', 2), ('RBX', 3), ('RSP', 4), ('RBP', 5), ('RSI', 6), ('RDI', 7), ('R8', 8), ('R9', 9), ('R10', 10), ('R11', 11), ('R12', 12), ('R13', 13), ('R14', 14), ('R15', 15)]
quarry_REGISTERS = quarry_two_way_dict(quarry_registers)
quarry_UWOP_PUSH_NONVOL = 0
quarry_UWOP_ALLOC_LARGE = 1
quarry_UWOP_ALLOC_SMALL = 2
quarry_UWOP_SET_FPREG = 3
quarry_UWOP_SAVE_NONVOL = 4
quarry_UWOP_SAVE_NONVOL_FAR = 5
quarry_UWOP_EPILOG = 6
quarry_UWOP_SAVE_XMM128 = 8
quarry_UWOP_SAVE_XMM128_FAR = 9
quarry_UWOP_PUSH_MACHFRAME = 10
quarry_resource_type = [('RT_CURSOR', 1), ('RT_BITMAP', 2), ('RT_ICON', 3), ('RT_MENU', 4), ('RT_DIALOG', 5), ('RT_STRING', 6), ('RT_FONTDIR', 7), ('RT_FONT', 8), ('RT_ACCELERATOR', 9), ('RT_RCDATA', 10), ('RT_MESSAGETABLE', 11), ('RT_GROUP_CURSOR', 12), ('RT_GROUP_ICON', 14), ('RT_VERSION', 16), ('RT_DLGINCLUDE', 17), ('RT_PLUGPLAY', 19), ('RT_VXD', 20), ('RT_ANICURSOR', 21), ('RT_ANIICON', 22), ('RT_HTML', 23), ('RT_MANIFEST', 24)]
quarry_RESOURCE_TYPE = quarry_two_way_dict(quarry_resource_type)
quarry_lang = [('LANG_NEUTRAL', 0), ('LANG_INVARIANT', 127), ('LANG_AFRIKAANS', 54), ('LANG_ALBANIAN', 28), ('LANG_ARABIC', 1), ('LANG_ARMENIAN', 43), ('LANG_ASSAMESE', 77), ('LANG_AZERI', 44), ('LANG_BASQUE', 45), ('LANG_BELARUSIAN', 35), ('LANG_BENGALI', 69), ('LANG_BULGARIAN', 2), ('LANG_CATALAN', 3), ('LANG_CHINESE', 4), ('LANG_CROATIAN', 26), ('LANG_CZECH', 5), ('LANG_DANISH', 6), ('LANG_DIVEHI', 101), ('LANG_DUTCH', 19), ('LANG_ENGLISH', 9), ('LANG_ESTONIAN', 37), ('LANG_FAEROESE', 56), ('LANG_FARSI', 41), ('LANG_FINNISH', 11), ('LANG_FRENCH', 12), ('LANG_GALICIAN', 86), ('LANG_GEORGIAN', 55), ('LANG_GERMAN', 7), ('LANG_GREEK', 8), ('LANG_GUJARATI', 71), ('LANG_HEBREW', 13), ('LANG_HINDI', 57), ('LANG_HUNGARIAN', 14), ('LANG_ICELANDIC', 15), ('LANG_INDONESIAN', 33), ('LANG_ITALIAN', 16), ('LANG_JAPANESE', 17), ('LANG_KANNADA', 75), ('LANG_KASHMIRI', 96), ('LANG_KAZAK', 63), ('LANG_KONKANI', 87), ('LANG_KOREAN', 18), ('LANG_KYRGYZ', 64), ('LANG_LATVIAN', 38), ('LANG_LITHUANIAN', 39), ('LANG_MACEDONIAN', 47), ('LANG_MALAY', 62), ('LANG_MALAYALAM', 76), ('LANG_MANIPURI', 88), ('LANG_MARATHI', 78), ('LANG_MONGOLIAN', 80), ('LANG_NEPALI', 97), ('LANG_NORWEGIAN', 20), ('LANG_ORIYA', 72), ('LANG_POLISH', 21), ('LANG_PORTUGUESE', 22), ('LANG_PUNJABI', 70), ('LANG_ROMANIAN', 24), ('LANG_RUSSIAN', 25), ('LANG_SANSKRIT', 79), ('LANG_SERBIAN', 26), ('LANG_SINDHI', 89), ('LANG_SLOVAK', 27), ('LANG_SLOVENIAN', 36), ('LANG_SPANISH', 10), ('LANG_SWAHILI', 65), ('LANG_SWEDISH', 29), ('LANG_SYRIAC', 90), ('LANG_TAMIL', 73), ('LANG_TATAR', 68), ('LANG_TELUGU', 74), ('LANG_THAI', 30), ('LANG_TURKISH', 31), ('LANG_UKRAINIAN', 34), ('LANG_URDU', 32), ('LANG_UZBEK', 67), ('LANG_VIETNAMESE', 42), ('LANG_GAELIC', 60), ('LANG_MALTESE', 58), ('LANG_MAORI', 40), ('LANG_RHAETO_ROMANCE', 23), ('LANG_SAAMI', 59), ('LANG_SORBIAN', 46), ('LANG_SUTU', 48), ('LANG_TSONGA', 49), ('LANG_TSWANA', 50), ('LANG_VENDA', 51), ('LANG_XHOSA', 52), ('LANG_ZULU', 53), ('LANG_ESPERANTO', 143), ('LANG_WALON', 144), ('LANG_CORNISH', 145), ('LANG_WELSH', 146), ('LANG_BRETON', 147)]
quarry_LANG = quarry_two_way_dict(quarry_lang)
quarry_sublang = [('SUBLANG_NEUTRAL', 0), ('SUBLANG_DEFAULT', 1), ('SUBLANG_SYS_DEFAULT', 2), ('SUBLANG_ARABIC_SAUDI_ARABIA', 1), ('SUBLANG_ARABIC_IRAQ', 2), ('SUBLANG_ARABIC_EGYPT', 3), ('SUBLANG_ARABIC_LIBYA', 4), ('SUBLANG_ARABIC_ALGERIA', 5), ('SUBLANG_ARABIC_MOROCCO', 6), ('SUBLANG_ARABIC_TUNISIA', 7), ('SUBLANG_ARABIC_OMAN', 8), ('SUBLANG_ARABIC_YEMEN', 9), ('SUBLANG_ARABIC_SYRIA', 10), ('SUBLANG_ARABIC_JORDAN', 11), ('SUBLANG_ARABIC_LEBANON', 12), ('SUBLANG_ARABIC_KUWAIT', 13), ('SUBLANG_ARABIC_UAE', 14), ('SUBLANG_ARABIC_BAHRAIN', 15), ('SUBLANG_ARABIC_QATAR', 16), ('SUBLANG_AZERI_LATIN', 1), ('SUBLANG_AZERI_CYRILLIC', 2), ('SUBLANG_CHINESE_TRADITIONAL', 1), ('SUBLANG_CHINESE_SIMPLIFIED', 2), ('SUBLANG_CHINESE_HONGKONG', 3), ('SUBLANG_CHINESE_SINGAPORE', 4), ('SUBLANG_CHINESE_MACAU', 5), ('SUBLANG_DUTCH', 1), ('SUBLANG_DUTCH_BELGIAN', 2), ('SUBLANG_ENGLISH_US', 1), ('SUBLANG_ENGLISH_UK', 2), ('SUBLANG_ENGLISH_AUS', 3), ('SUBLANG_ENGLISH_CAN', 4), ('SUBLANG_ENGLISH_NZ', 5), ('SUBLANG_ENGLISH_EIRE', 6), ('SUBLANG_ENGLISH_SOUTH_AFRICA', 7), ('SUBLANG_ENGLISH_JAMAICA', 8), ('SUBLANG_ENGLISH_CARIBBEAN', 9), ('SUBLANG_ENGLISH_BELIZE', 10), ('SUBLANG_ENGLISH_TRINIDAD', 11), ('SUBLANG_ENGLISH_ZIMBABWE', 12), ('SUBLANG_ENGLISH_PHILIPPINES', 13), ('SUBLANG_FRENCH', 1), ('SUBLANG_FRENCH_BELGIAN', 2), ('SUBLANG_FRENCH_CANADIAN', 3), ('SUBLANG_FRENCH_SWISS', 4), ('SUBLANG_FRENCH_LUXEMBOURG', 5), ('SUBLANG_FRENCH_MONACO', 6), ('SUBLANG_GERMAN', 1), ('SUBLANG_GERMAN_SWISS', 2), ('SUBLANG_GERMAN_AUSTRIAN', 3), ('SUBLANG_GERMAN_LUXEMBOURG', 4), ('SUBLANG_GERMAN_LIECHTENSTEIN', 5), ('SUBLANG_ITALIAN', 1), ('SUBLANG_ITALIAN_SWISS', 2), ('SUBLANG_KASHMIRI_SASIA', 2), ('SUBLANG_KASHMIRI_INDIA', 2), ('SUBLANG_KOREAN', 1), ('SUBLANG_LITHUANIAN', 1), ('SUBLANG_MALAY_MALAYSIA', 1), ('SUBLANG_MALAY_BRUNEI_DARUSSALAM', 2), ('SUBLANG_NEPALI_INDIA', 2), ('SUBLANG_NORWEGIAN_BOKMAL', 1), ('SUBLANG_NORWEGIAN_NYNORSK', 2), ('SUBLANG_PORTUGUESE', 2), ('SUBLANG_PORTUGUESE_BRAZILIAN', 1), ('SUBLANG_SERBIAN_LATIN', 2), ('SUBLANG_SERBIAN_CYRILLIC', 3), ('SUBLANG_SPANISH', 1), ('SUBLANG_SPANISH_MEXICAN', 2), ('SUBLANG_SPANISH_MODERN', 3), ('SUBLANG_SPANISH_GUATEMALA', 4), ('SUBLANG_SPANISH_COSTA_RICA', 5), ('SUBLANG_SPANISH_PANAMA', 6), ('SUBLANG_SPANISH_DOMINICAN_REPUBLIC', 7), ('SUBLANG_SPANISH_VENEZUELA', 8), ('SUBLANG_SPANISH_COLOMBIA', 9), ('SUBLANG_SPANISH_PERU', 10), ('SUBLANG_SPANISH_ARGENTINA', 11), ('SUBLANG_SPANISH_ECUADOR', 12), ('SUBLANG_SPANISH_CHILE', 13), ('SUBLANG_SPANISH_URUGUAY', 14), ('SUBLANG_SPANISH_PARAGUAY', 15), ('SUBLANG_SPANISH_BOLIVIA', 16), ('SUBLANG_SPANISH_EL_SALVADOR', 17), ('SUBLANG_SPANISH_HONDURAS', 18), ('SUBLANG_SPANISH_NICARAGUA', 19), ('SUBLANG_SPANISH_PUERTO_RICO', 20), ('SUBLANG_SWEDISH', 1), ('SUBLANG_SWEDISH_FINLAND', 2), ('SUBLANG_URDU_PAKISTAN', 1), ('SUBLANG_URDU_INDIA', 2), ('SUBLANG_UZBEK_LATIN', 1), ('SUBLANG_UZBEK_CYRILLIC', 2), ('SUBLANG_DUTCH_SURINAM', 3), ('SUBLANG_ROMANIAN', 1), ('SUBLANG_ROMANIAN_MOLDAVIA', 2), ('SUBLANG_RUSSIAN', 1), ('SUBLANG_RUSSIAN_MOLDAVIA', 2), ('SUBLANG_CROATIAN', 1), ('SUBLANG_LITHUANIAN_CLASSIC', 2), ('SUBLANG_GAELIC', 1), ('SUBLANG_GAELIC_SCOTTISH', 2), ('SUBLANG_GAELIC_MANX', 3)]
quarry_SUBLANG = dict(quarry_sublang)
for quarry_sublang_name, quarry_sublang_value in quarry_sublang:
    if quarry_sublang_value in quarry_SUBLANG:
        quarry_SUBLANG[quarry_sublang_value].append(quarry_sublang_name)
    else:
        quarry_SUBLANG[quarry_sublang_value] = [quarry_sublang_name]

@_name_boundary.callable_contract({'lang_value': 'quarry_lang_value_49d1fa9', 'sublang_value': 'quarry_sublang_value_f42ac4f'}, 'get_sublang_name_for_lang')
def quarry_get_sublang_name_for_lang(quarry_lang_value_49d1fa9, quarry_sublang_value_f42ac4f):
    quarry_lang_name_9431f62 = quarry_LANG.get(quarry_lang_value_49d1fa9, '*unknown*')
    for quarry_sublang_name_6fb4504 in quarry_SUBLANG.get(quarry_sublang_value_f42ac4f, []):
        if quarry_lang_name_9431f62 in quarry_sublang_name_6fb4504:
            return quarry_sublang_name_6fb4504
    return quarry_SUBLANG.get(quarry_sublang_value_f42ac4f, ['*unknown*'])[0]

@_name_boundary.callable_contract({'counter': 'quarry_counter_d31841a', 'l': 'quarry_l_750496d', 'data': 'quarry_data_local_1598bae'}, 'parse_strings')
def quarry_parse_strings(quarry_data_local_1598bae, quarry_counter_d31841a, quarry_l_750496d):
    quarry_i_86338e5 = 0
    quarry_error_count_a163065 = 0
    while quarry_i_86338e5 < len(quarry_data_local_1598bae):
        quarry_data_slice_94b07cd = quarry_data_local_1598bae[quarry_i_86338e5:quarry_i_86338e5 + 2]
        if len(quarry_data_slice_94b07cd) < 2:
            break
        quarry_len__1b3ffea = quarry_struct.unpack('<h', quarry_data_slice_94b07cd)[0]
        quarry_i_86338e5 += 2
        if 0 < quarry_len__1b3ffea * 2 <= len(quarry_data_local_1598bae):
            try:
                quarry_l_750496d[quarry_counter_d31841a] = _name_boundary.attributes(quarry_data_local_1598bae[quarry_i_86338e5:quarry_i_86338e5 + quarry_len__1b3ffea * 2])['decode']('utf-16le')
            except UnicodeDecodeError:
                quarry_error_count_a163065 += 1
            if quarry_error_count_a163065 >= 3:
                break
            quarry_i_86338e5 += quarry_len__1b3ffea * 2
        quarry_counter_d31841a += 1

@_name_boundary.callable_contract({'flag_dict': 'quarry_flag_dict_d7409d2', 'flag_filter': 'quarry_flag_filter_cdd1044'}, 'retrieve_flags')
def quarry_retrieve_flags(quarry_flag_dict_d7409d2, quarry_flag_filter_cdd1044):
    """Read the flags from a dictionary and return them in a usable form.

    Will return a list of (flag, value) for all flags in "flag_dict"
    matching the filter "flag_filter".
    """
    return [(quarry_flag_e257291, quarry_value_ef3821f) for quarry_flag_e257291, quarry_value_ef3821f in quarry_flag_dict_d7409d2.items() if isinstance(quarry_flag_e257291, (str, bytes)) and quarry_flag_e257291.startswith(quarry_flag_filter_cdd1044)]

@_name_boundary.callable_contract({'obj': 'quarry_obj_b3f3430', 'flag_field': 'quarry_flag_field_771b01f', 'flags': 'quarry_flags_545237c'}, 'set_flags')
def quarry_set_flags(quarry_obj_b3f3430, quarry_flag_field_771b01f, quarry_flags_545237c):
    """Will process the flags and set attributes in the object accordingly.

    The object "obj" will gain attributes named after the flags provided in
    "flags" and valued True/False, matching the results of applying each
    flag value from "flags" to flag_field.
    """
    for quarry_flag_7660b97, quarry_value_5441a42 in quarry_flags_545237c:
        if quarry_value_5441a42 & quarry_flag_field_771b01f:
            _name_boundary.namespace_view(quarry_obj_b3f3430)[quarry_flag_7660b97] = True
        else:
            _name_boundary.namespace_view(quarry_obj_b3f3430)[quarry_flag_7660b97] = False

@_name_boundary.callable_contract({'val': 'quarry_val_b68b9fe'}, 'power_of_two')
def quarry_power_of_two(quarry_val_b68b9fe):
    return quarry_val_b68b9fe != 0 and quarry_val_b68b9fe & quarry_val_b68b9fe - 1 == 0

@_name_boundary.class_contract('AddressSet', {'add': 'quarry_add', 'diff': 'quarry_diff', 'min': 'quarry_min', 'max': 'quarry_max'})
class quarry_AddressSet(set):

    @_name_boundary.callable_contract({'self': 'quarry_self_42cfe43'}, '__init__')
    def __init__(quarry_self_42cfe43):
        super().__init__()
        _name_boundary.attributes(quarry_self_42cfe43)['min'] = None
        _name_boundary.attributes(quarry_self_42cfe43)['max'] = None

    @_name_boundary.callable_contract({'self': 'quarry_self_63d5adb', 'value': 'quarry_value_14f2551'}, 'add')
    def quarry_add(quarry_self_63d5adb, quarry_value_14f2551):
        _name_boundary.attributes(super())['add'](quarry_value_14f2551)
        _name_boundary.attributes(quarry_self_63d5adb)['min'] = quarry_value_14f2551 if _name_boundary.attributes(quarry_self_63d5adb)['min'] is None else min(_name_boundary.attributes(quarry_self_63d5adb)['min'], quarry_value_14f2551)
        _name_boundary.attributes(quarry_self_63d5adb)['max'] = quarry_value_14f2551 if _name_boundary.attributes(quarry_self_63d5adb)['max'] is None else max(_name_boundary.attributes(quarry_self_63d5adb)['max'], quarry_value_14f2551)

    @_name_boundary.callable_contract({'self': 'quarry_self_10e95eb'}, 'diff')
    def quarry_diff(quarry_self_10e95eb):
        return 0 if _name_boundary.attributes(quarry_self_10e95eb)['min'] is None or _name_boundary.attributes(quarry_self_10e95eb)['max'] is None else _name_boundary.attributes(quarry_self_10e95eb)['max'] - _name_boundary.attributes(quarry_self_10e95eb)['min']

@_name_boundary.class_contract('UnicodeStringWrapperPostProcessor', {'get_rva': 'quarry_get_rva', 'decode': 'quarry_decode', 'invalidate': 'quarry_invalidate', 'render_pascal_16': 'quarry_render_pascal_16', 'get_pascal_16_length': 'quarry_get_pascal_16_length', '__get_word_value_at_rva': 'quarry___get_word_value_at_rva', 'ask_unicode_16': 'quarry_ask_unicode_16', 'render_unicode_16': 'quarry_render_unicode_16', 'rva_ptr': 'quarry_rva_ptr', 'string': 'quarry_string', 'length': 'quarry_length'})
class quarry_UnicodeStringWrapperPostProcessor:
    """This class attempts to help the process of identifying strings
    that might be plain Unicode or Pascal. A list of strings will be
    wrapped on it with the hope the overlappings will help make the
    decision about their type."""

    @_name_boundary.callable_contract({'self': 'quarry_self_f145250', 'rva_ptr': 'quarry_rva_ptr_d19f29f', 'pe': 'quarry_pe_local_cb2ae84'}, '__init__')
    def __init__(quarry_self_f145250, quarry_pe_local_cb2ae84, quarry_rva_ptr_d19f29f):
        quarry_self_f145250.pe = quarry_pe_local_cb2ae84
        _name_boundary.attributes(quarry_self_f145250)['rva_ptr'] = quarry_rva_ptr_d19f29f
        _name_boundary.attributes(quarry_self_f145250)['string'] = None

    @_name_boundary.callable_contract({'self': 'quarry_self_b190499'}, 'get_rva')
    def quarry_get_rva(quarry_self_b190499):
        """Get the RVA of the string."""
        return _name_boundary.attributes(quarry_self_b190499)['rva_ptr']

    @_name_boundary.callable_contract({'self': 'quarry_self_4c5e647'}, '__str__')
    def __str__(quarry_self_4c5e647):
        """Return the escaped UTF-8 representation of the string."""
        return _name_boundary.attributes(quarry_self_4c5e647)['decode']('utf-8', 'backslashreplace_')

    @_name_boundary.callable_contract({'self': 'quarry_self_fd9142f', 'args': 'quarry_args_803650e'}, 'decode')
    def quarry_decode(quarry_self_fd9142f, *quarry_args_803650e):
        if not _name_boundary.attributes(quarry_self_fd9142f)['string']:
            return ''
        return _name_boundary.attributes(_name_boundary.attributes(quarry_self_fd9142f)['string'])['decode'](*quarry_args_803650e)

    @_name_boundary.callable_contract({'self': 'quarry_self_f24add7'}, 'invalidate')
    def quarry_invalidate(quarry_self_f24add7):
        """Make this instance None, to express it's no known string type."""
        quarry_self_f24add7 = None

    @_name_boundary.callable_contract({'self': 'quarry_self_058a03d'}, 'render_pascal_16')
    def quarry_render_pascal_16(quarry_self_058a03d):
        try:
            _name_boundary.attributes(quarry_self_058a03d)['string'] = _name_boundary.attributes(quarry_self_058a03d.pe)['get_string_u_at_rva'](_name_boundary.attributes(quarry_self_058a03d)['rva_ptr'] + 2, max_length=_name_boundary.attributes(quarry_self_058a03d)['get_pascal_16_length']())
        except quarry_PEFormatError:
            _name_boundary.attributes(quarry_self_058a03d.pe)['get_warnings']().append(f"Failed rendering pascal string, attempting to read from RVA {_name_boundary.attributes(quarry_self_058a03d)['rva_ptr'] + 2:#x}")

    @_name_boundary.callable_contract({'self': 'quarry_self_65937dd'}, 'get_pascal_16_length')
    def quarry_get_pascal_16_length(quarry_self_65937dd):
        return _name_boundary.attributes(quarry_self_65937dd)['__get_word_value_at_rva'](_name_boundary.attributes(quarry_self_65937dd)['rva_ptr'])

    @_name_boundary.callable_contract({'self': 'quarry_self_ef57d54', 'rva': 'quarry_rva_6d15d49'}, '__get_word_value_at_rva')
    def quarry___get_word_value_at_rva(quarry_self_ef57d54, quarry_rva_6d15d49):
        try:
            quarry_data_local_c43433f = _name_boundary.attributes(quarry_self_ef57d54.pe)['get_data'](quarry_rva_6d15d49, 2)
        except quarry_PEFormatError:
            return False
        if len(quarry_data_local_c43433f) < 2:
            return False
        return quarry_struct.unpack('<H', quarry_data_local_c43433f)[0]

    @_name_boundary.callable_contract({'self': 'quarry_self_e6e38e9', 'next_rva_ptr': 'quarry_next_rva_ptr_f002703'}, 'ask_unicode_16')
    def quarry_ask_unicode_16(quarry_self_e6e38e9, quarry_next_rva_ptr_f002703):
        """The next RVA is taken to be the one immediately following this one.

        Such RVA could indicate the natural end of the string and will be checked
        to see if there's a Unicode NULL character there.
        """
        if _name_boundary.attributes(quarry_self_e6e38e9)['__get_word_value_at_rva'](quarry_next_rva_ptr_f002703 - 2) == 0:
            _name_boundary.attributes(quarry_self_e6e38e9)['length'] = quarry_next_rva_ptr_f002703 - _name_boundary.attributes(quarry_self_e6e38e9)['rva_ptr']
            return True
        return False

    @_name_boundary.callable_contract({'self': 'quarry_self_13f0364'}, 'render_unicode_16')
    def quarry_render_unicode_16(quarry_self_13f0364):
        try:
            _name_boundary.attributes(quarry_self_13f0364)['string'] = _name_boundary.attributes(quarry_self_13f0364.pe)['get_string_u_at_rva'](_name_boundary.attributes(quarry_self_13f0364)['rva_ptr'])
        except quarry_PEFormatError:
            _name_boundary.attributes(quarry_self_13f0364.pe)['get_warnings']().append(f"Failed rendering unicode string, attempting to read from RVA {_name_boundary.attributes(quarry_self_13f0364)['rva_ptr']:#x}")

@_name_boundary.class_contract('PEFormatError', {'value': 'quarry_value'})
class quarry_PEFormatError(Exception):
    """Generic PE format error exception."""

    @_name_boundary.callable_contract({'self': 'quarry_self_95c6dac', 'value': 'quarry_value_720263a'}, '__init__')
    def __init__(quarry_self_95c6dac, quarry_value_720263a):
        _name_boundary.attributes(quarry_self_95c6dac)['value'] = quarry_value_720263a

    @_name_boundary.callable_contract({'self': 'quarry_self_06cba00'}, '__str__')
    def __str__(quarry_self_06cba00):
        return repr(_name_boundary.attributes(quarry_self_06cba00)['value'])

@_name_boundary.class_contract('Dump', {'add_lines': 'quarry_add_lines', 'add_line': 'quarry_add_line', 'add': 'quarry_add', 'add_header': 'quarry_add_header', 'add_newline': 'quarry_add_newline', 'get_text': 'quarry_get_text', 'text': 'quarry_text'})
class quarry_Dump:
    """Convenience class for dumping the PE information."""

    @_name_boundary.callable_contract({'self': 'quarry_self_16dfcd8'}, '__init__')
    def __init__(quarry_self_16dfcd8):
        _name_boundary.attributes(quarry_self_16dfcd8)['text'] = []

    @_name_boundary.callable_contract({'self': 'quarry_self_4635aca', 'txt': 'quarry_txt_cdb7638', 'indent': 'quarry_indent_a470c1b'}, 'add_lines')
    def quarry_add_lines(quarry_self_4635aca, quarry_txt_cdb7638, quarry_indent_a470c1b=0):
        """Adds a list of lines.

        The list can be indented with the optional argument 'indent'.
        """
        for quarry_line_f0b0955 in quarry_txt_cdb7638:
            _name_boundary.attributes(quarry_self_4635aca)['add_line'](quarry_line_f0b0955, quarry_indent_a470c1b)

    @_name_boundary.callable_contract({'self': 'quarry_self_700952c', 'txt': 'quarry_txt_adf0959', 'indent': 'quarry_indent_9f2fc1a'}, 'add_line')
    def quarry_add_line(quarry_self_700952c, quarry_txt_adf0959, quarry_indent_9f2fc1a=0):
        """Adds a line.

        The line can be indented with the optional argument 'indent'.
        """
        _name_boundary.attributes(quarry_self_700952c)['add'](quarry_txt_adf0959 + '\n', quarry_indent_9f2fc1a)

    @_name_boundary.callable_contract({'self': 'quarry_self_50295a4', 'txt': 'quarry_txt_1c2c878', 'indent': 'quarry_indent_1dab5a9'}, 'add')
    def quarry_add(quarry_self_50295a4, quarry_txt_1c2c878, quarry_indent_1dab5a9=0):
        """Adds some text, no newline will be appended.

        The text can be indented with the optional argument 'indent'.
        """
        _name_boundary.attributes(quarry_self_50295a4)['text'].append(f"{' ' * quarry_indent_1dab5a9}{quarry_txt_1c2c878}")

    @_name_boundary.callable_contract({'self': 'quarry_self_bcf281f', 'txt': 'quarry_txt_46562ec'}, 'add_header')
    def quarry_add_header(quarry_self_bcf281f, quarry_txt_46562ec):
        """Adds a header element."""
        _name_boundary.attributes(quarry_self_bcf281f)['add_line']('{0}{1}{0}\n'.format('-' * 10, quarry_txt_46562ec))

    @_name_boundary.callable_contract({'self': 'quarry_self_e7201a4'}, 'add_newline')
    def quarry_add_newline(quarry_self_e7201a4):
        """Adds a newline."""
        _name_boundary.attributes(quarry_self_e7201a4)['text'].append('\n')

    @_name_boundary.callable_contract({'self': 'quarry_self_51ae1b8'}, 'get_text')
    def quarry_get_text(quarry_self_51ae1b8):
        """Get the text in its current state."""
        return ''.join((f'{quarry_b_bcd3970}' for quarry_b_bcd3970 in _name_boundary.attributes(quarry_self_51ae1b8)['text']))
quarry_STRUCT_SIZEOF_TYPES = {'x': 1, 'c': 1, 'b': 1, 'B': 1, 'h': 2, 'H': 2, 'i': 4, 'I': 4, 'l': 4, 'L': 4, 'f': 4, 'q': 8, 'Q': 8, 'd': 8, 's': 1}

@quarry_lru_cache(maxsize=2048)
@_name_boundary.callable_contract({'t': 'quarry_t_4df6d58'}, 'sizeof_type')
def quarry_sizeof_type(quarry_t_4df6d58):
    quarry_count_c94f6a5 = 1
    quarry__t_0144376 = quarry_t_4df6d58
    if quarry_t_4df6d58[0] in quarry_string.digits:
        quarry_count_c94f6a5 = int(''.join((quarry_d_8fe4dad for quarry_d_8fe4dad in quarry_t_4df6d58 if quarry_d_8fe4dad in quarry_string.digits)))
        quarry__t_0144376 = ''.join((quarry_d_a2abc07 for quarry_d_a2abc07 in quarry_t_4df6d58 if quarry_d_a2abc07 not in quarry_string.digits))
    return quarry_STRUCT_SIZEOF_TYPES[quarry__t_0144376] * quarry_count_c94f6a5

@quarry_lru_cache_copy(maxsize=2048)
@_name_boundary.callable_contract({'format': 'quarry_format_3ddba9f'}, 'set_format')
def quarry_set_format(quarry_format_3ddba9f):
    __format_str__ = '<'
    __unpacked_data_elms__ = []
    __field_offsets__ = {}
    __keys__ = []
    __format_length__ = 0
    quarry_offset_local_e328244 = 0
    for quarry_elm_efeddc1 in quarry_format_3ddba9f:
        if ',' in quarry_elm_efeddc1:
            quarry_elm_type_cd2586c, quarry_elm_name_c3adb92 = quarry_elm_efeddc1.split(',', 1)
            __format_str__ += quarry_elm_type_cd2586c
            __unpacked_data_elms__.append(None)
            quarry_elm_names_d5038ce = quarry_elm_name_c3adb92.split(',')
            quarry_names_59a841d = []
            for quarry_elm_name_c3adb92 in quarry_elm_names_d5038ce:
                if quarry_elm_name_c3adb92 in __keys__:
                    quarry_search_list_29be45f = [quarry_x_fa1f8dd[:len(quarry_elm_name_c3adb92)] for quarry_x_fa1f8dd in __keys__]
                    quarry_occ_count_45be692 = quarry_search_list_29be45f.count(quarry_elm_name_c3adb92)
                    quarry_elm_name_c3adb92 = f'{quarry_elm_name_c3adb92}_{quarry_occ_count_45be692:d}'
                quarry_names_59a841d.append(quarry_elm_name_c3adb92)
                __field_offsets__[quarry_elm_name_c3adb92] = quarry_offset_local_e328244
            quarry_offset_local_e328244 += quarry_sizeof_type(quarry_elm_type_cd2586c)
            __keys__.append(quarry_names_59a841d)
    __format_length__ = quarry_struct.calcsize(__format_str__)
    return (__format_str__, __unpacked_data_elms__, __field_offsets__, __keys__, __format_length__)

@_name_boundary.class_contract('Structure', {'get_field_absolute_offset': 'quarry_get_field_absolute_offset', 'get_field_relative_offset': 'quarry_get_field_relative_offset', 'get_file_offset': 'quarry_get_file_offset', 'set_file_offset': 'quarry_set_file_offset', 'all_zeroes': 'quarry_all_zeroes', 'sizeof': 'quarry_sizeof', 'dump_dict': 'quarry_dump_dict'})
class quarry_Structure:
    """Prepare structure object to extract members from data.

    Format is a list containing definitions for the elements
    of the structure.
    """

    @_name_boundary.callable_contract({'self': 'quarry_self_4f7bdbc', 'format': 'quarry_format_631b126', 'file_offset': 'quarry_file_offset_d367c49', 'name': 'quarry_name_local_4ca0411'}, '__init__')
    def __init__(quarry_self_4f7bdbc, quarry_format_631b126, quarry_name_local_4ca0411=None, quarry_file_offset_d367c49=None):
        quarry_self_4f7bdbc.__format_str__ = '<'
        quarry_self_4f7bdbc.__unpacked_data_elms__ = []
        quarry_self_4f7bdbc.__field_offsets__ = {}
        quarry_self_4f7bdbc.__keys__ = []
        quarry_self_4f7bdbc.__format_length__ = 0
        quarry_d_86577e8 = quarry_format_631b126[1]
        if not isinstance(quarry_d_86577e8, tuple):
            quarry_d_86577e8 = tuple(quarry_d_86577e8)
        quarry_self_4f7bdbc.__format_str__, quarry_self_4f7bdbc.__unpacked_data_elms__, quarry_self_4f7bdbc.__field_offsets__, quarry_self_4f7bdbc.__keys__, quarry_self_4f7bdbc.__format_length__ = quarry_set_format(quarry_d_86577e8)
        if quarry_name_local_4ca0411:
            quarry_self_4f7bdbc.name = quarry_name_local_4ca0411
        else:
            quarry_self_4f7bdbc.name = quarry_format_631b126[0]
        quarry_self_4f7bdbc.__file_offset__ = quarry_file_offset_d367c49
        quarry_self_4f7bdbc.__all_zeroes__ = False

    @_name_boundary.callable_contract({'self': 'quarry_self_df39069'}, '__get_format__')
    def __get_format__(quarry_self_df39069) -> str:
        return quarry_self_df39069.__format_str__

    @_name_boundary.callable_contract({'self': 'quarry_self_f5324e0', 'field_name': 'quarry_field_name_e49fe26'}, 'get_field_absolute_offset')
    def quarry_get_field_absolute_offset(quarry_self_f5324e0, quarry_field_name_e49fe26):
        """Return the offset within the field for the requested field in the structure."""
        return quarry_self_f5324e0.__file_offset__ + quarry_self_f5324e0.__field_offsets__[quarry_field_name_e49fe26]

    @_name_boundary.callable_contract({'self': 'quarry_self_1ee674e', 'field_name': 'quarry_field_name_ed49d1c'}, 'get_field_relative_offset')
    def quarry_get_field_relative_offset(quarry_self_1ee674e, quarry_field_name_ed49d1c):
        """Return the offset within the structure for the requested field."""
        return quarry_self_1ee674e.__field_offsets__[quarry_field_name_ed49d1c]

    @_name_boundary.callable_contract({'self': 'quarry_self_2142d62'}, 'get_file_offset')
    def quarry_get_file_offset(quarry_self_2142d62):
        return quarry_self_2142d62.__file_offset__

    @_name_boundary.callable_contract({'self': 'quarry_self_63923e9', 'offset': 'quarry_offset_local_ae3df65'}, 'set_file_offset')
    def quarry_set_file_offset(quarry_self_63923e9, quarry_offset_local_ae3df65):
        quarry_self_63923e9.__file_offset__ = quarry_offset_local_ae3df65

    @_name_boundary.callable_contract({'self': 'quarry_self_afb79ee'}, 'all_zeroes')
    def quarry_all_zeroes(quarry_self_afb79ee):
        """Returns true if the unpacked data is all zeros."""
        return quarry_self_afb79ee.__all_zeroes__

    @_name_boundary.callable_contract({'self': 'quarry_self_353c699'}, 'sizeof')
    def quarry_sizeof(quarry_self_353c699):
        """Return size of the structure."""
        return quarry_self_353c699.__format_length__

    @_name_boundary.callable_contract({'self': 'quarry_self_5a59789', 'data': 'quarry_data_local_67c869e'}, '__unpack__')
    def __unpack__(quarry_self_5a59789, quarry_data_local_67c869e):
        if len(quarry_data_local_67c869e) > quarry_self_5a59789.__format_length__:
            quarry_data_local_67c869e = quarry_data_local_67c869e[:quarry_self_5a59789.__format_length__]
        elif len(quarry_data_local_67c869e) < quarry_self_5a59789.__format_length__:
            raise quarry_PEFormatError('Data length less than expected header length.')
        if quarry_count_zeroes(quarry_data_local_67c869e) == len(quarry_data_local_67c869e):
            quarry_self_5a59789.__all_zeroes__ = True
        quarry_self_5a59789.__unpacked_data_elms__ = quarry_struct.unpack(quarry_self_5a59789.__format_str__, quarry_data_local_67c869e)
        for quarry_idx_234c606, quarry_val_4cee2a4 in enumerate(quarry_self_5a59789.__unpacked_data_elms__):
            for quarry_key_f484d61 in quarry_self_5a59789.__keys__[quarry_idx_234c606]:
                _name_boundary.write_attribute(quarry_self_5a59789, quarry_key_f484d61, quarry_val_4cee2a4)

    @_name_boundary.callable_contract({'self': 'quarry_self_59ea8ff'}, '__pack__')
    def __pack__(quarry_self_59ea8ff):
        quarry_new_values_f9a8522 = []
        for quarry_idx_a6894b9, quarry_val_0d88f32 in enumerate(quarry_self_59ea8ff.__unpacked_data_elms__):
            quarry_new_val_9b04b2b = None
            for quarry_key_9f90531 in quarry_self_59ea8ff.__keys__[quarry_idx_a6894b9]:
                quarry_new_val_9b04b2b = _name_boundary.read_attribute(quarry_self_59ea8ff, quarry_key_9f90531)
                if quarry_new_val_9b04b2b != quarry_val_0d88f32:
                    break
            quarry_new_values_f9a8522.append(quarry_new_val_9b04b2b)
        return quarry_struct.pack(quarry_self_59ea8ff.__format_str__, *quarry_new_values_f9a8522)

    @_name_boundary.callable_contract({'self': 'quarry_self_8d91b17'}, '__str__')
    def __str__(quarry_self_8d91b17):
        return '\n'.join(quarry_self_8d91b17.dump())

    @_name_boundary.callable_contract({'self': 'quarry_self_dc8d9d2'}, '__repr__')
    def __repr__(quarry_self_dc8d9d2):
        return f"<Structure: {' '.join([' '.join(quarry_s_9752868.split()) for quarry_s_9752868 in quarry_self_dc8d9d2.dump()])}>"

    @_name_boundary.callable_contract({'self': 'quarry_self_9ff97e2', 'indentation': 'quarry_indentation_6584ed6'}, 'dump')
    def dump(quarry_self_9ff97e2, quarry_indentation_6584ed6=0):
        """Returns a string representation of the structure."""
        quarry_dump_local_7968f48 = [f'[{quarry_self_9ff97e2.name}]']
        quarry_printable_bytes_25f2145 = [ord(quarry_i_e10db90) for quarry_i_e10db90 in quarry_string.printable if quarry_i_e10db90 not in quarry_string.whitespace]
        for quarry_keys_6e3f880 in quarry_self_9ff97e2.__keys__:
            for quarry_key_872e61d in quarry_keys_6e3f880:
                quarry_val_c3d086f = _name_boundary.read_attribute(quarry_self_9ff97e2, quarry_key_872e61d)
                if isinstance(quarry_val_c3d086f, int):
                    if quarry_key_872e61d.startswith('Signature_'):
                        quarry_val_str_d7b370d = f'{quarry_val_c3d086f:<8X}'
                    else:
                        quarry_val_str_d7b370d = f'0x{quarry_val_c3d086f:<8X}'
                    if quarry_key_872e61d == 'TimeDateStamp' or quarry_key_872e61d == 'dwTimeStamp':
                        try:
                            quarry_val_str_d7b370d += f' [{quarry_time.asctime(quarry_time.gmtime(quarry_val_c3d086f))} UTC]'
                        except ValueError:
                            quarry_val_str_d7b370d += ' [INVALID TIME]'
                else:
                    quarry_val_str_d7b370d = bytearray(quarry_val_c3d086f)
                    if quarry_key_872e61d.startswith('Signature'):
                        quarry_val_str_d7b370d = ''.join((f'{quarry_i_ce291bf:02X}' for quarry_i_ce291bf in quarry_val_str_d7b370d.rstrip(b'\x00')))
                    else:
                        quarry_val_str_d7b370d = ''.join((chr(quarry_i_f5a49a5) if quarry_i_f5a49a5 in quarry_printable_bytes_25f2145 else f'\\x{quarry_i_f5a49a5:02x}' for quarry_i_f5a49a5 in quarry_val_str_d7b370d.rstrip(b'\x00')))
                quarry_dump_local_7968f48.append('0x%-8X 0x%-3X %-30s %s' % (quarry_self_9ff97e2.__field_offsets__[quarry_key_872e61d] + quarry_self_9ff97e2.__file_offset__, quarry_self_9ff97e2.__field_offsets__[quarry_key_872e61d], quarry_key_872e61d + ':', quarry_val_str_d7b370d))
        return quarry_dump_local_7968f48

    @_name_boundary.callable_contract({'self': 'quarry_self_f4cf1ec'}, 'dump_dict')
    def quarry_dump_dict(quarry_self_f4cf1ec):
        """Returns a dictionary representation of the structure."""
        quarry_dump_dict_7245586 = {'Structure': quarry_self_f4cf1ec.name}
        for quarry_keys_c31b182 in quarry_self_f4cf1ec.__keys__:
            for quarry_key_72a2afc in quarry_keys_c31b182:
                quarry_val_bc85739 = _name_boundary.read_attribute(quarry_self_f4cf1ec, quarry_key_72a2afc)
                if isinstance(quarry_val_bc85739, int):
                    if quarry_key_72a2afc == 'TimeDateStamp' or quarry_key_72a2afc == 'dwTimeStamp':
                        try:
                            quarry_val_bc85739 = f'0x{quarry_val_bc85739:-8X} [{quarry_time.asctime(quarry_time.gmtime(quarry_val_bc85739))} UTC]'
                        except ValueError:
                            quarry_val_bc85739 = f'0x{quarry_val_bc85739:-8X} [INVALID TIME]'
                else:
                    quarry_val_bc85739 = ''.join((chr(quarry_d_387d5cd) if chr(quarry_d_387d5cd) in quarry_string.printable else f'\\x{quarry_d_387d5cd:02x}' for quarry_d_387d5cd in [ord(quarry_c_0eab5b5) if not isinstance(quarry_c_0eab5b5, int) else quarry_c_0eab5b5 for quarry_c_0eab5b5 in quarry_val_bc85739]))
                quarry_dump_dict_7245586[quarry_key_72a2afc] = {'FileOffset': quarry_self_f4cf1ec.__field_offsets__[quarry_key_72a2afc] + quarry_self_f4cf1ec.__file_offset__, 'Offset': quarry_self_f4cf1ec.__field_offsets__[quarry_key_72a2afc], 'Value': quarry_val_bc85739}
        return quarry_dump_dict_7245586

class quarry_SectionStructure(quarry_Structure):
    """Convenience section handling class."""

    @_name_boundary.callable_contract({'self': 'quarry_self_f446150', 'args': 'quarry_args_1ef68e6', 'kwargs': 'quarry_kwargs_12a8963'}, '__init__')
    def __init__(quarry_self_f446150, *quarry_args_1ef68e6, **quarry_kwargs_12a8963):
        if 'pe' in quarry_kwargs_12a8963:
            quarry_self_f446150.pe = quarry_kwargs_12a8963['pe']
            del quarry_kwargs_12a8963['pe']
        super().__init__(*quarry_args_1ef68e6, **quarry_kwargs_12a8963)
        quarry_self_f446150.Misc_VirtualSize = None
        quarry_self_f446150.VirtualAddress = None
        quarry_self_f446150.SizeOfRawData = None
        quarry_self_f446150.PointerToRawData = None
        quarry_self_f446150.VirtualAddress_adj = None
        quarry_self_f446150.PointerToRawData_adj = None
        quarry_self_f446150.section_min_addr = None
        quarry_self_f446150.section_max_addr = None
        quarry_self_f446150.index_in_file = None

    @_name_boundary.callable_contract({'self': 'quarry_self_151ff3b'}, 'get_PointerToRawData_adj')
    def quarry_get_PointerToRawData_adj(quarry_self_151ff3b):
        if quarry_self_151ff3b.PointerToRawData_adj is None and quarry_self_151ff3b.PointerToRawData is not None:
            if _name_boundary.attributes(quarry_self_151ff3b.pe)['OPTIONAL_HEADER'].SectionAlignment < 4096:
                quarry_self_151ff3b.PointerToRawData_adj = quarry_self_151ff3b.PointerToRawData
            else:
                quarry_self_151ff3b.PointerToRawData_adj = _name_boundary.attributes(quarry_self_151ff3b.pe)['adjust_PointerToRawData'](quarry_self_151ff3b.PointerToRawData)
        return quarry_self_151ff3b.PointerToRawData_adj

    @_name_boundary.callable_contract({'self': 'quarry_self_cbe2f40'}, 'get_VirtualAddress_adj')
    def quarry_get_VirtualAddress_adj(quarry_self_cbe2f40):
        if quarry_self_cbe2f40.VirtualAddress_adj is None and quarry_self_cbe2f40.VirtualAddress is not None:
            quarry_self_cbe2f40.VirtualAddress_adj = _name_boundary.attributes(quarry_self_cbe2f40.pe)['adjust_SectionAlignment'](quarry_self_cbe2f40.VirtualAddress, _name_boundary.attributes(quarry_self_cbe2f40.pe)['OPTIONAL_HEADER'].SectionAlignment, _name_boundary.attributes(quarry_self_cbe2f40.pe)['OPTIONAL_HEADER'].FileAlignment)
        return quarry_self_cbe2f40.VirtualAddress_adj

    @_name_boundary.callable_contract({'self': 'quarry_self_0e3e9b4', 'start': 'quarry_start_775ad1a', 'length': 'quarry_length_8d2e8f6', 'ignore_padding': 'quarry_ignore_padding_5a54b3d'}, 'get_data')
    def quarry_get_data(quarry_self_0e3e9b4, quarry_start_775ad1a=None, quarry_length_8d2e8f6=None, quarry_ignore_padding_5a54b3d=False):
        """Get data chunk from a section.

        Allows to query data from the section by passing the
        addresses where the PE file would be loaded by default.
        It is then possible to retrieve code and data by their real
        addresses as they would be if loaded.

        Note that sections on disk can include padding that would
        not be loaded to memory. That is the case if `section.SizeOfRawData`
        is greater than `section.Misc_VirtualSize`, and that means
        that data past `section.Misc_VirtualSize` is padding.
        In case you are not interested in this padding, passing
        `ignore_padding=True` will truncate the result in order
        not to return the padding (if any).

        Returns bytes().
        """
        if quarry_start_775ad1a is None:
            quarry_offset_local_81720ec = _name_boundary.attributes(quarry_self_0e3e9b4)['get_PointerToRawData_adj']()
        else:
            quarry_offset_local_81720ec = quarry_start_775ad1a - _name_boundary.attributes(quarry_self_0e3e9b4)['get_VirtualAddress_adj']() + _name_boundary.attributes(quarry_self_0e3e9b4)['get_PointerToRawData_adj']()
        if quarry_length_8d2e8f6 is not None:
            quarry_end_local_f18ef73 = quarry_offset_local_81720ec + quarry_length_8d2e8f6
        elif quarry_self_0e3e9b4.SizeOfRawData is not None:
            quarry_end_local_f18ef73 = quarry_offset_local_81720ec + quarry_self_0e3e9b4.SizeOfRawData
        else:
            quarry_end_local_f18ef73 = quarry_offset_local_81720ec
        if quarry_ignore_padding_5a54b3d and quarry_end_local_f18ef73 is not None and (quarry_offset_local_81720ec is not None):
            quarry_end_local_f18ef73 = min(quarry_end_local_f18ef73, quarry_offset_local_81720ec + quarry_self_0e3e9b4.Misc_VirtualSize)
        if quarry_self_0e3e9b4.PointerToRawData is not None and quarry_self_0e3e9b4.SizeOfRawData is not None:
            quarry_end_local_f18ef73 = min(quarry_end_local_f18ef73, quarry_self_0e3e9b4.PointerToRawData + quarry_self_0e3e9b4.SizeOfRawData)
        return quarry_self_0e3e9b4.pe.__data__[quarry_offset_local_81720ec:quarry_end_local_f18ef73]

    @_name_boundary.callable_contract({'self': 'quarry_self_ba10f34', 'val': 'quarry_val_730794b', 'name': 'quarry_name_local_12aa972'}, '__setattr__')
    def __setattr__(quarry_self_ba10f34, quarry_name_local_12aa972, quarry_val_730794b):
        if quarry_name_local_12aa972 == 'Characteristics':
            quarry_section_flags_local_c463804 = quarry_retrieve_flags(quarry_SECTION_CHARACTERISTICS, 'IMAGE_SCN_')
            quarry_set_flags(quarry_self_ba10f34, quarry_val_730794b, quarry_section_flags_local_c463804)
        elif 'IMAGE_SCN_' in quarry_name_local_12aa972 and _name_boundary.has_attribute(quarry_self_ba10f34, quarry_name_local_12aa972):
            if quarry_val_730794b:
                _name_boundary.namespace_view(quarry_self_ba10f34)['Characteristics'] |= quarry_SECTION_CHARACTERISTICS[quarry_name_local_12aa972]
            else:
                _name_boundary.namespace_view(quarry_self_ba10f34)['Characteristics'] ^= quarry_SECTION_CHARACTERISTICS[quarry_name_local_12aa972]
        _name_boundary.namespace_view(quarry_self_ba10f34)[quarry_name_local_12aa972] = quarry_val_730794b

    @_name_boundary.callable_contract({'self': 'quarry_self_931ac78', 'offset': 'quarry_offset_local_f60d344'}, 'get_rva_from_offset')
    def quarry_get_rva_from_offset(quarry_self_931ac78, quarry_offset_local_f60d344):
        return quarry_offset_local_f60d344 - _name_boundary.attributes(quarry_self_931ac78)['get_PointerToRawData_adj']() + _name_boundary.attributes(quarry_self_931ac78)['get_VirtualAddress_adj']()

    @_name_boundary.callable_contract({'self': 'quarry_self_28a7afa', 'rva': 'quarry_rva_9654e2c'}, 'get_offset_from_rva')
    def quarry_get_offset_from_rva(quarry_self_28a7afa, quarry_rva_9654e2c):
        return quarry_rva_9654e2c - _name_boundary.attributes(quarry_self_28a7afa)['get_VirtualAddress_adj']() + _name_boundary.attributes(quarry_self_28a7afa)['get_PointerToRawData_adj']()

    @_name_boundary.callable_contract({'self': 'quarry_self_2cfbb9f', 'offset': 'quarry_offset_local_064c4e1'}, 'contains_offset')
    def quarry_contains_offset(quarry_self_2cfbb9f, quarry_offset_local_064c4e1):
        """Check whether the section contains the file offset provided."""
        if quarry_self_2cfbb9f.PointerToRawData is None:
            return False
        quarry_PointerToRawData_adj_local_63a96b9 = _name_boundary.attributes(quarry_self_2cfbb9f)['get_PointerToRawData_adj']()
        return quarry_PointerToRawData_adj_local_63a96b9 <= quarry_offset_local_064c4e1 < quarry_PointerToRawData_adj_local_63a96b9 + quarry_self_2cfbb9f.SizeOfRawData

    @_name_boundary.callable_contract({'self': 'quarry_self_6cc7dbb', 'rva': 'quarry_rva_095d93c'}, 'contains_rva')
    def quarry_contains_rva(quarry_self_6cc7dbb, quarry_rva_095d93c):
        """Check whether the section contains the address provided."""
        if quarry_self_6cc7dbb.section_min_addr is not None and quarry_self_6cc7dbb.section_max_addr is not None:
            return quarry_self_6cc7dbb.section_min_addr <= quarry_rva_095d93c < quarry_self_6cc7dbb.section_max_addr
        quarry_VirtualAddress_adj_local_fdd13e9 = _name_boundary.attributes(quarry_self_6cc7dbb)['get_VirtualAddress_adj']()
        if len(quarry_self_6cc7dbb.pe.__data__) - _name_boundary.attributes(quarry_self_6cc7dbb)['get_PointerToRawData_adj']() < quarry_self_6cc7dbb.SizeOfRawData:
            quarry_size_local_6157711 = quarry_self_6cc7dbb.Misc_VirtualSize
        else:
            quarry_size_local_6157711 = max(quarry_self_6cc7dbb.SizeOfRawData, quarry_self_6cc7dbb.Misc_VirtualSize)
        if quarry_self_6cc7dbb.next_section_virtual_address is not None and quarry_self_6cc7dbb.VirtualAddress < quarry_self_6cc7dbb.next_section_virtual_address < quarry_VirtualAddress_adj_local_fdd13e9 + quarry_size_local_6157711:
            quarry_size_local_6157711 = quarry_self_6cc7dbb.next_section_virtual_address - quarry_VirtualAddress_adj_local_fdd13e9
        quarry_self_6cc7dbb.section_min_addr = quarry_VirtualAddress_adj_local_fdd13e9
        quarry_self_6cc7dbb.section_max_addr = quarry_VirtualAddress_adj_local_fdd13e9 + quarry_size_local_6157711
        return quarry_VirtualAddress_adj_local_fdd13e9 <= quarry_rva_095d93c < quarry_VirtualAddress_adj_local_fdd13e9 + quarry_size_local_6157711

    @_name_boundary.callable_contract({'self': 'quarry_self_8f40b19', 'rva': 'quarry_rva_4516ca8'}, 'contains')
    def quarry_contains(quarry_self_8f40b19, quarry_rva_4516ca8):
        return _name_boundary.attributes(quarry_self_8f40b19)['contains_rva'](quarry_rva_4516ca8)

    @_name_boundary.callable_contract({'self': 'quarry_self_79614e9'}, 'get_entropy')
    def quarry_get_entropy(quarry_self_79614e9):
        """Calculate and return the entropy for the section."""
        return _name_boundary.attributes(quarry_self_79614e9)['entropy_H'](_name_boundary.attributes(quarry_self_79614e9)['get_data']())

    @_name_boundary.callable_contract({'self': 'quarry_self_31345d4'}, 'get_hash_md5')
    def quarry_get_hash_md5(quarry_self_31345d4):
        """Get the MD5 hex-digest of the section's data."""
        if quarry_md5 is not None:
            return quarry_md5(_name_boundary.attributes(quarry_self_31345d4)['get_data']()).hexdigest()

    @_name_boundary.callable_contract({'self': 'quarry_self_33f44b0'}, 'get_hash_sha1')
    def quarry_get_hash_sha1(quarry_self_33f44b0):
        """Get the SHA-1 hex-digest of the section's data."""
        if quarry_sha1 is not None:
            return quarry_sha1(_name_boundary.attributes(quarry_self_33f44b0)['get_data']()).hexdigest()

    @_name_boundary.callable_contract({'self': 'quarry_self_042cec5'}, 'get_hash_sha256')
    def quarry_get_hash_sha256(quarry_self_042cec5):
        """Get the SHA-256 hex-digest of the section's data."""
        if quarry_sha256 is not None:
            return quarry_sha256(_name_boundary.attributes(quarry_self_042cec5)['get_data']()).hexdigest()

    @_name_boundary.callable_contract({'self': 'quarry_self_4146dbc'}, 'get_hash_sha512')
    def quarry_get_hash_sha512(quarry_self_4146dbc):
        """Get the SHA-512 hex-digest of the section's data."""
        if quarry_sha512 is not None:
            return quarry_sha512(_name_boundary.attributes(quarry_self_4146dbc)['get_data']()).hexdigest()

    @staticmethod
    @_name_boundary.callable_contract({'data': 'quarry_data_local_f234ed9'}, 'entropy_H')
    def quarry_entropy_H(quarry_data_local_f234ed9):
        """Calculate the entropy of a chunk of data."""
        if not quarry_data_local_f234ed9:
            return 0.0
        quarry_occurrences_local_fb988af = quarry_Counter(bytearray(quarry_data_local_f234ed9))
        quarry_entropy_local_cae624d = 0
        for quarry_x_26ced51 in quarry_occurrences_local_fb988af.values():
            quarry_p_x_local_e7128f6 = quarry_x_26ced51 / len(quarry_data_local_f234ed9)
            quarry_entropy_local_cae624d -= quarry_p_x_local_e7128f6 * quarry_math.log2(quarry_p_x_local_e7128f6)
        return quarry_entropy_local_cae624d
    get_PointerToRawData_adj = quarry_get_PointerToRawData_adj
    get_VirtualAddress_adj = quarry_get_VirtualAddress_adj
    get_data = quarry_get_data
    get_rva_from_offset = quarry_get_rva_from_offset
    get_offset_from_rva = quarry_get_offset_from_rva
    contains_offset = quarry_contains_offset
    contains_rva = quarry_contains_rva
    contains = quarry_contains
    get_entropy = quarry_get_entropy
    get_hash_md5 = quarry_get_hash_md5
    get_hash_sha1 = quarry_get_hash_sha1
    get_hash_sha256 = quarry_get_hash_sha256
    get_hash_sha512 = quarry_get_hash_sha512
    entropy_H = quarry_entropy_H

@quarry_lru_cache(maxsize=2048)
@_name_boundary.callable_contract({'format': 'quarry_format_8af4b92'}, 'set_bitfields_format')
def quarry_set_bitfields_format(quarry_format_8af4b92):

    @_name_boundary.class_contract('Accumulator', {'wrap_up': 'quarry_wrap_up', 'new_type': 'quarry_new_type', 'add_subfield': 'quarry_add_subfield', 'get_type': 'quarry_get_type', 'get_name': 'quarry_get_name', 'get_bits_left': 'quarry_get_bits_left', '_subfields': 'quarry__subfields', '_name': 'quarry__name', '_type': 'quarry__type', '_bits_left': 'quarry__bits_left', '_comp_fields': 'quarry__comp_fields', '_format': 'quarry__format'})
    class quarry_Accumulator_5bad9ea:

        @_name_boundary.callable_contract({'self': 'quarry_self_1a3835b', 'fmt': 'quarry_fmt_7d3c4b9', 'comp_fields': 'quarry_comp_fields_e75e333'}, '__init__')
        def __init__(quarry_self_1a3835b, quarry_fmt_7d3c4b9, quarry_comp_fields_e75e333):
            _name_boundary.attributes(quarry_self_1a3835b)['_subfields'] = []
            _name_boundary.attributes(quarry_self_1a3835b)['_name'] = '~'
            _name_boundary.attributes(quarry_self_1a3835b)['_type'] = None
            _name_boundary.attributes(quarry_self_1a3835b)['_bits_left'] = 0
            _name_boundary.attributes(quarry_self_1a3835b)['_comp_fields'] = quarry_comp_fields_e75e333
            _name_boundary.attributes(quarry_self_1a3835b)['_format'] = quarry_fmt_7d3c4b9

        @_name_boundary.callable_contract({'self': 'quarry_self_3fe6a44'}, 'wrap_up')
        def quarry_wrap_up(quarry_self_3fe6a44):
            if _name_boundary.attributes(quarry_self_3fe6a44)['_type'] is None:
                return
            _name_boundary.attributes(quarry_self_3fe6a44)['_format'].append(_name_boundary.attributes(quarry_self_3fe6a44)['_type'] + ',' + _name_boundary.attributes(quarry_self_3fe6a44)['_name'])
            _name_boundary.attributes(quarry_self_3fe6a44)['_comp_fields'][len(_name_boundary.attributes(quarry_self_3fe6a44)['_format']) - 1] = (_name_boundary.attributes(quarry_self_3fe6a44)['_type'], _name_boundary.attributes(quarry_self_3fe6a44)['_subfields'])
            _name_boundary.attributes(quarry_self_3fe6a44)['_name'] = '~'
            _name_boundary.attributes(quarry_self_3fe6a44)['_type'] = None
            _name_boundary.attributes(quarry_self_3fe6a44)['_subfields'] = []

        @_name_boundary.callable_contract({'self': 'quarry_self_48772f6', 'tp': 'quarry_tp_bf73421'}, 'new_type')
        def quarry_new_type(quarry_self_48772f6, quarry_tp_bf73421):
            _name_boundary.attributes(quarry_self_48772f6)['_bits_left'] = quarry_STRUCT_SIZEOF_TYPES[quarry_tp_bf73421] * 8
            _name_boundary.attributes(quarry_self_48772f6)['_type'] = quarry_tp_bf73421

        @_name_boundary.callable_contract({'self': 'quarry_self_6af53bc', 'bitcnt': 'quarry_bitcnt_fbaf8d4', 'name': 'quarry_name_local_85f45b6'}, 'add_subfield')
        def quarry_add_subfield(quarry_self_6af53bc, quarry_name_local_85f45b6, quarry_bitcnt_fbaf8d4):
            _name_boundary.attributes(quarry_self_6af53bc)['_name'] += quarry_name_local_85f45b6
            _name_boundary.attributes(quarry_self_6af53bc)['_bits_left'] -= quarry_bitcnt_fbaf8d4
            _name_boundary.attributes(quarry_self_6af53bc)['_subfields'].append((quarry_name_local_85f45b6, quarry_bitcnt_fbaf8d4))

        @_name_boundary.callable_contract({'self': 'quarry_self_f10216a'}, 'get_type')
        def quarry_get_type(quarry_self_f10216a):
            return _name_boundary.attributes(quarry_self_f10216a)['_type']

        @_name_boundary.callable_contract({'self': 'quarry_self_d915014'}, 'get_name')
        def quarry_get_name(quarry_self_d915014):
            return _name_boundary.attributes(quarry_self_d915014)['_name']

        @_name_boundary.callable_contract({'self': 'quarry_self_7c67b01'}, 'get_bits_left')
        def quarry_get_bits_left(quarry_self_7c67b01):
            return _name_boundary.attributes(quarry_self_7c67b01)['_bits_left']
    quarry_old_fmt_65388cd = []
    quarry_comp_fields_36fa210 = {}
    quarry_ac_ec0eb1d = quarry_Accumulator_5bad9ea(quarry_old_fmt_65388cd, quarry_comp_fields_36fa210)
    for quarry_elm_5f9d5f2 in quarry_format_8af4b92[1]:
        if ':' not in quarry_elm_5f9d5f2:
            _name_boundary.attributes(quarry_ac_ec0eb1d)['wrap_up']()
            quarry_old_fmt_65388cd.append(quarry_elm_5f9d5f2)
            continue
        quarry_elm_type_92ce8ed, quarry_elm_name_448fa1d = quarry_elm_5f9d5f2.split(',', 1)
        if ',' in quarry_elm_name_448fa1d:
            raise NotImplementedError('Structures with bitfields do not support unions yet')
        quarry_elm_type_92ce8ed, quarry_elm_bits_191529f = quarry_elm_type_92ce8ed.split(':', 1)
        quarry_elm_bits_191529f = int(quarry_elm_bits_191529f)
        if quarry_elm_type_92ce8ed != _name_boundary.attributes(quarry_ac_ec0eb1d)['get_type']() or quarry_elm_bits_191529f > _name_boundary.attributes(quarry_ac_ec0eb1d)['get_bits_left']():
            _name_boundary.attributes(quarry_ac_ec0eb1d)['wrap_up']()
            _name_boundary.attributes(quarry_ac_ec0eb1d)['new_type'](quarry_elm_type_92ce8ed)
        _name_boundary.attributes(quarry_ac_ec0eb1d)['add_subfield'](quarry_elm_name_448fa1d, quarry_elm_bits_191529f)
    _name_boundary.attributes(quarry_ac_ec0eb1d)['wrap_up']()
    quarry_format_str_5781571, quarry___98841a8, quarry_field_offsets_535b33f, quarry_keys_91d3597, quarry_format_length_4d20df0 = quarry_set_format(tuple(quarry_old_fmt_65388cd))
    quarry_extended_keys_9a63ab4 = []
    for quarry_idx_03e16ea, quarry_val_707e15e in enumerate(quarry_keys_91d3597):
        if quarry_idx_03e16ea not in quarry_comp_fields_36fa210:
            quarry_extended_keys_9a63ab4.append(quarry_val_707e15e)
            continue
        quarry___98841a8, quarry_sbf_38a363d = quarry_comp_fields_36fa210[quarry_idx_03e16ea]
        quarry_bf_names_ded0416 = [[quarry_f_22404d2[quarry_StructureWithBitfields.BTF_NAME_IDX]] for quarry_f_22404d2 in quarry_sbf_38a363d]
        quarry_extended_keys_9a63ab4.extend(quarry_bf_names_ded0416)
        for quarry_n_56d19e2 in quarry_bf_names_ded0416:
            quarry_field_offsets_535b33f[quarry_n_56d19e2[0]] = quarry_field_offsets_535b33f[quarry_val_707e15e[0]]
    return (quarry_format_str_5781571, quarry_format_length_4d20df0, quarry_field_offsets_535b33f, quarry_keys_91d3597, quarry_extended_keys_9a63ab4, quarry_comp_fields_36fa210)

class quarry_StructureWithBitfields(quarry_Structure):
    """
    Extends Structure's functionality with support for bitfields such as:
        ('B:4,LowerHalf', 'B:4,UpperHalf')
    To this end, two lists are maintained:
        * self.__keys__ that contains compound fields, for example
          ('B,~LowerHalfUpperHalf'), and is used during packing/unpaking
        * self.__keys_ext__ containing a separate key for each field (ex., LowerHalf,
          UpperHalf) to simplify implementation of dump()
    This way the implementation of unpacking/packing and dump() from Structure can be
    reused.

    In addition, we create a dictionary:
        <compound_field_index_in_keys> -->
            (data type, [ (subfield name, length in bits)+ ] )
    that facilitates bitfield packing and unpacking.

    With lru_cache() creating only one instance per format string, the memory
    overhead is negligible.
    """
    BTF_NAME_IDX = 0
    BTF_BITCNT_IDX = 1
    CF_TYPE_IDX = 0
    CF_SUBFLD_IDX = 1

    @_name_boundary.callable_contract({'self': 'quarry_self_c962cbc', 'format': 'quarry_format_9aa8e86', 'file_offset': 'quarry_file_offset_0a85496', 'name': 'quarry_name_local_3f6840d'}, '__init__')
    def __init__(quarry_self_c962cbc, quarry_format_9aa8e86, quarry_name_local_3f6840d=None, quarry_file_offset_0a85496=None):
        quarry_self_c962cbc.__format_str__, quarry_self_c962cbc.__format_length__, quarry_self_c962cbc.__field_offsets__, quarry_self_c962cbc.__keys__, quarry_self_c962cbc.__keys_ext__, quarry_self_c962cbc.__compound_fields__ = quarry_set_bitfields_format(quarry_format_9aa8e86)
        quarry_self_c962cbc.__unpacked_data_elms__ = [None for quarry___eb305f7 in range(quarry_self_c962cbc.__format_length__)]
        quarry_self_c962cbc.__all_zeroes__ = False
        quarry_self_c962cbc.__file_offset__ = quarry_file_offset_0a85496
        quarry_self_c962cbc.name = quarry_name_local_3f6840d if quarry_name_local_3f6840d is not None else quarry_format_9aa8e86[0]

    @_name_boundary.callable_contract({'self': 'quarry_self_3bded6c', 'data': 'quarry_data_local_b1a1ec2'}, '__unpack__')
    def __unpack__(quarry_self_3bded6c, quarry_data_local_b1a1ec2):
        super().__unpack__(quarry_data_local_b1a1ec2)
        _name_boundary.attributes(quarry_self_3bded6c)['_unpack_bitfield_attributes']()

    @_name_boundary.callable_contract({'self': 'quarry_self_ebf0647'}, '__pack__')
    def __pack__(quarry_self_ebf0647):
        _name_boundary.attributes(quarry_self_ebf0647)['_pack_bitfield_attributes']()
        try:
            quarry_data_local_58e01f0 = super().__pack__()
        finally:
            _name_boundary.attributes(quarry_self_ebf0647)['_unpack_bitfield_attributes']()
        return quarry_data_local_58e01f0

    @_name_boundary.callable_contract({'self': 'quarry_self_c92c1ab', 'indentation': 'quarry_indentation_204a090'}, 'dump')
    def dump(quarry_self_c92c1ab, quarry_indentation_204a090=0):
        quarry_tk_local_a047e81 = quarry_self_c92c1ab.__keys__
        quarry_self_c92c1ab.__keys__ = quarry_self_c92c1ab.__keys_ext__
        try:
            quarry_ret_local_0c816a7 = super().dump(quarry_indentation_204a090)
        finally:
            quarry_self_c92c1ab.__keys__ = quarry_tk_local_a047e81
        return quarry_ret_local_0c816a7

    @_name_boundary.callable_contract({'self': 'quarry_self_44dc260'}, 'dump_dict')
    def quarry_dump_dict(quarry_self_44dc260):
        quarry_tk_local_f153fa8 = quarry_self_44dc260.__keys__
        quarry_self_44dc260.__keys__ = quarry_self_44dc260.__keys_ext__
        try:
            quarry_ret_local_bf29c24 = _name_boundary.attributes(super())['dump_dict']()
        finally:
            quarry_self_44dc260.__keys__ = quarry_tk_local_f153fa8
        return quarry_ret_local_bf29c24

    @_name_boundary.callable_contract({'self': 'quarry_self_53a95e0'}, '_unpack_bitfield_attributes')
    def quarry__unpack_bitfield_attributes(quarry_self_53a95e0):
        """Replace compound attributes corresponding to bitfields with separate
        sub-fields.
        """
        for quarry_i_fb922b6 in quarry_self_53a95e0.__compound_fields__:
            quarry_cf_name_local_ed2f1ce = quarry_self_53a95e0.__keys__[quarry_i_fb922b6][0]
            quarry_cval_local_258ea7a = _name_boundary.read_attribute(quarry_self_53a95e0, quarry_cf_name_local_ed2f1ce)
            _name_boundary.remove_attribute(quarry_self_53a95e0, quarry_cf_name_local_ed2f1ce)
            quarry_offst_local_471e396 = 0
            for quarry_sf_03f29d2 in quarry_self_53a95e0.__compound_fields__[quarry_i_fb922b6][quarry_StructureWithBitfields.CF_SUBFLD_IDX]:
                quarry_mask_local_ef661d8 = (1 << quarry_sf_03f29d2[quarry_StructureWithBitfields.BTF_BITCNT_IDX]) - 1
                quarry_mask_local_ef661d8 <<= quarry_offst_local_471e396
                _name_boundary.write_attribute(quarry_self_53a95e0, quarry_sf_03f29d2[quarry_StructureWithBitfields.BTF_NAME_IDX], (quarry_cval_local_258ea7a & quarry_mask_local_ef661d8) >> quarry_offst_local_471e396)
                quarry_offst_local_471e396 += quarry_sf_03f29d2[quarry_StructureWithBitfields.BTF_BITCNT_IDX]

    @_name_boundary.callable_contract({'self': 'quarry_self_c0fbc1e'}, '_pack_bitfield_attributes')
    def quarry__pack_bitfield_attributes(quarry_self_c0fbc1e):
        """Pack attributes into a compound bitfield"""
        for quarry_i_c5c9aad in quarry_self_c0fbc1e.__compound_fields__:
            quarry_cf_name_local_55fd032 = quarry_self_c0fbc1e.__keys__[quarry_i_c5c9aad][0]
            quarry_offst_local_9a662cf, quarry_acc_val_e05f2c5 = (0, 0)
            for quarry_sf_4f38742 in quarry_self_c0fbc1e.__compound_fields__[quarry_i_c5c9aad][quarry_StructureWithBitfields.CF_SUBFLD_IDX]:
                quarry_mask_local_d9045b0 = (1 << quarry_sf_4f38742[quarry_StructureWithBitfields.BTF_BITCNT_IDX]) - 1
                quarry_field_val_local_330ba57 = _name_boundary.read_attribute(quarry_self_c0fbc1e, quarry_sf_4f38742[quarry_StructureWithBitfields.BTF_NAME_IDX]) & quarry_mask_local_d9045b0
                quarry_acc_val_e05f2c5 |= quarry_field_val_local_330ba57 << quarry_offst_local_9a662cf
                quarry_offst_local_9a662cf += quarry_sf_4f38742[quarry_StructureWithBitfields.BTF_BITCNT_IDX]
            _name_boundary.write_attribute(quarry_self_c0fbc1e, quarry_cf_name_local_55fd032, quarry_acc_val_e05f2c5)
    dump_dict = quarry_dump_dict
    _unpack_bitfield_attributes = quarry__unpack_bitfield_attributes
    _pack_bitfield_attributes = quarry__pack_bitfield_attributes

@_name_boundary.class_contract('DataContainer', {})
class quarry_DataContainer:
    """Generic data container."""

    @_name_boundary.callable_contract({'self': 'quarry_self_963643c', 'kwargs': 'quarry_kwargs_4e1cd27'}, '__init__')
    def __init__(quarry_self_963643c, **quarry_kwargs_4e1cd27):
        quarry_bare_setattr_97681c1 = super().__setattr__
        for quarry_key_d6a56e9, quarry_value_bd32a05 in quarry_kwargs_4e1cd27.items():
            quarry_bare_setattr_97681c1(quarry_key_d6a56e9, quarry_value_bd32a05)

@_name_boundary.class_contract('ImportDescData', {})
class quarry_ImportDescData(quarry_DataContainer):
    """Holds import descriptor information.

    dll:        name of the imported DLL
    imports:    list of imported symbols (ImportData instances)
    struct:     IMAGE_IMPORT_DESCRIPTOR structure
    """

@_name_boundary.class_contract('ImportData', {})
class quarry_ImportData(quarry_DataContainer):
    """Holds imported symbol's information.

    ordinal:    Ordinal of the symbol
    name:       Name of the symbol
    bound:      If the symbol is bound, this contains
                the address.
    """

    @_name_boundary.callable_contract({'self': 'quarry_self_feab544', 'val': 'quarry_val_c0ef249', 'name': 'quarry_name_local_2e0b007'}, '__setattr__')
    def __setattr__(quarry_self_feab544, quarry_name_local_2e0b007, quarry_val_c0ef249):
        if _name_boundary.has_attribute(quarry_self_feab544, 'ordinal') and _name_boundary.has_attribute(quarry_self_feab544, 'bound') and _name_boundary.has_attribute(quarry_self_feab544, 'name'):
            if quarry_name_local_2e0b007 == 'ordinal':
                if _name_boundary.attributes(quarry_self_feab544.pe)['PE_TYPE'] == quarry_OPTIONAL_HEADER_MAGIC_PE:
                    quarry_ordinal_flag_4c22416 = quarry_IMAGE_ORDINAL_FLAG
                elif _name_boundary.attributes(quarry_self_feab544.pe)['PE_TYPE'] == quarry_OPTIONAL_HEADER_MAGIC_PE_PLUS:
                    quarry_ordinal_flag_4c22416 = quarry_IMAGE_ORDINAL_FLAG64
                quarry_self_feab544.struct_table.Ordinal = quarry_ordinal_flag_4c22416 | quarry_val_c0ef249 & 65535
                quarry_self_feab544.struct_table.AddressOfData = quarry_self_feab544.struct_table.Ordinal
                quarry_self_feab544.struct_table.Function = quarry_self_feab544.struct_table.Ordinal
                quarry_self_feab544.struct_table.ForwarderString = quarry_self_feab544.struct_table.Ordinal
            elif quarry_name_local_2e0b007 == 'bound' and quarry_self_feab544.struct_iat is not None:
                quarry_self_feab544.struct_iat.AddressOfData = quarry_val_c0ef249
                quarry_self_feab544.struct_iat.Function = quarry_self_feab544.struct_iat.AddressOfData
                quarry_self_feab544.struct_iat.ForwarderString = quarry_self_feab544.struct_iat.AddressOfData
            elif quarry_name_local_2e0b007 == 'address':
                quarry_self_feab544.struct_table.AddressOfData = quarry_val_c0ef249
                quarry_self_feab544.struct_table.Ordinal = quarry_self_feab544.struct_table.AddressOfData
                quarry_self_feab544.struct_table.Function = quarry_self_feab544.struct_table.AddressOfData
                quarry_self_feab544.struct_table.ForwarderString = quarry_self_feab544.struct_table.AddressOfData
            elif quarry_name_local_2e0b007 == 'name' and quarry_self_feab544.name_offset:
                quarry_name_rva_51c720f = _name_boundary.attributes(quarry_self_feab544.pe)['get_rva_from_offset'](quarry_self_feab544.name_offset)
                _name_boundary.attributes(quarry_self_feab544.pe)['set_dword_at_offset'](quarry_self_feab544.ordinal_offset, 0 << 31 | quarry_name_rva_51c720f)
                if len(quarry_val_c0ef249) > len(quarry_self_feab544.name):
                    raise quarry_PEFormatError('The export name provided is longer than the existing one.')
                _name_boundary.attributes(quarry_self_feab544.pe)['set_bytes_at_offset'](quarry_self_feab544.name_offset, quarry_val_c0ef249)
        _name_boundary.namespace_view(quarry_self_feab544)[quarry_name_local_2e0b007] = quarry_val_c0ef249

@_name_boundary.class_contract('ExportDirData', {})
class quarry_ExportDirData(quarry_DataContainer):
    """Holds export directory information.

    struct:     IMAGE_EXPORT_DIRECTORY structure
    symbols:    list of exported symbols (ExportData instances)
    name:       name of the export DLL"""

@_name_boundary.class_contract('ExportData', {})
class quarry_ExportData(quarry_DataContainer):
    """Holds exported symbols' information.

    ordinal:    ordinal of the symbol
    address:    address of the symbol
    name:       name of the symbol (None if the symbol is
                exported by ordinal only)
    forwarder:  if the symbol is forwarded it will
                contain the name of the target symbol,
                None otherwise.
    """

    @_name_boundary.callable_contract({'self': 'quarry_self_392d08b', 'val': 'quarry_val_e959c77', 'name': 'quarry_name_local_db2134f'}, '__setattr__')
    def __setattr__(quarry_self_392d08b, quarry_name_local_db2134f, quarry_val_e959c77):
        if _name_boundary.has_attribute(quarry_self_392d08b, 'ordinal') and _name_boundary.has_attribute(quarry_self_392d08b, 'address') and _name_boundary.has_attribute(quarry_self_392d08b, 'forwarder') and _name_boundary.has_attribute(quarry_self_392d08b, 'name'):
            if quarry_name_local_db2134f == 'ordinal':
                _name_boundary.attributes(quarry_self_392d08b.pe)['set_word_at_offset'](quarry_self_392d08b.ordinal_offset, quarry_val_e959c77)
            elif quarry_name_local_db2134f == 'address':
                _name_boundary.attributes(quarry_self_392d08b.pe)['set_dword_at_offset'](quarry_self_392d08b.address_offset, quarry_val_e959c77)
            elif quarry_name_local_db2134f == 'name':
                if len(quarry_val_e959c77) > len(quarry_self_392d08b.name):
                    raise quarry_PEFormatError('The export name provided is longer than the existing one.')
                _name_boundary.attributes(quarry_self_392d08b.pe)['set_bytes_at_offset'](quarry_self_392d08b.name_offset, quarry_val_e959c77)
            elif quarry_name_local_db2134f == 'forwarder':
                if len(quarry_val_e959c77) > len(quarry_self_392d08b.forwarder):
                    raise quarry_PEFormatError('The forwarder name provided is longer than the existing one.')
                _name_boundary.attributes(quarry_self_392d08b.pe)['set_bytes_at_offset'](quarry_self_392d08b.forwarder_offset, quarry_val_e959c77)
        _name_boundary.namespace_view(quarry_self_392d08b)[quarry_name_local_db2134f] = quarry_val_e959c77

@_name_boundary.class_contract('ResourceDirData', {})
class quarry_ResourceDirData(quarry_DataContainer):
    """Holds resource directory information.

    struct:     IMAGE_RESOURCE_DIRECTORY structure
    entries:    list of entries (ResourceDirEntryData instances)
    """

@_name_boundary.class_contract('ResourceDirEntryData', {})
class quarry_ResourceDirEntryData(quarry_DataContainer):
    """Holds resource directory entry data.

    struct:     IMAGE_RESOURCE_DIRECTORY_ENTRY structure
    name:       If the resource is identified by name this
                attribute will contain the name string. None
                otherwise. If identified by id, the id is
                available at 'struct.Id'
    id:         the id, also in struct.Id
    directory:  If this entry has a lower level directory
                this attribute will point to the
                ResourceDirData instance representing it.
    data:       If this entry has no further lower directories
                and points to the actual resource data, this
                attribute will reference the corresponding
                ResourceDataEntryData instance.
    (Either of the 'directory' or 'data' attribute will exist,
    but not both.)
    """

@_name_boundary.class_contract('ResourceDataEntryData', {})
class quarry_ResourceDataEntryData(quarry_DataContainer):
    """Holds resource data entry information.

    struct:     IMAGE_RESOURCE_DATA_ENTRY structure
    lang:       Primary language ID
    sublang:    Sublanguage ID
    """

@_name_boundary.class_contract('DebugData', {})
class quarry_DebugData(quarry_DataContainer):
    """Holds debug information.

    struct:     IMAGE_DEBUG_DIRECTORY structure
    entries:    list of entries (IMAGE_DEBUG_TYPE instances)
    """

@_name_boundary.class_contract('DynamicRelocationData', {})
class quarry_DynamicRelocationData(quarry_DataContainer):
    """Holds dynamic relocation information.

    struct:        IMAGE_DYNAMIC_RELOCATION structure
    symbol:        Symbol to which dynamic relocations must be applied
    relocations:   List of dynamic relocations for this symbol (BaseRelocationData instances)
    """

@_name_boundary.class_contract('FunctionOverrideData', {})
class quarry_FunctionOverrideData(quarry_DataContainer):
    """Holds Function and bdd dynamic relocation information.

    struct:        IMAGE_DYNAMIC_RELOCATION structure
    symbol:        Symbol to which dynamic relocations must be applied
    bdd_relocs:    List of bdd dynamic relocations (BddDynamicRelocationData instances)
    func_relocs:   List of function override dynamic relocations (FunctionOverrideDynamicRelocationData instances)
    """

@_name_boundary.class_contract('FunctionOverrideDynamicRelocationData', {})
class quarry_FunctionOverrideDynamicRelocationData(quarry_DataContainer):
    """Holds Function override dynamic relocation information.

    struct:        IMAGE_FUNCTION_OVERRIDE_DYNAMIC_RELOCATION structure
    func_rva:      Original function rva
    override_rvas: List of overriding function rvas
    relocations:   List of dynamic relocations (BaseRelocationData instances)
    """

@_name_boundary.class_contract('BddDynamicRelocationData', {})
class quarry_BddDynamicRelocationData(quarry_DataContainer):
    """Holds Bdd dynamic relocation information.

    struct:        IMAGE_BDD_DYNAMIC_RELOCATION structure
    """

@_name_boundary.class_contract('BaseRelocationData', {})
class quarry_BaseRelocationData(quarry_DataContainer):
    """Holds base relocation information.

    struct:     IMAGE_BASE_RELOCATION structure
    entries:    list of relocation data (RelocationData instances)
    """

@_name_boundary.class_contract('RelocationData', {'struct': 'quarry_struct'})
class quarry_RelocationData(quarry_DataContainer):
    """Holds relocation information.

    type:       Type of relocation
                The type string can be obtained by
                RELOCATION_TYPE[type]
    rva:        RVA of the relocation
    """

    @_name_boundary.callable_contract({'self': 'quarry_self_de82711', 'val': 'quarry_val_ed7a425', 'name': 'quarry_name_local_7f7b219'}, '__setattr__')
    def __setattr__(quarry_self_de82711, quarry_name_local_7f7b219, quarry_val_ed7a425):
        if _name_boundary.has_attribute(quarry_self_de82711, 'struct'):
            quarry_word_0d7a5c4 = _name_boundary.attributes(quarry_self_de82711)['struct'].Data
            if quarry_name_local_7f7b219 == 'type':
                quarry_word_0d7a5c4 = quarry_val_ed7a425 << 12 | quarry_word_0d7a5c4 & 4095
            elif quarry_name_local_7f7b219 == 'rva':
                quarry_offset_local_0950141 = max(quarry_val_ed7a425 - quarry_self_de82711.base_rva, 0)
                quarry_word_0d7a5c4 = quarry_word_0d7a5c4 & 61440 | quarry_offset_local_0950141 & 4095
            _name_boundary.attributes(quarry_self_de82711)['struct'].Data = quarry_word_0d7a5c4
        _name_boundary.namespace_view(quarry_self_de82711)[quarry_name_local_7f7b219] = quarry_val_ed7a425

@_name_boundary.class_contract('TlsData', {})
class quarry_TlsData(quarry_DataContainer):
    """Holds TLS information.

    struct:     IMAGE_TLS_DIRECTORY structure
    """

@_name_boundary.class_contract('BoundImportDescData', {})
class quarry_BoundImportDescData(quarry_DataContainer):
    """Holds bound import descriptor data.

    This directory entry will provide information on the
    DLLs this PE file has been bound to (if bound at all).
    The structure will contain the name and timestamp of the
    DLL at the time of binding so that the loader can know
    whether it differs from the one currently present in the
    system and must, therefore, re-bind the PE's imports.

    struct:     IMAGE_BOUND_IMPORT_DESCRIPTOR structure
    name:       DLL name
    entries:    list of entries (BoundImportRefData instances)
                the entries will exist if this DLL has forwarded
                symbols. If so, the destination DLL will have an
                entry in this list.
    """

@_name_boundary.class_contract('LoadConfigData', {})
class quarry_LoadConfigData(quarry_DataContainer):
    """Holds Load Config data.

    struct:     IMAGE_LOAD_CONFIG_DIRECTORY structure
    dynamic_relocations: dynamic relocation information, if present
    """

@_name_boundary.class_contract('BoundImportRefData', {})
class quarry_BoundImportRefData(quarry_DataContainer):
    """Holds bound import forwarder reference data.

    Contains the same information as the bound descriptor but
    for forwarded DLLs, if any.

    struct:     IMAGE_BOUND_FORWARDER_REF structure
    name:       dll name
    """

@_name_boundary.class_contract('ExceptionsDirEntryData', {})
class quarry_ExceptionsDirEntryData(quarry_DataContainer):
    """Holds the data related to SEH (and stack unwinding, in particular)

    struct      an instance of RUNTIME_FUNTION
    unwindinfo  an instance of UNWIND_INFO
    """

class quarry_UnwindInfo(quarry_StructureWithBitfields):
    """Handles the complexities of UNWIND_INFO structure:
    * variable number of UWIND_CODEs
    * optional ExceptionHandler and FunctionEntry fields
    """

    @_name_boundary.callable_contract({'self': 'quarry_self_6c03012', 'file_offset': 'quarry_file_offset_b93a15d'}, '__init__')
    def __init__(quarry_self_6c03012, quarry_file_offset_b93a15d=0):
        super().__init__(('UNWIND_INFO', ('B:3,Version', 'B:5,Flags', 'B,SizeOfProlog', 'B,CountOfCodes', 'B:4,FrameRegister', 'B:4,FrameOffset')), file_offset=quarry_file_offset_b93a15d)
        quarry_self_6c03012._full_size = _name_boundary.attributes(super())['sizeof']()
        quarry_self_6c03012._opt_field_name = None
        quarry_self_6c03012._code_info = quarry_StructureWithBitfields(('UNWIND_CODE', ('B,CodeOffset', 'B:4,UnwindOp', 'B:4,OpInfo')), file_offset=0)
        quarry_self_6c03012._chained_entry = None
        quarry_self_6c03012._finished_unpacking = False

    @_name_boundary.callable_contract({'self': 'quarry_self_529849c', 'data': 'quarry_data_local_b6090f5'}, 'unpack_in_stages')
    def quarry_unpack_in_stages(quarry_self_529849c, quarry_data_local_b6090f5):
        """Unpacks the UNWIND_INFO "in two calls", with the first call establishing
        a full size of the structure and the second, performing the actual unpacking.
        """
        if quarry_self_529849c._finished_unpacking:
            return None
        super().__unpack__(quarry_data_local_b6090f5)
        quarry_codes_cnt_max_local_6a0a640 = quarry_self_529849c.CountOfCodes + 1 & ~1
        quarry_hdlr_offset_local_759742d = _name_boundary.attributes(super())['sizeof']() + quarry_codes_cnt_max_local_6a0a640 * _name_boundary.attributes(quarry_self_529849c._code_info)['sizeof']()
        quarry_self_529849c._full_size = quarry_hdlr_offset_local_759742d + (0 if quarry_self_529849c.Flags == 0 else quarry_STRUCT_SIZEOF_TYPES['I'])
        if len(quarry_data_local_b6090f5) < quarry_self_529849c._full_size:
            return None
        if quarry_self_529849c.Version != 1 and quarry_self_529849c.Version != 2:
            return 'Unsupported version of UNWIND_INFO at ' + hex(quarry_self_529849c.__file_offset__)
        quarry_self_529849c.UnwindCodes = []
        quarry_ro_local_eb6c53e = _name_boundary.attributes(super())['sizeof']()
        quarry_codes_left_local_b5bd6c4 = quarry_self_529849c.CountOfCodes
        while quarry_codes_left_local_b5bd6c4 > 0:
            quarry_self_529849c._code_info.__unpack__(quarry_data_local_b6090f5[quarry_ro_local_eb6c53e:quarry_ro_local_eb6c53e + _name_boundary.attributes(quarry_self_529849c._code_info)['sizeof']()])
            quarry_ucode_local_4119f94 = _name_boundary.attributes(quarry_PrologEpilogOpsFactory)['create'](quarry_self_529849c._code_info)
            if quarry_ucode_local_4119f94 is None:
                return 'Unknown UNWIND_CODE at ' + hex(quarry_self_529849c.__file_offset__ + quarry_ro_local_eb6c53e)
            quarry_len_in_codes_local_41de575 = _name_boundary.attributes(quarry_ucode_local_4119f94)['length_in_code_structures'](quarry_self_529849c._code_info, quarry_self_529849c)
            quarry_opc_size_local_cb4de5c = _name_boundary.attributes(quarry_self_529849c._code_info)['sizeof']() * quarry_len_in_codes_local_41de575
            _name_boundary.attributes(quarry_ucode_local_4119f94)['initialize'](quarry_self_529849c._code_info, quarry_data_local_b6090f5[quarry_ro_local_eb6c53e:quarry_ro_local_eb6c53e + quarry_opc_size_local_cb4de5c], quarry_self_529849c, quarry_self_529849c.__file_offset__ + quarry_ro_local_eb6c53e)
            quarry_ro_local_eb6c53e += quarry_opc_size_local_cb4de5c
            quarry_codes_left_local_b5bd6c4 -= quarry_len_in_codes_local_41de575
            quarry_self_529849c.UnwindCodes.append(quarry_ucode_local_4119f94)
        if quarry_self_529849c.UNW_FLAG_EHANDLER or quarry_self_529849c.UNW_FLAG_UHANDLER:
            quarry_self_529849c._opt_field_name = 'ExceptionHandler'
        if quarry_self_529849c.UNW_FLAG_CHAININFO:
            quarry_self_529849c._opt_field_name = 'FunctionEntry'
        if quarry_self_529849c._opt_field_name is not None:
            _name_boundary.write_attribute(quarry_self_529849c, quarry_self_529849c._opt_field_name, quarry_struct.unpack('<I', quarry_data_local_b6090f5[quarry_hdlr_offset_local_759742d:quarry_hdlr_offset_local_759742d + quarry_STRUCT_SIZEOF_TYPES['I']])[0])
        quarry_self_529849c._finished_unpacking = True
        return None

    @_name_boundary.callable_contract({'self': 'quarry_self_6334382', 'indentation': 'quarry_indentation_23c6713'}, 'dump')
    def dump(quarry_self_6334382, quarry_indentation_23c6713=0):
        if quarry_self_6334382._opt_field_name is not None:
            quarry_self_6334382.__field_offsets__[quarry_self_6334382._opt_field_name] = quarry_self_6334382._full_size - quarry_STRUCT_SIZEOF_TYPES['I']
            quarry_self_6334382.__keys_ext__.append([quarry_self_6334382._opt_field_name])
        try:
            quarry_dump_local_7c98783 = super().dump(quarry_indentation_23c6713)
        finally:
            if quarry_self_6334382._opt_field_name is not None:
                quarry_self_6334382.__keys_ext__.pop()
        quarry_dump_local_7c98783.append('Flags: ' + ', '.join((quarry_s_a62b1c3[0] for quarry_s_a62b1c3 in quarry_unwind_info_flags if _name_boundary.read_attribute(quarry_self_6334382, quarry_s_a62b1c3[0]))))
        quarry_dump_local_7c98783.append('Unwind codes: ' + '; '.join((str(quarry_c_219d1b7) for quarry_c_219d1b7 in quarry_self_6334382.UnwindCodes if _name_boundary.attributes(quarry_c_219d1b7)['is_valid']())))
        return quarry_dump_local_7c98783

    @_name_boundary.callable_contract({'self': 'quarry_self_4bc4a68'}, 'dump_dict')
    def quarry_dump_dict(quarry_self_4bc4a68):
        if quarry_self_4bc4a68._opt_field_name is not None:
            quarry_self_4bc4a68.__field_offsets__[quarry_self_4bc4a68._opt_field_name] = quarry_self_4bc4a68._full_size - quarry_STRUCT_SIZEOF_TYPES['I']
            quarry_self_4bc4a68.__keys_ext__.append([quarry_self_4bc4a68._opt_field_name])
        try:
            quarry_ret_local_5c3129e = _name_boundary.attributes(super())['dump_dict']()
        finally:
            if quarry_self_4bc4a68._opt_field_name is not None:
                quarry_self_4bc4a68.__keys_ext__.pop()
        return quarry_ret_local_5c3129e

    @_name_boundary.callable_contract({'self': 'quarry_self_1782b43', 'val': 'quarry_val_fdc5039', 'name': 'quarry_name_local_c6db7be'}, '__setattr__')
    def __setattr__(quarry_self_1782b43, quarry_name_local_c6db7be, quarry_val_fdc5039):
        if quarry_name_local_c6db7be == 'Flags':
            quarry_set_flags(quarry_self_1782b43, quarry_val_fdc5039, quarry_unwind_info_flags)
        elif 'UNW_FLAG_' in quarry_name_local_c6db7be and _name_boundary.has_attribute(quarry_self_1782b43, quarry_name_local_c6db7be):
            if quarry_val_fdc5039:
                _name_boundary.namespace_view(quarry_self_1782b43)['Flags'] |= quarry_UNWIND_INFO_FLAGS[quarry_name_local_c6db7be]
            else:
                _name_boundary.namespace_view(quarry_self_1782b43)['Flags'] ^= quarry_UNWIND_INFO_FLAGS[quarry_name_local_c6db7be]
        _name_boundary.namespace_view(quarry_self_1782b43)[quarry_name_local_c6db7be] = quarry_val_fdc5039

    @_name_boundary.callable_contract({'self': 'quarry_self_581e742'}, 'sizeof')
    def quarry_sizeof(quarry_self_581e742):
        return quarry_self_581e742._full_size

    @_name_boundary.callable_contract({'self': 'quarry_self_9670e00'}, '__pack__')
    def __pack__(quarry_self_9670e00):
        quarry_data_local_fcb8527 = bytearray(quarry_self_9670e00._full_size)
        quarry_data_local_fcb8527[0:_name_boundary.attributes(super())['sizeof']()] = super().__pack__()
        quarry_cur_offset_local_74d0805 = _name_boundary.attributes(super())['sizeof']()
        for quarry_uc_06681b8 in quarry_self_9670e00.UnwindCodes:
            if quarry_cur_offset_local_74d0805 + _name_boundary.attributes(_name_boundary.attributes(quarry_uc_06681b8)['struct'])['sizeof']() > quarry_self_9670e00._full_size:
                break
            quarry_data_local_fcb8527[quarry_cur_offset_local_74d0805:quarry_cur_offset_local_74d0805 + _name_boundary.attributes(_name_boundary.attributes(quarry_uc_06681b8)['struct'])['sizeof']()] = _name_boundary.attributes(quarry_uc_06681b8)['struct'].__pack__()
            quarry_cur_offset_local_74d0805 += _name_boundary.attributes(_name_boundary.attributes(quarry_uc_06681b8)['struct'])['sizeof']()
        if quarry_self_9670e00._opt_field_name is not None:
            quarry_data_local_fcb8527[quarry_self_9670e00._full_size - quarry_STRUCT_SIZEOF_TYPES['I']:quarry_self_9670e00._full_size] = quarry_struct.pack('<I', _name_boundary.read_attribute(quarry_self_9670e00, quarry_self_9670e00._opt_field_name))
        return quarry_data_local_fcb8527

    @_name_boundary.callable_contract({'self': 'quarry_self_e1180ba'}, 'get_chained_function_entry')
    def quarry_get_chained_function_entry(quarry_self_e1180ba):
        return quarry_self_e1180ba._chained_entry

    @_name_boundary.callable_contract({'self': 'quarry_self_a1c8a54', 'entry': 'quarry_entry_a7f826d'}, 'set_chained_function_entry')
    def quarry_set_chained_function_entry(quarry_self_a1c8a54, quarry_entry_a7f826d):
        if quarry_self_a1c8a54._chained_entry is not None:
            raise quarry_PEFormatError('Chained function entry cannot be changed')
        quarry_self_a1c8a54._chained_entry = quarry_entry_a7f826d
    unpack_in_stages = quarry_unpack_in_stages
    dump_dict = quarry_dump_dict
    sizeof = quarry_sizeof
    get_chained_function_entry = quarry_get_chained_function_entry
    set_chained_function_entry = quarry_set_chained_function_entry

@_name_boundary.class_contract('PrologEpilogOp', {'initialize': 'quarry_initialize', 'length_in_code_structures': 'quarry_length_in_code_structures', 'is_valid': 'quarry_is_valid', '_get_format': 'quarry__get_format', 'struct': 'quarry_struct'})
class quarry_PrologEpilogOp:
    """Meant as an abstract class representing a generic unwind code.
    There is a subclass of PrologEpilogOp for each member of UNWIND_OP_CODES enum.
    """

    @_name_boundary.callable_contract({'self': 'quarry_self_4995e2a', 'unw_code': 'quarry_unw_code_2f65066', 'unw_info': 'quarry_unw_info_aae4820', 'file_offset': 'quarry_file_offset_2badec6', 'data': 'quarry_data_local_5bef548'}, 'initialize')
    def quarry_initialize(quarry_self_4995e2a, quarry_unw_code_2f65066, quarry_data_local_5bef548, quarry_unw_info_aae4820, quarry_file_offset_2badec6):
        _name_boundary.attributes(quarry_self_4995e2a)['struct'] = quarry_StructureWithBitfields(_name_boundary.attributes(quarry_self_4995e2a)['_get_format'](quarry_unw_code_2f65066), file_offset=quarry_file_offset_2badec6)
        _name_boundary.attributes(quarry_self_4995e2a)['struct'].__unpack__(quarry_data_local_5bef548)

    @_name_boundary.callable_contract({'self': 'quarry_self_d4ab287', 'unw_code': 'quarry_unw_code_629f415', 'unw_info': 'quarry_unw_info_41bee76'}, 'length_in_code_structures')
    def quarry_length_in_code_structures(quarry_self_d4ab287, quarry_unw_code_629f415, quarry_unw_info_41bee76):
        """Computes how many UNWIND_CODE structures UNWIND_CODE occupies.
        May be called before initialize() and, for that reason, should not rely on
        the values of instance attributes.
        """
        return 1

    @_name_boundary.callable_contract({'self': 'quarry_self_58a6c3d'}, 'is_valid')
    def quarry_is_valid(quarry_self_58a6c3d):
        return True

    @_name_boundary.callable_contract({'self': 'quarry_self_849aa8b', 'unw_code': 'quarry_unw_code_d2df3e7'}, '_get_format')
    def quarry__get_format(quarry_self_849aa8b, quarry_unw_code_d2df3e7):
        return ('UNWIND_CODE', ('B,CodeOffset', 'B:4,UnwindOp', 'B:4,OpInfo'))

@_name_boundary.class_contract('PrologEpilogOpPushReg', {'_get_format': 'quarry__get_format', 'struct': 'quarry_struct'})
class quarry_PrologEpilogOpPushReg(quarry_PrologEpilogOp):
    """UWOP_PUSH_NONVOL"""

    @_name_boundary.callable_contract({'self': 'quarry_self_500fc08', 'unw_code': 'quarry_unw_code_53d805d'}, '_get_format')
    def quarry__get_format(quarry_self_500fc08, quarry_unw_code_53d805d):
        return ('UNWIND_CODE_PUSH_NONVOL', ('B,CodeOffset', 'B:4,UnwindOp', 'B:4,Reg'))

    @_name_boundary.callable_contract({'self': 'quarry_self_a33f6d0'}, '__str__')
    def __str__(quarry_self_a33f6d0):
        return '.PUSHREG ' + quarry_REGISTERS[_name_boundary.attributes(quarry_self_a33f6d0)['struct'].Reg]

@_name_boundary.class_contract('PrologEpilogOpAllocLarge', {'_get_format': 'quarry__get_format', 'length_in_code_structures': 'quarry_length_in_code_structures', 'get_alloc_size': 'quarry_get_alloc_size', 'struct': 'quarry_struct'})
class quarry_PrologEpilogOpAllocLarge(quarry_PrologEpilogOp):
    """UWOP_ALLOC_LARGE"""

    @_name_boundary.callable_contract({'self': 'quarry_self_e04e2ea', 'unw_code': 'quarry_unw_code_6e8362a'}, '_get_format')
    def quarry__get_format(quarry_self_e04e2ea, quarry_unw_code_6e8362a):
        return ('UNWIND_CODE_ALLOC_LARGE', ('B,CodeOffset', 'B:4,UnwindOp', 'B:4,OpInfo', 'H,AllocSizeInQwords' if quarry_unw_code_6e8362a.OpInfo == 0 else 'I,AllocSize'))

    @_name_boundary.callable_contract({'self': 'quarry_self_33a962f', 'unw_code': 'quarry_unw_code_27297f8', 'unw_info': 'quarry_unw_info_9c2edbd'}, 'length_in_code_structures')
    def quarry_length_in_code_structures(quarry_self_33a962f, quarry_unw_code_27297f8, quarry_unw_info_9c2edbd):
        return 2 if quarry_unw_code_27297f8.OpInfo == 0 else 3

    @_name_boundary.callable_contract({'self': 'quarry_self_7e4f505'}, 'get_alloc_size')
    def quarry_get_alloc_size(quarry_self_7e4f505):
        return _name_boundary.attributes(quarry_self_7e4f505)['struct'].AllocSizeInQwords * 8 if _name_boundary.attributes(quarry_self_7e4f505)['struct'].OpInfo == 0 else _name_boundary.attributes(quarry_self_7e4f505)['struct'].AllocSize

    @_name_boundary.callable_contract({'self': 'quarry_self_2cfd71b'}, '__str__')
    def __str__(quarry_self_2cfd71b):
        return '.ALLOCSTACK ' + hex(_name_boundary.attributes(quarry_self_2cfd71b)['get_alloc_size']())

@_name_boundary.class_contract('PrologEpilogOpAllocSmall', {'_get_format': 'quarry__get_format', 'get_alloc_size': 'quarry_get_alloc_size', 'struct': 'quarry_struct'})
class quarry_PrologEpilogOpAllocSmall(quarry_PrologEpilogOp):
    """UWOP_ALLOC_SMALL"""

    @_name_boundary.callable_contract({'self': 'quarry_self_336e051', 'unw_code': 'quarry_unw_code_a5f3774'}, '_get_format')
    def quarry__get_format(quarry_self_336e051, quarry_unw_code_a5f3774):
        return ('UNWIND_CODE_ALLOC_SMALL', ('B,CodeOffset', 'B:4,UnwindOp', 'B:4,AllocSizeInQwordsMinus8'))

    @_name_boundary.callable_contract({'self': 'quarry_self_3dc273a'}, 'get_alloc_size')
    def quarry_get_alloc_size(quarry_self_3dc273a):
        return _name_boundary.attributes(quarry_self_3dc273a)['struct'].AllocSizeInQwordsMinus8 * 8 + 8

    @_name_boundary.callable_contract({'self': 'quarry_self_9ee773e'}, '__str__')
    def __str__(quarry_self_9ee773e):
        return '.ALLOCSTACK ' + hex(_name_boundary.attributes(quarry_self_9ee773e)['get_alloc_size']())

@_name_boundary.class_contract('PrologEpilogOpSetFP', {'initialize': 'quarry_initialize', '_frame_register': 'quarry__frame_register', '_frame_offset': 'quarry__frame_offset'})
class quarry_PrologEpilogOpSetFP(quarry_PrologEpilogOp):
    """UWOP_SET_FPREG"""

    @_name_boundary.callable_contract({'self': 'quarry_self_7ecd232', 'unw_code': 'quarry_unw_code_8514f64', 'unw_info': 'quarry_unw_info_5224162', 'file_offset': 'quarry_file_offset_ae2daaf', 'data': 'quarry_data_local_dfffb61'}, 'initialize')
    def quarry_initialize(quarry_self_7ecd232, quarry_unw_code_8514f64, quarry_data_local_dfffb61, quarry_unw_info_5224162, quarry_file_offset_ae2daaf):
        _name_boundary.attributes(super())['initialize'](quarry_unw_code_8514f64, quarry_data_local_dfffb61, quarry_unw_info_5224162, quarry_file_offset_ae2daaf)
        _name_boundary.attributes(quarry_self_7ecd232)['_frame_register'] = quarry_unw_info_5224162.FrameRegister
        _name_boundary.attributes(quarry_self_7ecd232)['_frame_offset'] = quarry_unw_info_5224162.FrameOffset * 16

    @_name_boundary.callable_contract({'self': 'quarry_self_f26a997'}, '__str__')
    def __str__(quarry_self_f26a997):
        return '.SETFRAME ' + quarry_REGISTERS[_name_boundary.attributes(quarry_self_f26a997)['_frame_register']] + ', ' + hex(_name_boundary.attributes(quarry_self_f26a997)['_frame_offset'])

@_name_boundary.class_contract('PrologEpilogOpSaveReg', {'length_in_code_structures': 'quarry_length_in_code_structures', 'get_offset': 'quarry_get_offset', '_get_format': 'quarry__get_format', 'struct': 'quarry_struct'})
class quarry_PrologEpilogOpSaveReg(quarry_PrologEpilogOp):
    """UWOP_SAVE_NONVOL"""

    @_name_boundary.callable_contract({'self': 'quarry_self_6888747', 'unwcode': 'quarry_unwcode_5449fb7', 'unw_info': 'quarry_unw_info_f73cbd3'}, 'length_in_code_structures')
    def quarry_length_in_code_structures(quarry_self_6888747, quarry_unwcode_5449fb7, quarry_unw_info_f73cbd3):
        return 2

    @_name_boundary.callable_contract({'self': 'quarry_self_c033892'}, 'get_offset')
    def quarry_get_offset(quarry_self_c033892):
        return _name_boundary.attributes(quarry_self_c033892)['struct'].OffsetInQwords * 8

    @_name_boundary.callable_contract({'self': 'quarry_self_8955d9c', 'unw_code': 'quarry_unw_code_dfaaf37'}, '_get_format')
    def quarry__get_format(quarry_self_8955d9c, quarry_unw_code_dfaaf37):
        return ('UNWIND_CODE_SAVE_NONVOL', ('B,CodeOffset', 'B:4,UnwindOp', 'B:4,Reg', 'H,OffsetInQwords'))

    @_name_boundary.callable_contract({'self': 'quarry_self_b76480a'}, '__str__')
    def __str__(quarry_self_b76480a):
        return '.SAVEREG ' + quarry_REGISTERS[_name_boundary.attributes(quarry_self_b76480a)['struct'].Reg] + ', ' + hex(_name_boundary.attributes(quarry_self_b76480a)['get_offset']())

@_name_boundary.class_contract('PrologEpilogOpSaveRegFar', {'length_in_code_structures': 'quarry_length_in_code_structures', 'get_offset': 'quarry_get_offset', '_get_format': 'quarry__get_format', 'struct': 'quarry_struct'})
class quarry_PrologEpilogOpSaveRegFar(quarry_PrologEpilogOp):
    """UWOP_SAVE_NONVOL_FAR"""

    @_name_boundary.callable_contract({'self': 'quarry_self_918fedc', 'unw_code': 'quarry_unw_code_52c6244', 'unw_info': 'quarry_unw_info_b43f534'}, 'length_in_code_structures')
    def quarry_length_in_code_structures(quarry_self_918fedc, quarry_unw_code_52c6244, quarry_unw_info_b43f534):
        return 3

    @_name_boundary.callable_contract({'self': 'quarry_self_f13c6e2'}, 'get_offset')
    def quarry_get_offset(quarry_self_f13c6e2):
        return _name_boundary.attributes(quarry_self_f13c6e2)['struct'].Offset

    @_name_boundary.callable_contract({'self': 'quarry_self_eab6aac', 'unw_code': 'quarry_unw_code_e5f1975'}, '_get_format')
    def quarry__get_format(quarry_self_eab6aac, quarry_unw_code_e5f1975):
        return ('UNWIND_CODE_SAVE_NONVOL_FAR', ('B,CodeOffset', 'B:4,UnwindOp', 'B:4,Reg', 'I,Offset'))

    @_name_boundary.callable_contract({'self': 'quarry_self_46fd40b'}, '__str__')
    def __str__(quarry_self_46fd40b):
        return '.SAVEREG ' + quarry_REGISTERS[_name_boundary.attributes(quarry_self_46fd40b)['struct'].Reg] + ', ' + hex(_name_boundary.attributes(quarry_self_46fd40b)['struct'].Offset)

@_name_boundary.class_contract('PrologEpilogOpSaveXMM', {'_get_format': 'quarry__get_format', 'length_in_code_structures': 'quarry_length_in_code_structures', 'get_offset': 'quarry_get_offset', 'struct': 'quarry_struct'})
class quarry_PrologEpilogOpSaveXMM(quarry_PrologEpilogOp):
    """UWOP_SAVE_XMM128"""

    @_name_boundary.callable_contract({'self': 'quarry_self_56641c3', 'unw_code': 'quarry_unw_code_9620275'}, '_get_format')
    def quarry__get_format(quarry_self_56641c3, quarry_unw_code_9620275):
        return ('UNWIND_CODE_SAVE_XMM128', ('B,CodeOffset', 'B:4,UnwindOp', 'B:4,Reg', 'H,OffsetIn2Qwords'))

    @_name_boundary.callable_contract({'self': 'quarry_self_8f144dc', 'unw_code': 'quarry_unw_code_f278795', 'unw_info': 'quarry_unw_info_429d2e0'}, 'length_in_code_structures')
    def quarry_length_in_code_structures(quarry_self_8f144dc, quarry_unw_code_f278795, quarry_unw_info_429d2e0):
        return 2

    @_name_boundary.callable_contract({'self': 'quarry_self_a2fd375'}, 'get_offset')
    def quarry_get_offset(quarry_self_a2fd375):
        return _name_boundary.attributes(quarry_self_a2fd375)['struct'].OffsetIn2Qwords * 16

    @_name_boundary.callable_contract({'self': 'quarry_self_39e3cf2'}, '__str__')
    def __str__(quarry_self_39e3cf2):
        return '.SAVEXMM128 XMM' + str(_name_boundary.attributes(quarry_self_39e3cf2)['struct'].Reg) + ', ' + hex(_name_boundary.attributes(quarry_self_39e3cf2)['get_offset']())

@_name_boundary.class_contract('PrologEpilogOpSaveXMMFar', {'_get_format': 'quarry__get_format', 'length_in_code_structures': 'quarry_length_in_code_structures', 'get_offset': 'quarry_get_offset', 'struct': 'quarry_struct'})
class quarry_PrologEpilogOpSaveXMMFar(quarry_PrologEpilogOp):
    """UWOP_SAVE_XMM128_FAR"""

    @_name_boundary.callable_contract({'self': 'quarry_self_21b824e', 'unw_code': 'quarry_unw_code_e7f40f8'}, '_get_format')
    def quarry__get_format(quarry_self_21b824e, quarry_unw_code_e7f40f8):
        return ('UNWIND_CODE_SAVE_XMM128_FAR', ('B,CodeOffset', 'B:4,UnwindOp', 'B:4,Reg', 'I,Offset'))

    @_name_boundary.callable_contract({'self': 'quarry_self_76948dd', 'unw_code': 'quarry_unw_code_560c159', 'unw_info': 'quarry_unw_info_118b2d3'}, 'length_in_code_structures')
    def quarry_length_in_code_structures(quarry_self_76948dd, quarry_unw_code_560c159, quarry_unw_info_118b2d3):
        return 3

    @_name_boundary.callable_contract({'self': 'quarry_self_509f55b'}, 'get_offset')
    def quarry_get_offset(quarry_self_509f55b):
        return _name_boundary.attributes(quarry_self_509f55b)['struct'].Offset

    @_name_boundary.callable_contract({'self': 'quarry_self_7cee853'}, '__str__')
    def __str__(quarry_self_7cee853):
        return '.SAVEXMM128 XMM' + str(_name_boundary.attributes(quarry_self_7cee853)['struct'].Reg) + ', ' + hex(_name_boundary.attributes(quarry_self_7cee853)['struct'].Offset)

@_name_boundary.class_contract('PrologEpilogOpPushFrame', {'struct': 'quarry_struct'})
class quarry_PrologEpilogOpPushFrame(quarry_PrologEpilogOp):
    """UWOP_PUSH_MACHFRAME"""

    @_name_boundary.callable_contract({'self': 'quarry_self_1eb513f'}, '__str__')
    def __str__(quarry_self_1eb513f):
        return '.PUSHFRAME' + (' <code>' if _name_boundary.attributes(quarry_self_1eb513f)['struct'].OpInfo else '')

@_name_boundary.class_contract('PrologEpilogOpEpilogMarker', {'initialize': 'quarry_initialize', '_get_format': 'quarry__get_format', 'length_in_code_structures': 'quarry_length_in_code_structures', 'get_offset': 'quarry_get_offset', 'is_valid': 'quarry_is_valid', '_long_offst': 'quarry__long_offst', '_first': 'quarry__first', '_epilog_size': 'quarry__epilog_size', 'struct': 'quarry_struct'})
class quarry_PrologEpilogOpEpilogMarker(quarry_PrologEpilogOp):
    """UWOP_EPILOG"""

    @_name_boundary.callable_contract({'self': 'quarry_self_1d539a2', 'unw_code': 'quarry_unw_code_3281fd9', 'unw_info': 'quarry_unw_info_a54dde0', 'file_offset': 'quarry_file_offset_d69f4bd', 'data': 'quarry_data_local_8faa24a'}, 'initialize')
    def quarry_initialize(quarry_self_1d539a2, quarry_unw_code_3281fd9, quarry_data_local_8faa24a, quarry_unw_info_a54dde0, quarry_file_offset_d69f4bd):
        _name_boundary.attributes(quarry_self_1d539a2)['_long_offst'] = True
        _name_boundary.attributes(quarry_self_1d539a2)['_first'] = not _name_boundary.has_attribute(quarry_unw_info_a54dde0, 'SizeOfEpilog')
        _name_boundary.attributes(super())['initialize'](quarry_unw_code_3281fd9, quarry_data_local_8faa24a, quarry_unw_info_a54dde0, quarry_file_offset_d69f4bd)
        if _name_boundary.attributes(quarry_self_1d539a2)['_first']:
            quarry_unw_info_a54dde0.SizeOfEpilog = _name_boundary.attributes(quarry_self_1d539a2)['struct'].Size
            _name_boundary.attributes(quarry_self_1d539a2)['_long_offst'] = quarry_unw_code_3281fd9.OpInfo & 1 == 0
        _name_boundary.attributes(quarry_self_1d539a2)['_epilog_size'] = quarry_unw_info_a54dde0.SizeOfEpilog

    @_name_boundary.callable_contract({'self': 'quarry_self_21e4f78', 'unw_code': 'quarry_unw_code_584c5d8'}, '_get_format')
    def quarry__get_format(quarry_self_21e4f78, quarry_unw_code_584c5d8):
        if _name_boundary.attributes(quarry_self_21e4f78)['_first']:
            return ('UNWIND_CODE_EPILOG', ('B,OffsetLow,Size', 'B:4,UnwindOp', 'B:4,Flags') if quarry_unw_code_584c5d8.OpInfo & 1 == 1 else ('B,Size', 'B:4,UnwindOp', 'B:4,Flags', 'B,OffsetLow', 'B:4,Unused', 'B:4,OffsetHigh'))
        else:
            return ('UNWIND_CODE_EPILOG', ('B,OffsetLow', 'B:4,UnwindOp', 'B:4,OffsetHigh'))

    @_name_boundary.callable_contract({'self': 'quarry_self_15aae07', 'unw_code': 'quarry_unw_code_2a964ab', 'unw_info': 'quarry_unw_info_e4a5b22'}, 'length_in_code_structures')
    def quarry_length_in_code_structures(quarry_self_15aae07, quarry_unw_code_2a964ab, quarry_unw_info_e4a5b22):
        return 2 if not _name_boundary.has_attribute(quarry_unw_info_e4a5b22, 'SizeOfEpilog') and quarry_unw_code_2a964ab.OpInfo & 1 == 0 else 1

    @_name_boundary.callable_contract({'self': 'quarry_self_cdf663f'}, 'get_offset')
    def quarry_get_offset(quarry_self_cdf663f):
        return _name_boundary.attributes(quarry_self_cdf663f)['struct'].OffsetLow | (_name_boundary.attributes(quarry_self_cdf663f)['struct'].OffsetHigh << 8 if _name_boundary.attributes(quarry_self_cdf663f)['_long_offst'] else 0)

    @_name_boundary.callable_contract({'self': 'quarry_self_a98b5e8'}, 'is_valid')
    def quarry_is_valid(quarry_self_a98b5e8):
        return _name_boundary.attributes(quarry_self_a98b5e8)['get_offset']() > 0

    @_name_boundary.callable_contract({'self': 'quarry_self_bc9e65b'}, '__str__')
    def __str__(quarry_self_bc9e65b):
        return 'EPILOG: size=' + hex(_name_boundary.attributes(quarry_self_bc9e65b)['_epilog_size']) + ', offset from the end=-' + hex(_name_boundary.attributes(quarry_self_bc9e65b)['get_offset']()) if _name_boundary.attributes(quarry_self_bc9e65b)['get_offset']() > 0 else ''

@_name_boundary.class_contract('PrologEpilogOpsFactory', {'_class_dict': 'quarry__class_dict', 'create': 'quarry_create'})
class quarry_PrologEpilogOpsFactory:
    """A factory for creating unwind codes based on the value of UnwindOp"""
    quarry__class_dict = {quarry_UWOP_PUSH_NONVOL: quarry_PrologEpilogOpPushReg, quarry_UWOP_ALLOC_LARGE: quarry_PrologEpilogOpAllocLarge, quarry_UWOP_ALLOC_SMALL: quarry_PrologEpilogOpAllocSmall, quarry_UWOP_SET_FPREG: quarry_PrologEpilogOpSetFP, quarry_UWOP_SAVE_NONVOL: quarry_PrologEpilogOpSaveReg, quarry_UWOP_SAVE_NONVOL_FAR: quarry_PrologEpilogOpSaveRegFar, quarry_UWOP_SAVE_XMM128: quarry_PrologEpilogOpSaveXMM, quarry_UWOP_SAVE_XMM128_FAR: quarry_PrologEpilogOpSaveXMMFar, quarry_UWOP_PUSH_MACHFRAME: quarry_PrologEpilogOpPushFrame, quarry_UWOP_EPILOG: quarry_PrologEpilogOpEpilogMarker}

    @staticmethod
    @_name_boundary.callable_contract({'unwcode': 'quarry_unwcode_a060a41'}, 'create')
    def quarry_create(quarry_unwcode_a060a41):
        quarry_code_6434d05 = quarry_unwcode_a060a41.UnwindOp
        return _name_boundary.attributes(quarry_PrologEpilogOpsFactory)['_class_dict'][quarry_code_6434d05]() if quarry_code_6434d05 in _name_boundary.attributes(quarry_PrologEpilogOpsFactory)['_class_dict'] else None

@_name_boundary.callable_contract({'value': 'quarry_value_b8e7929'}, 'human_readable_size')
def quarry_human_readable_size(quarry_value_b8e7929: int) -> str:
    """
    Convert bytes into a human readable string using binary prefixes (KiB, MiB, etc.).

    value should be a positive integer representing the number of bytes.
    """
    if quarry_value_b8e7929 == 0:
        return '0B'
    quarry_units_839888a = ['B', 'KiB', 'MiB', 'GiB', 'TiB', 'PiB', 'EiB', 'ZiB', 'YiB']
    quarry_i_597954d = min((quarry_value_b8e7929.bit_length() - 1) // 10, len(quarry_units_839888a) - 1)
    quarry_display_value_1c1d4a2 = quarry_value_b8e7929 / (1 << 10 * quarry_i_597954d)
    if quarry_display_value_1c1d4a2.is_integer():
        quarry_precision_cbba2c9 = 0
    else:
        quarry_precision_cbba2c9 = 1
        quarry_display_value_1c1d4a2 = quarry_math.floor(quarry_value_b8e7929 * 10) / 10
    return f'{quarry_display_value_1c1d4a2:.{quarry_precision_cbba2c9}f}{quarry_units_839888a[quarry_i_597954d]}'
quarry_allowed_filename = (quarry_string.ascii_lowercase + quarry_string.ascii_uppercase + quarry_string.digits + "!#$%&'()-@^_`{}~+,.;=[]:").encode()

@_name_boundary.callable_contract({'s': 'quarry_s_9b98e6f'}, 'is_valid_dos_filename')
def quarry_is_valid_dos_filename(quarry_s_9b98e6f):
    if quarry_s_9b98e6f is None or not isinstance(quarry_s_9b98e6f, (str, bytes, bytearray)):
        return False
    quarry_allowed_5aed755 = quarry_allowed_filename + b'\\/'
    return all((quarry_c_ce1f2d9 in quarry_allowed_5aed755 for quarry_c_ce1f2d9 in set(quarry_s_9b98e6f)))
quarry_allowed_function_name = (quarry_string.ascii_lowercase + quarry_string.ascii_uppercase + quarry_string.digits).encode()

@quarry_lru_cache(maxsize=2048)
@_name_boundary.callable_contract({'s': 'quarry_s_3d165b3', 'relax_allowed_characters': 'quarry_relax_allowed_characters_79e28e9'}, 'is_valid_function_name')
def quarry_is_valid_function_name(quarry_s_3d165b3: str | bytes | bytearray, quarry_relax_allowed_characters_79e28e9: bool=False) -> bool:
    """
    MangleChars = "$:?([.)]"        // watcom
                  "@$%?"            // microsoft
                  "@$%&";           // borland
    Source: ida.cfg

    "_" is also used in mangled names
    "<>" C++ templates, e.g. functions in wincorlib.dll
    """
    quarry_allowed_extra_6d005b6 = b'$%&().:<>?@[]_'
    if quarry_relax_allowed_characters_79e28e9:
        quarry_allowed_extra_6d005b6 = quarry_string.punctuation.encode()
    return quarry_s_3d165b3 is not None and isinstance(quarry_s_3d165b3, (str, bytes, bytearray)) and all((quarry_c_f63af05 in quarry_allowed_function_name + quarry_allowed_extra_6d005b6 for quarry_c_f63af05 in set(quarry_s_3d165b3)))

@_name_boundary.class_contract('PE', {'_close_data': 'quarry__close_data', 'close': 'quarry_close', 'parse_rich_header': 'quarry_parse_rich_header', 'get_warnings': 'quarry_get_warnings', 'show_warnings': 'quarry_show_warnings', 'full_load': 'quarry_full_load', 'write': 'quarry_write', 'parse_sections': 'quarry_parse_sections', 'parse_data_directories': 'quarry_parse_data_directories', 'parse_exceptions_directory': 'quarry_parse_exceptions_directory', 'parse_directory_bound_imports': 'quarry_parse_directory_bound_imports', 'parse_directory_tls': 'quarry_parse_directory_tls', 'parse_directory_load_config': 'quarry_parse_directory_load_config', 'parse_dynamic_relocations': 'quarry_parse_dynamic_relocations', 'parse_function_override_data': 'quarry_parse_function_override_data', 'parse_relocations_directory': 'quarry_parse_relocations_directory', 'parse_image_base_relocation_list': 'quarry_parse_image_base_relocation_list', 'parse_relocations': 'quarry_parse_relocations', 'parse_relocations_with_format': 'quarry_parse_relocations_with_format', 'parse_debug_directory': 'quarry_parse_debug_directory', 'parse_resources_directory': 'quarry_parse_resources_directory', 'parse_resource_data_entry': 'quarry_parse_resource_data_entry', 'parse_resource_entry': 'quarry_parse_resource_entry', 'parse_version_information': 'quarry_parse_version_information', 'parse_export_directory': 'quarry_parse_export_directory', 'dword_align': 'quarry_dword_align', 'normalize_import_va': 'quarry_normalize_import_va', 'parse_delay_import_directory': 'quarry_parse_delay_import_directory', 'get_rich_header_hash': 'quarry_get_rich_header_hash', 'get_imphash': 'quarry_get_imphash', 'get_exphash': 'quarry_get_exphash', 'parse_import_directory': 'quarry_parse_import_directory', 'parse_imports': 'quarry_parse_imports', 'get_import_table': 'quarry_get_import_table', 'get_memory_mapped_image': 'quarry_get_memory_mapped_image', 'get_resources_strings': 'quarry_get_resources_strings', 'get_data': 'quarry_get_data', 'get_rva_from_offset': 'quarry_get_rva_from_offset', 'get_offset_from_rva': 'quarry_get_offset_from_rva', 'get_string_at_rva': 'quarry_get_string_at_rva', 'get_bytes_from_data': 'quarry_get_bytes_from_data', 'get_string_from_data': 'quarry_get_string_from_data', 'get_string_u_at_rva': 'quarry_get_string_u_at_rva', 'get_section_by_offset': 'quarry_get_section_by_offset', 'get_section_by_rva': 'quarry_get_section_by_rva', 'has_relocs': 'quarry_has_relocs', 'has_dynamic_relocs': 'quarry_has_dynamic_relocs', 'print_info': 'quarry_print_info', 'dump_info': 'quarry_dump_info', 'dump_dict': 'quarry_dump_dict', 'get_physical_by_rva': 'quarry_get_physical_by_rva', 'get_data_from_dword': 'quarry_get_data_from_dword', 'get_dword_from_data': 'quarry_get_dword_from_data', 'get_dword_at_rva': 'quarry_get_dword_at_rva', 'get_dword_from_offset': 'quarry_get_dword_from_offset', 'set_dword_at_rva': 'quarry_set_dword_at_rva', 'set_dword_at_offset': 'quarry_set_dword_at_offset', 'get_data_from_word': 'quarry_get_data_from_word', 'get_word_from_data': 'quarry_get_word_from_data', 'get_word_at_rva': 'quarry_get_word_at_rva', 'get_word_from_offset': 'quarry_get_word_from_offset', 'set_word_at_rva': 'quarry_set_word_at_rva', 'set_word_at_offset': 'quarry_set_word_at_offset', 'get_data_from_qword': 'quarry_get_data_from_qword', 'get_qword_from_data': 'quarry_get_qword_from_data', 'get_qword_at_rva': 'quarry_get_qword_at_rva', 'get_qword_from_offset': 'quarry_get_qword_from_offset', 'set_qword_at_rva': 'quarry_set_qword_at_rva', 'set_qword_at_offset': 'quarry_set_qword_at_offset', 'set_bytes_at_rva': 'quarry_set_bytes_at_rva', 'set_bytes_at_offset': 'quarry_set_bytes_at_offset', 'set_data_bytes': 'quarry_set_data_bytes', 'merge_modified_section_data': 'quarry_merge_modified_section_data', 'relocate_image': 'quarry_relocate_image', 'verify_checksum': 'quarry_verify_checksum', 'generate_checksum': 'quarry_generate_checksum', 'is_exe': 'quarry_is_exe', 'is_dll': 'quarry_is_dll', 'is_driver': 'quarry_is_driver', 'get_overlay_data_start_offset': 'quarry_get_overlay_data_start_offset', 'get_overlay': 'quarry_get_overlay', 'trim': 'quarry_trim', 'adjust_PointerToRawData': 'quarry_adjust_PointerToRawData', 'adjust_SectionAlignment': 'quarry_adjust_SectionAlignment', 'max_symbol_exports': 'quarry_max_symbol_exports', 'max_repeated_symbol': 'quarry_max_repeated_symbol', '_get_section_by_rva_last_used': 'quarry__get_section_by_rva_last_used', 'sections': 'quarry_sections', '__warnings': 'quarry___warnings', 'PE_TYPE': 'quarry_PE_TYPE', '__from_file': 'quarry___from_file', 'FileAlignment_Warning': 'quarry_FileAlignment_Warning', 'SectionAlignment_Warning': 'quarry_SectionAlignment_Warning', '__total_resource_entries_count': 'quarry___total_resource_entries_count', '__total_resource_bytes': 'quarry___total_resource_bytes', '__total_import_symbols': 'quarry___total_import_symbols', 'dynamic_relocation_format_by_symbol': 'quarry_dynamic_relocation_format_by_symbol', '__resource_size_limit_upperbounds': 'quarry___resource_size_limit_upperbounds', '__resource_size_limit_reached': 'quarry___resource_size_limit_reached', 'DOS_HEADER': 'quarry_DOS_HEADER', 'NT_HEADERS': 'quarry_NT_HEADERS', 'FILE_HEADER': 'quarry_FILE_HEADER', 'OPTIONAL_HEADER': 'quarry_OPTIONAL_HEADER', 'header': 'quarry_header', 'RICH_HEADER': 'quarry_RICH_HEADER', 'FileInfo': 'quarry_FileInfo', 'VS_VERSIONINFO': 'quarry_VS_VERSIONINFO', 'VS_FIXEDFILEINFO': 'quarry_VS_FIXEDFILEINFO', 'fileno': 'quarry_fileno'})
class quarry_PE:
    """A Portable Executable representation.

    This class provides access to most of the information in a PE file.

    It expects to be supplied the name of the file to load or PE data
    to process and an optional argument 'fast_load' (False by default)
    which controls whether to load all the directories information,
    which can be quite time consuming.

    pe = pefile.PE('module.dll')
    pe = pefile.PE(name='module.dll')

    would load 'module.dll' and process it. If the data is already
    available in a buffer the same can be achieved with:

    pe = pefile.PE(data=module_dll_data)

    The "fast_load" can be set to a default by setting its value in the
    module itself by means, for instance, of a "pefile.fast_load = True".
    That will make all the subsequent instances not to load the
    whole PE structure. The "full_load" method can be used to parse
    the missing data at a later stage.

    Warnings will be raised during parsing if a section is larger and/or
    at a higher offset than the limit configured by the 'max_offset'
    parameter, which defaults to '0x10000000' (256MiB).

    Basic headers information will be available in the attributes:

    DOS_HEADER
    NT_HEADERS
    FILE_HEADER
    OPTIONAL_HEADER

    All of them will contain among their attributes the members of the
    corresponding structures as defined in WINNT.H

    The raw data corresponding to the header (from the beginning of the
    file up to the start of the first section) will be available in the
    instance's attribute 'header' as a string.

    The sections will be available as a list in the 'sections' attribute.
    Each entry will contain as attributes all the structure's members.

    Directory entries will be available as attributes (if they exist):
    (no other entries are processed at this point)

    DIRECTORY_ENTRY_IMPORT (list of ImportDescData instances)
    DIRECTORY_ENTRY_EXPORT (ExportDirData instance)
    DIRECTORY_ENTRY_RESOURCE (ResourceDirData instance)
    DIRECTORY_ENTRY_DEBUG (list of DebugData instances)
    DIRECTORY_ENTRY_BASERELOC (list of BaseRelocationData instances)
    DIRECTORY_ENTRY_TLS
    DIRECTORY_ENTRY_BOUND_IMPORT (list of BoundImportData instances)

    The following dictionary attributes provide ways of mapping different
    constants. They will accept the numeric value and return the string
    representation and the opposite, feed in the string and get the
    numeric constant:

    DIRECTORY_ENTRY
    IMAGE_CHARACTERISTICS
    SECTION_CHARACTERISTICS
    DEBUG_TYPE
    SUBSYSTEM_TYPE
    MACHINE_TYPE
    RELOCATION_TYPE
    RESOURCE_TYPE
    LANG
    SUBLANG
    """
    __IMAGE_DOS_HEADER_format__ = ('IMAGE_DOS_HEADER', ('H,e_magic', 'H,e_cblp', 'H,e_cp', 'H,e_crlc', 'H,e_cparhdr', 'H,e_minalloc', 'H,e_maxalloc', 'H,e_ss', 'H,e_sp', 'H,e_csum', 'H,e_ip', 'H,e_cs', 'H,e_lfarlc', 'H,e_ovno', '8s,e_res', 'H,e_oemid', 'H,e_oeminfo', '20s,e_res2', 'I,e_lfanew'))
    __IMAGE_NT_HEADERS_format__ = ('IMAGE_NT_HEADERS', ('I,Signature',))
    __IMAGE_FILE_HEADER_format__ = ('IMAGE_FILE_HEADER', ('H,Machine', 'H,NumberOfSections', 'I,TimeDateStamp', 'I,PointerToSymbolTable', 'I,NumberOfSymbols', 'H,SizeOfOptionalHeader', 'H,Characteristics'))
    __IMAGE_OPTIONAL_HEADER_format__ = ('IMAGE_OPTIONAL_HEADER', ('H,Magic', 'B,MajorLinkerVersion', 'B,MinorLinkerVersion', 'I,SizeOfCode', 'I,SizeOfInitializedData', 'I,SizeOfUninitializedData', 'I,AddressOfEntryPoint', 'I,BaseOfCode', 'I,BaseOfData', 'I,ImageBase', 'I,SectionAlignment', 'I,FileAlignment', 'H,MajorOperatingSystemVersion', 'H,MinorOperatingSystemVersion', 'H,MajorImageVersion', 'H,MinorImageVersion', 'H,MajorSubsystemVersion', 'H,MinorSubsystemVersion', 'I,Reserved1', 'I,SizeOfImage', 'I,SizeOfHeaders', 'I,CheckSum', 'H,Subsystem', 'H,DllCharacteristics', 'I,SizeOfStackReserve', 'I,SizeOfStackCommit', 'I,SizeOfHeapReserve', 'I,SizeOfHeapCommit', 'I,LoaderFlags', 'I,NumberOfRvaAndSizes'))
    __IMAGE_OPTIONAL_HEADER64_format__ = ('IMAGE_OPTIONAL_HEADER64', ('H,Magic', 'B,MajorLinkerVersion', 'B,MinorLinkerVersion', 'I,SizeOfCode', 'I,SizeOfInitializedData', 'I,SizeOfUninitializedData', 'I,AddressOfEntryPoint', 'I,BaseOfCode', 'Q,ImageBase', 'I,SectionAlignment', 'I,FileAlignment', 'H,MajorOperatingSystemVersion', 'H,MinorOperatingSystemVersion', 'H,MajorImageVersion', 'H,MinorImageVersion', 'H,MajorSubsystemVersion', 'H,MinorSubsystemVersion', 'I,Reserved1', 'I,SizeOfImage', 'I,SizeOfHeaders', 'I,CheckSum', 'H,Subsystem', 'H,DllCharacteristics', 'Q,SizeOfStackReserve', 'Q,SizeOfStackCommit', 'Q,SizeOfHeapReserve', 'Q,SizeOfHeapCommit', 'I,LoaderFlags', 'I,NumberOfRvaAndSizes'))
    __IMAGE_DATA_DIRECTORY_format__ = ('IMAGE_DATA_DIRECTORY', ('I,VirtualAddress', 'I,Size'))
    __IMAGE_SECTION_HEADER_format__ = ('IMAGE_SECTION_HEADER', ('8s,Name', 'I,Misc,Misc_PhysicalAddress,Misc_VirtualSize', 'I,VirtualAddress', 'I,SizeOfRawData', 'I,PointerToRawData', 'I,PointerToRelocations', 'I,PointerToLinenumbers', 'H,NumberOfRelocations', 'H,NumberOfLinenumbers', 'I,Characteristics'))
    __IMAGE_DELAY_IMPORT_DESCRIPTOR_format__ = ('IMAGE_DELAY_IMPORT_DESCRIPTOR', ('I,grAttrs', 'I,szName', 'I,phmod', 'I,pIAT', 'I,pINT', 'I,pBoundIAT', 'I,pUnloadIAT', 'I,dwTimeStamp'))
    __IMAGE_IMPORT_DESCRIPTOR_format__ = ('IMAGE_IMPORT_DESCRIPTOR', ('I,OriginalFirstThunk,Characteristics', 'I,TimeDateStamp', 'I,ForwarderChain', 'I,Name', 'I,FirstThunk'))
    __IMAGE_EXPORT_DIRECTORY_format__ = ('IMAGE_EXPORT_DIRECTORY', ('I,Characteristics', 'I,TimeDateStamp', 'H,MajorVersion', 'H,MinorVersion', 'I,Name', 'I,Base', 'I,NumberOfFunctions', 'I,NumberOfNames', 'I,AddressOfFunctions', 'I,AddressOfNames', 'I,AddressOfNameOrdinals'))
    __IMAGE_RESOURCE_DIRECTORY_format__ = ('IMAGE_RESOURCE_DIRECTORY', ('I,Characteristics', 'I,TimeDateStamp', 'H,MajorVersion', 'H,MinorVersion', 'H,NumberOfNamedEntries', 'H,NumberOfIdEntries'))
    __IMAGE_RESOURCE_DIRECTORY_ENTRY_format__ = ('IMAGE_RESOURCE_DIRECTORY_ENTRY', ('I,Name', 'I,OffsetToData'))
    __IMAGE_RESOURCE_DATA_ENTRY_format__ = ('IMAGE_RESOURCE_DATA_ENTRY', ('I,OffsetToData', 'I,Size', 'I,CodePage', 'I,Reserved'))
    __VS_VERSIONINFO_format__ = ('VS_VERSIONINFO', ('H,Length', 'H,ValueLength', 'H,Type'))
    __VS_FIXEDFILEINFO_format__ = ('VS_FIXEDFILEINFO', ('I,Signature', 'I,StrucVersion', 'I,FileVersionMS', 'I,FileVersionLS', 'I,ProductVersionMS', 'I,ProductVersionLS', 'I,FileFlagsMask', 'I,FileFlags', 'I,FileOS', 'I,FileType', 'I,FileSubtype', 'I,FileDateMS', 'I,FileDateLS'))
    __StringFileInfo_format__ = ('StringFileInfo', ('H,Length', 'H,ValueLength', 'H,Type'))
    __StringTable_format__ = ('StringTable', ('H,Length', 'H,ValueLength', 'H,Type'))
    __String_format__ = ('String', ('H,Length', 'H,ValueLength', 'H,Type'))
    __Var_format__ = ('Var', ('H,Length', 'H,ValueLength', 'H,Type'))
    __IMAGE_THUNK_DATA_format__ = ('IMAGE_THUNK_DATA', ('I,ForwarderString,Function,Ordinal,AddressOfData',))
    __IMAGE_THUNK_DATA64_format__ = ('IMAGE_THUNK_DATA', ('Q,ForwarderString,Function,Ordinal,AddressOfData',))
    __IMAGE_DEBUG_DIRECTORY_format__ = ('IMAGE_DEBUG_DIRECTORY', ('I,Characteristics', 'I,TimeDateStamp', 'H,MajorVersion', 'H,MinorVersion', 'I,Type', 'I,SizeOfData', 'I,AddressOfRawData', 'I,PointerToRawData'))
    __IMAGE_BASE_RELOCATION_format__ = ('IMAGE_BASE_RELOCATION', ('I,VirtualAddress', 'I,SizeOfBlock'))
    __IMAGE_BASE_RELOCATION_ENTRY_format__ = ('IMAGE_BASE_RELOCATION_ENTRY', ('H,Data',))
    __IMAGE_IMPORT_CONTROL_TRANSFER_DYNAMIC_RELOCATION_format__ = ('IMAGE_IMPORT_CONTROL_TRANSFER_DYNAMIC_RELOCATION', ('I:12,PageRelativeOffset', 'I:1,IndirectCall', 'I:19,IATIndex'))
    __IMAGE_INDIR_CONTROL_TRANSFER_DYNAMIC_RELOCATION_format__ = ('IMAGE_INDIR_CONTROL_TRANSFER_DYNAMIC_RELOCATION', ('H:12,PageRelativeOffset', 'H:1,IndirectCall', 'H:1,RexWPrefix', 'H:1,CfgCheck', 'H:1,Reserved'))
    __IMAGE_SWITCHTABLE_BRANCH_DYNAMIC_RELOCATION_format__ = ('IMAGE_SWITCHTABLE_BRANCH_DYNAMIC_RELOCATION', ('H:12,PageRelativeOffset', 'H:4,RegisterNumber'))
    __IMAGE_FUNCTION_OVERRIDE_HEADER_format__ = ('IMAGE_FUNCTION_OVERRIDE_HEADER', ('I,FuncOverrideSize',))
    __IMAGE_FUNCTION_OVERRIDE_DYNAMIC_RELOCATION_format__ = ('IMAGE_FUNCTION_OVERRIDE_DYNAMIC_RELOCATION', ('I,OriginalRva', 'I,BDDOffset', 'I,RvaSize', 'I,BaseRelocSize'))
    __IMAGE_BDD_INFO_format__ = ('IMAGE_BDD_INFO', ('I,Version', 'I,BDDSize'))
    __IMAGE_BDD_DYNAMIC_RELOCATION_format__ = ('IMAGE_BDD_DYNAMIC_RELOCATION', ('H,Left', 'H,Right', 'I,Value'))
    __IMAGE_TLS_DIRECTORY_format__ = ('IMAGE_TLS_DIRECTORY', ('I,StartAddressOfRawData', 'I,EndAddressOfRawData', 'I,AddressOfIndex', 'I,AddressOfCallBacks', 'I,SizeOfZeroFill', 'I,Characteristics'))
    __IMAGE_TLS_DIRECTORY64_format__ = ('IMAGE_TLS_DIRECTORY', ('Q,StartAddressOfRawData', 'Q,EndAddressOfRawData', 'Q,AddressOfIndex', 'Q,AddressOfCallBacks', 'I,SizeOfZeroFill', 'I,Characteristics'))
    __IMAGE_LOAD_CONFIG_DIRECTORY_format__ = ('IMAGE_LOAD_CONFIG_DIRECTORY', ('I,Size', 'I,TimeDateStamp', 'H,MajorVersion', 'H,MinorVersion', 'I,GlobalFlagsClear', 'I,GlobalFlagsSet', 'I,CriticalSectionDefaultTimeout', 'I,DeCommitFreeBlockThreshold', 'I,DeCommitTotalFreeThreshold', 'I,LockPrefixTable', 'I,MaximumAllocationSize', 'I,VirtualMemoryThreshold', 'I,ProcessHeapFlags', 'I,ProcessAffinityMask', 'H,CSDVersion', 'H,DependentLoadFlags', 'I,EditList', 'I,SecurityCookie', 'I,SEHandlerTable', 'I,SEHandlerCount', 'I,GuardCFCheckFunctionPointer', 'I,GuardCFDispatchFunctionPointer', 'I,GuardCFFunctionTable', 'I,GuardCFFunctionCount', 'I,GuardFlags', 'H,CodeIntegrityFlags', 'H,CodeIntegrityCatalog', 'I,CodeIntegrityCatalogOffset', 'I,CodeIntegrityReserved', 'I,GuardAddressTakenIatEntryTable', 'I,GuardAddressTakenIatEntryCount', 'I,GuardLongJumpTargetTable', 'I,GuardLongJumpTargetCount', 'I,DynamicValueRelocTable', 'I,CHPEMetadataPointer', 'I,GuardRFFailureRoutine', 'I,GuardRFFailureRoutineFunctionPointer', 'I,DynamicValueRelocTableOffset', 'H,DynamicValueRelocTableSection', 'H,Reserved2', 'I,GuardRFVerifyStackPointerFunctionPointer', 'I,HotPatchTableOffset', 'I,Reserved3', 'I,EnclaveConfigurationPointer', 'I,VolatileMetadataPointer', 'I,GuardEHContinuationTable', 'I,GuardEHContinuationCount', 'I,GuardXFGCheckFunctionPointer', 'I,GuardXFGDispatchFunctionPointer', 'I,GuardXFGTableDispatchFunctionPointer', 'I,CastGuardOsDeterminedFailureMode', 'I,GuardMemcpyFunctionPointer'))
    __IMAGE_LOAD_CONFIG_DIRECTORY64_format__ = ('IMAGE_LOAD_CONFIG_DIRECTORY', ('I,Size', 'I,TimeDateStamp', 'H,MajorVersion', 'H,MinorVersion', 'I,GlobalFlagsClear', 'I,GlobalFlagsSet', 'I,CriticalSectionDefaultTimeout', 'Q,DeCommitFreeBlockThreshold', 'Q,DeCommitTotalFreeThreshold', 'Q,LockPrefixTable', 'Q,MaximumAllocationSize', 'Q,VirtualMemoryThreshold', 'Q,ProcessAffinityMask', 'I,ProcessHeapFlags', 'H,CSDVersion', 'H,DependentLoadFlags', 'Q,EditList', 'Q,SecurityCookie', 'Q,SEHandlerTable', 'Q,SEHandlerCount', 'Q,GuardCFCheckFunctionPointer', 'Q,GuardCFDispatchFunctionPointer', 'Q,GuardCFFunctionTable', 'Q,GuardCFFunctionCount', 'I,GuardFlags', 'H,CodeIntegrityFlags', 'H,CodeIntegrityCatalog', 'I,CodeIntegrityCatalogOffset', 'I,CodeIntegrityReserved', 'Q,GuardAddressTakenIatEntryTable', 'Q,GuardAddressTakenIatEntryCount', 'Q,GuardLongJumpTargetTable', 'Q,GuardLongJumpTargetCount', 'Q,DynamicValueRelocTable', 'Q,CHPEMetadataPointer', 'Q,GuardRFFailureRoutine', 'Q,GuardRFFailureRoutineFunctionPointer', 'I,DynamicValueRelocTableOffset', 'H,DynamicValueRelocTableSection', 'H,Reserved2', 'Q,GuardRFVerifyStackPointerFunctionPointer', 'I,HotPatchTableOffset', 'I,Reserved3', 'Q,EnclaveConfigurationPointer', 'Q,VolatileMetadataPointer', 'Q,GuardEHContinuationTable', 'Q,GuardEHContinuationCount', 'Q,GuardXFGCheckFunctionPointer', 'Q,GuardXFGDispatchFunctionPointer', 'Q,GuardXFGTableDispatchFunctionPointer', 'Q,CastGuardOsDeterminedFailureMode', 'Q,GuardMemcpyFunctionPointer'))
    __IMAGE_DYNAMIC_RELOCATION_TABLE_format__ = ('IMAGE_DYNAMIC_RELOCATION_TABLE', ('I,Version', 'I,Size'))
    __IMAGE_DYNAMIC_RELOCATION_format__ = ('IMAGE_DYNAMIC_RELOCATION', ('I,Symbol', 'I,BaseRelocSize'))
    __IMAGE_DYNAMIC_RELOCATION64_format__ = ('IMAGE_DYNAMIC_RELOCATION64', ('Q,Symbol', 'I,BaseRelocSize'))
    __IMAGE_DYNAMIC_RELOCATION_V2_format__ = ('IMAGE_DYNAMIC_RELOCATION_V2', ('I,HeaderSize', 'I,FixupInfoSize', 'I,Symbol', 'I,SymbolGroup', 'I,Flags'))
    __IMAGE_DYNAMIC_RELOCATION64_V2_format__ = ('IMAGE_DYNAMIC_RELOCATION64_V2', ('I,HeaderSize', 'I,FixupInfoSize', 'Q,Symbol', 'I,SymbolGroup', 'I,Flags'))
    __IMAGE_BOUND_IMPORT_DESCRIPTOR_format__ = ('IMAGE_BOUND_IMPORT_DESCRIPTOR', ('I,TimeDateStamp', 'H,OffsetModuleName', 'H,NumberOfModuleForwarderRefs'))
    __IMAGE_BOUND_FORWARDER_REF_format__ = ('IMAGE_BOUND_FORWARDER_REF', ('I,TimeDateStamp', 'H,OffsetModuleName', 'H,Reserved'))
    __RUNTIME_FUNCTION_format__ = ('RUNTIME_FUNCTION', ('I,BeginAddress', 'I,EndAddress', 'I,UnwindData'))

    @_name_boundary.callable_contract({'self': 'quarry_self_e6c9ec5', 'fast_load': 'quarry_fast_load_67d872a', 'max_symbol_exports': 'quarry_max_symbol_exports_4e129d8', 'max_repeated_symbol': 'quarry_max_repeated_symbol_faa7853', 'max_offset': 'quarry_max_offset_d8b6150', 'max_input_size': 'quarry_max_input_size', 'max_mapped_size': 'quarry_max_mapped_size', 'max_structures': 'quarry_max_structures', 'max_data_reads': 'quarry_max_data_reads', 'name': 'quarry_name_local_ba04eb2', 'data': 'quarry_data_local_1465b4c'}, '__init__')
    def __init__(quarry_self_e6c9ec5, quarry_name_local_ba04eb2=None, quarry_data_local_1465b4c=None, quarry_fast_load_67d872a=None, quarry_max_symbol_exports_4e129d8=quarry_MAX_SYMBOL_EXPORT_COUNT, quarry_max_repeated_symbol_faa7853=120, *, quarry_max_offset_d8b6150=268435456, quarry_max_input_size=quarry_INPUT_LIMIT, quarry_max_mapped_size=quarry_MAPPED_LIMIT, quarry_max_structures=131072, quarry_max_data_reads=1048576):
        quarry_self_e6c9ec5._quarry_input_limit = quarry_positive_limit(quarry_max_input_size, 'max_input_size')
        quarry_self_e6c9ec5._quarry_mapped_limit = quarry_positive_limit(quarry_max_mapped_size, 'max_mapped_size')
        quarry_self_e6c9ec5._quarry_structure_limit = quarry_positive_limit(quarry_max_structures, 'max_structures')
        quarry_self_e6c9ec5._quarry_read_limit = quarry_positive_limit(quarry_max_data_reads, 'max_data_reads')
        quarry_self_e6c9ec5._quarry_structure_count = 0
        quarry_self_e6c9ec5._quarry_read_count = 0
        _name_boundary.attributes(quarry_self_e6c9ec5)['max_symbol_exports'] = quarry_max_symbol_exports_4e129d8
        _name_boundary.attributes(quarry_self_e6c9ec5)['max_repeated_symbol'] = quarry_max_repeated_symbol_faa7853
        _name_boundary.attributes(quarry_self_e6c9ec5)['_get_section_by_rva_last_used'] = None
        _name_boundary.attributes(quarry_self_e6c9ec5)['sections'] = []
        _name_boundary.attributes(quarry_self_e6c9ec5)['__warnings'] = []
        _name_boundary.attributes(quarry_self_e6c9ec5)['PE_TYPE'] = None
        if quarry_name_local_ba04eb2 is None and quarry_data_local_1465b4c is None:
            raise ValueError('Must supply either name or data')
        quarry_self_e6c9ec5.__structures__ = []
        _name_boundary.attributes(quarry_self_e6c9ec5)['__from_file'] = None
        _name_boundary.attributes(quarry_self_e6c9ec5)['FileAlignment_Warning'] = False
        _name_boundary.attributes(quarry_self_e6c9ec5)['SectionAlignment_Warning'] = False
        _name_boundary.attributes(quarry_self_e6c9ec5)['__total_resource_entries_count'] = 0
        _name_boundary.attributes(quarry_self_e6c9ec5)['__total_resource_bytes'] = 0
        _name_boundary.attributes(quarry_self_e6c9ec5)['__total_import_symbols'] = 0
        _name_boundary.attributes(quarry_self_e6c9ec5)['dynamic_relocation_format_by_symbol'] = {3: quarry_PE.__IMAGE_IMPORT_CONTROL_TRANSFER_DYNAMIC_RELOCATION_format__, 4: quarry_PE.__IMAGE_INDIR_CONTROL_TRANSFER_DYNAMIC_RELOCATION_format__, 5: quarry_PE.__IMAGE_SWITCHTABLE_BRANCH_DYNAMIC_RELOCATION_format__}
        quarry_fast_load_67d872a = quarry_fast_load_67d872a if quarry_fast_load_67d872a is not None else globals()['fast_load']
        try:
            quarry_self_e6c9ec5.__parse__(quarry_name_local_ba04eb2, quarry_data_local_1465b4c, quarry_fast_load_67d872a, quarry_max_offset_d8b6150)
        except Exception:
            _name_boundary.attributes(quarry_self_e6c9ec5)['close']()
            raise

    @_name_boundary.callable_contract({'self': 'quarry_self_58e77bd'}, '__enter__')
    def __enter__(quarry_self_58e77bd):
        return quarry_self_58e77bd

    @_name_boundary.callable_contract({'self': 'quarry_self_1232fde', 'type': 'quarry_type_4144611', 'value': 'quarry_value_3b9a7fd', 'traceback': 'quarry_traceback_52731f1'}, '__exit__')
    def __exit__(quarry_self_1232fde, quarry_type_4144611, quarry_value_3b9a7fd, quarry_traceback_52731f1):
        _name_boundary.attributes(quarry_self_1232fde)['close']()

    @_name_boundary.callable_contract({'self': 'quarry_self_9aa5f63'}, '_close_data')
    def quarry__close_data(quarry_self_9aa5f63):
        if _name_boundary.attributes(quarry_self_9aa5f63)['__from_file'] is True and hasattr(quarry_self_9aa5f63, '__data__'):
            del quarry_self_9aa5f63.__data__

    @_name_boundary.callable_contract({'self': 'quarry_self_67d9cfa'}, 'close')
    def quarry_close(quarry_self_67d9cfa):
        _name_boundary.attributes(quarry_self_67d9cfa)['_close_data']()

    @_name_boundary.callable_contract({'self': 'quarry_self_a6b47e4', 'format': 'quarry_format_8ad1d3b', 'file_offset': 'quarry_file_offset_1c3de14', 'data': 'quarry_data_local_2139489'}, '__unpack_data__')
    def __unpack_data__(quarry_self_a6b47e4, quarry_format_8ad1d3b, quarry_data_local_2139489, quarry_file_offset_1c3de14):
        """Apply structure format to raw data.

        Returns an unpacked structure object if successful, None otherwise.
        """
        quarry_self_a6b47e4._quarry_structure_count += 1
        if quarry_self_a6b47e4._quarry_structure_count > quarry_self_a6b47e4._quarry_structure_limit:
            raise quarry_LimitError('parsed structure budget exceeded')
        quarry_structure_2e5234f = quarry_Structure(quarry_format_8ad1d3b, file_offset=quarry_file_offset_1c3de14)
        try:
            quarry_structure_2e5234f.__unpack__(quarry_data_local_2139489)
        except quarry_PEFormatError as quarry_err_46821e9:
            _name_boundary.attributes(quarry_self_a6b47e4)['__warnings'].append(f'Corrupt header "{quarry_format_8ad1d3b[0]}" at file offset {quarry_file_offset_1c3de14}. Exception: {quarry_err_46821e9}')
            return None
        quarry_self_a6b47e4.__structures__.append(quarry_structure_2e5234f)
        return quarry_structure_2e5234f

    @_name_boundary.callable_contract({'self': 'quarry_self_b7fe96a', 'format': 'quarry_format_87cdec7', 'file_offset': 'quarry_file_offset_e3687fa', 'data': 'quarry_data_local_0bb0ee2'}, '__unpack_data_with_bitfields__')
    def __unpack_data_with_bitfields__(quarry_self_b7fe96a, quarry_format_87cdec7, quarry_data_local_0bb0ee2, quarry_file_offset_e3687fa):
        """Apply structure format to raw data.

        Returns an unpacked structure object if successful, None otherwise.
        """
        quarry_self_b7fe96a._quarry_structure_count += 1
        if quarry_self_b7fe96a._quarry_structure_count > quarry_self_b7fe96a._quarry_structure_limit:
            raise quarry_LimitError('parsed structure budget exceeded')
        quarry_structure_91e1c2b = quarry_StructureWithBitfields(quarry_format_87cdec7, file_offset=quarry_file_offset_e3687fa)
        try:
            quarry_structure_91e1c2b.__unpack__(quarry_data_local_0bb0ee2)
        except quarry_PEFormatError as quarry_err_2f4a068:
            _name_boundary.attributes(quarry_self_b7fe96a)['__warnings'].append(f'Corrupt header "{quarry_format_87cdec7[0]}" at file offset {quarry_file_offset_e3687fa}. Exception: {quarry_err_2f4a068}')
            return None
        quarry_self_b7fe96a.__structures__.append(quarry_structure_91e1c2b)
        return quarry_structure_91e1c2b

    @_name_boundary.callable_contract({'self': 'quarry_self_1d604c3', 'fname': 'quarry_fname_ecdee91', 'fast_load': 'quarry_fast_load_d165bfb', 'max_offset': 'quarry_max_offset_9250085', 'data': 'quarry_data_local_617ff48'}, '__parse__')
    def __parse__(quarry_self_1d604c3, quarry_fname_ecdee91, quarry_data_local_617ff48, quarry_fast_load_d165bfb, quarry_max_offset_9250085):
        """Parse a Portable Executable file.

        Loads a PE file, parsing all its structures and making them available
        through the instance's attributes.
        """
        if quarry_fname_ecdee91 is not None:
            try:
                quarry_self_1d604c3.__data__ = quarry_read_regular(quarry_fname_ecdee91, quarry_self_1d604c3._quarry_input_limit)
            except FileNotFoundError:
                raise
            except OSError as quarry_error:
                raise Exception(f"Unable to access file '{quarry_fname_ecdee91}': {quarry_error}") from quarry_error
            _name_boundary.attributes(quarry_self_1d604c3)['__from_file'] = True
            if not quarry_self_1d604c3.__data__:
                raise quarry_PEFormatError('The file is empty')
        elif quarry_data_local_617ff48 is not None:
            quarry_self_1d604c3.__data__ = quarry_in_memory_bytes(quarry_data_local_617ff48, quarry_self_1d604c3._quarry_input_limit)
            _name_boundary.attributes(quarry_self_1d604c3)['__from_file'] = False
        _name_boundary.attributes(quarry_self_1d604c3)['__resource_size_limit_upperbounds'] = len(quarry_self_1d604c3.__data__)
        _name_boundary.attributes(quarry_self_1d604c3)['__resource_size_limit_reached'] = False
        if not quarry_fast_load_d165bfb:
            for quarry_byte_7c15c47, quarry_byte_count_9b901c8 in quarry_Counter(bytearray(quarry_self_1d604c3.__data__)).items():
                if quarry_byte_7c15c47 == 0 and quarry_byte_count_9b901c8 / len(quarry_self_1d604c3.__data__) > 0.5 or (quarry_byte_7c15c47 != 0 and quarry_byte_count_9b901c8 / len(quarry_self_1d604c3.__data__) > 0.15):
                    _name_boundary.attributes(quarry_self_1d604c3)['__warnings'].append(f"Byte 0x{quarry_byte_7c15c47:02x} makes up {100.0 * quarry_byte_count_9b901c8 / len(quarry_self_1d604c3.__data__):.4f}% of the file's contents. This may indicate truncation / malformation.")
        quarry_dos_header_data_4085ebf = quarry_self_1d604c3.__data__[:64]
        if len(quarry_dos_header_data_4085ebf) != 64:
            raise quarry_PEFormatError('Unable to read the DOS Header, possibly a truncated file.')
        _name_boundary.attributes(quarry_self_1d604c3)['DOS_HEADER'] = quarry_self_1d604c3.__unpack_data__(quarry_self_1d604c3.__IMAGE_DOS_HEADER_format__, quarry_dos_header_data_4085ebf, file_offset=0)
        if _name_boundary.attributes(quarry_self_1d604c3)['DOS_HEADER'].e_magic == quarry_IMAGE_DOSZM_SIGNATURE:
            raise quarry_PEFormatError('Probably a ZM Executable (not a PE file).')
        if not _name_boundary.attributes(quarry_self_1d604c3)['DOS_HEADER'] or _name_boundary.attributes(quarry_self_1d604c3)['DOS_HEADER'].e_magic != quarry_IMAGE_DOS_SIGNATURE:
            raise quarry_PEFormatError('DOS Header magic not found.')
        if _name_boundary.attributes(quarry_self_1d604c3)['DOS_HEADER'].e_lfanew > len(quarry_self_1d604c3.__data__):
            raise quarry_PEFormatError('Invalid e_lfanew value, probably not a PE file')
        quarry_nt_headers_offset_fe20a0e = _name_boundary.attributes(quarry_self_1d604c3)['DOS_HEADER'].e_lfanew
        _name_boundary.attributes(quarry_self_1d604c3)['NT_HEADERS'] = quarry_self_1d604c3.__unpack_data__(quarry_self_1d604c3.__IMAGE_NT_HEADERS_format__, quarry_self_1d604c3.__data__[quarry_nt_headers_offset_fe20a0e:quarry_nt_headers_offset_fe20a0e + 4], file_offset=quarry_nt_headers_offset_fe20a0e)
        if not _name_boundary.attributes(quarry_self_1d604c3)['NT_HEADERS'] or not _name_boundary.attributes(quarry_self_1d604c3)['NT_HEADERS'].Signature:
            raise quarry_PEFormatError('NT Headers not found.')
        if _name_boundary.attributes(quarry_self_1d604c3)['NT_HEADERS'].Signature & 65535 == quarry_IMAGE_NE_SIGNATURE:
            raise quarry_PEFormatError('Invalid NT Headers signature. Probably a NE file')
        if _name_boundary.attributes(quarry_self_1d604c3)['NT_HEADERS'].Signature & 65535 == quarry_IMAGE_LE_SIGNATURE:
            raise quarry_PEFormatError('Invalid NT Headers signature. Probably a LE file')
        if _name_boundary.attributes(quarry_self_1d604c3)['NT_HEADERS'].Signature & 65535 == quarry_IMAGE_LX_SIGNATURE:
            raise quarry_PEFormatError('Invalid NT Headers signature. Probably a LX file')
        if _name_boundary.attributes(quarry_self_1d604c3)['NT_HEADERS'].Signature & 65535 == quarry_IMAGE_TE_SIGNATURE:
            raise quarry_PEFormatError('Invalid NT Headers signature. Probably a TE file')
        if _name_boundary.attributes(quarry_self_1d604c3)['NT_HEADERS'].Signature != quarry_IMAGE_NT_SIGNATURE:
            raise quarry_PEFormatError('Invalid NT Headers signature.')
        _name_boundary.attributes(quarry_self_1d604c3)['FILE_HEADER'] = quarry_self_1d604c3.__unpack_data__(quarry_self_1d604c3.__IMAGE_FILE_HEADER_format__, quarry_self_1d604c3.__data__[quarry_nt_headers_offset_fe20a0e + 4:quarry_nt_headers_offset_fe20a0e + 4 + 32], file_offset=quarry_nt_headers_offset_fe20a0e + 4)
        if not _name_boundary.attributes(quarry_self_1d604c3)['FILE_HEADER']:
            raise quarry_PEFormatError('File Header missing')
        quarry_image_flags_6d26edc = quarry_retrieve_flags(quarry_IMAGE_CHARACTERISTICS, 'IMAGE_FILE_')
        quarry_set_flags(_name_boundary.attributes(quarry_self_1d604c3)['FILE_HEADER'], _name_boundary.attributes(quarry_self_1d604c3)['FILE_HEADER'].Characteristics, quarry_image_flags_6d26edc)
        quarry_optional_header_offset_c49fad8 = quarry_nt_headers_offset_fe20a0e + 4 + _name_boundary.attributes(_name_boundary.attributes(quarry_self_1d604c3)['FILE_HEADER'])['sizeof']()
        quarry_sections_offset_f865944 = quarry_optional_header_offset_c49fad8 + _name_boundary.attributes(quarry_self_1d604c3)['FILE_HEADER'].SizeOfOptionalHeader
        _name_boundary.attributes(quarry_self_1d604c3)['OPTIONAL_HEADER'] = quarry_self_1d604c3.__unpack_data__(quarry_self_1d604c3.__IMAGE_OPTIONAL_HEADER_format__, quarry_self_1d604c3.__data__[quarry_optional_header_offset_c49fad8:quarry_optional_header_offset_c49fad8 + 256], file_offset=quarry_optional_header_offset_c49fad8)
        quarry_MINIMUM_VALID_OPTIONAL_HEADER_RAW_SIZE_0c3713f = 69
        if _name_boundary.attributes(quarry_self_1d604c3)['OPTIONAL_HEADER'] is None and len(quarry_self_1d604c3.__data__[quarry_optional_header_offset_c49fad8:quarry_optional_header_offset_c49fad8 + 512]) >= quarry_MINIMUM_VALID_OPTIONAL_HEADER_RAW_SIZE_0c3713f:
            quarry_padding_length_e0291c0 = 128
            quarry_padded_data_76c84be = quarry_self_1d604c3.__data__[quarry_optional_header_offset_c49fad8:quarry_optional_header_offset_c49fad8 + 512] + b'\x00' * quarry_padding_length_e0291c0
            _name_boundary.attributes(quarry_self_1d604c3)['OPTIONAL_HEADER'] = quarry_self_1d604c3.__unpack_data__(quarry_self_1d604c3.__IMAGE_OPTIONAL_HEADER_format__, quarry_padded_data_76c84be, file_offset=quarry_optional_header_offset_c49fad8)
        if _name_boundary.attributes(quarry_self_1d604c3)['OPTIONAL_HEADER'] is not None:
            if _name_boundary.attributes(quarry_self_1d604c3)['OPTIONAL_HEADER'].Magic == quarry_OPTIONAL_HEADER_MAGIC_PE:
                _name_boundary.attributes(quarry_self_1d604c3)['PE_TYPE'] = quarry_OPTIONAL_HEADER_MAGIC_PE
            elif _name_boundary.attributes(quarry_self_1d604c3)['OPTIONAL_HEADER'].Magic == quarry_OPTIONAL_HEADER_MAGIC_PE_PLUS:
                _name_boundary.attributes(quarry_self_1d604c3)['PE_TYPE'] = quarry_OPTIONAL_HEADER_MAGIC_PE_PLUS
                _name_boundary.attributes(quarry_self_1d604c3)['OPTIONAL_HEADER'] = quarry_self_1d604c3.__unpack_data__(quarry_self_1d604c3.__IMAGE_OPTIONAL_HEADER64_format__, quarry_self_1d604c3.__data__[quarry_optional_header_offset_c49fad8:quarry_optional_header_offset_c49fad8 + 512], file_offset=quarry_optional_header_offset_c49fad8)
                quarry_MINIMUM_VALID_OPTIONAL_HEADER_RAW_SIZE_0c3713f = 69 + 4
                if _name_boundary.attributes(quarry_self_1d604c3)['OPTIONAL_HEADER'] is None and len(quarry_self_1d604c3.__data__[quarry_optional_header_offset_c49fad8:quarry_optional_header_offset_c49fad8 + 512]) >= quarry_MINIMUM_VALID_OPTIONAL_HEADER_RAW_SIZE_0c3713f:
                    quarry_padding_length_e0291c0 = 128
                    quarry_padded_data_76c84be = quarry_self_1d604c3.__data__[quarry_optional_header_offset_c49fad8:quarry_optional_header_offset_c49fad8 + 512] + b'\x00' * quarry_padding_length_e0291c0
                    _name_boundary.attributes(quarry_self_1d604c3)['OPTIONAL_HEADER'] = quarry_self_1d604c3.__unpack_data__(quarry_self_1d604c3.__IMAGE_OPTIONAL_HEADER64_format__, quarry_padded_data_76c84be, file_offset=quarry_optional_header_offset_c49fad8)
        if _name_boundary.attributes(quarry_self_1d604c3)['OPTIONAL_HEADER'] is None:
            raise quarry_PEFormatError('No Optional Header found, invalid PE32 or PE32+ file.')
        if _name_boundary.attributes(quarry_self_1d604c3)['PE_TYPE'] is None:
            _name_boundary.attributes(quarry_self_1d604c3)['__warnings'].append(f"Invalid type 0x{_name_boundary.attributes(quarry_self_1d604c3)['OPTIONAL_HEADER'].Magic:04x} in Optional Header.")
        quarry_dll_characteristics_flags_3182804 = quarry_retrieve_flags(quarry_DLL_CHARACTERISTICS, 'IMAGE_DLLCHARACTERISTICS_')
        quarry_set_flags(_name_boundary.attributes(quarry_self_1d604c3)['OPTIONAL_HEADER'], _name_boundary.attributes(quarry_self_1d604c3)['OPTIONAL_HEADER'].DllCharacteristics, quarry_dll_characteristics_flags_3182804)
        _name_boundary.attributes(quarry_self_1d604c3)['OPTIONAL_HEADER'].DATA_DIRECTORY = []
        quarry_offset_local_cb0f990 = quarry_optional_header_offset_c49fad8 + _name_boundary.attributes(_name_boundary.attributes(quarry_self_1d604c3)['OPTIONAL_HEADER'])['sizeof']()
        _name_boundary.attributes(_name_boundary.attributes(quarry_self_1d604c3)['NT_HEADERS'])['FILE_HEADER'] = _name_boundary.attributes(quarry_self_1d604c3)['FILE_HEADER']
        _name_boundary.attributes(_name_boundary.attributes(quarry_self_1d604c3)['NT_HEADERS'])['OPTIONAL_HEADER'] = _name_boundary.attributes(quarry_self_1d604c3)['OPTIONAL_HEADER']
        quarry_directory_count_f055855 = int(_name_boundary.attributes(quarry_self_1d604c3)['OPTIONAL_HEADER'].NumberOfRvaAndSizes & 2147483647)
        quarry_directory_delta_57114f8 = max(0, (_name_boundary.attributes(quarry_self_1d604c3)['FILE_HEADER'].SizeOfOptionalHeader - (_name_boundary.attributes(_name_boundary.attributes(quarry_self_1d604c3)['OPTIONAL_HEADER'])['sizeof']() + quarry_directory_count_f055855 * 8)) // 8)
        if 0 < quarry_directory_delta_57114f8 <= 16 - quarry_directory_count_f055855:
            _name_boundary.attributes(quarry_self_1d604c3)['__warnings'].append(f'SizeOfOptionalHeader indicates that NumberOfRvaAndSizes is off by at least {quarry_directory_delta_57114f8}.')
            quarry_directory_count_f055855 += quarry_directory_delta_57114f8
        if _name_boundary.attributes(quarry_self_1d604c3)['OPTIONAL_HEADER'].AddressOfEntryPoint < _name_boundary.attributes(quarry_self_1d604c3)['OPTIONAL_HEADER'].SizeOfHeaders:
            _name_boundary.attributes(quarry_self_1d604c3)['__warnings'].append('SizeOfHeaders is smaller than AddressOfEntryPoint: this file cannot run under Windows 8.')
        if _name_boundary.attributes(quarry_self_1d604c3)['OPTIONAL_HEADER'].NumberOfRvaAndSizes > 16:
            _name_boundary.attributes(quarry_self_1d604c3)['__warnings'].append(f"Suspicious NumberOfRvaAndSizes in the Optional Header. Normal values are never larger than 0x10, the value is: {_name_boundary.attributes(quarry_self_1d604c3)['OPTIONAL_HEADER'].NumberOfRvaAndSizes:#x}")
        quarry_MAX_ASSUMED_VALID_NUMBER_OF_RVA_AND_SIZES_6f8956e = 256
        for quarry_i_a5b4718 in range(quarry_directory_count_f055855):
            if len(quarry_self_1d604c3.__data__) - quarry_offset_local_cb0f990 == 0:
                break
            if len(quarry_self_1d604c3.__data__) - quarry_offset_local_cb0f990 < 8:
                quarry_data_local_617ff48 = quarry_self_1d604c3.__data__[quarry_offset_local_cb0f990:] + b'\x00' * 8
            else:
                quarry_data_local_617ff48 = quarry_self_1d604c3.__data__[quarry_offset_local_cb0f990:quarry_offset_local_cb0f990 + quarry_MAX_ASSUMED_VALID_NUMBER_OF_RVA_AND_SIZES_6f8956e]
            quarry_dir_entry_e199113 = quarry_self_1d604c3.__unpack_data__(quarry_self_1d604c3.__IMAGE_DATA_DIRECTORY_format__, quarry_data_local_617ff48, file_offset=quarry_offset_local_cb0f990)
            if quarry_dir_entry_e199113 is None:
                break
            try:
                quarry_dir_entry_e199113.name = quarry_DIRECTORY_ENTRY[quarry_i_a5b4718]
            except (KeyError, AttributeError):
                break
            quarry_offset_local_cb0f990 += _name_boundary.attributes(quarry_dir_entry_e199113)['sizeof']()
            _name_boundary.attributes(quarry_self_1d604c3)['OPTIONAL_HEADER'].DATA_DIRECTORY.append(quarry_dir_entry_e199113)
            if quarry_offset_local_cb0f990 >= quarry_optional_header_offset_c49fad8 + _name_boundary.attributes(_name_boundary.attributes(quarry_self_1d604c3)['OPTIONAL_HEADER'])['sizeof']() + quarry_IMAGE_NUMBEROF_DIRECTORY_ENTRIES * 8:
                break
        quarry_offset_local_cb0f990 = _name_boundary.attributes(quarry_self_1d604c3)['parse_sections'](quarry_sections_offset_f865944, quarry_max_offset_9250085)
        quarry_rawDataPointers_905867c = [_name_boundary.attributes(quarry_self_1d604c3)['adjust_PointerToRawData'](quarry_s_4494a4e.PointerToRawData) for quarry_s_4494a4e in _name_boundary.attributes(quarry_self_1d604c3)['sections'] if quarry_s_4494a4e.PointerToRawData > 0]
        if len(quarry_rawDataPointers_905867c) > 0:
            quarry_lowest_section_offset_f00567b = min(quarry_rawDataPointers_905867c)
        else:
            quarry_lowest_section_offset_f00567b = None
        if not quarry_lowest_section_offset_f00567b or quarry_lowest_section_offset_f00567b < quarry_offset_local_cb0f990:
            _name_boundary.attributes(quarry_self_1d604c3)['header'] = quarry_self_1d604c3.__data__[:quarry_offset_local_cb0f990]
        else:
            _name_boundary.attributes(quarry_self_1d604c3)['header'] = quarry_self_1d604c3.__data__[:quarry_lowest_section_offset_f00567b]
        if _name_boundary.attributes(quarry_self_1d604c3)['get_section_by_rva'](_name_boundary.attributes(quarry_self_1d604c3)['OPTIONAL_HEADER'].AddressOfEntryPoint) is not None:
            quarry_ep_offset_105a8b1 = _name_boundary.attributes(quarry_self_1d604c3)['get_offset_from_rva'](_name_boundary.attributes(quarry_self_1d604c3)['OPTIONAL_HEADER'].AddressOfEntryPoint)
            if quarry_ep_offset_105a8b1 > len(quarry_self_1d604c3.__data__):
                _name_boundary.attributes(quarry_self_1d604c3)['__warnings'].append(f"Possibly corrupt file. AddressOfEntryPoint lies outside the file. AddressOfEntryPoint: {_name_boundary.attributes(quarry_self_1d604c3)['OPTIONAL_HEADER'].AddressOfEntryPoint:#x}")
        else:
            _name_boundary.attributes(quarry_self_1d604c3)['__warnings'].append(f"AddressOfEntryPoint lies outside the sections' boundaries. AddressOfEntryPoint: {_name_boundary.attributes(quarry_self_1d604c3)['OPTIONAL_HEADER'].AddressOfEntryPoint:#x}")
        if not quarry_fast_load_d165bfb:
            _name_boundary.attributes(quarry_self_1d604c3)['full_load']()

    @_name_boundary.callable_contract({'self': 'quarry_self_b6114c8'}, 'parse_rich_header')
    def quarry_parse_rich_header(quarry_self_b6114c8):
        """Parses the Rich Header
        https://www.ntcore.com/files/richsign.htm

        Structure:
        00 DanS ^ checksum, checksum, checksum, checksum
        10 Symbol RVA ^ checksum, Symbol size ^ checksum...
        ...
        XX Rich, checksum, 0, 0,...
        """
        quarry_DANS_0193e19 = 1399742788
        quarry_RICH_332b152 = 1751345490
        quarry_rich_index_99b2cd3 = quarry_self_b6114c8.__data__.find(b'Rich', 80, _name_boundary.attributes(_name_boundary.attributes(quarry_self_b6114c8)['OPTIONAL_HEADER'])['get_file_offset']())
        if quarry_rich_index_99b2cd3 == -1:
            return None
        quarry_dans_index_f8739e5 = quarry_self_b6114c8.__data__.find(bytes((quarry_x_16bbc18 ^ quarry_y_f1eecea for quarry_x_16bbc18, quarry_y_f1eecea in zip(b'DanS', quarry_self_b6114c8.__data__[quarry_rich_index_99b2cd3 + 4:quarry_rich_index_99b2cd3 + 8]))), 64, _name_boundary.attributes(_name_boundary.attributes(quarry_self_b6114c8)['OPTIONAL_HEADER'])['get_file_offset']())
        if quarry_dans_index_f8739e5 == -1:
            quarry_dans_index_f8739e5 = 128
        try:
            quarry_rich_data_fc7be50 = quarry_self_b6114c8.__data__[quarry_dans_index_f8739e5:quarry_rich_index_99b2cd3 + 8]
            quarry_rich_data_fc7be50 = quarry_rich_data_fc7be50[:4 * (len(quarry_rich_data_fc7be50) // 4)]
            quarry_data_local_73279bb = list(quarry_struct.unpack(f'<{len(quarry_rich_data_fc7be50) // 4}I', quarry_rich_data_fc7be50))
            if quarry_RICH_332b152 not in quarry_data_local_73279bb:
                return None
        except quarry_PEFormatError:
            return None
        quarry_key_6bb91b5 = quarry_struct.pack('<L', quarry_data_local_73279bb[quarry_data_local_73279bb.index(quarry_RICH_332b152) + 1])
        quarry_result_c474896 = {'key': quarry_key_6bb91b5}
        quarry_raw_data_1fd1d8d = quarry_rich_data_fc7be50[:quarry_rich_data_fc7be50.find(b'Rich')]
        quarry_result_c474896['raw_data'] = quarry_raw_data_1fd1d8d
        quarry_ord__f290d7b = lambda quarry_c_2b2414c: ord(quarry_c_2b2414c) if not isinstance(quarry_c_2b2414c, int) else quarry_c_2b2414c
        quarry_clear_data_e5c69eb = bytearray()
        for quarry_idx_bf803df, quarry_val_80270c9 in enumerate(quarry_raw_data_1fd1d8d):
            quarry_clear_data_e5c69eb.append(quarry_ord__f290d7b(quarry_val_80270c9) ^ quarry_ord__f290d7b(quarry_key_6bb91b5[quarry_idx_bf803df % len(quarry_key_6bb91b5)]))
        quarry_result_c474896['clear_data'] = bytes(quarry_clear_data_e5c69eb)
        quarry_checksum_0e73e1b = int.from_bytes(quarry_key_6bb91b5, 'little')
        if quarry_data_local_73279bb[0] != quarry_DANS_0193e19 ^ quarry_checksum_0e73e1b or quarry_data_local_73279bb[1] != quarry_checksum_0e73e1b or quarry_data_local_73279bb[2] != quarry_checksum_0e73e1b or (quarry_data_local_73279bb[3] != quarry_checksum_0e73e1b):
            _name_boundary.attributes(quarry_self_b6114c8)['__warnings'].append('Rich Header is not in Microsoft format, possibly malformed')
        quarry_result_c474896['checksum'] = quarry_checksum_0e73e1b
        quarry_headervalues_561e221 = []
        quarry_result_c474896['values'] = quarry_headervalues_561e221
        quarry_data_local_73279bb = quarry_data_local_73279bb[4:]
        for quarry_i_379893e in range(len(quarry_data_local_73279bb) // 2):
            if quarry_data_local_73279bb[2 * quarry_i_379893e] == quarry_RICH_332b152:
                if quarry_data_local_73279bb[2 * quarry_i_379893e + 1] != quarry_checksum_0e73e1b:
                    _name_boundary.attributes(quarry_self_b6114c8)['__warnings'].append('Rich Header is malformed')
                break
            quarry_headervalues_561e221 += [quarry_data_local_73279bb[2 * quarry_i_379893e] ^ quarry_checksum_0e73e1b, quarry_data_local_73279bb[2 * quarry_i_379893e + 1] ^ quarry_checksum_0e73e1b]
        return quarry_result_c474896

    @_name_boundary.callable_contract({'self': 'quarry_self_ef6dc8c'}, 'get_warnings')
    def quarry_get_warnings(quarry_self_ef6dc8c):
        """Return the list of warnings.

        Non-critical problems found when parsing the PE file are
        appended to a list of warnings. This method returns the
        full list.
        """
        return _name_boundary.attributes(quarry_self_ef6dc8c)['__warnings']

    @_name_boundary.callable_contract({'self': 'quarry_self_8a55d62'}, 'show_warnings')
    def quarry_show_warnings(quarry_self_8a55d62):
        """Print the list of warnings.

        Non-critical problems found when parsing the PE file are
        appended to a list of warnings. This method prints the
        full list to standard output.
        """
        for quarry_warning_c7fb15d in _name_boundary.attributes(quarry_self_8a55d62)['__warnings']:
            print('>', quarry_warning_c7fb15d)

    @_name_boundary.callable_contract({'self': 'quarry_self_dc535bc'}, 'full_load')
    def quarry_full_load(quarry_self_dc535bc):
        """Process the data directories.

        This method will load the data directories which might not have
        been loaded if the "fast_load" option was used.

        It also parses the rich header, which may or may not present.
        """
        _name_boundary.attributes(quarry_self_dc535bc)['parse_data_directories']()

        @_name_boundary.class_contract('RichHeader', {})
        class quarry_RichHeader_dd7120d:
            pass
        quarry_rich_header_d273e9a = _name_boundary.attributes(quarry_self_dc535bc)['parse_rich_header']()
        if quarry_rich_header_d273e9a:
            _name_boundary.attributes(quarry_self_dc535bc)['RICH_HEADER'] = quarry_RichHeader_dd7120d()
            _name_boundary.attributes(quarry_self_dc535bc)['RICH_HEADER'].checksum = quarry_rich_header_d273e9a.get('checksum', None)
            _name_boundary.attributes(quarry_self_dc535bc)['RICH_HEADER'].values = quarry_rich_header_d273e9a.get('values', None)
            _name_boundary.attributes(quarry_self_dc535bc)['RICH_HEADER'].key = quarry_rich_header_d273e9a.get('key', None)
            _name_boundary.attributes(quarry_self_dc535bc)['RICH_HEADER'].raw_data = quarry_rich_header_d273e9a.get('raw_data', None)
            _name_boundary.attributes(quarry_self_dc535bc)['RICH_HEADER'].clear_data = quarry_rich_header_d273e9a.get('clear_data', None)
        else:
            _name_boundary.attributes(quarry_self_dc535bc)['RICH_HEADER'] = None

    @_name_boundary.callable_contract({'self': 'quarry_self', 'filename': 'quarry_filename_3f7a101'}, 'write')
    def quarry_write(quarry_self, quarry_filename_3f7a101=None):
        """Serialize changes to bounded bytes, or an explicitly named output.

        In-memory serialization retains ordinary upstream header editing and
        small padding extensions. Invalid offsets, shrinking string edits and
        unbounded expansion are rejected before opening the output path.
        """
        quarry_limit = quarry_self._quarry_input_limit
        if len(quarry_self.__data__) > quarry_limit:
            raise quarry_LimitError('serialized input exceeds byte limit')
        quarry_output = bytearray(quarry_self.__data__)
        for quarry_structure in quarry_self.__structures__:
            quarry_packed = quarry_structure.__pack__()
            quarry_offset = quarry_structure.get_file_offset()
            if type(quarry_offset) is not int or not 0 <= quarry_offset <= len(quarry_output):
                raise quarry_PEFormatError('serialized structure offset is outside the file')
            if len(quarry_packed) > quarry_limit - quarry_offset:
                raise quarry_LimitError('serialized structure exceeds output byte limit')
            quarry_output[quarry_offset:quarry_offset + len(quarry_packed)] = quarry_packed
        if hasattr(quarry_self, 'VS_VERSIONINFO') and hasattr(quarry_self, 'FileInfo'):
            for quarry_group in quarry_self.FileInfo:
                for quarry_entry in quarry_group:
                    if not hasattr(quarry_entry, 'StringTable'):
                        continue
                    for quarry_table in quarry_entry.StringTable:
                        for quarry_key, quarry_value in quarry_table.entries.items():
                            quarry_offsets = quarry_table.entries_offsets[quarry_key]
                            quarry_lengths = quarry_table.entries_lengths[quarry_key]
                            quarry_offset, quarry_capacity = quarry_offsets[1], quarry_lengths[1]
                            if type(quarry_offset) is not int or type(quarry_capacity) is not int or quarry_offset < 0 or quarry_capacity < 0 or quarry_offset > len(quarry_output) or quarry_capacity > (len(quarry_output) - quarry_offset) // 2:
                                raise quarry_PEFormatError('version string span is outside the file')
                            if not isinstance(quarry_value, bytes):
                                raise TypeError('version string values must be UTF-8 bytes')
                            if len(quarry_value) > quarry_limit:
                                raise quarry_LimitError('version string value exceeds byte limit')
                            quarry_encoded = quarry_value.decode('utf-8').encode('utf-16le')[:quarry_capacity * 2]
                            # Assign only produced bytes: bytearray slice resizing
                            # cannot shift following structures or shrink the file.
                            quarry_output[quarry_offset:quarry_offset + len(quarry_encoded)] = quarry_encoded
        if not quarry_filename_3f7a101:
            return quarry_output
        quarry_write_regular(quarry_filename_3f7a101, quarry_output)

    @_name_boundary.callable_contract({'self': 'quarry_self_95faa03', 'max_offset': 'quarry_max_offset_c623bcc', 'offset': 'quarry_offset_local_b0fd54b'}, 'parse_sections')
    def quarry_parse_sections(quarry_self_95faa03, quarry_offset_local_b0fd54b, quarry_max_offset_c623bcc=268435456):
        """Fetch the PE file sections.

        The sections will be readily available in the "sections" attribute.
        Its attributes will contain all the section information plus "data"
        a buffer containing the section's data.

        The "Characteristics" member will be processed and attributes
        representing the section characteristics (with the 'IMAGE_SCN_'
        string trimmed from the constant's names) will be added to the
        section instance.

        Refer to the SectionStructure class for additional info.

        The method will raise a warning if a section is larger and/or at
        a higher offset than the limit configured by the 'max_offset'
        parameter.
        """
        _name_boundary.attributes(quarry_self_95faa03)['sections'] = []
        quarry_MAX_SIMULTANEOUS_ERRORS_e2e2197 = 3
        for quarry_i_c3143d6 in range(_name_boundary.attributes(quarry_self_95faa03)['FILE_HEADER'].NumberOfSections):
            if quarry_i_c3143d6 >= quarry_MAX_SECTIONS:
                _name_boundary.attributes(quarry_self_95faa03)['__warnings'].append(f"Too many sections {_name_boundary.attributes(quarry_self_95faa03)['FILE_HEADER'].NumberOfSections} (>={quarry_MAX_SECTIONS})")
                break
            quarry_simultaneous_errors_5303ab6 = 0
            quarry_section_3b861b6 = quarry_SectionStructure(quarry_self_95faa03.__IMAGE_SECTION_HEADER_format__, pe=quarry_self_95faa03)
            if not quarry_section_3b861b6:
                break
            quarry_section_offset_6bd5edd = quarry_offset_local_b0fd54b + _name_boundary.attributes(quarry_section_3b861b6)['sizeof']() * quarry_i_c3143d6
            _name_boundary.attributes(quarry_section_3b861b6)['set_file_offset'](quarry_section_offset_6bd5edd)
            quarry_section_data_c64481f = quarry_self_95faa03.__data__[quarry_section_offset_6bd5edd:quarry_section_offset_6bd5edd + _name_boundary.attributes(quarry_section_3b861b6)['sizeof']()]
            if quarry_count_zeroes(quarry_section_data_c64481f) == _name_boundary.attributes(quarry_section_3b861b6)['sizeof']():
                _name_boundary.attributes(quarry_self_95faa03)['__warnings'].append(f'Invalid section {quarry_i_c3143d6}. Contents are null-bytes.')
                break
            if not quarry_section_data_c64481f:
                _name_boundary.attributes(quarry_self_95faa03)['__warnings'].append(f"Invalid section {quarry_i_c3143d6}. No data in the file (is this corkami's virtsectblXP?).")
                break
            quarry_section_3b861b6.__unpack__(quarry_section_data_c64481f)
            quarry_self_95faa03.__structures__.append(quarry_section_3b861b6)
            if quarry_section_3b861b6.SizeOfRawData + quarry_section_3b861b6.PointerToRawData > len(quarry_self_95faa03.__data__):
                quarry_simultaneous_errors_5303ab6 += 1
                _name_boundary.attributes(quarry_self_95faa03)['__warnings'].append(f'Error parsing section {quarry_i_c3143d6}. SizeOfRawData is larger than file.')
            if _name_boundary.attributes(quarry_self_95faa03)['adjust_PointerToRawData'](quarry_section_3b861b6.PointerToRawData) > len(quarry_self_95faa03.__data__):
                quarry_simultaneous_errors_5303ab6 += 1
                _name_boundary.attributes(quarry_self_95faa03)['__warnings'].append(f'Error parsing section {quarry_i_c3143d6}. PointerToRawData points beyond the end of the file.')
            if quarry_section_3b861b6.Misc_VirtualSize > quarry_max_offset_c623bcc:
                quarry_simultaneous_errors_5303ab6 += 1
                _name_boundary.attributes(quarry_self_95faa03)['__warnings'].append(f'Suspicious value found parsing section {quarry_i_c3143d6}. VirtualSize is extremely large > {quarry_human_readable_size(quarry_max_offset_c623bcc)}.')
            if _name_boundary.attributes(quarry_self_95faa03)['adjust_SectionAlignment'](quarry_section_3b861b6.VirtualAddress, _name_boundary.attributes(quarry_self_95faa03)['OPTIONAL_HEADER'].SectionAlignment, _name_boundary.attributes(quarry_self_95faa03)['OPTIONAL_HEADER'].FileAlignment) > quarry_max_offset_c623bcc:
                quarry_simultaneous_errors_5303ab6 += 1
                _name_boundary.attributes(quarry_self_95faa03)['__warnings'].append(f'Suspicious value found parsing section {quarry_i_c3143d6}. VirtualAddress is beyond {quarry_max_offset_c623bcc:#x}.')
            if _name_boundary.attributes(quarry_self_95faa03)['OPTIONAL_HEADER'].FileAlignment != 0 and quarry_section_3b861b6.PointerToRawData % _name_boundary.attributes(quarry_self_95faa03)['OPTIONAL_HEADER'].FileAlignment != 0:
                quarry_simultaneous_errors_5303ab6 += 1
                _name_boundary.attributes(quarry_self_95faa03)['__warnings'].append(f'Error parsing section {quarry_i_c3143d6}. PointerToRawData should normally be a multiple of FileAlignment, this might imply the file is trying to confuse tools which parse this incorrectly.')
            if quarry_simultaneous_errors_5303ab6 >= quarry_MAX_SIMULTANEOUS_ERRORS_e2e2197:
                _name_boundary.attributes(quarry_self_95faa03)['__warnings'].append('Too many warnings parsing section. Aborting.')
                break
            quarry_section_flags_local_b9f5e31 = quarry_retrieve_flags(quarry_SECTION_CHARACTERISTICS, 'IMAGE_SCN_')
            quarry_set_flags(quarry_section_3b861b6, quarry_section_3b861b6.Characteristics, quarry_section_flags_local_b9f5e31)
            quarry_section_3b861b6.index_in_file = quarry_i_c3143d6
            _name_boundary.attributes(quarry_self_95faa03)['sections'].append(quarry_section_3b861b6)
        _name_boundary.attributes(quarry_self_95faa03)['sections'].sort(key=lambda quarry_a_59ab49f: quarry_a_59ab49f.VirtualAddress)
        for quarry_idx_5b906b2, quarry_section_3b861b6 in enumerate(_name_boundary.attributes(quarry_self_95faa03)['sections']):
            if quarry_idx_5b906b2 == len(_name_boundary.attributes(quarry_self_95faa03)['sections']) - 1:
                quarry_section_3b861b6.next_section_virtual_address = None
            else:
                quarry_section_3b861b6.next_section_virtual_address = _name_boundary.attributes(quarry_self_95faa03)['sections'][quarry_idx_5b906b2 + 1].VirtualAddress
        for quarry_section_3b861b6 in _name_boundary.attributes(quarry_self_95faa03)['sections']:
            if _name_boundary.read_attribute(quarry_section_3b861b6, 'IMAGE_SCN_MEM_WRITE', False) and _name_boundary.read_attribute(quarry_section_3b861b6, 'IMAGE_SCN_MEM_EXECUTE', False):
                if quarry_section_3b861b6.Name.rstrip(b'\x00') == b'PAGE' and _name_boundary.attributes(quarry_self_95faa03)['is_driver']():
                    pass
                else:
                    _name_boundary.attributes(quarry_self_95faa03)['__warnings'].append(f'Suspicious flags set for section {quarry_section_3b861b6.index_in_file}. Both IMAGE_SCN_MEM_WRITE and IMAGE_SCN_MEM_EXECUTE are set. This might indicate a packed executable.')
        if _name_boundary.attributes(quarry_self_95faa03)['FILE_HEADER'].NumberOfSections > 0 and _name_boundary.attributes(quarry_self_95faa03)['sections']:
            return quarry_offset_local_b0fd54b + _name_boundary.attributes(_name_boundary.attributes(quarry_self_95faa03)['sections'][0])['sizeof']() * _name_boundary.attributes(quarry_self_95faa03)['FILE_HEADER'].NumberOfSections
        else:
            return quarry_offset_local_b0fd54b

    @_name_boundary.callable_contract({'self': 'quarry_self_f9106df', 'directories': 'quarry_directories_7fbbace', 'forwarded_exports_only': 'quarry_forwarded_exports_only_331d93a', 'import_dllnames_only': 'quarry_import_dllnames_only_2aa4d44'}, 'parse_data_directories')
    def quarry_parse_data_directories(quarry_self_f9106df, quarry_directories_7fbbace=None, quarry_forwarded_exports_only_331d93a=False, quarry_import_dllnames_only_2aa4d44=False):
        """Parse and process the PE file's data directories.

        If the optional argument 'directories' is given, only
        the directories at the specified indexes will be parsed.
        Such functionality allows parsing of areas of interest
        without the burden of having to parse all others.
        The directories can then be specified as:

        For export / import only:

        directories = [ 0, 1 ]

        or (more verbosely):

        directories = [
            DIRECTORY_ENTRY['IMAGE_DIRECTORY_ENTRY_EXPORT'],
            DIRECTORY_ENTRY['IMAGE_DIRECTORY_ENTRY_IMPORT']
        ]

        If 'directories' is a list, the ones that are processed will be removed,
        leaving only the ones that are not present in the image.

        If `forwarded_exports_only` is True, the IMAGE_DIRECTORY_ENTRY_EXPORT
        attribute will only contain exports that are forwarded to another DLL.

        If `import_dllnames_only` is True, symbols will not be parsed from
        the import table and the entries in the IMAGE_DIRECTORY_ENTRY_IMPORT
        attribute will not have a `symbols` attribute.
        """
        if quarry_directories_7fbbace is not None and (not isinstance(quarry_directories_7fbbace, (tuple, list))):
            quarry_directories_7fbbace = [quarry_directories_7fbbace]
        quarry_directory_parsing_d2d7f8d = (('IMAGE_DIRECTORY_ENTRY_EXPORT', _name_boundary.attributes(quarry_self_f9106df)['parse_export_directory']), ('IMAGE_DIRECTORY_ENTRY_IMPORT', _name_boundary.attributes(quarry_self_f9106df)['parse_import_directory']), ('IMAGE_DIRECTORY_ENTRY_RESOURCE', _name_boundary.attributes(quarry_self_f9106df)['parse_resources_directory']), ('IMAGE_DIRECTORY_ENTRY_EXCEPTION', _name_boundary.attributes(quarry_self_f9106df)['parse_exceptions_directory']), ('IMAGE_DIRECTORY_ENTRY_BASERELOC', _name_boundary.attributes(quarry_self_f9106df)['parse_relocations_directory']), ('IMAGE_DIRECTORY_ENTRY_DEBUG', _name_boundary.attributes(quarry_self_f9106df)['parse_debug_directory']), ('IMAGE_DIRECTORY_ENTRY_TLS', _name_boundary.attributes(quarry_self_f9106df)['parse_directory_tls']), ('IMAGE_DIRECTORY_ENTRY_LOAD_CONFIG', _name_boundary.attributes(quarry_self_f9106df)['parse_directory_load_config']), ('IMAGE_DIRECTORY_ENTRY_BOUND_IMPORT', _name_boundary.attributes(quarry_self_f9106df)['parse_directory_bound_imports']), ('IMAGE_DIRECTORY_ENTRY_DELAY_IMPORT', _name_boundary.attributes(quarry_self_f9106df)['parse_delay_import_directory']))
        for quarry_entry_f488000 in quarry_directory_parsing_d2d7f8d:
            try:
                quarry_directory_index_7e4d974 = quarry_DIRECTORY_ENTRY[quarry_entry_f488000[0]]
                quarry_dir_entry_556af8a = _name_boundary.attributes(quarry_self_f9106df)['OPTIONAL_HEADER'].DATA_DIRECTORY[quarry_directory_index_7e4d974]
            except IndexError:
                break
            if quarry_directories_7fbbace is None or quarry_directory_index_7e4d974 in quarry_directories_7fbbace:
                quarry_value_2e2aa22 = None
                if quarry_dir_entry_556af8a.VirtualAddress:
                    if quarry_forwarded_exports_only_331d93a and quarry_entry_f488000[0] == 'IMAGE_DIRECTORY_ENTRY_EXPORT':
                        quarry_value_2e2aa22 = quarry_entry_f488000[1](quarry_dir_entry_556af8a.VirtualAddress, quarry_dir_entry_556af8a.Size, forwarded_only=True)
                    elif quarry_import_dllnames_only_2aa4d44 and quarry_entry_f488000[0] == 'IMAGE_DIRECTORY_ENTRY_IMPORT':
                        quarry_value_2e2aa22 = quarry_entry_f488000[1](quarry_dir_entry_556af8a.VirtualAddress, quarry_dir_entry_556af8a.Size, dllnames_only=True)
                    else:
                        try:
                            quarry_value_2e2aa22 = quarry_entry_f488000[1](quarry_dir_entry_556af8a.VirtualAddress, quarry_dir_entry_556af8a.Size)
                        except quarry_PEFormatError as quarry_excp_0954240:
                            _name_boundary.attributes(quarry_self_f9106df)['__warnings'].append(f'Failed to process directory "{quarry_entry_f488000[0]}": {quarry_excp_0954240}')
                    if quarry_value_2e2aa22:
                        _name_boundary.write_attribute(quarry_self_f9106df, quarry_entry_f488000[0][6:], quarry_value_2e2aa22)
            if quarry_directories_7fbbace is not None and isinstance(quarry_directories_7fbbace, list) and (quarry_entry_f488000[0] in quarry_directories_7fbbace):
                quarry_directories_7fbbace.remove(quarry_directory_index_7e4d974)

    @_name_boundary.callable_contract({'self': 'quarry_self_826e310', 'rva': 'quarry_rva_1ffb12c', 'size': 'quarry_size_local_c5cc65a'}, 'parse_exceptions_directory')
    def quarry_parse_exceptions_directory(quarry_self_826e310, quarry_rva_1ffb12c, quarry_size_local_c5cc65a):
        """Parses exception directory

        All the code related to handling exception directories is documented in
        https://auscitte.github.io/posts/Exception-Directory-pefile#implementation-details
        """
        if _name_boundary.attributes(quarry_self_826e310)['FILE_HEADER'].Machine != quarry_MACHINE_TYPE['IMAGE_FILE_MACHINE_AMD64'] and _name_boundary.attributes(quarry_self_826e310)['FILE_HEADER'].Machine != quarry_MACHINE_TYPE['IMAGE_FILE_MACHINE_IA64']:
            return None
        quarry_rf_c6b091b = quarry_Structure(quarry_self_826e310.__RUNTIME_FUNCTION_format__)
        quarry_rf_size_a029d62 = _name_boundary.attributes(quarry_rf_c6b091b)['sizeof']()
        quarry_rva2rt_e8d67ca = {}
        quarry_rt_funcs_ea49dfe = []
        quarry_rva2infos_370721d = {}
        for quarry___972a358 in range(quarry_size_local_c5cc65a // quarry_rf_size_a029d62):
            quarry_rf_c6b091b = quarry_self_826e310.__unpack_data__(quarry_self_826e310.__RUNTIME_FUNCTION_format__, _name_boundary.attributes(quarry_self_826e310)['get_data'](quarry_rva_1ffb12c, quarry_rf_size_a029d62), file_offset=_name_boundary.attributes(quarry_self_826e310)['get_offset_from_rva'](quarry_rva_1ffb12c))
            if quarry_rf_c6b091b is None:
                break
            quarry_ui_cece937 = None
            if quarry_rf_c6b091b.UnwindData & 1 == 0:
                if quarry_rf_c6b091b.UnwindData in quarry_rva2infos_370721d:
                    quarry_ui_cece937 = quarry_rva2infos_370721d[quarry_rf_c6b091b.UnwindData]
                else:
                    quarry_ui_cece937 = quarry_UnwindInfo(file_offset=_name_boundary.attributes(quarry_self_826e310)['get_offset_from_rva'](quarry_rf_c6b091b.UnwindData))
                    quarry_rva2infos_370721d[quarry_rf_c6b091b.UnwindData] = quarry_ui_cece937
                quarry_ws_6b98c97 = _name_boundary.attributes(quarry_ui_cece937)['unpack_in_stages'](_name_boundary.attributes(quarry_self_826e310)['get_data'](quarry_rf_c6b091b.UnwindData, _name_boundary.attributes(quarry_ui_cece937)['sizeof']()))
                if quarry_ws_6b98c97 is not None:
                    _name_boundary.attributes(quarry_self_826e310)['__warnings'].append(quarry_ws_6b98c97)
                    break
                quarry_ws_6b98c97 = _name_boundary.attributes(quarry_ui_cece937)['unpack_in_stages'](_name_boundary.attributes(quarry_self_826e310)['get_data'](quarry_rf_c6b091b.UnwindData, _name_boundary.attributes(quarry_ui_cece937)['sizeof']()))
                if quarry_ws_6b98c97 is not None:
                    _name_boundary.attributes(quarry_self_826e310)['__warnings'].append(quarry_ws_6b98c97)
                    break
                quarry_self_826e310.__structures__.append(quarry_ui_cece937)
            quarry_entry_0f65aa7 = quarry_ExceptionsDirEntryData(struct=quarry_rf_c6b091b, unwindinfo=quarry_ui_cece937)
            quarry_rt_funcs_ea49dfe.append(quarry_entry_0f65aa7)
            quarry_rva2rt_e8d67ca[quarry_rf_c6b091b.BeginAddress] = quarry_entry_0f65aa7
            quarry_rva_1ffb12c += quarry_rf_size_a029d62
        for quarry_rf_c6b091b in quarry_rt_funcs_ea49dfe:
            if quarry_rf_c6b091b.unwindinfo is None:
                continue
            if not _name_boundary.has_attribute(quarry_rf_c6b091b.unwindinfo, 'FunctionEntry'):
                continue
            if quarry_rf_c6b091b.unwindinfo.FunctionEntry not in quarry_rva2rt_e8d67ca:
                _name_boundary.attributes(quarry_self_826e310)['__warnings'].append(f"FunctionEntry of UNWIND_INFO at {_name_boundary.attributes(_name_boundary.attributes(quarry_rf_c6b091b)['struct'])['get_file_offset']():x} points to an entry that does not exist")
                continue
            try:
                _name_boundary.attributes(quarry_rf_c6b091b.unwindinfo)['set_chained_function_entry'](quarry_rva2rt_e8d67ca[quarry_rf_c6b091b.unwindinfo.FunctionEntry])
            except quarry_PEFormatError as quarry_excp_88080a2:
                _name_boundary.attributes(quarry_self_826e310)['__warnings'].append(f"Failed parsing FunctionEntry of UNWIND_INFO at {_name_boundary.attributes(_name_boundary.attributes(quarry_rf_c6b091b)['struct'])['get_file_offset']():x}: {quarry_excp_88080a2}")
                continue
        return quarry_rt_funcs_ea49dfe

    @_name_boundary.callable_contract({'self': 'quarry_self_71efb09', 'rva': 'quarry_rva_944bbbc', 'size': 'quarry_size_local_dac19d1'}, 'parse_directory_bound_imports')
    def quarry_parse_directory_bound_imports(quarry_self_71efb09, quarry_rva_944bbbc, quarry_size_local_dac19d1):
        """Parse the bound import table."""
        quarry_bnd_descr_fb90d50 = quarry_Structure(quarry_self_71efb09.__IMAGE_BOUND_IMPORT_DESCRIPTOR_format__)
        quarry_bnd_descr_size_4d3f55e = _name_boundary.attributes(quarry_bnd_descr_fb90d50)['sizeof']()
        quarry_start_30cea58 = quarry_rva_944bbbc
        quarry_bound_imports_6929105 = []
        while True:
            quarry_bnd_descr_fb90d50 = quarry_self_71efb09.__unpack_data__(quarry_self_71efb09.__IMAGE_BOUND_IMPORT_DESCRIPTOR_format__, quarry_self_71efb09.__data__[quarry_rva_944bbbc:quarry_rva_944bbbc + quarry_bnd_descr_size_4d3f55e], file_offset=quarry_rva_944bbbc)
            if quarry_bnd_descr_fb90d50 is None:
                _name_boundary.attributes(quarry_self_71efb09)['__warnings'].append("The Bound Imports directory exists but can't be parsed.")
                return None
            if _name_boundary.attributes(quarry_bnd_descr_fb90d50)['all_zeroes']():
                break
            quarry_rva_944bbbc += _name_boundary.attributes(quarry_bnd_descr_fb90d50)['sizeof']()
            quarry_section_59edd76 = _name_boundary.attributes(quarry_self_71efb09)['get_section_by_offset'](quarry_rva_944bbbc)
            quarry_file_offset_8284e89 = _name_boundary.attributes(quarry_self_71efb09)['get_offset_from_rva'](quarry_rva_944bbbc)
            if quarry_section_59edd76 is None:
                quarry_safety_boundary_f9e9d2b = len(quarry_self_71efb09.__data__) - quarry_file_offset_8284e89
                quarry_sections_after_offset_2f1c398 = [quarry_s_f86728c.PointerToRawData for quarry_s_f86728c in _name_boundary.attributes(quarry_self_71efb09)['sections'] if quarry_s_f86728c.PointerToRawData > quarry_file_offset_8284e89]
                if quarry_sections_after_offset_2f1c398:
                    quarry_first_section_after_offset_1adfd98 = min(quarry_sections_after_offset_2f1c398)
                    quarry_section_59edd76 = _name_boundary.attributes(quarry_self_71efb09)['get_section_by_offset'](quarry_first_section_after_offset_1adfd98)
                    if quarry_section_59edd76 is not None:
                        quarry_safety_boundary_f9e9d2b = quarry_section_59edd76.PointerToRawData - quarry_file_offset_8284e89
            else:
                quarry_safety_boundary_f9e9d2b = quarry_section_59edd76.PointerToRawData + len(_name_boundary.attributes(quarry_section_59edd76)['get_data']()) - quarry_file_offset_8284e89
            if not quarry_section_59edd76:
                _name_boundary.attributes(quarry_self_71efb09)['__warnings'].append(f'RVA of IMAGE_BOUND_IMPORT_DESCRIPTOR points to an invalid address: {quarry_rva_944bbbc:x}')
                return None
            quarry_forwarder_refs_255cf9d = []
            for quarry___f9ae2c4 in range(min(quarry_bnd_descr_fb90d50.NumberOfModuleForwarderRefs, int(quarry_safety_boundary_f9e9d2b / 8))):
                quarry_bnd_frwd_ref_23b1e40 = quarry_self_71efb09.__unpack_data__(quarry_self_71efb09.__IMAGE_BOUND_FORWARDER_REF_format__, quarry_self_71efb09.__data__[quarry_rva_944bbbc:quarry_rva_944bbbc + quarry_bnd_descr_size_4d3f55e], file_offset=quarry_rva_944bbbc)
                if not quarry_bnd_frwd_ref_23b1e40:
                    raise quarry_PEFormatError('IMAGE_BOUND_FORWARDER_REF cannot be read')
                quarry_rva_944bbbc += _name_boundary.attributes(quarry_bnd_frwd_ref_23b1e40)['sizeof']()
                quarry_offset_local_f29c739 = quarry_start_30cea58 + quarry_bnd_frwd_ref_23b1e40.OffsetModuleName
                quarry_name_str_bcb0d12 = _name_boundary.attributes(quarry_self_71efb09)['get_string_from_data'](0, quarry_self_71efb09.__data__[quarry_offset_local_f29c739:quarry_offset_local_f29c739 + quarry_MAX_STRING_LENGTH])
                if quarry_name_str_bcb0d12:
                    quarry_invalid_chars_e082634 = [quarry_c_ab5375a for quarry_c_ab5375a in bytearray(quarry_name_str_bcb0d12) if chr(quarry_c_ab5375a) not in quarry_string.printable]
                    if len(quarry_name_str_bcb0d12) > 256 or quarry_invalid_chars_e082634:
                        break
                quarry_forwarder_refs_255cf9d.append(quarry_BoundImportRefData(struct=quarry_bnd_frwd_ref_23b1e40, name=quarry_name_str_bcb0d12))
            quarry_offset_local_f29c739 = quarry_start_30cea58 + quarry_bnd_descr_fb90d50.OffsetModuleName
            quarry_name_str_bcb0d12 = _name_boundary.attributes(quarry_self_71efb09)['get_string_from_data'](0, quarry_self_71efb09.__data__[quarry_offset_local_f29c739:quarry_offset_local_f29c739 + quarry_MAX_STRING_LENGTH])
            if quarry_name_str_bcb0d12:
                quarry_invalid_chars_e082634 = [quarry_c_642e718 for quarry_c_642e718 in bytearray(quarry_name_str_bcb0d12) if chr(quarry_c_642e718) not in quarry_string.printable]
                if len(quarry_name_str_bcb0d12) > 256 or quarry_invalid_chars_e082634:
                    break
            if not quarry_name_str_bcb0d12:
                break
            quarry_bound_imports_6929105.append(quarry_BoundImportDescData(struct=quarry_bnd_descr_fb90d50, name=quarry_name_str_bcb0d12, entries=quarry_forwarder_refs_255cf9d))
        return quarry_bound_imports_6929105

    @_name_boundary.callable_contract({'self': 'quarry_self_cac396b', 'rva': 'quarry_rva_5ab54d2', 'size': 'quarry_size_local_f0fbf66'}, 'parse_directory_tls')
    def quarry_parse_directory_tls(quarry_self_cac396b, quarry_rva_5ab54d2, quarry_size_local_f0fbf66):
        """Parse the thread local storage (TLS) table."""
        quarry_format_dd051cd = quarry_self_cac396b.__IMAGE_TLS_DIRECTORY_format__
        if _name_boundary.attributes(quarry_self_cac396b)['PE_TYPE'] == quarry_OPTIONAL_HEADER_MAGIC_PE_PLUS:
            quarry_format_dd051cd = quarry_self_cac396b.__IMAGE_TLS_DIRECTORY64_format__
        try:
            quarry_tls_struct_e558d24 = quarry_self_cac396b.__unpack_data__(quarry_format_dd051cd, _name_boundary.attributes(quarry_self_cac396b)['get_data'](quarry_rva_5ab54d2, _name_boundary.attributes(quarry_Structure(quarry_format_dd051cd))['sizeof']()), file_offset=_name_boundary.attributes(quarry_self_cac396b)['get_offset_from_rva'](quarry_rva_5ab54d2))
        except quarry_PEFormatError:
            _name_boundary.attributes(quarry_self_cac396b)['__warnings'].append(f"Invalid TLS information. Can't read data at RVA: {quarry_rva_5ab54d2:#x}")
            quarry_tls_struct_e558d24 = None
        if not quarry_tls_struct_e558d24:
            return None
        return quarry_TlsData(struct=quarry_tls_struct_e558d24)

    @_name_boundary.callable_contract({'self': 'quarry_self_29a45ba', 'rva': 'quarry_rva_f573975', 'size': 'quarry_size_local_85919d0'}, 'parse_directory_load_config')
    def quarry_parse_directory_load_config(quarry_self_29a45ba, quarry_rva_f573975, quarry_size_local_85919d0):
        """Parse the load configuration table."""
        if _name_boundary.attributes(quarry_self_29a45ba)['PE_TYPE'] == quarry_OPTIONAL_HEADER_MAGIC_PE:
            quarry_load_config_dir_sz_f81fe8e = _name_boundary.attributes(quarry_self_29a45ba)['get_dword_at_rva'](quarry_rva_f573975)
            quarry_fmt_79291d6 = quarry_self_29a45ba.__IMAGE_LOAD_CONFIG_DIRECTORY_format__
        elif _name_boundary.attributes(quarry_self_29a45ba)['PE_TYPE'] == quarry_OPTIONAL_HEADER_MAGIC_PE_PLUS:
            quarry_load_config_dir_sz_f81fe8e = _name_boundary.attributes(quarry_self_29a45ba)['get_dword_at_rva'](quarry_rva_f573975)
            quarry_fmt_79291d6 = quarry_self_29a45ba.__IMAGE_LOAD_CONFIG_DIRECTORY64_format__
        else:
            _name_boundary.attributes(quarry_self_29a45ba)['__warnings'].append("Don't know how to parse LOAD_CONFIG information for non-PE32/PE32+ file")
            return None
        quarry_fields_counter_0628010 = 0
        quarry_cumulative_sz_6840661 = 0
        for quarry_field_c88c6d3 in quarry_fmt_79291d6[1]:
            quarry_fields_counter_0628010 += 1
            quarry_cumulative_sz_6840661 += quarry_STRUCT_SIZEOF_TYPES[quarry_field_c88c6d3.split(',')[0]]
            if quarry_cumulative_sz_6840661 == quarry_load_config_dir_sz_f81fe8e:
                break
        quarry_fmt_79291d6 = (quarry_fmt_79291d6[0], quarry_fmt_79291d6[1][:quarry_fields_counter_0628010])
        quarry_load_config_b994af1 = None
        try:
            quarry_load_config_b994af1 = quarry_self_29a45ba.__unpack_data__(quarry_fmt_79291d6, _name_boundary.attributes(quarry_self_29a45ba)['get_data'](quarry_rva_f573975, _name_boundary.attributes(quarry_Structure(quarry_fmt_79291d6))['sizeof']()), file_offset=_name_boundary.attributes(quarry_self_29a45ba)['get_offset_from_rva'](quarry_rva_f573975))
        except quarry_PEFormatError:
            _name_boundary.attributes(quarry_self_29a45ba)['__warnings'].append(f"Invalid LOAD_CONFIG information. Can't read data at RVA: {quarry_rva_f573975:#x}")
        if not quarry_load_config_b994af1:
            return None
        quarry_dynamic_relocations_5b32927 = None
        if quarry_fields_counter_0628010 > 35:
            quarry_dynamic_relocations_5b32927 = _name_boundary.attributes(quarry_self_29a45ba)['parse_dynamic_relocations'](quarry_load_config_b994af1.DynamicValueRelocTableOffset, quarry_load_config_b994af1.DynamicValueRelocTableSection)
        return quarry_LoadConfigData(struct=quarry_load_config_b994af1, dynamic_relocations=quarry_dynamic_relocations_5b32927)

    @_name_boundary.callable_contract({'self': 'quarry_self_9b853b1', 'dynamic_value_reloc_table_offset': 'quarry_dynamic_value_reloc_table_offset_00c79cb', 'dynamic_value_reloc_table_section': 'quarry_dynamic_value_reloc_table_section_60accba'}, 'parse_dynamic_relocations')
    def quarry_parse_dynamic_relocations(quarry_self_9b853b1, quarry_dynamic_value_reloc_table_offset_00c79cb, quarry_dynamic_value_reloc_table_section_60accba):
        if not quarry_dynamic_value_reloc_table_offset_00c79cb:
            return None
        if not quarry_dynamic_value_reloc_table_section_60accba:
            return None
        if quarry_dynamic_value_reloc_table_section_60accba > len(_name_boundary.attributes(quarry_self_9b853b1)['sections']):
            return None
        quarry_section_64292a6 = _name_boundary.attributes(quarry_self_9b853b1)['sections'][quarry_dynamic_value_reloc_table_section_60accba - 1]
        quarry_rva_1c0f84d = quarry_section_64292a6.VirtualAddress + quarry_dynamic_value_reloc_table_offset_00c79cb
        quarry_reloc_table_size_b29ee47 = _name_boundary.attributes(quarry_Structure(quarry_self_9b853b1.__IMAGE_DYNAMIC_RELOCATION_TABLE_format__))['sizeof']()
        try:
            quarry_image_dynamic_reloc_table_struct_60e9bc8 = quarry_self_9b853b1.__unpack_data__(quarry_self_9b853b1.__IMAGE_DYNAMIC_RELOCATION_TABLE_format__, _name_boundary.attributes(quarry_self_9b853b1)['get_data'](quarry_rva_1c0f84d, quarry_reloc_table_size_b29ee47), file_offset=_name_boundary.attributes(quarry_self_9b853b1)['get_offset_from_rva'](quarry_rva_1c0f84d))
        except quarry_PEFormatError:
            _name_boundary.attributes(quarry_self_9b853b1)['__warnings'].append(f"Invalid IMAGE_DYNAMIC_RELOCATION_TABLE information. Can't read data at RVA: {quarry_rva_1c0f84d:#x}")
            return None
        if quarry_image_dynamic_reloc_table_struct_60e9bc8.Version != 1:
            _name_boundary.attributes(quarry_self_9b853b1)['__warnings'].append(f'No parsing available for IMAGE_DYNAMIC_RELOCATION_TABLE.Version = {quarry_image_dynamic_reloc_table_struct_60e9bc8.Version}')
            return None
        quarry_rva_1c0f84d += quarry_reloc_table_size_b29ee47
        quarry_end_local_3458dd7 = quarry_rva_1c0f84d + quarry_image_dynamic_reloc_table_struct_60e9bc8.Size
        quarry_dynamic_relocations_3ec3051 = []
        while quarry_rva_1c0f84d < quarry_end_local_3458dd7:
            quarry_format_38ca3aa = quarry_self_9b853b1.__IMAGE_DYNAMIC_RELOCATION_format__
            if _name_boundary.attributes(quarry_self_9b853b1)['PE_TYPE'] == quarry_OPTIONAL_HEADER_MAGIC_PE_PLUS:
                quarry_format_38ca3aa = quarry_self_9b853b1.__IMAGE_DYNAMIC_RELOCATION64_format__
            quarry_rlc_size_6a86ebc = _name_boundary.attributes(quarry_Structure(quarry_format_38ca3aa))['sizeof']()
            try:
                quarry_dynamic_rlc_33b1712 = quarry_self_9b853b1.__unpack_data__(quarry_format_38ca3aa, _name_boundary.attributes(quarry_self_9b853b1)['get_data'](quarry_rva_1c0f84d, quarry_rlc_size_6a86ebc), file_offset=_name_boundary.attributes(quarry_self_9b853b1)['get_offset_from_rva'](quarry_rva_1c0f84d))
            except quarry_PEFormatError:
                _name_boundary.attributes(quarry_self_9b853b1)['__warnings'].append(f"Invalid relocation information. Can't read data at RVA: {quarry_rva_1c0f84d:#x}")
                quarry_dynamic_rlc_33b1712 = None
            if not quarry_dynamic_rlc_33b1712:
                break
            quarry_rva_1c0f84d += quarry_rlc_size_6a86ebc
            quarry_symbol_716ea28 = quarry_dynamic_rlc_33b1712.Symbol
            quarry_size_local_29bc1f1 = quarry_dynamic_rlc_33b1712.BaseRelocSize
            if 3 <= quarry_symbol_716ea28 <= 5:
                quarry_relocations_b1f8c6b = _name_boundary.attributes(quarry_self_9b853b1)['parse_image_base_relocation_list'](quarry_rva_1c0f84d, quarry_size_local_29bc1f1, _name_boundary.attributes(quarry_self_9b853b1)['dynamic_relocation_format_by_symbol'][quarry_symbol_716ea28])
                quarry_dynamic_relocations_3ec3051.append(quarry_DynamicRelocationData(struct=quarry_dynamic_rlc_33b1712, symbol=quarry_symbol_716ea28, relocations=quarry_relocations_b1f8c6b))
            elif quarry_symbol_716ea28 == 7:
                quarry_func_relocs_9dc52ae, quarry_bdd_relocs_43321b1 = _name_boundary.attributes(quarry_self_9b853b1)['parse_function_override_data'](quarry_rva_1c0f84d)
                quarry_dynamic_relocations_3ec3051.append(quarry_FunctionOverrideData(struct=quarry_dynamic_rlc_33b1712, symbol=quarry_symbol_716ea28, bdd_relocs=quarry_bdd_relocs_43321b1, func_relocs=quarry_func_relocs_9dc52ae))
            elif quarry_symbol_716ea28 > 5:
                quarry_relocations_b1f8c6b = _name_boundary.attributes(quarry_self_9b853b1)['parse_image_base_relocation_list'](quarry_rva_1c0f84d, quarry_size_local_29bc1f1)
                quarry_dynamic_relocations_3ec3051.append(quarry_DynamicRelocationData(struct=quarry_dynamic_rlc_33b1712, symbol=quarry_symbol_716ea28, relocations=quarry_relocations_b1f8c6b))
            quarry_rva_1c0f84d += quarry_size_local_29bc1f1
        return quarry_dynamic_relocations_3ec3051

    @_name_boundary.callable_contract({'self': 'quarry_self_dfe7dd5', 'rva': 'quarry_rva_0131963'}, 'parse_function_override_data')
    def quarry_parse_function_override_data(quarry_self_dfe7dd5, quarry_rva_0131963):
        """Parse function override data."""
        quarry_func_relocs_b0b7f1d = []
        quarry_bdd_relocs_214093f = []
        quarry_format_fd32dfb = quarry_self_dfe7dd5.__IMAGE_FUNCTION_OVERRIDE_HEADER_format__
        quarry_func_header_a8f3744 = quarry_self_dfe7dd5.__unpack_data__(quarry_format_fd32dfb, _name_boundary.attributes(quarry_self_dfe7dd5)['get_data'](quarry_rva_0131963, _name_boundary.attributes(quarry_Structure(quarry_format_fd32dfb))['sizeof']()), _name_boundary.attributes(quarry_self_dfe7dd5)['get_offset_from_rva'](quarry_rva_0131963))
        if not quarry_func_header_a8f3744:
            _name_boundary.attributes(quarry_self_dfe7dd5)['__warnings'].append(f"Invalid function override header. Can't read data at RVA: {quarry_rva_0131963:#x}")
            return (quarry_func_relocs_b0b7f1d, quarry_bdd_relocs_214093f)
        quarry_rva_0131963 += _name_boundary.attributes(quarry_Structure(quarry_format_fd32dfb))['sizeof']()
        quarry_func_end_d67a353 = quarry_rva_0131963 + quarry_func_header_a8f3744.FuncOverrideSize
        while quarry_rva_0131963 < quarry_func_end_d67a353:
            quarry_format_fd32dfb = quarry_self_dfe7dd5.__IMAGE_FUNCTION_OVERRIDE_DYNAMIC_RELOCATION_format__
            quarry_func_info_0a70afb = quarry_self_dfe7dd5.__unpack_data__(quarry_format_fd32dfb, _name_boundary.attributes(quarry_self_dfe7dd5)['get_data'](quarry_rva_0131963, _name_boundary.attributes(quarry_Structure(quarry_format_fd32dfb))['sizeof']()), _name_boundary.attributes(quarry_self_dfe7dd5)['get_offset_from_rva'](quarry_rva_0131963))
            if not quarry_func_info_0a70afb:
                _name_boundary.attributes(quarry_self_dfe7dd5)['__warnings'].append(f"Invalid function override info. Can't read data at RVA: {quarry_rva_0131963:#x}")
                return (quarry_func_relocs_b0b7f1d, quarry_bdd_relocs_214093f)
            quarry_rva_0131963 += _name_boundary.attributes(quarry_Structure(quarry_format_fd32dfb))['sizeof']()
            quarry_override_rvas_959435f = []
            for quarry___ebd5fd9 in range(quarry_func_info_0a70afb.RvaSize // 4):
                quarry_override_rvas_959435f.append(quarry_struct.unpack('<I', _name_boundary.attributes(quarry_self_dfe7dd5)['get_data'](quarry_rva_0131963, 4))[0])
                quarry_rva_0131963 += 4
            quarry_relocations_ff83303 = _name_boundary.attributes(quarry_self_dfe7dd5)['parse_image_base_relocation_list'](quarry_rva_0131963, quarry_func_info_0a70afb.BaseRelocSize)
            quarry_rva_0131963 += quarry_func_info_0a70afb.BaseRelocSize
            quarry_func_relocs_b0b7f1d.append(quarry_FunctionOverrideDynamicRelocationData(struct=quarry_func_info_0a70afb, func_rva=quarry_func_info_0a70afb.OriginalRva, override_rvas=quarry_override_rvas_959435f, relocations=quarry_relocations_ff83303))
        quarry_format_fd32dfb = quarry_self_dfe7dd5.__IMAGE_BDD_INFO_format__
        quarry_bdd_info_c203c14 = quarry_self_dfe7dd5.__unpack_data__(quarry_format_fd32dfb, _name_boundary.attributes(quarry_self_dfe7dd5)['get_data'](quarry_rva_0131963, _name_boundary.attributes(quarry_Structure(quarry_format_fd32dfb))['sizeof']()), _name_boundary.attributes(quarry_self_dfe7dd5)['get_offset_from_rva'](quarry_rva_0131963))
        if not quarry_bdd_info_c203c14:
            _name_boundary.attributes(quarry_self_dfe7dd5)['__warnings'].append(f"Invalid bdd info. Can't read data at RVA: {quarry_rva_0131963:#x}")
            return (quarry_func_relocs_b0b7f1d, quarry_bdd_relocs_214093f)
        quarry_rva_0131963 += _name_boundary.attributes(quarry_Structure(quarry_format_fd32dfb))['sizeof']()
        for quarry___ebd5fd9 in range(quarry_bdd_info_c203c14.BDDSize // 8):
            quarry_format_fd32dfb = quarry_self_dfe7dd5.__IMAGE_BDD_DYNAMIC_RELOCATION_format__
            quarry_bdd_reloc_d93406e = quarry_self_dfe7dd5.__unpack_data__(quarry_format_fd32dfb, _name_boundary.attributes(quarry_self_dfe7dd5)['get_data'](quarry_rva_0131963, _name_boundary.attributes(quarry_Structure(quarry_format_fd32dfb))['sizeof']()), _name_boundary.attributes(quarry_self_dfe7dd5)['get_offset_from_rva'](quarry_rva_0131963))
            if not quarry_bdd_reloc_d93406e:
                _name_boundary.attributes(quarry_self_dfe7dd5)['__warnings'].append(f"Invalid bdd dynamic relocation. Can't read data at RVA: {quarry_rva_0131963:#x}")
                return (quarry_func_relocs_b0b7f1d, quarry_bdd_relocs_214093f)
            quarry_rva_0131963 += _name_boundary.attributes(quarry_Structure(quarry_format_fd32dfb))['sizeof']()
            quarry_bdd_relocs_214093f.append(quarry_BddDynamicRelocationData(struct=quarry_bdd_reloc_d93406e))
        return (quarry_func_relocs_b0b7f1d, quarry_bdd_relocs_214093f)

    @_name_boundary.callable_contract({'self': 'quarry_self_5a66cf2', 'rva': 'quarry_rva_1e89b20', 'size': 'quarry_size_local_0632a28'}, 'parse_relocations_directory')
    def quarry_parse_relocations_directory(quarry_self_5a66cf2, quarry_rva_1e89b20, quarry_size_local_0632a28):
        """Parse the base relocation table."""
        return _name_boundary.attributes(quarry_self_5a66cf2)['parse_image_base_relocation_list'](quarry_rva_1e89b20, quarry_size_local_0632a28)

    @_name_boundary.callable_contract({'self': 'quarry_self_d8e9803', 'rva': 'quarry_rva_6ba0b1a', 'fmt': 'quarry_fmt_caec92c', 'size': 'quarry_size_local_7068cfd'}, 'parse_image_base_relocation_list')
    def quarry_parse_image_base_relocation_list(quarry_self_d8e9803, quarry_rva_6ba0b1a, quarry_size_local_7068cfd, quarry_fmt_caec92c=None):
        quarry_rlc_size_4cb10fd = _name_boundary.attributes(quarry_Structure(quarry_self_d8e9803.__IMAGE_BASE_RELOCATION_format__))['sizeof']()
        quarry_end_local_f8117d6 = quarry_rva_6ba0b1a + quarry_size_local_7068cfd
        quarry_relocations_0c61a63 = []
        while quarry_rva_6ba0b1a < quarry_end_local_f8117d6:
            try:
                quarry_rlc_e3e2c3b = quarry_self_d8e9803.__unpack_data__(quarry_self_d8e9803.__IMAGE_BASE_RELOCATION_format__, _name_boundary.attributes(quarry_self_d8e9803)['get_data'](quarry_rva_6ba0b1a, quarry_rlc_size_4cb10fd), file_offset=_name_boundary.attributes(quarry_self_d8e9803)['get_offset_from_rva'](quarry_rva_6ba0b1a))
            except quarry_PEFormatError:
                _name_boundary.attributes(quarry_self_d8e9803)['__warnings'].append(f"Invalid relocation information. Can't read data at RVA: {quarry_rva_6ba0b1a:#x}")
                quarry_rlc_e3e2c3b = None
            if not quarry_rlc_e3e2c3b:
                break
            if quarry_rlc_e3e2c3b.VirtualAddress > _name_boundary.attributes(quarry_self_d8e9803)['OPTIONAL_HEADER'].SizeOfImage:
                _name_boundary.attributes(quarry_self_d8e9803)['__warnings'].append(f'Invalid relocation information. VirtualAddress outside of Image: {quarry_rlc_e3e2c3b.VirtualAddress:#x}')
                break
            if quarry_rlc_e3e2c3b.SizeOfBlock > _name_boundary.attributes(quarry_self_d8e9803)['OPTIONAL_HEADER'].SizeOfImage:
                _name_boundary.attributes(quarry_self_d8e9803)['__warnings'].append(f'Invalid relocation information. SizeOfBlock too large: {quarry_rlc_e3e2c3b.SizeOfBlock}')
                break
            if quarry_rlc_e3e2c3b.SizeOfBlock == 0:
                # A retained terminal padding block contains no entries; do not
                # convert its absent payload into a negative data-read length.
                quarry_reloc_entries_b708412 = []
            elif quarry_fmt_caec92c is None:
                quarry_reloc_entries_b708412 = _name_boundary.attributes(quarry_self_d8e9803)['parse_relocations'](quarry_rva_6ba0b1a + quarry_rlc_size_4cb10fd, quarry_rlc_e3e2c3b.VirtualAddress, quarry_rlc_e3e2c3b.SizeOfBlock - quarry_rlc_size_4cb10fd)
            else:
                quarry_reloc_entries_b708412 = _name_boundary.attributes(quarry_self_d8e9803)['parse_relocations_with_format'](quarry_rva_6ba0b1a + quarry_rlc_size_4cb10fd, quarry_rlc_e3e2c3b.VirtualAddress, quarry_rlc_e3e2c3b.SizeOfBlock - quarry_rlc_size_4cb10fd, quarry_fmt_caec92c)
            quarry_relocations_0c61a63.append(quarry_BaseRelocationData(struct=quarry_rlc_e3e2c3b, entries=quarry_reloc_entries_b708412))
            if not quarry_rlc_e3e2c3b.SizeOfBlock:
                break
            quarry_rva_6ba0b1a += quarry_rlc_e3e2c3b.SizeOfBlock
        return quarry_relocations_0c61a63

    @_name_boundary.callable_contract({'self': 'quarry_self_f4dd6fc', 'data_rva': 'quarry_data_rva_76afcb3', 'rva': 'quarry_rva_7b1d7a5', 'size': 'quarry_size_local_c783ca5'}, 'parse_relocations')
    def quarry_parse_relocations(quarry_self_f4dd6fc, quarry_data_rva_76afcb3, quarry_rva_7b1d7a5, quarry_size_local_c783ca5):
        """Parse relocations."""
        try:
            quarry_data_local_fa417e9 = _name_boundary.attributes(quarry_self_f4dd6fc)['get_data'](quarry_data_rva_76afcb3, quarry_size_local_c783ca5)
            quarry_file_offset_d5ed933 = _name_boundary.attributes(quarry_self_f4dd6fc)['get_offset_from_rva'](quarry_data_rva_76afcb3)
        except quarry_PEFormatError:
            _name_boundary.attributes(quarry_self_f4dd6fc)['__warnings'].append(f'Bad RVA in relocation data: {quarry_data_rva_76afcb3:#x}')
            return []
        quarry_entries_cc17ed2 = []
        quarry_offsets_and_type_ed9a2e6 = set()
        for quarry_idx_a7db56c in range(len(quarry_data_local_fa417e9) // 2):
            quarry_entry_0ea3fb7 = quarry_self_f4dd6fc.__unpack_data__(quarry_self_f4dd6fc.__IMAGE_BASE_RELOCATION_ENTRY_format__, quarry_data_local_fa417e9[quarry_idx_a7db56c * 2:(quarry_idx_a7db56c + 1) * 2], file_offset=quarry_file_offset_d5ed933)
            if not quarry_entry_0ea3fb7:
                break
            quarry_word_69fa654 = quarry_entry_0ea3fb7.Data
            quarry_reloc_type_dfdbbf0 = quarry_word_69fa654 >> 12
            quarry_reloc_offset_cd31acd = quarry_word_69fa654 & 4095
            if (quarry_reloc_offset_cd31acd, quarry_reloc_type_dfdbbf0) in quarry_offsets_and_type_ed9a2e6:
                _name_boundary.attributes(quarry_self_f4dd6fc)['__warnings'].append('Overlapping offsets in relocation data at RVA: 0x%x' % (quarry_reloc_offset_cd31acd + quarry_rva_7b1d7a5))
                break
            _name_boundary.attributes(quarry_offsets_and_type_ed9a2e6)['add']((quarry_reloc_offset_cd31acd, quarry_reloc_type_dfdbbf0))
            quarry_entries_cc17ed2.append(quarry_RelocationData(struct=quarry_entry_0ea3fb7, type=quarry_reloc_type_dfdbbf0, base_rva=quarry_rva_7b1d7a5, rva=quarry_reloc_offset_cd31acd + quarry_rva_7b1d7a5))
            quarry_file_offset_d5ed933 += _name_boundary.attributes(quarry_entry_0ea3fb7)['sizeof']()
        return quarry_entries_cc17ed2

    @_name_boundary.callable_contract({'self': 'quarry_self_d57a27d', 'data_rva': 'quarry_data_rva_c49228c', 'rva': 'quarry_rva_4b6a2da', 'format': 'quarry_format_f2407af', 'size': 'quarry_size_local_1166c31'}, 'parse_relocations_with_format')
    def quarry_parse_relocations_with_format(quarry_self_d57a27d, quarry_data_rva_c49228c, quarry_rva_4b6a2da, quarry_size_local_1166c31, quarry_format_f2407af):
        """Parse relocations with format."""
        try:
            quarry_data_local_9f3b2aa = _name_boundary.attributes(quarry_self_d57a27d)['get_data'](quarry_data_rva_c49228c, quarry_size_local_1166c31)
            quarry_file_offset_0c59e86 = _name_boundary.attributes(quarry_self_d57a27d)['get_offset_from_rva'](quarry_data_rva_c49228c)
        except quarry_PEFormatError:
            _name_boundary.attributes(quarry_self_d57a27d)['__warnings'].append(f'Bad RVA in relocation data: {quarry_data_rva_c49228c:#x}')
            return []
        quarry_entry_size_ef5520f = _name_boundary.attributes(quarry_StructureWithBitfields(quarry_format_f2407af))['sizeof']()
        quarry_entries_2811df4 = []
        quarry_offsets_2756322 = set()
        for quarry_idx_394dd38 in range(len(quarry_data_local_9f3b2aa) // quarry_entry_size_ef5520f):
            quarry_entry_01fa406 = quarry_self_d57a27d.__unpack_data_with_bitfields__(quarry_format_f2407af, quarry_data_local_9f3b2aa[quarry_idx_394dd38 * quarry_entry_size_ef5520f:(quarry_idx_394dd38 + 1) * quarry_entry_size_ef5520f], file_offset=quarry_file_offset_0c59e86)
            if not quarry_entry_01fa406:
                break
            quarry_reloc_offset_ba6c84f = quarry_entry_01fa406.PageRelativeOffset
            if quarry_reloc_offset_ba6c84f in quarry_offsets_2756322:
                _name_boundary.attributes(quarry_self_d57a27d)['__warnings'].append('Overlapping offsets in relocation data at RVA: 0x%x' % (quarry_reloc_offset_ba6c84f + quarry_rva_4b6a2da))
                break
            _name_boundary.attributes(quarry_offsets_2756322)['add'](quarry_reloc_offset_ba6c84f)
            quarry_entries_2811df4.append(quarry_RelocationData(struct=quarry_entry_01fa406, base_rva=quarry_rva_4b6a2da, rva=quarry_reloc_offset_ba6c84f + quarry_rva_4b6a2da))
            quarry_file_offset_0c59e86 += quarry_entry_size_ef5520f
        return quarry_entries_2811df4

    @_name_boundary.callable_contract({'self': 'quarry_self_53b64a2', 'rva': 'quarry_rva_be3f0fd', 'size': 'quarry_size_local_2f74c48'}, 'parse_debug_directory')
    def quarry_parse_debug_directory(quarry_self_53b64a2, quarry_rva_be3f0fd, quarry_size_local_2f74c48):
        """Parse the debug data."""
        quarry_dbg_size_e462462 = _name_boundary.attributes(quarry_Structure(quarry_self_53b64a2.__IMAGE_DEBUG_DIRECTORY_format__))['sizeof']()
        quarry_debug_5ad0764 = []
        for quarry_idx_c01683f in range(quarry_size_local_2f74c48 // quarry_dbg_size_e462462):
            try:
                quarry_data_local_41fd31e = _name_boundary.attributes(quarry_self_53b64a2)['get_data'](quarry_rva_be3f0fd + quarry_dbg_size_e462462 * quarry_idx_c01683f, quarry_dbg_size_e462462)
            except quarry_PEFormatError:
                _name_boundary.attributes(quarry_self_53b64a2)['__warnings'].append(f"Invalid debug information. Can't read data at RVA: {quarry_rva_be3f0fd:#x}")
                return None
            quarry_dbg_da0a32b = quarry_self_53b64a2.__unpack_data__(quarry_self_53b64a2.__IMAGE_DEBUG_DIRECTORY_format__, quarry_data_local_41fd31e, file_offset=_name_boundary.attributes(quarry_self_53b64a2)['get_offset_from_rva'](quarry_rva_be3f0fd + quarry_dbg_size_e462462 * quarry_idx_c01683f))
            if not quarry_dbg_da0a32b:
                return None
            quarry_dbg_type_c8f428e = None
            if quarry_dbg_da0a32b.Type == 1:
                pass
            elif quarry_dbg_da0a32b.Type == 2:
                quarry_dbg_type_offset_4076dc8 = quarry_dbg_da0a32b.PointerToRawData
                quarry_dbg_type_size_7ee93a4 = quarry_dbg_da0a32b.SizeOfData
                quarry_dbg_type_data_32d2aa7 = quarry_self_53b64a2.__data__[quarry_dbg_type_offset_4076dc8:quarry_dbg_type_offset_4076dc8 + quarry_dbg_type_size_7ee93a4]
                if quarry_dbg_type_data_32d2aa7[:4] == b'RSDS':
                    __CV_INFO_PDB70_format__ = ['CV_INFO_PDB70', ['4s,CvSignature', 'I,Signature_Data1', 'H,Signature_Data2', 'H,Signature_Data3', 'B,Signature_Data4', 'B,Signature_Data5', '6s,Signature_Data6', 'I,Age']]
                    quarry_pdbFileName_size_a8b1eaf = quarry_dbg_type_size_7ee93a4 - _name_boundary.attributes(quarry_Structure(__CV_INFO_PDB70_format__))['sizeof']()
                    if quarry_pdbFileName_size_a8b1eaf > 0:
                        __CV_INFO_PDB70_format__[1].append(f'{quarry_pdbFileName_size_a8b1eaf}s,PdbFileName')
                    quarry_dbg_type_c8f428e = quarry_self_53b64a2.__unpack_data__(__CV_INFO_PDB70_format__, quarry_dbg_type_data_32d2aa7, quarry_dbg_type_offset_4076dc8)
                    if quarry_dbg_type_c8f428e is not None:
                        quarry_dbg_type_c8f428e.Signature_Data6_value = quarry_struct.unpack('>Q', b'\x00\x00' + quarry_dbg_type_c8f428e.Signature_Data6)[0]
                        quarry_dbg_type_c8f428e.Signature_String = str(quarry_uuid.UUID(fields=(quarry_dbg_type_c8f428e.Signature_Data1, quarry_dbg_type_c8f428e.Signature_Data2, quarry_dbg_type_c8f428e.Signature_Data3, quarry_dbg_type_c8f428e.Signature_Data4, quarry_dbg_type_c8f428e.Signature_Data5, quarry_dbg_type_c8f428e.Signature_Data6_value))).replace('-', '').upper() + f'{quarry_dbg_type_c8f428e.Age:X}'
                elif quarry_dbg_type_data_32d2aa7[:4] == b'NB10':
                    __CV_INFO_PDB20_format__ = ['CV_INFO_PDB20', ['I,CvHeaderSignature', 'I,CvHeaderOffset', 'I,Signature', 'I,Age']]
                    quarry_pdbFileName_size_a8b1eaf = quarry_dbg_type_size_7ee93a4 - _name_boundary.attributes(quarry_Structure(__CV_INFO_PDB20_format__))['sizeof']()
                    if quarry_pdbFileName_size_a8b1eaf > 0:
                        __CV_INFO_PDB20_format__[1].append(f'{quarry_pdbFileName_size_a8b1eaf}s,PdbFileName')
                    quarry_dbg_type_c8f428e = quarry_self_53b64a2.__unpack_data__(__CV_INFO_PDB20_format__, quarry_dbg_type_data_32d2aa7, quarry_dbg_type_offset_4076dc8)
            elif quarry_dbg_da0a32b.Type == 4:
                quarry_dbg_type_offset_4076dc8 = quarry_dbg_da0a32b.PointerToRawData
                quarry_dbg_type_size_7ee93a4 = quarry_dbg_da0a32b.SizeOfData
                quarry_dbg_type_data_32d2aa7 = quarry_self_53b64a2.__data__[quarry_dbg_type_offset_4076dc8:quarry_dbg_type_offset_4076dc8 + quarry_dbg_type_size_7ee93a4]
                ___IMAGE_DEBUG_MISC_format__ = ['IMAGE_DEBUG_MISC', ['I,DataType', 'I,Length', 'B,Unicode', 'B,Reserved1', 'H,Reserved2']]
                quarry_dbg_type_partial_355e6fe = quarry_self_53b64a2.__unpack_data__(___IMAGE_DEBUG_MISC_format__, quarry_dbg_type_data_32d2aa7, quarry_dbg_type_offset_4076dc8)
                if quarry_dbg_type_partial_355e6fe:
                    if quarry_dbg_type_partial_355e6fe.Unicode in (0, 1):
                        quarry_data_size_774c14b = quarry_dbg_type_size_7ee93a4 - _name_boundary.attributes(quarry_Structure(___IMAGE_DEBUG_MISC_format__))['sizeof']()
                        if quarry_data_size_774c14b > 0:
                            ___IMAGE_DEBUG_MISC_format__[1].append(f'{quarry_data_size_774c14b}s,Data')
                        quarry_dbg_type_c8f428e = quarry_self_53b64a2.__unpack_data__(___IMAGE_DEBUG_MISC_format__, quarry_dbg_type_data_32d2aa7, quarry_dbg_type_offset_4076dc8)
            elif quarry_dbg_da0a32b.Type == 20:
                quarry_dbg_type_offset_4076dc8 = quarry_dbg_da0a32b.PointerToRawData
                quarry_dbg_type_size_7ee93a4 = quarry_dbg_da0a32b.SizeOfData
                quarry_dbg_type_data_32d2aa7 = quarry_self_53b64a2.__data__[quarry_dbg_type_offset_4076dc8:quarry_dbg_type_offset_4076dc8 + quarry_dbg_type_size_7ee93a4]
                ___IMAGE_DEBUG_EX_DLLCHARACTERISTICS_format__ = ['IMAGE_DEBUG_EX_DLLCHARACTERISTICS', ['I,ExDllCharacteristics']]
                quarry_dbg_type_c8f428e = quarry_self_53b64a2.__unpack_data__(___IMAGE_DEBUG_EX_DLLCHARACTERISTICS_format__, quarry_dbg_type_data_32d2aa7, quarry_dbg_type_offset_4076dc8)
                quarry_ex_dll_characteristics_flags_8496ac6 = quarry_retrieve_flags(quarry_EX_DLL_CHARACTERISTICS, 'IMAGE_DLLCHARACTERISTICS_EX_')
                quarry_set_flags(quarry_dbg_type_c8f428e, quarry_dbg_type_c8f428e.ExDllCharacteristics, quarry_ex_dll_characteristics_flags_8496ac6)
            quarry_debug_5ad0764.append(quarry_DebugData(struct=quarry_dbg_da0a32b, entry=quarry_dbg_type_c8f428e))
        return quarry_debug_5ad0764

    @_name_boundary.callable_contract({'self': 'quarry_self_a47e071', 'rva': 'quarry_rva_d301385', 'base_rva': 'quarry_base_rva_ce2f676', 'level': 'quarry_level_bf15713', 'dirs': 'quarry_dirs_73b4820', 'size': 'quarry_size_local_cfb9449'}, 'parse_resources_directory')
    def quarry_parse_resources_directory(quarry_self_a47e071, quarry_rva_d301385, quarry_size_local_cfb9449=0, quarry_base_rva_ce2f676=None, quarry_level_bf15713=0, quarry_dirs_73b4820=None):
        """Parse the resources directory.

        Given the RVA of the resources directory, it will process all
        its entries.

        The root will have the corresponding member of its structure,
        IMAGE_RESOURCE_DIRECTORY plus 'entries', a list of all the
        entries in the directory.

        Those entries will have, correspondingly, all the structure's
        members (IMAGE_RESOURCE_DIRECTORY_ENTRY) and an additional one,
        "directory", pointing to the IMAGE_RESOURCE_DIRECTORY structure
        representing upper layers of the tree. This one will also have
        an 'entries' attribute, pointing to the 3rd, and last, level.
        Another directory with more entries. Those last entries will
        have a new attribute (both 'leaf' or 'data_entry' can be used to
        access it). This structure finally points to the resource data.
        All the members of this structure, IMAGE_RESOURCE_DATA_ENTRY,
        are available as its attributes.
        """
        if quarry_dirs_73b4820 is None:
            quarry_dirs_73b4820 = [quarry_rva_d301385]
        if quarry_base_rva_ce2f676 is None:
            quarry_base_rva_ce2f676 = quarry_rva_d301385
        if quarry_level_bf15713 > quarry_MAX_RESOURCE_DEPTH:
            _name_boundary.attributes(quarry_self_a47e071)['__warnings'].append(f'Error parsing the resources directory. Excessively nested table depth {quarry_level_bf15713} (>{quarry_MAX_RESOURCE_DEPTH})')
            return None
        try:
            quarry_data_local_d917526 = _name_boundary.attributes(quarry_self_a47e071)['get_data'](quarry_rva_d301385, _name_boundary.attributes(quarry_Structure(quarry_self_a47e071.__IMAGE_RESOURCE_DIRECTORY_format__))['sizeof']())
        except quarry_PEFormatError:
            _name_boundary.attributes(quarry_self_a47e071)['__warnings'].append(f"Invalid resources directory. Can't read directory data at RVA: {quarry_rva_d301385:#x}")
            return None
        quarry_resource_dir_a0934cb = quarry_self_a47e071.__unpack_data__(quarry_self_a47e071.__IMAGE_RESOURCE_DIRECTORY_format__, quarry_data_local_d917526, file_offset=_name_boundary.attributes(quarry_self_a47e071)['get_offset_from_rva'](quarry_rva_d301385))
        if quarry_resource_dir_a0934cb is None:
            _name_boundary.attributes(quarry_self_a47e071)['__warnings'].append(f"Invalid resources directory. Can't parse directory data at RVA: {quarry_rva_d301385:#x}")
            return None
        quarry_dir_entries_2eec245 = []
        quarry_rva_d301385 += _name_boundary.attributes(quarry_resource_dir_a0934cb)['sizeof']()
        quarry_number_of_entries_692b449 = quarry_resource_dir_a0934cb.NumberOfNamedEntries + quarry_resource_dir_a0934cb.NumberOfIdEntries
        quarry_MAX_ALLOWED_ENTRIES_27b1fc5 = 4096
        if quarry_number_of_entries_692b449 > quarry_MAX_ALLOWED_ENTRIES_27b1fc5:
            _name_boundary.attributes(quarry_self_a47e071)['__warnings'].append(f'Error parsing the resources directory. The directory contains {quarry_number_of_entries_692b449} entries (>{quarry_MAX_ALLOWED_ENTRIES_27b1fc5})')
            return None
        _name_boundary.attributes(quarry_self_a47e071)['__total_resource_entries_count'] += quarry_number_of_entries_692b449
        if _name_boundary.attributes(quarry_self_a47e071)['__total_resource_entries_count'] > quarry_MAX_RESOURCE_ENTRIES:
            _name_boundary.attributes(quarry_self_a47e071)['__warnings'].append(f"Error parsing the resources directory. The file contains at least {_name_boundary.attributes(quarry_self_a47e071)['__total_resource_entries_count']} entries (>{quarry_MAX_RESOURCE_ENTRIES})")
            return None
        quarry_strings_to_postprocess_8b7e160 = []
        quarry_last_name_begin_end_1a5e62d = None
        for quarry_idx_d2dcd02 in range(quarry_number_of_entries_692b449):
            if not _name_boundary.attributes(quarry_self_a47e071)['__resource_size_limit_reached'] and _name_boundary.attributes(quarry_self_a47e071)['__total_resource_bytes'] > _name_boundary.attributes(quarry_self_a47e071)['__resource_size_limit_upperbounds']:
                _name_boundary.attributes(quarry_self_a47e071)['__resource_size_limit_reached'] = True
                _name_boundary.attributes(quarry_self_a47e071)['__warnings'].append(f"Resource size {_name_boundary.attributes(quarry_self_a47e071)['__total_resource_bytes']:#x} exceeds file size {_name_boundary.attributes(quarry_self_a47e071)['__resource_size_limit_upperbounds']:#x}, overlapping resources found.")
            quarry_res_d9e503e = _name_boundary.attributes(quarry_self_a47e071)['parse_resource_entry'](quarry_rva_d301385)
            if quarry_res_d9e503e is None:
                _name_boundary.attributes(quarry_self_a47e071)['__warnings'].append(f'Error parsing the resources directory, Entry {quarry_idx_d2dcd02} is invalid, RVA = {quarry_rva_d301385:#x}. ')
                break
            quarry_entry_name_d0f27bf = None
            quarry_entry_id_49b3a5c = None
            if not quarry_res_d9e503e.NameIsString:
                quarry_entry_id_49b3a5c = quarry_res_d9e503e.Name
            else:
                quarry_ustr_offset_c87a65d = quarry_base_rva_ce2f676 + quarry_res_d9e503e.NameOffset
                try:
                    quarry_entry_name_d0f27bf = quarry_UnicodeStringWrapperPostProcessor(quarry_self_a47e071, quarry_ustr_offset_c87a65d)
                    _name_boundary.attributes(quarry_self_a47e071)['__total_resource_bytes'] += _name_boundary.attributes(quarry_entry_name_d0f27bf)['get_pascal_16_length']()
                    if quarry_last_name_begin_end_1a5e62d and quarry_last_name_begin_end_1a5e62d[0] < quarry_ustr_offset_c87a65d <= quarry_last_name_begin_end_1a5e62d[1]:
                        quarry_strings_to_postprocess_8b7e160.pop()
                        _name_boundary.attributes(quarry_self_a47e071)['__warnings'].append(f'Error parsing the resources directory, attempting to read entry name. Entry names overlap {quarry_ustr_offset_c87a65d:#x}')
                        break
                    quarry_last_name_begin_end_1a5e62d = (quarry_ustr_offset_c87a65d, quarry_ustr_offset_c87a65d + _name_boundary.attributes(quarry_entry_name_d0f27bf)['get_pascal_16_length']())
                    quarry_strings_to_postprocess_8b7e160.append(quarry_entry_name_d0f27bf)
                except quarry_PEFormatError:
                    _name_boundary.attributes(quarry_self_a47e071)['__warnings'].append(f"Error parsing the resources directory, attempting to read entry name. Can't read unicode string at offset {quarry_ustr_offset_c87a65d:#x}")
            if quarry_res_d9e503e.DataIsDirectory:
                if quarry_base_rva_ce2f676 + quarry_res_d9e503e.OffsetToDirectory in quarry_dirs_73b4820:
                    break
                quarry_entry_directory_f45ab4c = _name_boundary.attributes(quarry_self_a47e071)['parse_resources_directory'](quarry_base_rva_ce2f676 + quarry_res_d9e503e.OffsetToDirectory, quarry_size_local_cfb9449 - (quarry_rva_d301385 - quarry_base_rva_ce2f676), base_rva=quarry_base_rva_ce2f676, level=quarry_level_bf15713 + 1, dirs=quarry_dirs_73b4820 + [quarry_base_rva_ce2f676 + quarry_res_d9e503e.OffsetToDirectory])
                if not quarry_entry_directory_f45ab4c:
                    break
                if quarry_entry_id_49b3a5c == quarry_RESOURCE_TYPE['RT_STRING']:
                    quarry_strings_ddb9b9a = {}
                    for quarry_resource_id_b6a5fb3 in quarry_entry_directory_f45ab4c.entries:
                        if _name_boundary.has_attribute(quarry_resource_id_b6a5fb3, 'directory'):
                            quarry_resource_strings_995d9b4 = {}
                            for quarry_resource_lang_089fa11 in quarry_resource_id_b6a5fb3.directory.entries:
                                if quarry_resource_lang_089fa11 is None or not _name_boundary.has_attribute(quarry_resource_lang_089fa11, 'data') or _name_boundary.attributes(quarry_resource_lang_089fa11.data)['struct'].Size is None or (quarry_resource_id_b6a5fb3.id is None):
                                    continue
                                quarry_string_entry_rva_1bbc762 = _name_boundary.attributes(quarry_resource_lang_089fa11.data)['struct'].OffsetToData
                                quarry_string_entry_size_216e77c = _name_boundary.attributes(quarry_resource_lang_089fa11.data)['struct'].Size
                                quarry_string_entry_id_6fc8d92 = quarry_resource_id_b6a5fb3.id
                                try:
                                    quarry_string_entry_data_40183b1 = _name_boundary.attributes(quarry_self_a47e071)['get_data'](quarry_string_entry_rva_1bbc762, quarry_string_entry_size_216e77c)
                                except quarry_PEFormatError:
                                    _name_boundary.attributes(quarry_self_a47e071)['__warnings'].append(f'Error parsing resource of type RT_STRING at RVA {quarry_string_entry_rva_1bbc762:#x} with size {quarry_string_entry_size_216e77c}')
                                    continue
                                quarry_parse_strings(quarry_string_entry_data_40183b1, (int(quarry_string_entry_id_6fc8d92) - 1) * 16, quarry_resource_strings_995d9b4)
                                quarry_strings_ddb9b9a.update(quarry_resource_strings_995d9b4)
                            quarry_resource_id_b6a5fb3.directory.strings = quarry_resource_strings_995d9b4
                quarry_dir_entries_2eec245.append(quarry_ResourceDirEntryData(struct=quarry_res_d9e503e, name=quarry_entry_name_d0f27bf, id=quarry_entry_id_49b3a5c, directory=quarry_entry_directory_f45ab4c))
            else:
                quarry_struct_f4c5a3d = _name_boundary.attributes(quarry_self_a47e071)['parse_resource_data_entry'](quarry_base_rva_ce2f676 + quarry_res_d9e503e.OffsetToDirectory)
                if quarry_struct_f4c5a3d:
                    _name_boundary.attributes(quarry_self_a47e071)['__total_resource_bytes'] += quarry_struct_f4c5a3d.Size
                    quarry_entry_data_cbdbd97 = quarry_ResourceDataEntryData(struct=quarry_struct_f4c5a3d, lang=quarry_res_d9e503e.Name & 1023, sublang=quarry_res_d9e503e.Name >> 10)
                    quarry_dir_entries_2eec245.append(quarry_ResourceDirEntryData(struct=quarry_res_d9e503e, name=quarry_entry_name_d0f27bf, id=quarry_entry_id_49b3a5c, data=quarry_entry_data_cbdbd97))
                else:
                    break
            if quarry_level_bf15713 == 0 and quarry_res_d9e503e.Id == quarry_RESOURCE_TYPE['RT_VERSION']:
                if quarry_dir_entries_2eec245:
                    quarry_last_entry_43e8cb7 = quarry_dir_entries_2eec245[-1]
                try:
                    quarry_version_entries_072e6fa = quarry_last_entry_43e8cb7.directory.entries[0].directory.entries
                except (AttributeError, IndexError):
                    pass
                else:
                    for quarry_version_entry_cc42407 in quarry_version_entries_072e6fa:
                        quarry_rt_version_struct_8818b0d = None
                        try:
                            quarry_rt_version_struct_8818b0d = _name_boundary.attributes(quarry_version_entry_cc42407.data)['struct']
                        except (AttributeError, IndexError):
                            pass
                        if quarry_rt_version_struct_8818b0d is not None:
                            _name_boundary.attributes(quarry_self_a47e071)['parse_version_information'](quarry_rt_version_struct_8818b0d)
            quarry_rva_d301385 += _name_boundary.attributes(quarry_res_d9e503e)['sizeof']()
        quarry_string_rvas_74ebc15 = [_name_boundary.attributes(quarry_s_3bdc313)['get_rva']() for quarry_s_3bdc313 in quarry_strings_to_postprocess_8b7e160]
        quarry_string_rvas_74ebc15.sort()
        for quarry_s_4ff6c1a in quarry_strings_to_postprocess_8b7e160:
            _name_boundary.attributes(quarry_s_4ff6c1a)['render_pascal_16']()
        quarry_resource_directory_data_7997799 = quarry_ResourceDirData(struct=quarry_resource_dir_a0934cb, entries=quarry_dir_entries_2eec245)
        return quarry_resource_directory_data_7997799

    @_name_boundary.callable_contract({'self': 'quarry_self_4c00f68', 'rva': 'quarry_rva_54d9a0a'}, 'parse_resource_data_entry')
    def quarry_parse_resource_data_entry(quarry_self_4c00f68, quarry_rva_54d9a0a):
        """Parse a data entry from the resources directory."""
        try:
            quarry_data_local_34ccf0b = _name_boundary.attributes(quarry_self_4c00f68)['get_data'](quarry_rva_54d9a0a, _name_boundary.attributes(quarry_Structure(quarry_self_4c00f68.__IMAGE_RESOURCE_DATA_ENTRY_format__))['sizeof']())
        except quarry_PEFormatError:
            _name_boundary.attributes(quarry_self_4c00f68)['__warnings'].append(f'Error parsing a resource directory data entry, the RVA is invalid: {quarry_rva_54d9a0a:#x}')
            return None
        quarry_data_entry_12ba5a2 = quarry_self_4c00f68.__unpack_data__(quarry_self_4c00f68.__IMAGE_RESOURCE_DATA_ENTRY_format__, quarry_data_local_34ccf0b, file_offset=_name_boundary.attributes(quarry_self_4c00f68)['get_offset_from_rva'](quarry_rva_54d9a0a))
        return quarry_data_entry_12ba5a2

    @_name_boundary.callable_contract({'self': 'quarry_self_d988853', 'rva': 'quarry_rva_c0933ad'}, 'parse_resource_entry')
    def quarry_parse_resource_entry(quarry_self_d988853, quarry_rva_c0933ad):
        """Parse a directory entry from the resources directory."""
        try:
            quarry_data_local_2a511b2 = _name_boundary.attributes(quarry_self_d988853)['get_data'](quarry_rva_c0933ad, _name_boundary.attributes(quarry_Structure(quarry_self_d988853.__IMAGE_RESOURCE_DIRECTORY_ENTRY_format__))['sizeof']())
        except quarry_PEFormatError:
            return None
        quarry_resource_46bc5f3 = quarry_self_d988853.__unpack_data__(quarry_self_d988853.__IMAGE_RESOURCE_DIRECTORY_ENTRY_format__, quarry_data_local_2a511b2, file_offset=_name_boundary.attributes(quarry_self_d988853)['get_offset_from_rva'](quarry_rva_c0933ad))
        if quarry_resource_46bc5f3 is None:
            return None
        quarry_resource_46bc5f3.NameOffset = quarry_resource_46bc5f3.Name & 2147483647
        quarry_resource_46bc5f3.NameIsString = (quarry_resource_46bc5f3.Name & 2147483648) >> 31
        quarry_resource_46bc5f3.Id = quarry_resource_46bc5f3.Name & 65535
        quarry_resource_46bc5f3.OffsetToDirectory = quarry_resource_46bc5f3.OffsetToData & 2147483647
        quarry_resource_46bc5f3.DataIsDirectory = (quarry_resource_46bc5f3.OffsetToData & 2147483648) >> 31
        return quarry_resource_46bc5f3

    @_name_boundary.callable_contract({'self': 'quarry_self_f47cf38', 'version_struct': 'quarry_version_struct_3aab9d9'}, 'parse_version_information')
    def quarry_parse_version_information(quarry_self_f47cf38, quarry_version_struct_3aab9d9):
        """Parse version information structure.

        The data will be made available in three attributes of the PE object.

        VS_VERSIONINFO will contain the first three fields of the main structure:
            'Length', 'ValueLength', and 'Type'

        VS_FIXEDFILEINFO will hold the rest of the fields, accessible as sub-attributes:
            'Signature'
            'StrucVersion'
            'FileVersionMS'
            'FileVersionLS'
            'ProductVersionMS'
            'ProductVersionLS'
            'FileFlagsMask'
            'FileFlags'
            'FileOS'
            'FileType'
            'FileSubtype'
            'FileDateMS'
            'FileDateLS'
            
        FileInfo is a list of all StringFileInfo and VarFileInfo structures.

        StringFileInfo structures will have a list as an attribute named 'StringTable'
        containing all the StringTable structures. Each of those structures contains a
        dictionary 'entries' with all the key-value version information string pairs.

        VarFileInfo structures will have a list as an attribute named 'Var' containing
        all Var structures. Each Var structure will have a dictionary as an attribute
        named 'entry' which will contain the name and value of the Var.
        """
        try:
            quarry_start_offset_9ac0123 = _name_boundary.attributes(quarry_self_f47cf38)['get_offset_from_rva'](quarry_version_struct_3aab9d9.OffsetToData)
        except quarry_PEFormatError:
            _name_boundary.attributes(quarry_self_f47cf38)['__warnings'].append(f'Error parsing the version information, attempting to read OffsetToData with RVA: {quarry_version_struct_3aab9d9.OffsetToData:#x}')
            return
        quarry_raw_data_b14daad = quarry_self_f47cf38.__data__[quarry_start_offset_9ac0123:quarry_start_offset_9ac0123 + quarry_version_struct_3aab9d9.Size]
        quarry_versioninfo_struct_5b0bdb0 = quarry_self_f47cf38.__unpack_data__(quarry_self_f47cf38.__VS_VERSIONINFO_format__, quarry_raw_data_b14daad, file_offset=quarry_start_offset_9ac0123)
        if quarry_versioninfo_struct_5b0bdb0 is None:
            return
        quarry_ustr_offset_d15c99a = quarry_version_struct_3aab9d9.OffsetToData + _name_boundary.attributes(quarry_versioninfo_struct_5b0bdb0)['sizeof']()
        quarry_section_7f505dc = _name_boundary.attributes(quarry_self_f47cf38)['get_section_by_rva'](quarry_ustr_offset_d15c99a)
        quarry_section_end_804f2e9 = None
        if quarry_section_7f505dc:
            quarry_section_end_804f2e9 = quarry_section_7f505dc.VirtualAddress + max(quarry_section_7f505dc.SizeOfRawData, quarry_section_7f505dc.Misc_VirtualSize)
        quarry_versioninfo_string_8e7d6ee = None
        try:
            if quarry_section_end_804f2e9 is None:
                quarry_versioninfo_string_8e7d6ee = _name_boundary.attributes(quarry_self_f47cf38)['get_string_u_at_rva'](quarry_ustr_offset_d15c99a, encoding='ascii')
            else:
                quarry_versioninfo_string_8e7d6ee = _name_boundary.attributes(quarry_self_f47cf38)['get_string_u_at_rva'](quarry_ustr_offset_d15c99a, quarry_section_end_804f2e9 - quarry_ustr_offset_d15c99a >> 1, encoding='ascii')
        except quarry_PEFormatError:
            _name_boundary.attributes(quarry_self_f47cf38)['__warnings'].append(f"Error parsing the version information, attempting to read VS_VERSION_INFO string. Can't read unicode string at offset {quarry_ustr_offset_d15c99a:#x}")
        if quarry_versioninfo_string_8e7d6ee is None:
            _name_boundary.attributes(quarry_self_f47cf38)['__warnings'].append(f'Invalid VS_VERSION_INFO block: {quarry_versioninfo_string_8e7d6ee}')
            return
        if quarry_versioninfo_string_8e7d6ee != b'VS_VERSION_INFO':
            if len(quarry_versioninfo_string_8e7d6ee) > 128:
                quarry_excerpt_ead8699 = _name_boundary.attributes(quarry_versioninfo_string_8e7d6ee[:128])['decode']('ascii')
                quarry_excerpt_ead8699 = quarry_excerpt_ead8699[:quarry_excerpt_ead8699.rfind('\\u')]
                quarry_versioninfo_string_8e7d6ee = f'{quarry_excerpt_ead8699} ... ({len(quarry_versioninfo_string_8e7d6ee)} bytes, too long to display)'.encode()
            _name_boundary.attributes(quarry_self_f47cf38)['__warnings'].append('Invalid VS_VERSION_INFO block: {}'.format(_name_boundary.attributes(quarry_versioninfo_string_8e7d6ee)['decode']('ascii').replace('\x00', '\\00')))
            return
        if not _name_boundary.has_attribute(quarry_self_f47cf38, 'VS_VERSIONINFO'):
            _name_boundary.attributes(quarry_self_f47cf38)['VS_VERSIONINFO'] = []
        quarry_vinfo_dc4606b = quarry_versioninfo_struct_5b0bdb0
        quarry_vinfo_dc4606b.Key = quarry_versioninfo_string_8e7d6ee
        _name_boundary.attributes(quarry_self_f47cf38)['VS_VERSIONINFO'].append(quarry_vinfo_dc4606b)
        quarry_fixedfileinfo_offset_f27b356 = _name_boundary.attributes(quarry_self_f47cf38)['dword_align'](_name_boundary.attributes(quarry_versioninfo_struct_5b0bdb0)['sizeof']() + 2 * (len(quarry_versioninfo_string_8e7d6ee) + 1), quarry_version_struct_3aab9d9.OffsetToData)
        quarry_fixedfileinfo_struct_57ff0d2 = quarry_self_f47cf38.__unpack_data__(quarry_self_f47cf38.__VS_FIXEDFILEINFO_format__, quarry_raw_data_b14daad[quarry_fixedfileinfo_offset_f27b356:], file_offset=quarry_start_offset_9ac0123 + quarry_fixedfileinfo_offset_f27b356)
        if not quarry_fixedfileinfo_struct_57ff0d2:
            return
        if not _name_boundary.has_attribute(quarry_self_f47cf38, 'VS_FIXEDFILEINFO'):
            _name_boundary.attributes(quarry_self_f47cf38)['VS_FIXEDFILEINFO'] = []
        _name_boundary.attributes(quarry_self_f47cf38)['VS_FIXEDFILEINFO'].append(quarry_fixedfileinfo_struct_57ff0d2)
        quarry_stringfileinfo_offset_f8bd444 = _name_boundary.attributes(quarry_self_f47cf38)['dword_align'](quarry_fixedfileinfo_offset_f27b356 + _name_boundary.attributes(quarry_fixedfileinfo_struct_57ff0d2)['sizeof'](), quarry_version_struct_3aab9d9.OffsetToData)
        if not _name_boundary.has_attribute(quarry_self_f47cf38, 'FileInfo'):
            _name_boundary.attributes(quarry_self_f47cf38)['FileInfo'] = []
        quarry_finfo_5d7b577 = []
        while True:
            quarry_stringfileinfo_struct_83aaeb1 = quarry_self_f47cf38.__unpack_data__(quarry_self_f47cf38.__StringFileInfo_format__, quarry_raw_data_b14daad[quarry_stringfileinfo_offset_f8bd444:], file_offset=quarry_start_offset_9ac0123 + quarry_stringfileinfo_offset_f8bd444)
            if quarry_stringfileinfo_struct_83aaeb1 is None:
                _name_boundary.attributes(quarry_self_f47cf38)['__warnings'].append('Error parsing StringFileInfo/VarFileInfo struct')
                return
            quarry_ustr_offset_d15c99a = quarry_version_struct_3aab9d9.OffsetToData + quarry_stringfileinfo_offset_f8bd444 + _name_boundary.attributes(quarry_versioninfo_struct_5b0bdb0)['sizeof']()
            try:
                quarry_stringfileinfo_string_d33cfed = _name_boundary.attributes(quarry_self_f47cf38)['get_string_u_at_rva'](quarry_ustr_offset_d15c99a)
            except quarry_PEFormatError:
                _name_boundary.attributes(quarry_self_f47cf38)['__warnings'].append(f"Error parsing the version information, attempting to read StringFileInfo string. Can't read unicode string at offset {quarry_ustr_offset_d15c99a:#x}")
                break
            quarry_stringfileinfo_struct_83aaeb1.Key = quarry_stringfileinfo_string_d33cfed
            quarry_finfo_5d7b577.append(quarry_stringfileinfo_struct_83aaeb1)
            if quarry_stringfileinfo_string_d33cfed and quarry_stringfileinfo_string_d33cfed.startswith(b'StringFileInfo'):
                if quarry_stringfileinfo_struct_83aaeb1.Type in (0, 1) and quarry_stringfileinfo_struct_83aaeb1.ValueLength == 0:
                    quarry_stringtable_offset_6cddc4b = _name_boundary.attributes(quarry_self_f47cf38)['dword_align'](quarry_stringfileinfo_offset_f8bd444 + _name_boundary.attributes(quarry_stringfileinfo_struct_83aaeb1)['sizeof']() + 2 * (len(quarry_stringfileinfo_string_d33cfed) + 1), quarry_version_struct_3aab9d9.OffsetToData)
                    quarry_stringfileinfo_struct_83aaeb1.StringTable = []
                    while True:
                        quarry_stringtable_struct_fc2df49 = quarry_self_f47cf38.__unpack_data__(quarry_self_f47cf38.__StringTable_format__, quarry_raw_data_b14daad[quarry_stringtable_offset_6cddc4b:], file_offset=quarry_start_offset_9ac0123 + quarry_stringtable_offset_6cddc4b)
                        if not quarry_stringtable_struct_fc2df49:
                            break
                        quarry_ustr_offset_d15c99a = quarry_version_struct_3aab9d9.OffsetToData + quarry_stringtable_offset_6cddc4b + _name_boundary.attributes(quarry_stringtable_struct_fc2df49)['sizeof']()
                        try:
                            quarry_stringtable_string_1780c27 = _name_boundary.attributes(quarry_self_f47cf38)['get_string_u_at_rva'](quarry_ustr_offset_d15c99a)
                        except quarry_PEFormatError:
                            _name_boundary.attributes(quarry_self_f47cf38)['__warnings'].append(f"Error parsing the version information, attempting to read StringTable string. Can't read unicode string at offset {quarry_ustr_offset_d15c99a:#x}")
                            break
                        quarry_stringtable_struct_fc2df49.LangID = quarry_stringtable_string_1780c27
                        quarry_stringtable_struct_fc2df49.entries = {}
                        quarry_stringtable_struct_fc2df49.entries_offsets = {}
                        quarry_stringtable_struct_fc2df49.entries_lengths = {}
                        quarry_stringfileinfo_struct_83aaeb1.StringTable.append(quarry_stringtable_struct_fc2df49)
                        quarry_entry_offset_d6f7080 = _name_boundary.attributes(quarry_self_f47cf38)['dword_align'](quarry_stringtable_offset_6cddc4b + _name_boundary.attributes(quarry_stringtable_struct_fc2df49)['sizeof']() + 2 * (len(quarry_stringtable_string_1780c27) + 1), quarry_version_struct_3aab9d9.OffsetToData)
                        while quarry_entry_offset_d6f7080 < quarry_stringtable_offset_6cddc4b + quarry_stringtable_struct_fc2df49.Length:
                            quarry_string_struct_69bc636 = quarry_self_f47cf38.__unpack_data__(quarry_self_f47cf38.__String_format__, quarry_raw_data_b14daad[quarry_entry_offset_d6f7080:], file_offset=quarry_start_offset_9ac0123 + quarry_entry_offset_d6f7080)
                            if not quarry_string_struct_69bc636:
                                break
                            quarry_ustr_offset_d15c99a = quarry_version_struct_3aab9d9.OffsetToData + quarry_entry_offset_d6f7080 + _name_boundary.attributes(quarry_string_struct_69bc636)['sizeof']()
                            try:
                                quarry_key_42443b6 = _name_boundary.attributes(quarry_self_f47cf38)['get_string_u_at_rva'](quarry_ustr_offset_d15c99a)
                                quarry_key_offset_c8c0ada = _name_boundary.attributes(quarry_self_f47cf38)['get_offset_from_rva'](quarry_ustr_offset_d15c99a)
                            except quarry_PEFormatError:
                                _name_boundary.attributes(quarry_self_f47cf38)['__warnings'].append(f"Error parsing the version information, attempting to read StringTable Key string. Can't read unicode string at offset {quarry_ustr_offset_d15c99a:#x}")
                                break
                            quarry_value_offset_d232137 = _name_boundary.attributes(quarry_self_f47cf38)['dword_align'](2 * (len(quarry_key_42443b6) + 1) + quarry_entry_offset_d6f7080 + _name_boundary.attributes(quarry_string_struct_69bc636)['sizeof'](), quarry_version_struct_3aab9d9.OffsetToData)
                            quarry_ustr_offset_d15c99a = quarry_version_struct_3aab9d9.OffsetToData + quarry_value_offset_d232137
                            try:
                                quarry_value_b7a6a8a = _name_boundary.attributes(quarry_self_f47cf38)['get_string_u_at_rva'](quarry_ustr_offset_d15c99a, max_length=quarry_string_struct_69bc636.ValueLength)
                                quarry_value_offset_d232137 = _name_boundary.attributes(quarry_self_f47cf38)['get_offset_from_rva'](quarry_ustr_offset_d15c99a)
                            except quarry_PEFormatError:
                                _name_boundary.attributes(quarry_self_f47cf38)['__warnings'].append(f"Error parsing the version information, attempting to read StringTable Value string. Can't read unicode string at offset {quarry_ustr_offset_d15c99a:#x}")
                                break
                            if quarry_string_struct_69bc636.Length == 0:
                                quarry_entry_offset_d6f7080 = quarry_stringtable_offset_6cddc4b + quarry_stringtable_struct_fc2df49.Length
                            else:
                                quarry_entry_offset_d6f7080 = _name_boundary.attributes(quarry_self_f47cf38)['dword_align'](quarry_string_struct_69bc636.Length + quarry_entry_offset_d6f7080, quarry_version_struct_3aab9d9.OffsetToData)
                            quarry_stringtable_struct_fc2df49.entries[quarry_key_42443b6] = quarry_value_b7a6a8a
                            quarry_stringtable_struct_fc2df49.entries_offsets[quarry_key_42443b6] = (quarry_key_offset_c8c0ada, quarry_value_offset_d232137)
                            quarry_stringtable_struct_fc2df49.entries_lengths[quarry_key_42443b6] = (len(quarry_key_42443b6), len(quarry_value_b7a6a8a))
                        quarry_new_stringtable_offset_aa3358d = _name_boundary.attributes(quarry_self_f47cf38)['dword_align'](quarry_stringtable_struct_fc2df49.Length + quarry_stringtable_offset_6cddc4b, quarry_version_struct_3aab9d9.OffsetToData)
                        if quarry_new_stringtable_offset_aa3358d == quarry_stringtable_offset_6cddc4b:
                            break
                        quarry_stringtable_offset_6cddc4b = quarry_new_stringtable_offset_aa3358d
                        if quarry_stringtable_offset_6cddc4b >= quarry_stringfileinfo_struct_83aaeb1.Length:
                            break
            elif quarry_stringfileinfo_string_d33cfed and quarry_stringfileinfo_string_d33cfed.startswith(b'VarFileInfo'):
                quarry_varfileinfo_struct_00d6146 = quarry_stringfileinfo_struct_83aaeb1
                quarry_varfileinfo_struct_00d6146.name = 'VarFileInfo'
                if quarry_varfileinfo_struct_00d6146.Type in (0, 1) and quarry_varfileinfo_struct_00d6146.ValueLength == 0:
                    quarry_var_offset_9918357 = _name_boundary.attributes(quarry_self_f47cf38)['dword_align'](quarry_stringfileinfo_offset_f8bd444 + _name_boundary.attributes(quarry_varfileinfo_struct_00d6146)['sizeof']() + 2 * (len(quarry_stringfileinfo_string_d33cfed) + 1), quarry_version_struct_3aab9d9.OffsetToData)
                    quarry_varfileinfo_struct_00d6146.Var = []
                    while True:
                        quarry_var_struct_bb4f8c2 = quarry_self_f47cf38.__unpack_data__(quarry_self_f47cf38.__Var_format__, quarry_raw_data_b14daad[quarry_var_offset_9918357:], file_offset=quarry_start_offset_9ac0123 + quarry_var_offset_9918357)
                        if not quarry_var_struct_bb4f8c2:
                            break
                        quarry_ustr_offset_d15c99a = quarry_version_struct_3aab9d9.OffsetToData + quarry_var_offset_9918357 + _name_boundary.attributes(quarry_var_struct_bb4f8c2)['sizeof']()
                        try:
                            quarry_var_string_571fd53 = _name_boundary.attributes(quarry_self_f47cf38)['get_string_u_at_rva'](quarry_ustr_offset_d15c99a)
                        except quarry_PEFormatError:
                            _name_boundary.attributes(quarry_self_f47cf38)['__warnings'].append(f"Error parsing the version information, attempting to read VarFileInfo Var string. Can't read unicode string at offset {quarry_ustr_offset_d15c99a:#x}")
                            break
                        if quarry_var_string_571fd53 is None:
                            break
                        quarry_varfileinfo_struct_00d6146.Var.append(quarry_var_struct_bb4f8c2)
                        quarry_varword_offset_a604227 = _name_boundary.attributes(quarry_self_f47cf38)['dword_align'](2 * (len(quarry_var_string_571fd53) + 1) + quarry_var_offset_9918357 + _name_boundary.attributes(quarry_var_struct_bb4f8c2)['sizeof'](), quarry_version_struct_3aab9d9.OffsetToData)
                        quarry_orig_varword_offset_9891d62 = quarry_varword_offset_a604227
                        while quarry_varword_offset_a604227 < quarry_orig_varword_offset_9891d62 + quarry_var_struct_bb4f8c2.ValueLength:
                            quarry_word1_37fe903 = _name_boundary.attributes(quarry_self_f47cf38)['get_word_from_data'](quarry_raw_data_b14daad[quarry_varword_offset_a604227:quarry_varword_offset_a604227 + 2], 0)
                            quarry_word2_98403f1 = _name_boundary.attributes(quarry_self_f47cf38)['get_word_from_data'](quarry_raw_data_b14daad[quarry_varword_offset_a604227 + 2:quarry_varword_offset_a604227 + 4], 0)
                            quarry_varword_offset_a604227 += 4
                            if isinstance(quarry_word1_37fe903, int) and isinstance(quarry_word2_98403f1, int):
                                quarry_var_struct_bb4f8c2.entry = {quarry_var_string_571fd53: f'0x{quarry_word1_37fe903:04x} 0x{quarry_word2_98403f1:04x}'}
                        quarry_var_offset_9918357 = _name_boundary.attributes(quarry_self_f47cf38)['dword_align'](quarry_var_offset_9918357 + quarry_var_struct_bb4f8c2.Length, quarry_version_struct_3aab9d9.OffsetToData)
                        if quarry_var_offset_9918357 <= quarry_var_offset_9918357 + quarry_var_struct_bb4f8c2.Length:
                            break
            quarry_stringfileinfo_offset_f8bd444 = _name_boundary.attributes(quarry_self_f47cf38)['dword_align'](quarry_stringfileinfo_struct_83aaeb1.Length + quarry_stringfileinfo_offset_f8bd444, quarry_version_struct_3aab9d9.OffsetToData)
            if quarry_stringfileinfo_struct_83aaeb1.Length == 0 or quarry_stringfileinfo_offset_f8bd444 >= quarry_versioninfo_struct_5b0bdb0.Length:
                break
        _name_boundary.attributes(quarry_self_f47cf38)['FileInfo'].append(quarry_finfo_5d7b577)

    @_name_boundary.callable_contract({'self': 'quarry_self_3373b52', 'rva': 'quarry_rva_9c05383', 'forwarded_only': 'quarry_forwarded_only_e9c126f', 'size': 'quarry_size_local_9b99bc9'}, 'parse_export_directory')
    def quarry_parse_export_directory(quarry_self_3373b52, quarry_rva_9c05383, quarry_size_local_9b99bc9, quarry_forwarded_only_e9c126f=False):
        """Parse the export directory.

        Given the RVA of the export directory, it will process all
        its entries.

        The exports will be made available as a list of ExportData
        instances in the 'IMAGE_DIRECTORY_ENTRY_EXPORT' PE attribute.
        """
        try:
            quarry_export_dir_bdfd7be = quarry_self_3373b52.__unpack_data__(quarry_self_3373b52.__IMAGE_EXPORT_DIRECTORY_format__, _name_boundary.attributes(quarry_self_3373b52)['get_data'](quarry_rva_9c05383, _name_boundary.attributes(quarry_Structure(quarry_self_3373b52.__IMAGE_EXPORT_DIRECTORY_format__))['sizeof']()), file_offset=_name_boundary.attributes(quarry_self_3373b52)['get_offset_from_rva'](quarry_rva_9c05383))
        except quarry_PEFormatError:
            _name_boundary.attributes(quarry_self_3373b52)['__warnings'].append(f'Error parsing export directory at RVA: {quarry_rva_9c05383:#x}')
            return None
        if not quarry_export_dir_bdfd7be:
            return None

        @_name_boundary.callable_contract({'rva': 'quarry_rva_46ca5b1'}, 'length_until_eof')
        def quarry_length_until_eof_08a8669(quarry_rva_46ca5b1):
            return len(quarry_self_3373b52.__data__) - _name_boundary.attributes(quarry_self_3373b52)['get_offset_from_rva'](quarry_rva_46ca5b1)
        try:
            quarry_address_of_names_0d84cc7 = _name_boundary.attributes(quarry_self_3373b52)['get_data'](quarry_export_dir_bdfd7be.AddressOfNames, min(quarry_length_until_eof_08a8669(quarry_export_dir_bdfd7be.AddressOfNames), quarry_export_dir_bdfd7be.NumberOfNames * 4))
            quarry_address_of_name_ordinals_7de43f1 = _name_boundary.attributes(quarry_self_3373b52)['get_data'](quarry_export_dir_bdfd7be.AddressOfNameOrdinals, min(quarry_length_until_eof_08a8669(quarry_export_dir_bdfd7be.AddressOfNameOrdinals), quarry_export_dir_bdfd7be.NumberOfNames * 4))
            quarry_address_of_functions_0e6868f = _name_boundary.attributes(quarry_self_3373b52)['get_data'](quarry_export_dir_bdfd7be.AddressOfFunctions, min(quarry_length_until_eof_08a8669(quarry_export_dir_bdfd7be.AddressOfFunctions), quarry_export_dir_bdfd7be.NumberOfFunctions * 4))
        except quarry_PEFormatError:
            _name_boundary.attributes(quarry_self_3373b52)['__warnings'].append(f'Error parsing export directory at RVA: {quarry_rva_9c05383:#x}')
            return None
        quarry_exports_95bb75e = []
        quarry_max_failed_entries_before_giving_up_00d59bf = 10
        quarry_section_a8ae128 = _name_boundary.attributes(quarry_self_3373b52)['get_section_by_rva'](quarry_export_dir_bdfd7be.AddressOfNames)
        quarry_safety_boundary_992776b = len(quarry_self_3373b52.__data__)
        if quarry_section_a8ae128:
            quarry_safety_boundary_992776b = quarry_section_a8ae128.VirtualAddress + len(_name_boundary.attributes(quarry_section_a8ae128)['get_data']()) - quarry_export_dir_bdfd7be.AddressOfNames
        quarry_symbol_counts_105e785 = quarry_defaultdict(int)
        quarry_export_parsing_loop_completed_normally_74a9a56 = True
        for quarry_i_4ee4268 in range(min(quarry_export_dir_bdfd7be.NumberOfNames, int(quarry_safety_boundary_992776b / 4))):
            quarry_symbol_ordinal_6c0d3ec = _name_boundary.attributes(quarry_self_3373b52)['get_word_from_data'](quarry_address_of_name_ordinals_7de43f1, quarry_i_4ee4268)
            if quarry_symbol_ordinal_6c0d3ec is not None and quarry_symbol_ordinal_6c0d3ec * 4 < len(quarry_address_of_functions_0e6868f):
                quarry_symbol_address_61000de = _name_boundary.attributes(quarry_self_3373b52)['get_dword_from_data'](quarry_address_of_functions_0e6868f, quarry_symbol_ordinal_6c0d3ec)
            else:
                return None
            if quarry_symbol_address_61000de is None or quarry_symbol_address_61000de == 0:
                continue
            if quarry_rva_9c05383 <= quarry_symbol_address_61000de < quarry_rva_9c05383 + quarry_size_local_9b99bc9:
                quarry_forwarder_str_35e36df = _name_boundary.attributes(quarry_self_3373b52)['get_string_at_rva'](quarry_symbol_address_61000de)
                try:
                    quarry_forwarder_offset_35f05a8 = _name_boundary.attributes(quarry_self_3373b52)['get_offset_from_rva'](quarry_symbol_address_61000de)
                except quarry_PEFormatError:
                    continue
            else:
                if quarry_forwarded_only_e9c126f:
                    continue
                quarry_forwarder_str_35e36df = None
                quarry_forwarder_offset_35f05a8 = None
            quarry_symbol_name_address_c7c432f = _name_boundary.attributes(quarry_self_3373b52)['get_dword_from_data'](quarry_address_of_names_0d84cc7, quarry_i_4ee4268)
            if quarry_symbol_name_address_c7c432f is None:
                quarry_max_failed_entries_before_giving_up_00d59bf -= 1
                if quarry_max_failed_entries_before_giving_up_00d59bf <= 0:
                    quarry_export_parsing_loop_completed_normally_74a9a56 = False
                    break
            quarry_symbol_name_ec82707 = _name_boundary.attributes(quarry_self_3373b52)['get_string_at_rva'](quarry_symbol_name_address_c7c432f, quarry_MAX_SYMBOL_NAME_LENGTH)
            if not quarry_is_valid_function_name(quarry_symbol_name_ec82707, relax_allowed_characters=True):
                quarry_export_parsing_loop_completed_normally_74a9a56 = False
                break
            try:
                quarry_symbol_name_offset_a016dfe = _name_boundary.attributes(quarry_self_3373b52)['get_offset_from_rva'](quarry_symbol_name_address_c7c432f)
            except quarry_PEFormatError:
                quarry_max_failed_entries_before_giving_up_00d59bf -= 1
                if quarry_max_failed_entries_before_giving_up_00d59bf <= 0:
                    quarry_export_parsing_loop_completed_normally_74a9a56 = False
                    break
                try:
                    quarry_symbol_name_offset_a016dfe = _name_boundary.attributes(quarry_self_3373b52)['get_offset_from_rva'](quarry_symbol_name_address_c7c432f)
                except quarry_PEFormatError:
                    quarry_max_failed_entries_before_giving_up_00d59bf -= 1
                    if quarry_max_failed_entries_before_giving_up_00d59bf <= 0:
                        quarry_export_parsing_loop_completed_normally_74a9a56 = False
                        break
                    continue
            quarry_symbol_counts_105e785[quarry_symbol_name_ec82707, quarry_symbol_address_61000de] += 1
            if quarry_symbol_counts_105e785[quarry_symbol_name_ec82707, quarry_symbol_address_61000de] > 10:
                _name_boundary.attributes(quarry_self_3373b52)['__warnings'].append(f'Export directory contains more than 10 repeated entries ({quarry_symbol_name_ec82707}, {quarry_symbol_address_61000de:#02x}). Assuming corrupt.')
                break
            elif len(quarry_symbol_counts_105e785) > _name_boundary.attributes(quarry_self_3373b52)['max_symbol_exports']:
                _name_boundary.attributes(quarry_self_3373b52)['__warnings'].append(f"Export directory contains more than {_name_boundary.attributes(quarry_self_3373b52)['max_symbol_exports']} symbol entries. Assuming corrupt.")
                break
            quarry_exports_95bb75e.append(quarry_ExportData(pe=quarry_self_3373b52, ordinal=quarry_export_dir_bdfd7be.Base + quarry_symbol_ordinal_6c0d3ec, ordinal_offset=_name_boundary.attributes(quarry_self_3373b52)['get_offset_from_rva'](quarry_export_dir_bdfd7be.AddressOfNameOrdinals + 2 * quarry_i_4ee4268), address=quarry_symbol_address_61000de, address_offset=_name_boundary.attributes(quarry_self_3373b52)['get_offset_from_rva'](quarry_export_dir_bdfd7be.AddressOfFunctions + 4 * quarry_symbol_ordinal_6c0d3ec), name=quarry_symbol_name_ec82707, name_offset=quarry_symbol_name_offset_a016dfe, forwarder=quarry_forwarder_str_35e36df, forwarder_offset=quarry_forwarder_offset_35f05a8))
        if not quarry_export_parsing_loop_completed_normally_74a9a56:
            _name_boundary.attributes(quarry_self_3373b52)['__warnings'].append(f'RVA AddressOfNames in the export directory points to an invalid address: {quarry_export_dir_bdfd7be.AddressOfNames:x}')
        quarry_ordinals_bd4a0f0 = {quarry_exp_a6daba7.ordinal for quarry_exp_a6daba7 in quarry_exports_95bb75e}
        quarry_max_failed_entries_before_giving_up_00d59bf = 10
        quarry_section_a8ae128 = _name_boundary.attributes(quarry_self_3373b52)['get_section_by_rva'](quarry_export_dir_bdfd7be.AddressOfFunctions)
        quarry_safety_boundary_992776b = len(quarry_self_3373b52.__data__)
        if quarry_section_a8ae128:
            quarry_safety_boundary_992776b = quarry_section_a8ae128.VirtualAddress + len(_name_boundary.attributes(quarry_section_a8ae128)['get_data']()) - quarry_export_dir_bdfd7be.AddressOfFunctions
        quarry_symbol_counts_105e785 = quarry_defaultdict(int)
        quarry_export_parsing_loop_completed_normally_74a9a56 = True
        for quarry_idx_53203d2 in range(min(quarry_export_dir_bdfd7be.NumberOfFunctions, int(quarry_safety_boundary_992776b / 4))):
            if quarry_idx_53203d2 + quarry_export_dir_bdfd7be.Base not in quarry_ordinals_bd4a0f0:
                try:
                    quarry_symbol_address_61000de = _name_boundary.attributes(quarry_self_3373b52)['get_dword_from_data'](quarry_address_of_functions_0e6868f, quarry_idx_53203d2)
                except quarry_PEFormatError:
                    quarry_symbol_address_61000de = None
                if quarry_symbol_address_61000de is None:
                    quarry_max_failed_entries_before_giving_up_00d59bf -= 1
                    if quarry_max_failed_entries_before_giving_up_00d59bf <= 0:
                        quarry_export_parsing_loop_completed_normally_74a9a56 = False
                        break
                if quarry_symbol_address_61000de == 0:
                    continue
                if quarry_symbol_address_61000de is not None and quarry_rva_9c05383 <= quarry_symbol_address_61000de < quarry_rva_9c05383 + quarry_size_local_9b99bc9:
                    quarry_forwarder_str_35e36df = _name_boundary.attributes(quarry_self_3373b52)['get_string_at_rva'](quarry_symbol_address_61000de)
                else:
                    quarry_forwarder_str_35e36df = None
                quarry_symbol_counts_105e785[quarry_symbol_address_61000de] += 1
                if quarry_symbol_counts_105e785[quarry_symbol_address_61000de] > _name_boundary.attributes(quarry_self_3373b52)['max_repeated_symbol']:
                    _name_boundary.attributes(quarry_self_3373b52)['__warnings'].append(f"Export directory contains more than {_name_boundary.attributes(quarry_self_3373b52)['max_repeated_symbol']} repeated ordinal entries ({quarry_symbol_address_61000de:#x}). Assuming corrupt.")
                    break
                elif len(quarry_symbol_counts_105e785) > _name_boundary.attributes(quarry_self_3373b52)['max_symbol_exports']:
                    _name_boundary.attributes(quarry_self_3373b52)['__warnings'].append(f"Export directory contains more than {_name_boundary.attributes(quarry_self_3373b52)['max_symbol_exports']} ordinal entries. Assuming corrupt.")
                    break
                quarry_exports_95bb75e.append(quarry_ExportData(ordinal=quarry_export_dir_bdfd7be.Base + quarry_idx_53203d2, address=quarry_symbol_address_61000de, name=None, forwarder=quarry_forwarder_str_35e36df))
        if not quarry_export_parsing_loop_completed_normally_74a9a56:
            _name_boundary.attributes(quarry_self_3373b52)['__warnings'].append(f'RVA AddressOfFunctions in the export directory points to an invalid address: {quarry_export_dir_bdfd7be.AddressOfFunctions:x}')
            return None
        if not quarry_exports_95bb75e and _name_boundary.attributes(quarry_export_dir_bdfd7be)['all_zeroes']():
            return None
        return quarry_ExportDirData(struct=quarry_export_dir_bdfd7be, symbols=quarry_exports_95bb75e, name=_name_boundary.attributes(quarry_self_3373b52)['get_string_at_rva'](quarry_export_dir_bdfd7be.Name))

    @staticmethod
    @_name_boundary.callable_contract({'base': 'quarry_base_f8d9db3', 'offset': 'quarry_offset_local_e1578c5'}, 'dword_align')
    def quarry_dword_align(quarry_offset_local_e1578c5, quarry_base_f8d9db3):
        return (quarry_offset_local_e1578c5 + quarry_base_f8d9db3 + 3 & 4294967292) - (quarry_base_f8d9db3 & 4294967292)

    @_name_boundary.callable_contract({'self': 'quarry_self_419cab4', 'va': 'quarry_va_0575f30'}, 'normalize_import_va')
    def quarry_normalize_import_va(quarry_self_419cab4, quarry_va_0575f30):
        quarry_begin_of_image_e8c6b9e = _name_boundary.attributes(quarry_self_419cab4)['OPTIONAL_HEADER'].ImageBase
        quarry_end_of_image_c69ce41 = _name_boundary.attributes(quarry_self_419cab4)['OPTIONAL_HEADER'].ImageBase + _name_boundary.attributes(quarry_self_419cab4)['OPTIONAL_HEADER'].SizeOfImage
        if quarry_begin_of_image_e8c6b9e <= quarry_va_0575f30 < quarry_end_of_image_c69ce41:
            quarry_va_0575f30 -= quarry_begin_of_image_e8c6b9e
        return quarry_va_0575f30

    @_name_boundary.callable_contract({'self': 'quarry_self_6de4e75', 'rva': 'quarry_rva_d32ce71', 'size': 'quarry_size_local_73a0b02'}, 'parse_delay_import_directory')
    def quarry_parse_delay_import_directory(quarry_self_6de4e75, quarry_rva_d32ce71, quarry_size_local_73a0b02):
        """Walk and parse the delay import directory."""
        quarry_import_descs_df4ac24 = []
        quarry_error_count_38ac845 = 0
        while True:
            try:
                quarry_data_local_906d22f = _name_boundary.attributes(quarry_self_6de4e75)['get_data'](quarry_rva_d32ce71, _name_boundary.attributes(quarry_Structure(quarry_self_6de4e75.__IMAGE_DELAY_IMPORT_DESCRIPTOR_format__))['sizeof']())
            except quarry_PEFormatError:
                _name_boundary.attributes(quarry_self_6de4e75)['__warnings'].append(f'Error parsing the Delay import directory at RVA: {quarry_rva_d32ce71:#x}')
                break
            quarry_file_offset_6f9d3e9 = _name_boundary.attributes(quarry_self_6de4e75)['get_offset_from_rva'](quarry_rva_d32ce71)
            quarry_import_desc_ba0e10f = quarry_self_6de4e75.__unpack_data__(quarry_self_6de4e75.__IMAGE_DELAY_IMPORT_DESCRIPTOR_format__, quarry_data_local_906d22f, file_offset=quarry_file_offset_6f9d3e9)
            if not quarry_import_desc_ba0e10f or _name_boundary.attributes(quarry_import_desc_ba0e10f)['all_zeroes']():
                break
            quarry_contains_addresses_3152bd0 = False
            if quarry_import_desc_ba0e10f.grAttrs == 0 and _name_boundary.attributes(quarry_self_6de4e75)['FILE_HEADER'].Machine == quarry_MACHINE_TYPE['IMAGE_FILE_MACHINE_I386']:
                quarry_import_desc_ba0e10f.pBoundIAT = _name_boundary.attributes(quarry_self_6de4e75)['normalize_import_va'](quarry_import_desc_ba0e10f.pBoundIAT)
                quarry_import_desc_ba0e10f.pIAT = _name_boundary.attributes(quarry_self_6de4e75)['normalize_import_va'](quarry_import_desc_ba0e10f.pIAT)
                quarry_import_desc_ba0e10f.pINT = _name_boundary.attributes(quarry_self_6de4e75)['normalize_import_va'](quarry_import_desc_ba0e10f.pINT)
                quarry_import_desc_ba0e10f.pUnloadIAT = _name_boundary.attributes(quarry_self_6de4e75)['normalize_import_va'](quarry_import_desc_ba0e10f.pUnloadIAT)
                quarry_import_desc_ba0e10f.phmod = _name_boundary.attributes(quarry_self_6de4e75)['normalize_import_va'](quarry_import_desc_ba0e10f.pUnloadIAT)
                quarry_import_desc_ba0e10f.szName = _name_boundary.attributes(quarry_self_6de4e75)['normalize_import_va'](quarry_import_desc_ba0e10f.szName)
                quarry_contains_addresses_3152bd0 = True
            quarry_rva_d32ce71 += _name_boundary.attributes(quarry_import_desc_ba0e10f)['sizeof']()
            quarry_max_len_ebad11f = len(quarry_self_6de4e75.__data__) - quarry_file_offset_6f9d3e9
            if quarry_rva_d32ce71 > quarry_import_desc_ba0e10f.pINT or quarry_rva_d32ce71 > quarry_import_desc_ba0e10f.pIAT:
                quarry_max_len_ebad11f = max(quarry_rva_d32ce71 - quarry_import_desc_ba0e10f.pINT, quarry_rva_d32ce71 - quarry_import_desc_ba0e10f.pIAT)
            quarry_import_data_4becdd7 = []
            try:
                quarry_import_data_4becdd7 = _name_boundary.attributes(quarry_self_6de4e75)['parse_imports'](quarry_import_desc_ba0e10f.pINT, quarry_import_desc_ba0e10f.pIAT, None, quarry_max_len_ebad11f, quarry_contains_addresses_3152bd0)
            except quarry_PEFormatError as quarry_excp_b127b88:
                _name_boundary.attributes(quarry_self_6de4e75)['__warnings'].append(f"Error parsing the Delay import directory. Invalid import data at RVA: {quarry_rva_d32ce71:#x} ({_name_boundary.attributes(quarry_excp_b127b88)['value']})")
            if quarry_error_count_38ac845 > 5:
                _name_boundary.attributes(quarry_self_6de4e75)['__warnings'].append(f'Too many errors parsing the Delay import directory. Invalid import data at RVA: {quarry_rva_d32ce71:#x}')
                break
            if not quarry_import_data_4becdd7:
                quarry_error_count_38ac845 += 1
                continue
            if _name_boundary.attributes(quarry_self_6de4e75)['__total_import_symbols'] > quarry_MAX_IMPORT_SYMBOLS:
                _name_boundary.attributes(quarry_self_6de4e75)['__warnings'].append(f"Error, too many imported symbols {_name_boundary.attributes(quarry_self_6de4e75)['__total_import_symbols']} (>{quarry_MAX_IMPORT_SYMBOLS})")
                break
            quarry_dll_7319470 = _name_boundary.attributes(quarry_self_6de4e75)['get_string_at_rva'](quarry_import_desc_ba0e10f.szName, quarry_MAX_DLL_LENGTH)
            if not quarry_is_valid_dos_filename(quarry_dll_7319470):
                quarry_dll_7319470 = b'*invalid*'
            if quarry_dll_7319470:
                for quarry_symbol_07649f9 in quarry_import_data_4becdd7:
                    if quarry_symbol_07649f9.name is None:
                        quarry_funcname_068ac43 = quarry_ordlookup.ordinal_lookup(quarry_dll_7319470.lower(), quarry_symbol_07649f9.ordinal)
                        if quarry_funcname_068ac43:
                            quarry_symbol_07649f9.name = quarry_funcname_068ac43
                            quarry_symbol_07649f9.name_from_ordinal = True
                quarry_import_descs_df4ac24.append(quarry_ImportDescData(struct=quarry_import_desc_ba0e10f, imports=quarry_import_data_4becdd7, dll=quarry_dll_7319470))
        return quarry_import_descs_df4ac24

    @_name_boundary.callable_contract({'self': 'quarry_self_bba07f6', 'algorithm': 'quarry_algorithm_5e645a8'}, 'get_rich_header_hash')
    def quarry_get_rich_header_hash(quarry_self_bba07f6, quarry_algorithm_5e645a8='md5'):
        if not _name_boundary.has_attribute(quarry_self_bba07f6, 'RICH_HEADER') or _name_boundary.attributes(quarry_self_bba07f6)['RICH_HEADER'] is None:
            return ''
        if quarry_algorithm_5e645a8 == 'md5':
            return quarry_md5(_name_boundary.attributes(quarry_self_bba07f6)['RICH_HEADER'].clear_data).hexdigest()
        elif quarry_algorithm_5e645a8 == 'sha1':
            return quarry_sha1(_name_boundary.attributes(quarry_self_bba07f6)['RICH_HEADER'].clear_data).hexdigest()
        elif quarry_algorithm_5e645a8 == 'sha256':
            return quarry_sha256(_name_boundary.attributes(quarry_self_bba07f6)['RICH_HEADER'].clear_data).hexdigest()
        elif quarry_algorithm_5e645a8 == 'sha512':
            return quarry_sha512(_name_boundary.attributes(quarry_self_bba07f6)['RICH_HEADER'].clear_data).hexdigest()
        raise Exception('Invalid hashing algorithm specified')

    @_name_boundary.callable_contract({'self': 'quarry_self_55d3d5b', 'usedforsecurity': 'quarry_usedforsecurity_6b3526b'}, 'get_imphash')
    def quarry_get_imphash(quarry_self_55d3d5b, quarry_usedforsecurity_6b3526b=True):
        """Return the imphash of the PE file.

        Creates a hash based on imported symbol names and their specific order within
        the executable:
        https://cloud.google.com/blog/topics/threat-intelligence/tracking-malware-import-hashing/

        Returns:
            The hexdigest of the MD5 hash of the exported symbols.
        """
        quarry_impstrs_eeb6a88 = []
        quarry_exts_7a10a73 = ['ocx', 'sys', 'dll']
        if not _name_boundary.has_attribute(quarry_self_55d3d5b, 'DIRECTORY_ENTRY_IMPORT'):
            return ''
        for quarry_entry_9013672 in quarry_self_55d3d5b.DIRECTORY_ENTRY_IMPORT:
            if isinstance(quarry_entry_9013672.dll, bytes):
                quarry_libname_7b1cbd6 = _name_boundary.attributes(quarry_entry_9013672.dll)['decode']().lower()
            else:
                quarry_libname_7b1cbd6 = quarry_entry_9013672.dll.lower()
            quarry_parts_cab91be = quarry_libname_7b1cbd6.rsplit('.', 1)
            if len(quarry_parts_cab91be) > 1 and quarry_parts_cab91be[1] in quarry_exts_7a10a73:
                quarry_libname_7b1cbd6 = quarry_parts_cab91be[0]
            quarry_entry_dll_lower_cd86ce9 = quarry_entry_9013672.dll.lower()
            for quarry_imp_5fb0174 in quarry_entry_9013672.imports:
                if not quarry_imp_5fb0174.name or _name_boundary.read_attribute(quarry_imp_5fb0174, 'name_from_ordinal', False):
                    quarry_funcname_dea8e76 = quarry_ordlookup.imphash_ordinal_lookup(quarry_entry_dll_lower_cd86ce9, quarry_imp_5fb0174.ordinal, make_name=True)
                    if not quarry_funcname_dea8e76:
                        raise quarry_PEFormatError(f'Unable to look up ordinal {quarry_entry_9013672.dll}:{quarry_imp_5fb0174.ordinal:04x}')
                else:
                    quarry_funcname_dea8e76 = quarry_imp_5fb0174.name
                if not quarry_funcname_dea8e76:
                    continue
                if isinstance(quarry_funcname_dea8e76, bytes):
                    quarry_funcname_dea8e76 = _name_boundary.attributes(quarry_funcname_dea8e76)['decode']()
                quarry_impstrs_eeb6a88.append(f'{quarry_libname_7b1cbd6.lower()}.{quarry_funcname_dea8e76.lower()}')
        return quarry_md5(','.join(quarry_impstrs_eeb6a88).encode(), usedforsecurity=quarry_usedforsecurity_6b3526b).hexdigest()

    @_name_boundary.callable_contract({'self': 'quarry_self_8ebb6c3'}, 'get_exphash')
    def quarry_get_exphash(quarry_self_8ebb6c3):
        """Return the exphash of the PE file.

        Similar to imphash, but based on exported symbol names and their specific order.

        Returns:
            The hexdigest of the MD5 hash of the exported symbols.
        """
        if not _name_boundary.has_attribute(quarry_self_8ebb6c3, 'DIRECTORY_ENTRY_EXPORT'):
            return ''
        if not _name_boundary.has_attribute(quarry_self_8ebb6c3.DIRECTORY_ENTRY_EXPORT, 'symbols'):
            return ''
        quarry_export_list_04fa27d = [_name_boundary.attributes(quarry_e_587461d.name)['decode']().lower() for quarry_e_587461d in quarry_self_8ebb6c3.DIRECTORY_ENTRY_EXPORT.symbols if quarry_e_587461d and quarry_e_587461d.name is not None]
        if len(quarry_export_list_04fa27d) == 0:
            return ''
        return quarry_md5(','.join(quarry_export_list_04fa27d).encode()).hexdigest()

    @_name_boundary.callable_contract({'self': 'quarry_self_4db832b', 'rva': 'quarry_rva_183ce1d', 'dllnames_only': 'quarry_dllnames_only_76a7e8d', 'size': 'quarry_size_local_c52e51e'}, 'parse_import_directory')
    def quarry_parse_import_directory(quarry_self_4db832b, quarry_rva_183ce1d, quarry_size_local_c52e51e, quarry_dllnames_only_76a7e8d=False):
        """Walk and parse the import directory."""
        quarry_import_descs_35c0fd6 = []
        quarry_error_count_17e16c1 = 0
        quarry_image_import_descriptor_size_7cf4e14 = _name_boundary.attributes(quarry_Structure(quarry_self_4db832b.__IMAGE_IMPORT_DESCRIPTOR_format__))['sizeof']()
        while True:
            try:
                quarry_data_local_e78460d = _name_boundary.attributes(quarry_self_4db832b)['get_data'](quarry_rva_183ce1d, quarry_image_import_descriptor_size_7cf4e14)
            except quarry_PEFormatError:
                _name_boundary.attributes(quarry_self_4db832b)['__warnings'].append(f'Error parsing the import directory at RVA: {quarry_rva_183ce1d:#x}')
                break
            quarry_file_offset_a360753 = _name_boundary.attributes(quarry_self_4db832b)['get_offset_from_rva'](quarry_rva_183ce1d)
            quarry_import_desc_4081dfc = quarry_self_4db832b.__unpack_data__(quarry_self_4db832b.__IMAGE_IMPORT_DESCRIPTOR_format__, quarry_data_local_e78460d, file_offset=quarry_file_offset_a360753)
            if not quarry_import_desc_4081dfc or _name_boundary.attributes(quarry_import_desc_4081dfc)['all_zeroes']():
                break
            quarry_rva_183ce1d += _name_boundary.attributes(quarry_import_desc_4081dfc)['sizeof']()
            quarry_max_len_b02e64b = len(quarry_self_4db832b.__data__) - quarry_file_offset_a360753
            if quarry_rva_183ce1d > quarry_import_desc_4081dfc.OriginalFirstThunk or quarry_rva_183ce1d > quarry_import_desc_4081dfc.FirstThunk:
                quarry_max_len_b02e64b = max(quarry_rva_183ce1d - quarry_import_desc_4081dfc.OriginalFirstThunk, quarry_rva_183ce1d - quarry_import_desc_4081dfc.FirstThunk)
            quarry_import_data_bae2e00 = []
            if not quarry_dllnames_only_76a7e8d:
                try:
                    quarry_import_data_bae2e00 = _name_boundary.attributes(quarry_self_4db832b)['parse_imports'](quarry_import_desc_4081dfc.OriginalFirstThunk, quarry_import_desc_4081dfc.FirstThunk, quarry_import_desc_4081dfc.ForwarderChain, max_length=quarry_max_len_b02e64b)
                except quarry_PEFormatError as quarry_e_d26632e:
                    _name_boundary.attributes(quarry_self_4db832b)['__warnings'].append(f"Error parsing the import directory. Invalid Import data at RVA: {quarry_rva_183ce1d:#x} ({_name_boundary.attributes(quarry_e_d26632e)['value']})")
                if quarry_error_count_17e16c1 > 5:
                    _name_boundary.attributes(quarry_self_4db832b)['__warnings'].append(f'Too many errors parsing the import directory. Invalid import data at RVA: {quarry_rva_183ce1d:#x}')
                    break
                if not quarry_import_data_bae2e00:
                    quarry_error_count_17e16c1 += 1
                    continue
            quarry_dll_cd9a1d8 = _name_boundary.attributes(quarry_self_4db832b)['get_string_at_rva'](quarry_import_desc_4081dfc.Name, quarry_MAX_DLL_LENGTH)
            if not quarry_is_valid_dos_filename(quarry_dll_cd9a1d8):
                quarry_dll_cd9a1d8 = b'*invalid*'
            if quarry_dll_cd9a1d8:
                for quarry_symbol_56211fb in quarry_import_data_bae2e00:
                    if quarry_symbol_56211fb.name is None:
                        quarry_funcname_b2c614c = quarry_ordlookup.ordinal_lookup(quarry_dll_cd9a1d8.lower(), quarry_symbol_56211fb.ordinal)
                        if quarry_funcname_b2c614c:
                            quarry_symbol_56211fb.name = quarry_funcname_b2c614c
                            quarry_symbol_56211fb.name_from_ordinal = True
                quarry_import_descs_35c0fd6.append(quarry_ImportDescData(struct=quarry_import_desc_4081dfc, imports=quarry_import_data_bae2e00, dll=quarry_dll_cd9a1d8))
        if not quarry_dllnames_only_76a7e8d:
            quarry_suspicious_imports_fb373da = {'LoadLibrary', 'GetProcAddress'}
            quarry_suspicious_imports_count_932ed8a = 0
            quarry_total_symbols_8d920cc = 0
            for quarry_imp_dll_8b0452b in quarry_import_descs_35c0fd6:
                for quarry_symbol_56211fb in quarry_imp_dll_8b0452b.imports:
                    for quarry_suspicious_symbol_1f93460 in quarry_suspicious_imports_fb373da:
                        if not quarry_symbol_56211fb or not quarry_symbol_56211fb.name:
                            continue
                        quarry_name_local_8ab1a24 = quarry_symbol_56211fb.name
                        if isinstance(quarry_symbol_56211fb.name, bytes):
                            quarry_name_local_8ab1a24 = _name_boundary.attributes(quarry_symbol_56211fb.name)['decode']('utf-8')
                        if quarry_name_local_8ab1a24.startswith(quarry_suspicious_symbol_1f93460):
                            quarry_suspicious_imports_count_932ed8a += 1
                            break
                    quarry_total_symbols_8d920cc += 1
            if quarry_suspicious_imports_count_932ed8a == len(quarry_suspicious_imports_fb373da) and quarry_total_symbols_8d920cc < 20:
                _name_boundary.attributes(quarry_self_4db832b)['__warnings'].append('Imported symbols contain entries typical of packed executables.')
        return quarry_import_descs_35c0fd6

    @_name_boundary.callable_contract({'self': 'quarry_self_20cbf72', 'original_first_thunk': 'quarry_original_first_thunk_9ee1a40', 'first_thunk': 'quarry_first_thunk_06b9c41', 'forwarder_chain': 'quarry_forwarder_chain_81b9857', 'max_length': 'quarry_max_length_c40e0b5', 'contains_addresses': 'quarry_contains_addresses_e8216c5'}, 'parse_imports')
    def quarry_parse_imports(quarry_self_20cbf72, quarry_original_first_thunk_9ee1a40, quarry_first_thunk_06b9c41, quarry_forwarder_chain_81b9857, quarry_max_length_c40e0b5=None, quarry_contains_addresses_e8216c5=False):
        """Parse the imported symbols.

        It will fill a list, which will be available as the dictionary
        attribute "imports". Its keys will be the DLL names and the values
        of all the symbols imported from that object.
        """
        quarry_imported_symbols_3e23648 = []
        quarry_ilt_2502f30 = _name_boundary.attributes(quarry_self_20cbf72)['get_import_table'](quarry_original_first_thunk_9ee1a40, quarry_max_length_c40e0b5, quarry_contains_addresses_e8216c5)
        quarry_iat_ea2c715 = _name_boundary.attributes(quarry_self_20cbf72)['get_import_table'](quarry_first_thunk_06b9c41, quarry_max_length_c40e0b5, quarry_contains_addresses_e8216c5)
        if not quarry_iat_ea2c715 and (not quarry_ilt_2502f30):
            _name_boundary.attributes(quarry_self_20cbf72)['__warnings'].append(f'Damaged Import Table information. ILT and/or IAT appear to be broken. OriginalFirstThunk: {quarry_original_first_thunk_9ee1a40:#x} FirstThunk: {quarry_first_thunk_06b9c41:#x}')
            return []
        if quarry_ilt_2502f30:
            quarry_table_fd525fe = quarry_ilt_2502f30
        elif quarry_iat_ea2c715:
            quarry_table_fd525fe = quarry_iat_ea2c715
        else:
            return None
        quarry_imp_offset_538fecc = 4
        quarry_address_mask_3a2ed20 = 2147483647
        if _name_boundary.attributes(quarry_self_20cbf72)['PE_TYPE'] == quarry_OPTIONAL_HEADER_MAGIC_PE:
            quarry_ordinal_flag_ee8ce89 = quarry_IMAGE_ORDINAL_FLAG
        elif _name_boundary.attributes(quarry_self_20cbf72)['PE_TYPE'] == quarry_OPTIONAL_HEADER_MAGIC_PE_PLUS:
            quarry_ordinal_flag_ee8ce89 = quarry_IMAGE_ORDINAL_FLAG64
            quarry_imp_offset_538fecc = 8
            quarry_address_mask_3a2ed20 = 9223372036854775807
        else:
            quarry_ordinal_flag_ee8ce89 = quarry_IMAGE_ORDINAL_FLAG
        quarry_num_invalid_d17bdc8 = 0
        for quarry_idx_3729d99, quarry_tbl_entry_4b39f46 in enumerate(quarry_table_fd525fe):
            quarry_imp_ord_9be0e79 = None
            quarry_imp_hint_e1fdc81 = None
            quarry_imp_name_4346f57 = None
            quarry_name_offset_220cc61 = None
            quarry_hint_name_table_rva_397b57f = None
            quarry_import_by_ordinal_bbf310c = False
            if quarry_tbl_entry_4b39f46.AddressOfData:
                if quarry_tbl_entry_4b39f46.AddressOfData & quarry_ordinal_flag_ee8ce89:
                    quarry_import_by_ordinal_bbf310c = True
                    quarry_imp_ord_9be0e79 = quarry_tbl_entry_4b39f46.AddressOfData & 65535
                    quarry_imp_name_4346f57 = None
                    quarry_name_offset_220cc61 = None
                else:
                    quarry_import_by_ordinal_bbf310c = False
                    try:
                        quarry_hint_name_table_rva_397b57f = quarry_tbl_entry_4b39f46.AddressOfData & quarry_address_mask_3a2ed20
                        quarry_data_local_4a11602 = _name_boundary.attributes(quarry_self_20cbf72)['get_data'](quarry_hint_name_table_rva_397b57f, 2)
                        quarry_imp_hint_e1fdc81 = _name_boundary.attributes(quarry_self_20cbf72)['get_word_from_data'](quarry_data_local_4a11602, 0)
                        quarry_imp_name_4346f57 = _name_boundary.attributes(quarry_self_20cbf72)['get_string_at_rva'](quarry_tbl_entry_4b39f46.AddressOfData + 2, quarry_MAX_IMPORT_NAME_LENGTH)
                        if not quarry_is_valid_function_name(quarry_imp_name_4346f57):
                            quarry_imp_name_4346f57 = b'*invalid*'
                        quarry_name_offset_220cc61 = _name_boundary.attributes(quarry_self_20cbf72)['get_offset_from_rva'](quarry_tbl_entry_4b39f46.AddressOfData + 2)
                    except quarry_PEFormatError:
                        pass
                quarry_thunk_offset_681b5f5 = _name_boundary.attributes(quarry_tbl_entry_4b39f46)['get_file_offset']()
                quarry_thunk_rva_d3abcc3 = _name_boundary.attributes(quarry_self_20cbf72)['get_rva_from_offset'](quarry_thunk_offset_681b5f5)
            quarry_imp_address_e69071e = quarry_first_thunk_06b9c41 + _name_boundary.attributes(quarry_self_20cbf72)['OPTIONAL_HEADER'].ImageBase + quarry_idx_3729d99 * quarry_imp_offset_538fecc
            quarry_struct_iat_3fad5d0 = None
            try:
                if quarry_iat_ea2c715 and quarry_ilt_2502f30 and (quarry_ilt_2502f30[quarry_idx_3729d99].AddressOfData != quarry_iat_ea2c715[quarry_idx_3729d99].AddressOfData):
                    quarry_imp_bound_11cb083 = quarry_iat_ea2c715[quarry_idx_3729d99].AddressOfData
                    quarry_struct_iat_3fad5d0 = quarry_iat_ea2c715[quarry_idx_3729d99]
                else:
                    quarry_imp_bound_11cb083 = None
            except IndexError:
                quarry_imp_bound_11cb083 = None
            if quarry_imp_ord_9be0e79 is None and quarry_imp_name_4346f57 is None:
                raise quarry_PEFormatError('Invalid entries, aborting parsing.')
            if quarry_imp_name_4346f57 == b'*invalid*':
                if quarry_num_invalid_d17bdc8 > 1000 and quarry_num_invalid_d17bdc8 == quarry_idx_3729d99:
                    raise quarry_PEFormatError('Too many invalid names, aborting parsing.')
                quarry_num_invalid_d17bdc8 += 1
                continue
            if quarry_imp_ord_9be0e79 or quarry_imp_name_4346f57:
                quarry_imported_symbols_3e23648.append(quarry_ImportData(pe=quarry_self_20cbf72, struct_table=quarry_tbl_entry_4b39f46, struct_iat=quarry_struct_iat_3fad5d0, import_by_ordinal=quarry_import_by_ordinal_bbf310c, ordinal=quarry_imp_ord_9be0e79, ordinal_offset=_name_boundary.attributes(quarry_tbl_entry_4b39f46)['get_file_offset'](), hint=quarry_imp_hint_e1fdc81, name=quarry_imp_name_4346f57, name_offset=quarry_name_offset_220cc61, name_from_ordinal=False, bound=quarry_imp_bound_11cb083, address=quarry_imp_address_e69071e, hint_name_table_rva=quarry_hint_name_table_rva_397b57f, thunk_offset=quarry_thunk_offset_681b5f5, thunk_rva=quarry_thunk_rva_d3abcc3))
        return quarry_imported_symbols_3e23648

    @_name_boundary.callable_contract({'self': 'quarry_self_d946155', 'rva': 'quarry_rva_01b7646', 'max_length': 'quarry_max_length_4819d6a', 'contains_addresses': 'quarry_contains_addresses_7858e96'}, 'get_import_table')
    def quarry_get_import_table(quarry_self_d946155, quarry_rva_01b7646, quarry_max_length_4819d6a=None, quarry_contains_addresses_7858e96=False):
        if _name_boundary.attributes(quarry_self_d946155)['PE_TYPE'] == quarry_OPTIONAL_HEADER_MAGIC_PE:
            quarry_ordinal_flag_d55e08e = quarry_IMAGE_ORDINAL_FLAG
            quarry_format_ead9ddf = quarry_self_d946155.__IMAGE_THUNK_DATA_format__
        elif _name_boundary.attributes(quarry_self_d946155)['PE_TYPE'] == quarry_OPTIONAL_HEADER_MAGIC_PE_PLUS:
            quarry_ordinal_flag_d55e08e = quarry_IMAGE_ORDINAL_FLAG64
            quarry_format_ead9ddf = quarry_self_d946155.__IMAGE_THUNK_DATA64_format__
        else:
            quarry_ordinal_flag_d55e08e = quarry_IMAGE_ORDINAL_FLAG
            quarry_format_ead9ddf = quarry_self_d946155.__IMAGE_THUNK_DATA_format__
        quarry_expected_size_c90b29b = _name_boundary.attributes(quarry_Structure(quarry_format_ead9ddf))['sizeof']()
        quarry_MAX_ADDRESS_SPREAD_ace7390 = 128 * 2 ** 20
        quarry_ADDR_4GB_42c5d47 = 2 ** 32
        quarry_MAX_REPEATED_ADDRESSES_b9dfdd4 = 15
        quarry_repeated_address_2029542 = 0
        quarry_addresses_of_data_set_64_16eb336 = quarry_AddressSet()
        quarry_addresses_of_data_set_32_1901643 = quarry_AddressSet()
        quarry_start_rva_c1b8fad = quarry_rva_01b7646
        quarry_table_4e17b47 = []
        while quarry_rva_01b7646:
            if quarry_max_length_4819d6a is not None and quarry_rva_01b7646 >= quarry_start_rva_c1b8fad + quarry_max_length_4819d6a:
                _name_boundary.attributes(quarry_self_d946155)['__warnings'].append('Error parsing the import table. Entries go beyond bounds.')
                break
            if _name_boundary.attributes(quarry_self_d946155)['__total_import_symbols'] > quarry_MAX_IMPORT_SYMBOLS:
                _name_boundary.attributes(quarry_self_d946155)['__warnings'].append(f"Excessive number of imports {_name_boundary.attributes(quarry_self_d946155)['__total_import_symbols']} (>{quarry_MAX_IMPORT_SYMBOLS})")
                break
            _name_boundary.attributes(quarry_self_d946155)['__total_import_symbols'] += 1
            if quarry_repeated_address_2029542 >= quarry_MAX_REPEATED_ADDRESSES_b9dfdd4:
                return []
            if _name_boundary.attributes(quarry_addresses_of_data_set_32_1901643)['diff']() > quarry_MAX_ADDRESS_SPREAD_ace7390:
                return []
            if _name_boundary.attributes(quarry_addresses_of_data_set_64_16eb336)['diff']() > quarry_MAX_ADDRESS_SPREAD_ace7390:
                return []
            quarry_failed_5c05a71 = False
            try:
                quarry_data_local_762cd29 = _name_boundary.attributes(quarry_self_d946155)['get_data'](quarry_rva_01b7646, quarry_expected_size_c90b29b)
            except quarry_PEFormatError:
                quarry_failed_5c05a71 = True
            if quarry_failed_5c05a71 or len(quarry_data_local_762cd29) != quarry_expected_size_c90b29b:
                _name_boundary.attributes(quarry_self_d946155)['__warnings'].append(f'Error parsing the import table. Invalid data at RVA: {quarry_rva_01b7646:#x}')
                return None
            quarry_thunk_data_ab88169 = quarry_self_d946155.__unpack_data__(quarry_format_ead9ddf, quarry_data_local_762cd29, file_offset=_name_boundary.attributes(quarry_self_d946155)['get_offset_from_rva'](quarry_rva_01b7646))
            if quarry_contains_addresses_7858e96:
                quarry_thunk_data_ab88169.AddressOfData = _name_boundary.attributes(quarry_self_d946155)['normalize_import_va'](quarry_thunk_data_ab88169.AddressOfData)
                quarry_thunk_data_ab88169.ForwarderString = _name_boundary.attributes(quarry_self_d946155)['normalize_import_va'](quarry_thunk_data_ab88169.ForwarderString)
                quarry_thunk_data_ab88169.Function = _name_boundary.attributes(quarry_self_d946155)['normalize_import_va'](quarry_thunk_data_ab88169.Function)
                quarry_thunk_data_ab88169.Ordinal = _name_boundary.attributes(quarry_self_d946155)['normalize_import_va'](quarry_thunk_data_ab88169.Ordinal)
            if quarry_thunk_data_ab88169 and quarry_start_rva_c1b8fad <= quarry_thunk_data_ab88169.AddressOfData <= quarry_rva_01b7646:
                _name_boundary.attributes(quarry_self_d946155)['__warnings'].append(f'Error parsing the import table. AddressOfData overlaps with THUNK_DATA for THUNK at RVA {quarry_rva_01b7646:#x}')
                break
            if quarry_thunk_data_ab88169 and quarry_thunk_data_ab88169.AddressOfData:
                quarry_addr_of_data_9417b92 = quarry_thunk_data_ab88169.AddressOfData
                if quarry_addr_of_data_9417b92 & quarry_ordinal_flag_d55e08e:
                    if quarry_addr_of_data_9417b92 & 2147483647 > 65535:
                        return []
                else:
                    if quarry_addr_of_data_9417b92 >= quarry_ADDR_4GB_42c5d47:
                        quarry_the_set_4747445 = quarry_addresses_of_data_set_64_16eb336
                    else:
                        quarry_the_set_4747445 = quarry_addresses_of_data_set_32_1901643
                    if quarry_addr_of_data_9417b92 in quarry_the_set_4747445:
                        quarry_repeated_address_2029542 += 1
                    _name_boundary.attributes(quarry_the_set_4747445)['add'](quarry_addr_of_data_9417b92)
            if not quarry_thunk_data_ab88169 or _name_boundary.attributes(quarry_thunk_data_ab88169)['all_zeroes']():
                break
            quarry_rva_01b7646 += _name_boundary.attributes(quarry_thunk_data_ab88169)['sizeof']()
            quarry_table_4e17b47.append(quarry_thunk_data_ab88169)
        return quarry_table_4e17b47

    @_name_boundary.callable_contract({'self': 'quarry_self', 'max_virtual_address': 'quarry_max_virtual_address_e6bc56f', 'ImageBase': 'quarry_ImageBase_d22b716'}, 'get_memory_mapped_image')
    def quarry_get_memory_mapped_image(quarry_self, quarry_max_virtual_address_e6bc56f=268435456, quarry_ImageBase_d22b716=None):
        """Build a bounded static memory layout; never load or execute the PE.

        max_virtual_address retains its starting-RVA selection convention.
        max_mapped_size additionally caps the entire produced byte image.
        ImageBase retains the upstream permanent structure-relocation effect;
        raw bytes are restored even if mapping fails after relocation.
        """
        quarry_positive_limit(quarry_max_virtual_address_e6bc56f, 'max_virtual_address')
        quarry_limit = quarry_self._quarry_mapped_limit
        quarry_plan = []
        quarry_size = len(quarry_self.header)
        if quarry_size > quarry_limit:
            raise quarry_LimitError('mapped header exceeds byte limit')
        for quarry_section in quarry_self.sections:
            quarry_raw_size = quarry_section.SizeOfRawData
            quarry_virtual_size = quarry_section.Misc_VirtualSize
            if quarry_virtual_size == 0 and quarry_raw_size == 0:
                continue
            quarry_raw_start = quarry_self.adjust_PointerToRawData(quarry_section.PointerToRawData)
            quarry_rva = quarry_self.adjust_SectionAlignment(quarry_section.VirtualAddress, quarry_self.OPTIONAL_HEADER.SectionAlignment, quarry_self.OPTIONAL_HEADER.FileAlignment)
            if any(type(quarry_v) is not int or quarry_v < 0 for quarry_v in (quarry_raw_size, quarry_virtual_size, quarry_raw_start, quarry_rva)):
                raise quarry_PEFormatError('negative or non-integer mapped section span')
            if quarry_raw_start > len(quarry_self.__data__) or quarry_raw_size > len(quarry_self.__data__) - quarry_raw_start or quarry_rva >= quarry_max_virtual_address_e6bc56f:
                continue
            quarry_data = quarry_section.get_data()
            quarry_length = quarry_virtual_size or len(quarry_data)
            if quarry_rva > quarry_limit or quarry_length > quarry_limit - quarry_rva:
                raise quarry_LimitError('mapped section exceeds byte limit')
            quarry_plan.append((quarry_section, quarry_rva, quarry_length))
            quarry_size = quarry_rva + quarry_length
        quarry_original_data = quarry_self.__data__
        quarry_original_bytes = bytes(quarry_original_data) if quarry_ImageBase_d22b716 is not None else None
        try:
            if quarry_ImageBase_d22b716 is not None:
                _name_boundary.attributes(quarry_self)['relocate_image'](quarry_ImageBase_d22b716)
            quarry_output = bytearray(quarry_self.header)
            for quarry_section, quarry_rva, quarry_length in quarry_plan:
                if len(quarry_output) > quarry_rva:
                    del quarry_output[quarry_rva:]
                elif len(quarry_output) < quarry_rva:
                    quarry_output.extend(bytes(quarry_rva - len(quarry_output)))
                quarry_data = quarry_section.get_data()
                quarry_output.extend(quarry_data[:quarry_length])
                if len(quarry_data) < quarry_length:
                    quarry_output.extend(bytes(quarry_length - len(quarry_data)))
            return bytes(quarry_output)
        finally:
            if quarry_ImageBase_d22b716 is not None:
                if isinstance(quarry_original_data, bytearray):
                    quarry_original_data[:] = quarry_original_bytes
                quarry_self.__data__ = quarry_original_data

    @_name_boundary.callable_contract({'self': 'quarry_self_6264130'}, 'get_resources_strings')
    def quarry_get_resources_strings(quarry_self_6264130):
        """Returns a list of all the strings found within the resources (if any).

        This method will scan all entries in the resources directory of the PE, if
        there is one, and will return a [] with the strings.

        An empty list will be returned otherwise.
        """
        quarry_resources_strings_c0d2eed = []
        if _name_boundary.has_attribute(quarry_self_6264130, 'DIRECTORY_ENTRY_RESOURCE'):
            for quarry_res_type_09ed2bb in quarry_self_6264130.DIRECTORY_ENTRY_RESOURCE.entries:
                if _name_boundary.has_attribute(quarry_res_type_09ed2bb, 'directory'):
                    for quarry_resource_id_5da7146 in quarry_res_type_09ed2bb.directory.entries:
                        if _name_boundary.has_attribute(quarry_resource_id_5da7146, 'directory') and _name_boundary.has_attribute(quarry_resource_id_5da7146.directory, 'strings') and quarry_resource_id_5da7146.directory.strings:
                            for quarry_res_string_08f7c75 in quarry_resource_id_5da7146.directory.strings.values():
                                quarry_resources_strings_c0d2eed.append(quarry_res_string_08f7c75)
        return quarry_resources_strings_c0d2eed

    @_name_boundary.callable_contract({'self': 'quarry_self_592d8a9', 'rva': 'quarry_rva_642c28a', 'length': 'quarry_length_2b4e96b'}, 'get_data')
    def quarry_get_data(quarry_self_592d8a9, quarry_rva_642c28a=0, quarry_length_2b4e96b=None):
        """Get data regardless of the section where it lies on.

        Given a RVA and the size of the chunk to retrieve, this method
        will find the section where the data lies and return the data.
        """
        quarry_self_592d8a9._quarry_read_count += 1
        if quarry_self_592d8a9._quarry_read_count > quarry_self_592d8a9._quarry_read_limit:
            raise quarry_LimitError('PE data read budget exceeded')
        if type(quarry_rva_642c28a) is not int or quarry_rva_642c28a < 0 or (quarry_length_2b4e96b is not None and (type(quarry_length_2b4e96b) is not int or quarry_length_2b4e96b < 0)):
            raise quarry_PEFormatError('data RVA and length must be nonnegative integers')
        quarry_s_272cfa2 = _name_boundary.attributes(quarry_self_592d8a9)['get_section_by_rva'](quarry_rva_642c28a)
        if quarry_length_2b4e96b is None:
            quarry_end_local_aa447e6 = None
        else:
            quarry_end_local_aa447e6 = quarry_rva_642c28a + quarry_length_2b4e96b
        if not quarry_s_272cfa2:
            if quarry_rva_642c28a < len(_name_boundary.attributes(quarry_self_592d8a9)['header']):
                return _name_boundary.attributes(quarry_self_592d8a9)['header'][quarry_rva_642c28a:quarry_end_local_aa447e6]
            if quarry_rva_642c28a < len(quarry_self_592d8a9.__data__):
                return quarry_self_592d8a9.__data__[quarry_rva_642c28a:quarry_end_local_aa447e6]
            raise quarry_PEFormatError("data at RVA can't be fetched. Corrupt header?")
        return _name_boundary.attributes(quarry_s_272cfa2)['get_data'](quarry_rva_642c28a, quarry_length_2b4e96b)

    @_name_boundary.callable_contract({'self': 'quarry_self_98025d4', 'offset': 'quarry_offset_local_f89e138'}, 'get_rva_from_offset')
    def quarry_get_rva_from_offset(quarry_self_98025d4, quarry_offset_local_f89e138):
        """Get the RVA corresponding to this file offset."""
        quarry_s_f7cba4e = _name_boundary.attributes(quarry_self_98025d4)['get_section_by_offset'](quarry_offset_local_f89e138)
        if not quarry_s_f7cba4e:
            if _name_boundary.attributes(quarry_self_98025d4)['sections']:
                quarry_lowest_rva_5735e1d = min([_name_boundary.attributes(quarry_self_98025d4)['adjust_SectionAlignment'](quarry_s_4b2dd90.VirtualAddress, _name_boundary.attributes(quarry_self_98025d4)['OPTIONAL_HEADER'].SectionAlignment, _name_boundary.attributes(quarry_self_98025d4)['OPTIONAL_HEADER'].FileAlignment) for quarry_s_4b2dd90 in _name_boundary.attributes(quarry_self_98025d4)['sections']])
                if quarry_offset_local_f89e138 < quarry_lowest_rva_5735e1d:
                    return quarry_offset_local_f89e138
                return None
            else:
                return quarry_offset_local_f89e138
        return _name_boundary.attributes(quarry_s_f7cba4e)['get_rva_from_offset'](quarry_offset_local_f89e138)

    @_name_boundary.callable_contract({'self': 'quarry_self_cb12317', 'rva': 'quarry_rva_2cf607f'}, 'get_offset_from_rva')
    def quarry_get_offset_from_rva(quarry_self_cb12317, quarry_rva_2cf607f):
        """Get the file offset corresponding to this RVA.

        Given a RVA, this method will find the section where the
        data lies and return the offset within the file.
        """
        quarry_s_88e94ec = _name_boundary.attributes(quarry_self_cb12317)['get_section_by_rva'](quarry_rva_2cf607f)
        if not quarry_s_88e94ec:
            if quarry_rva_2cf607f < len(quarry_self_cb12317.__data__):
                return quarry_rva_2cf607f
            raise quarry_PEFormatError(f"data at RVA {quarry_rva_2cf607f:#x} can't be fetched")
        return _name_boundary.attributes(quarry_s_88e94ec)['get_offset_from_rva'](quarry_rva_2cf607f)

    @_name_boundary.callable_contract({'self': 'quarry_self_5f221f0', 'rva': 'quarry_rva_cdba5a0', 'max_length': 'quarry_max_length_b0c0c36'}, 'get_string_at_rva')
    def quarry_get_string_at_rva(quarry_self_5f221f0, quarry_rva_cdba5a0, quarry_max_length_b0c0c36=quarry_MAX_STRING_LENGTH):
        """Get an ASCII string located at the given address."""
        if quarry_rva_cdba5a0 is None:
            return None
        quarry_s_ae7aa9b = _name_boundary.attributes(quarry_self_5f221f0)['get_section_by_rva'](quarry_rva_cdba5a0)
        if not quarry_s_ae7aa9b:
            return _name_boundary.attributes(quarry_self_5f221f0)['get_string_from_data'](0, quarry_self_5f221f0.__data__[quarry_rva_cdba5a0:quarry_rva_cdba5a0 + quarry_max_length_b0c0c36])
        return _name_boundary.attributes(quarry_self_5f221f0)['get_string_from_data'](0, _name_boundary.attributes(quarry_s_ae7aa9b)['get_data'](quarry_rva_cdba5a0, length=quarry_max_length_b0c0c36))

    @staticmethod
    @_name_boundary.callable_contract({'offset': 'quarry_offset_local_3c2d22e', 'data': 'quarry_data_local_05808d2'}, 'get_bytes_from_data')
    def quarry_get_bytes_from_data(quarry_offset_local_3c2d22e, quarry_data_local_05808d2):
        """Get bytes from data."""
        if quarry_offset_local_3c2d22e > len(quarry_data_local_05808d2):
            return b''
        quarry_d_027c329 = quarry_data_local_05808d2[quarry_offset_local_3c2d22e:]
        if isinstance(quarry_d_027c329, bytearray):
            return bytes(quarry_d_027c329)
        return quarry_d_027c329

    @_name_boundary.callable_contract({'self': 'quarry_self_521704b', 'offset': 'quarry_offset_local_310433b', 'data': 'quarry_data_local_ce330f9'}, 'get_string_from_data')
    def quarry_get_string_from_data(quarry_self_521704b, quarry_offset_local_310433b, quarry_data_local_ce330f9):
        """Get an ASCII string from data."""
        quarry_s_c67d0f3 = _name_boundary.attributes(quarry_self_521704b)['get_bytes_from_data'](quarry_offset_local_310433b, quarry_data_local_ce330f9)
        quarry_end_local_59a5de9 = quarry_s_c67d0f3.find(b'\x00')
        if quarry_end_local_59a5de9 >= 0:
            quarry_s_c67d0f3 = quarry_s_c67d0f3[:quarry_end_local_59a5de9]
        return quarry_s_c67d0f3

    @_name_boundary.callable_contract({'self': 'quarry_self_6f08926', 'rva': 'quarry_rva_3ecb107', 'max_length': 'quarry_max_length_5df64be', 'encoding': 'quarry_encoding_45a0748'}, 'get_string_u_at_rva')
    def quarry_get_string_u_at_rva(quarry_self_6f08926, quarry_rva_3ecb107, quarry_max_length_5df64be=2 ** 16, quarry_encoding_45a0748=None):
        """Get a Unicode string located at the given address."""
        if quarry_max_length_5df64be == 0:
            return b''
        quarry___84aae0b = _name_boundary.attributes(quarry_self_6f08926)['get_data'](quarry_rva_3ecb107, 2)
        quarry_max_length_5df64be <<= 1
        quarry_requested_2a345c7 = min(quarry_max_length_5df64be, 256)
        quarry_data_local_41bd8c7 = _name_boundary.attributes(quarry_self_6f08926)['get_data'](quarry_rva_3ecb107, quarry_requested_2a345c7)
        quarry_null_index_1b67f33 = -1
        while True:
            quarry_null_index_1b67f33 = quarry_data_local_41bd8c7.find(b'\x00\x00', quarry_null_index_1b67f33 + 1)
            if quarry_null_index_1b67f33 == -1:
                quarry_data_length_4fc2bc0 = len(quarry_data_local_41bd8c7)
                if quarry_data_length_4fc2bc0 < quarry_requested_2a345c7 or quarry_data_length_4fc2bc0 == quarry_max_length_5df64be:
                    quarry_null_index_1b67f33 = len(quarry_data_local_41bd8c7) >> 1
                    break
                quarry_data_local_41bd8c7 += _name_boundary.attributes(quarry_self_6f08926)['get_data'](quarry_rva_3ecb107 + quarry_data_length_4fc2bc0, quarry_max_length_5df64be - quarry_data_length_4fc2bc0)
                quarry_null_index_1b67f33 = quarry_requested_2a345c7 - 1
                quarry_requested_2a345c7 = quarry_max_length_5df64be
            elif quarry_null_index_1b67f33 % 2 == 0:
                quarry_null_index_1b67f33 >>= 1
                break
        quarry_s_bbc7a64 = _name_boundary.attributes(quarry_data_local_41bd8c7[:quarry_null_index_1b67f33 * 2])['decode']('utf-16-le', errors='backslashreplace')
        if quarry_encoding_45a0748:
            return quarry_s_bbc7a64.encode(quarry_encoding_45a0748, 'backslashreplace_')
        return quarry_s_bbc7a64.encode('utf-8', 'backslashreplace_')

    @_name_boundary.callable_contract({'self': 'quarry_self_157e28e', 'offset': 'quarry_offset_local_f424922'}, 'get_section_by_offset')
    def quarry_get_section_by_offset(quarry_self_157e28e, quarry_offset_local_f424922):
        """Get the section containing the given file offset."""
        for quarry_section_f8155f7 in _name_boundary.attributes(quarry_self_157e28e)['sections']:
            if _name_boundary.attributes(quarry_section_f8155f7)['contains_offset'](quarry_offset_local_f424922):
                return quarry_section_f8155f7
        return None

    @_name_boundary.callable_contract({'self': 'quarry_self_5c3ffcb', 'rva': 'quarry_rva_f93a8c0'}, 'get_section_by_rva')
    def quarry_get_section_by_rva(quarry_self_5c3ffcb, quarry_rva_f93a8c0):
        """Get the section containing the given address."""
        if _name_boundary.attributes(quarry_self_5c3ffcb)['_get_section_by_rva_last_used'] is not None and _name_boundary.attributes(_name_boundary.attributes(quarry_self_5c3ffcb)['_get_section_by_rva_last_used'])['contains_rva'](quarry_rva_f93a8c0):
            return _name_boundary.attributes(quarry_self_5c3ffcb)['_get_section_by_rva_last_used']
        for quarry_section_147860d in _name_boundary.attributes(quarry_self_5c3ffcb)['sections']:
            if _name_boundary.attributes(quarry_section_147860d)['contains_rva'](quarry_rva_f93a8c0):
                _name_boundary.attributes(quarry_self_5c3ffcb)['_get_section_by_rva_last_used'] = quarry_section_147860d
                return quarry_section_147860d
        return None

    @_name_boundary.callable_contract({'self': 'quarry_self_a095f86'}, '__str__')
    def __str__(quarry_self_a095f86):
        return _name_boundary.attributes(quarry_self_a095f86)['dump_info']()

    @_name_boundary.callable_contract({'self': 'quarry_self_8ce5418'}, 'has_relocs')
    def quarry_has_relocs(quarry_self_8ce5418):
        """Checks if the PE file has a relocation directory"""
        return _name_boundary.has_attribute(quarry_self_8ce5418, 'DIRECTORY_ENTRY_BASERELOC')

    @_name_boundary.callable_contract({'self': 'quarry_self_9717903'}, 'has_dynamic_relocs')
    def quarry_has_dynamic_relocs(quarry_self_9717903):
        return bool(_name_boundary.has_attribute(quarry_self_9717903, 'DIRECTORY_ENTRY_LOAD_CONFIG') and quarry_self_9717903.DIRECTORY_ENTRY_LOAD_CONFIG.dynamic_relocations)

    @_name_boundary.callable_contract({'self': 'quarry_self_7f5d617', 'encoding': 'quarry_encoding_59fbdf8'}, 'print_info')
    def quarry_print_info(quarry_self_7f5d617, quarry_encoding_59fbdf8='utf-8'):
        """Print all the PE header information in a human readable form."""
        print(_name_boundary.attributes(quarry_self_7f5d617)['dump_info'](encoding=quarry_encoding_59fbdf8))

    @_name_boundary.callable_contract({'self': 'quarry_self_d1bc31a', 'encoding': 'quarry_encoding_34c42aa', 'dump': 'quarry_dump_local_99a8954'}, 'dump_info')
    def quarry_dump_info(quarry_self_d1bc31a, quarry_dump_local_99a8954=None, quarry_encoding_34c42aa='ascii'):
        """Dump all the PE header information into a human readable string."""
        if quarry_dump_local_99a8954 is None:
            quarry_dump_local_99a8954 = quarry_Dump()
        quarry_warnings_f1347c2 = _name_boundary.attributes(quarry_self_d1bc31a)['get_warnings']()
        if quarry_warnings_f1347c2:
            _name_boundary.attributes(quarry_dump_local_99a8954)['add_header']('Parsing Warnings')
            for quarry_warning_579edbe in quarry_warnings_f1347c2:
                _name_boundary.attributes(quarry_dump_local_99a8954)['add_line'](quarry_warning_579edbe)
                _name_boundary.attributes(quarry_dump_local_99a8954)['add_newline']()
        _name_boundary.attributes(quarry_dump_local_99a8954)['add_header']('DOS_HEADER')
        _name_boundary.attributes(quarry_dump_local_99a8954)['add_lines'](_name_boundary.attributes(quarry_self_d1bc31a)['DOS_HEADER'].dump())
        _name_boundary.attributes(quarry_dump_local_99a8954)['add_newline']()
        _name_boundary.attributes(quarry_dump_local_99a8954)['add_header']('NT_HEADERS')
        _name_boundary.attributes(quarry_dump_local_99a8954)['add_lines'](_name_boundary.attributes(quarry_self_d1bc31a)['NT_HEADERS'].dump())
        _name_boundary.attributes(quarry_dump_local_99a8954)['add_newline']()
        _name_boundary.attributes(quarry_dump_local_99a8954)['add_header']('FILE_HEADER')
        _name_boundary.attributes(quarry_dump_local_99a8954)['add_lines'](_name_boundary.attributes(quarry_self_d1bc31a)['FILE_HEADER'].dump())
        quarry_image_flags_db3e9c4 = quarry_retrieve_flags(quarry_IMAGE_CHARACTERISTICS, 'IMAGE_FILE_')
        _name_boundary.attributes(quarry_dump_local_99a8954)['add']('Flags: ')
        quarry_flags_792406b = []
        for quarry_flag_e313ca2 in sorted(quarry_image_flags_db3e9c4):
            if _name_boundary.read_attribute(_name_boundary.attributes(quarry_self_d1bc31a)['FILE_HEADER'], quarry_flag_e313ca2[0]):
                quarry_flags_792406b.append(quarry_flag_e313ca2[0])
        _name_boundary.attributes(quarry_dump_local_99a8954)['add_line'](', '.join(quarry_flags_792406b))
        _name_boundary.attributes(quarry_dump_local_99a8954)['add_newline']()
        if _name_boundary.has_attribute(quarry_self_d1bc31a, 'OPTIONAL_HEADER') and _name_boundary.attributes(quarry_self_d1bc31a)['OPTIONAL_HEADER'] is not None:
            _name_boundary.attributes(quarry_dump_local_99a8954)['add_header']('OPTIONAL_HEADER')
            _name_boundary.attributes(quarry_dump_local_99a8954)['add_lines'](_name_boundary.attributes(quarry_self_d1bc31a)['OPTIONAL_HEADER'].dump())
        quarry_dll_characteristics_flags_ab22bfd = quarry_retrieve_flags(quarry_DLL_CHARACTERISTICS, 'IMAGE_DLLCHARACTERISTICS_')
        _name_boundary.attributes(quarry_dump_local_99a8954)['add']('DllCharacteristics: ')
        quarry_flags_792406b = []
        for quarry_flag_e313ca2 in sorted(quarry_dll_characteristics_flags_ab22bfd):
            if _name_boundary.read_attribute(_name_boundary.attributes(quarry_self_d1bc31a)['OPTIONAL_HEADER'], quarry_flag_e313ca2[0]):
                quarry_flags_792406b.append(quarry_flag_e313ca2[0])
        _name_boundary.attributes(quarry_dump_local_99a8954)['add_line'](', '.join(quarry_flags_792406b))
        quarry_ex_dll_characteristics_flags_f18b64f = quarry_retrieve_flags(quarry_EX_DLL_CHARACTERISTICS, 'IMAGE_DLLCHARACTERISTICS_EX_')
        if quarry_ex_dll_characteristics_flags_f18b64f:
            quarry_flags_792406b = []
            if _name_boundary.has_attribute(quarry_self_d1bc31a, 'DIRECTORY_ENTRY_DEBUG') and quarry_self_d1bc31a.DIRECTORY_ENTRY_DEBUG is not None:
                for quarry_debug_entry_0ac2d41 in quarry_self_d1bc31a.DIRECTORY_ENTRY_DEBUG:
                    if _name_boundary.attributes(quarry_debug_entry_0ac2d41)['struct'].Type == quarry_DEBUG_TYPE['IMAGE_DEBUG_TYPE_EX_DLLCHARACTERISTICS']:
                        for quarry_flag_e313ca2 in sorted(quarry_ex_dll_characteristics_flags_f18b64f):
                            if _name_boundary.read_attribute(quarry_debug_entry_0ac2d41.entry, quarry_flag_e313ca2[0]):
                                quarry_flags_792406b.append(quarry_flag_e313ca2[0])
            if quarry_flags_792406b:
                _name_boundary.attributes(quarry_dump_local_99a8954)['add']('ExDllCharacteristics: ')
                _name_boundary.attributes(quarry_dump_local_99a8954)['add_line'](', '.join(quarry_flags_792406b))
        _name_boundary.attributes(quarry_dump_local_99a8954)['add_newline']()
        _name_boundary.attributes(quarry_dump_local_99a8954)['add_header']('PE Sections')
        quarry_section_flags_local_1d8acb3 = quarry_retrieve_flags(quarry_SECTION_CHARACTERISTICS, 'IMAGE_SCN_')
        for quarry_section_3ed1497 in _name_boundary.attributes(quarry_self_d1bc31a)['sections']:
            _name_boundary.attributes(quarry_dump_local_99a8954)['add_lines'](quarry_section_3ed1497.dump())
            _name_boundary.attributes(quarry_dump_local_99a8954)['add']('Flags: ')
            quarry_flags_792406b = []
            for quarry_flag_e313ca2 in sorted(quarry_section_flags_local_1d8acb3):
                if _name_boundary.read_attribute(quarry_section_3ed1497, quarry_flag_e313ca2[0]):
                    quarry_flags_792406b.append(quarry_flag_e313ca2[0])
            _name_boundary.attributes(quarry_dump_local_99a8954)['add_line'](', '.join(quarry_flags_792406b))
            _name_boundary.attributes(quarry_dump_local_99a8954)['add_line'](f"Entropy: {_name_boundary.attributes(quarry_section_3ed1497)['get_entropy']():f} (Min=0.0, Max=8.0)")
            if quarry_md5 is not None:
                _name_boundary.attributes(quarry_dump_local_99a8954)['add_line'](f"MD5     hash: {_name_boundary.attributes(quarry_section_3ed1497)['get_hash_md5']()}")
            if quarry_sha1 is not None:
                _name_boundary.attributes(quarry_dump_local_99a8954)['add_line'](f"SHA-1   hash: {_name_boundary.attributes(quarry_section_3ed1497)['get_hash_sha1']()}")
            if quarry_sha256 is not None:
                _name_boundary.attributes(quarry_dump_local_99a8954)['add_line'](f"SHA-256 hash: {_name_boundary.attributes(quarry_section_3ed1497)['get_hash_sha256']()}")
            if quarry_sha512 is not None:
                _name_boundary.attributes(quarry_dump_local_99a8954)['add_line'](f"SHA-512 hash: {_name_boundary.attributes(quarry_section_3ed1497)['get_hash_sha512']()}")
            _name_boundary.attributes(quarry_dump_local_99a8954)['add_newline']()
        if _name_boundary.has_attribute(quarry_self_d1bc31a, 'OPTIONAL_HEADER') and _name_boundary.has_attribute(_name_boundary.attributes(quarry_self_d1bc31a)['OPTIONAL_HEADER'], 'DATA_DIRECTORY'):
            _name_boundary.attributes(quarry_dump_local_99a8954)['add_header']('Directories')
            for quarry_directory_54ec4ed in _name_boundary.attributes(quarry_self_d1bc31a)['OPTIONAL_HEADER'].DATA_DIRECTORY:
                if quarry_directory_54ec4ed is not None:
                    _name_boundary.attributes(quarry_dump_local_99a8954)['add_lines'](quarry_directory_54ec4ed.dump())
            _name_boundary.attributes(quarry_dump_local_99a8954)['add_newline']()
        if _name_boundary.has_attribute(quarry_self_d1bc31a, 'VS_VERSIONINFO'):
            for quarry_idx_19af12c, quarry_vinfo_entry_2f05c04 in enumerate(_name_boundary.attributes(quarry_self_d1bc31a)['VS_VERSIONINFO']):
                if len(_name_boundary.attributes(quarry_self_d1bc31a)['VS_VERSIONINFO']) > 1:
                    _name_boundary.attributes(quarry_dump_local_99a8954)['add_header'](f'Version Information {quarry_idx_19af12c + 1}')
                else:
                    _name_boundary.attributes(quarry_dump_local_99a8954)['add_header']('Version Information')
                if quarry_vinfo_entry_2f05c04 is not None:
                    _name_boundary.attributes(quarry_dump_local_99a8954)['add_lines'](quarry_vinfo_entry_2f05c04.dump())
                _name_boundary.attributes(quarry_dump_local_99a8954)['add_newline']()
                if _name_boundary.has_attribute(quarry_self_d1bc31a, 'VS_FIXEDFILEINFO'):
                    _name_boundary.attributes(quarry_dump_local_99a8954)['add_lines'](_name_boundary.attributes(quarry_self_d1bc31a)['VS_FIXEDFILEINFO'][quarry_idx_19af12c].dump())
                    _name_boundary.attributes(quarry_dump_local_99a8954)['add_newline']()
                if _name_boundary.has_attribute(quarry_self_d1bc31a, 'FileInfo') and len(_name_boundary.attributes(quarry_self_d1bc31a)['FileInfo']) > quarry_idx_19af12c:
                    for quarry_entry_2e6d845 in _name_boundary.attributes(quarry_self_d1bc31a)['FileInfo'][quarry_idx_19af12c]:
                        _name_boundary.attributes(quarry_dump_local_99a8954)['add_lines'](quarry_entry_2e6d845.dump())
                        _name_boundary.attributes(quarry_dump_local_99a8954)['add_newline']()
                        if _name_boundary.has_attribute(quarry_entry_2e6d845, 'StringTable'):
                            for quarry_st_entry_9218025 in quarry_entry_2e6d845.StringTable:
                                [_name_boundary.attributes(quarry_dump_local_99a8954)['add_line']('  ' + quarry_line_0c2125d) for quarry_line_0c2125d in quarry_st_entry_9218025.dump()]
                                _name_boundary.attributes(quarry_dump_local_99a8954)['add_line']('  LangID: {}'.format(_name_boundary.attributes(quarry_st_entry_9218025.LangID)['decode'](quarry_encoding_34c42aa, 'backslashreplace_')))
                                _name_boundary.attributes(quarry_dump_local_99a8954)['add_newline']()
                                for quarry_str_entry_9745219 in sorted(quarry_st_entry_9218025.entries.items()):
                                    _name_boundary.attributes(quarry_dump_local_99a8954)['add_line']('    {}: {}'.format(_name_boundary.attributes(quarry_str_entry_9745219[0])['decode'](quarry_encoding_34c42aa, 'backslashreplace_'), _name_boundary.attributes(quarry_str_entry_9745219[1])['decode'](quarry_encoding_34c42aa, 'backslashreplace_')))
                            _name_boundary.attributes(quarry_dump_local_99a8954)['add_newline']()
                        elif _name_boundary.has_attribute(quarry_entry_2e6d845, 'Var'):
                            for quarry_var_entry_d3bb493 in quarry_entry_2e6d845.Var:
                                if _name_boundary.has_attribute(quarry_var_entry_d3bb493, 'entry'):
                                    [_name_boundary.attributes(quarry_dump_local_99a8954)['add_line']('  ' + quarry_line_c13a6b0) for quarry_line_c13a6b0 in quarry_var_entry_d3bb493.dump()]
                                    _name_boundary.attributes(quarry_dump_local_99a8954)['add_line']('    {}: {}'.format(_name_boundary.attributes(list(quarry_var_entry_d3bb493.entry.keys())[0])['decode']('utf-8', 'backslashreplace_'), list(quarry_var_entry_d3bb493.entry.values())[0]))
                            _name_boundary.attributes(quarry_dump_local_99a8954)['add_newline']()
        if _name_boundary.has_attribute(quarry_self_d1bc31a, 'DIRECTORY_ENTRY_EXPORT'):
            _name_boundary.attributes(quarry_dump_local_99a8954)['add_header']('Exported symbols')
            _name_boundary.attributes(quarry_dump_local_99a8954)['add_lines'](_name_boundary.attributes(quarry_self_d1bc31a.DIRECTORY_ENTRY_EXPORT)['struct'].dump())
            _name_boundary.attributes(quarry_dump_local_99a8954)['add_newline']()
            _name_boundary.attributes(quarry_dump_local_99a8954)['add_line'](f"{'Ordinal':10}   {'RVA':10}  Name")
            for quarry_export_a7ef143 in quarry_self_d1bc31a.DIRECTORY_ENTRY_EXPORT.symbols:
                if quarry_export_a7ef143.address is not None:
                    quarry_name_local_63a40d3 = b'None'
                    if quarry_export_a7ef143.name:
                        quarry_name_local_63a40d3 = quarry_export_a7ef143.name
                    _name_boundary.attributes(quarry_dump_local_99a8954)['add']('%-10d 0x%08X    %s' % (quarry_export_a7ef143.ordinal, quarry_export_a7ef143.address, _name_boundary.attributes(quarry_name_local_63a40d3)['decode'](quarry_encoding_34c42aa)))
                    if quarry_export_a7ef143.forwarder:
                        _name_boundary.attributes(quarry_dump_local_99a8954)['add_line'](' forwarder: {}'.format(_name_boundary.attributes(quarry_export_a7ef143.forwarder)['decode'](quarry_encoding_34c42aa, 'backslashreplace_')))
                    else:
                        _name_boundary.attributes(quarry_dump_local_99a8954)['add_newline']()
            _name_boundary.attributes(quarry_dump_local_99a8954)['add_newline']()
        if _name_boundary.has_attribute(quarry_self_d1bc31a, 'DIRECTORY_ENTRY_IMPORT'):
            _name_boundary.attributes(quarry_dump_local_99a8954)['add_header']('Imported symbols')
            for quarry_module_4c56e9e in quarry_self_d1bc31a.DIRECTORY_ENTRY_IMPORT:
                _name_boundary.attributes(quarry_dump_local_99a8954)['add_lines'](_name_boundary.attributes(quarry_module_4c56e9e)['struct'].dump())
                if not quarry_module_4c56e9e.imports:
                    _name_boundary.attributes(quarry_dump_local_99a8954)['add']('  Name -> {}'.format(_name_boundary.attributes(_name_boundary.attributes(quarry_self_d1bc31a)['get_string_at_rva'](_name_boundary.attributes(quarry_module_4c56e9e)['struct'].Name))['decode'](quarry_encoding_34c42aa, 'backslashreplace_')))
                    _name_boundary.attributes(quarry_dump_local_99a8954)['add_newline']()
                _name_boundary.attributes(quarry_dump_local_99a8954)['add_newline']()
                for quarry_symbol_a202189 in quarry_module_4c56e9e.imports:
                    if quarry_symbol_a202189.import_by_ordinal is True:
                        if quarry_symbol_a202189.name is not None:
                            _name_boundary.attributes(quarry_dump_local_99a8954)['add']('{}.{} Ordinal[{}] (Imported by Ordinal)'.format(_name_boundary.attributes(quarry_module_4c56e9e.dll)['decode']('utf-8'), _name_boundary.attributes(quarry_symbol_a202189.name)['decode']('utf-8'), quarry_symbol_a202189.ordinal))
                        else:
                            _name_boundary.attributes(quarry_dump_local_99a8954)['add']('{} Ordinal[{}] (Imported by Ordinal)'.format(_name_boundary.attributes(quarry_module_4c56e9e.dll)['decode']('utf-8'), quarry_symbol_a202189.ordinal))
                    else:
                        _name_boundary.attributes(quarry_dump_local_99a8954)['add']('{}.{} Hint[{:d}]'.format(_name_boundary.attributes(quarry_module_4c56e9e.dll)['decode'](quarry_encoding_34c42aa, 'backslashreplace_'), _name_boundary.attributes(quarry_symbol_a202189.name)['decode'](quarry_encoding_34c42aa, 'backslashreplace_'), quarry_symbol_a202189.hint))
                    if quarry_symbol_a202189.bound:
                        _name_boundary.attributes(quarry_dump_local_99a8954)['add_line'](f' Bound: 0x{quarry_symbol_a202189.bound:08X}')
                    else:
                        _name_boundary.attributes(quarry_dump_local_99a8954)['add_newline']()
                _name_boundary.attributes(quarry_dump_local_99a8954)['add_newline']()
        if _name_boundary.has_attribute(quarry_self_d1bc31a, 'DIRECTORY_ENTRY_BOUND_IMPORT'):
            _name_boundary.attributes(quarry_dump_local_99a8954)['add_header']('Bound imports')
            for quarry_bound_imp_desc_6b4407f in quarry_self_d1bc31a.DIRECTORY_ENTRY_BOUND_IMPORT:
                _name_boundary.attributes(quarry_dump_local_99a8954)['add_lines'](_name_boundary.attributes(quarry_bound_imp_desc_6b4407f)['struct'].dump())
                _name_boundary.attributes(quarry_dump_local_99a8954)['add_line'](f"DLL: {_name_boundary.attributes(quarry_bound_imp_desc_6b4407f.name)['decode'](quarry_encoding_34c42aa, 'backslashreplace_')}")
                _name_boundary.attributes(quarry_dump_local_99a8954)['add_newline']()
                for quarry_bound_imp_ref_44b6dc7 in quarry_bound_imp_desc_6b4407f.entries:
                    _name_boundary.attributes(quarry_dump_local_99a8954)['add_lines'](_name_boundary.attributes(quarry_bound_imp_ref_44b6dc7)['struct'].dump(), 4)
                    _name_boundary.attributes(quarry_dump_local_99a8954)['add_line']('DLL: {}'.format(_name_boundary.attributes(quarry_bound_imp_ref_44b6dc7.name)['decode'](quarry_encoding_34c42aa, 'backslashreplace_')), 4)
                    _name_boundary.attributes(quarry_dump_local_99a8954)['add_newline']()
        if _name_boundary.has_attribute(quarry_self_d1bc31a, 'DIRECTORY_ENTRY_DELAY_IMPORT'):
            _name_boundary.attributes(quarry_dump_local_99a8954)['add_header']('Delay Imported symbols')
            for quarry_module_4c56e9e in quarry_self_d1bc31a.DIRECTORY_ENTRY_DELAY_IMPORT:
                _name_boundary.attributes(quarry_dump_local_99a8954)['add_lines'](_name_boundary.attributes(quarry_module_4c56e9e)['struct'].dump())
                _name_boundary.attributes(quarry_dump_local_99a8954)['add_newline']()
                for quarry_symbol_a202189 in quarry_module_4c56e9e.imports:
                    if quarry_symbol_a202189.import_by_ordinal is True:
                        _name_boundary.attributes(quarry_dump_local_99a8954)['add']('{} Ordinal[{:d}] (Imported by Ordinal)'.format(_name_boundary.attributes(quarry_module_4c56e9e.dll)['decode'](quarry_encoding_34c42aa, 'backslashreplace_'), quarry_symbol_a202189.ordinal))
                    else:
                        _name_boundary.attributes(quarry_dump_local_99a8954)['add']('{}.{} Hint[{}]'.format(_name_boundary.attributes(quarry_module_4c56e9e.dll)['decode'](quarry_encoding_34c42aa, 'backslashreplace_'), _name_boundary.attributes(quarry_symbol_a202189.name)['decode'](quarry_encoding_34c42aa, 'backslashreplace_'), quarry_symbol_a202189.hint))
                    if quarry_symbol_a202189.bound:
                        _name_boundary.attributes(quarry_dump_local_99a8954)['add_line'](f' Bound: 0x{quarry_symbol_a202189.bound:08X}')
                    else:
                        _name_boundary.attributes(quarry_dump_local_99a8954)['add_newline']()
                _name_boundary.attributes(quarry_dump_local_99a8954)['add_newline']()
        if _name_boundary.has_attribute(quarry_self_d1bc31a, 'DIRECTORY_ENTRY_RESOURCE'):
            _name_boundary.attributes(quarry_dump_local_99a8954)['add_header']('Resource directory')
            _name_boundary.attributes(quarry_dump_local_99a8954)['add_lines'](_name_boundary.attributes(quarry_self_d1bc31a.DIRECTORY_ENTRY_RESOURCE)['struct'].dump())
            for quarry_res_type_c1beb21 in quarry_self_d1bc31a.DIRECTORY_ENTRY_RESOURCE.entries:
                if quarry_res_type_c1beb21.name is not None:
                    quarry_name_local_63a40d3 = _name_boundary.attributes(quarry_res_type_c1beb21.name)['decode'](quarry_encoding_34c42aa, 'backslashreplace_')
                    _name_boundary.attributes(quarry_dump_local_99a8954)['add_line'](f'Name: [{quarry_name_local_63a40d3}]', 2)
                else:
                    quarry_res_type_id_531f56d = quarry_RESOURCE_TYPE.get(_name_boundary.attributes(quarry_res_type_c1beb21)['struct'].Id, '-')
                    _name_boundary.attributes(quarry_dump_local_99a8954)['add_line'](f"Id: [0x{_name_boundary.attributes(quarry_res_type_c1beb21)['struct'].Id:X}] ({quarry_res_type_id_531f56d})", 2)
                _name_boundary.attributes(quarry_dump_local_99a8954)['add_lines'](_name_boundary.attributes(quarry_res_type_c1beb21)['struct'].dump(), 2)
                if _name_boundary.has_attribute(quarry_res_type_c1beb21, 'directory'):
                    _name_boundary.attributes(quarry_dump_local_99a8954)['add_lines'](_name_boundary.attributes(quarry_res_type_c1beb21.directory)['struct'].dump(), 4)
                    for quarry_resource_id_b858765 in quarry_res_type_c1beb21.directory.entries:
                        if quarry_resource_id_b858765.name is not None:
                            quarry_name_local_63a40d3 = _name_boundary.attributes(quarry_resource_id_b858765.name)['decode']('utf-8', 'backslashreplace_')
                            _name_boundary.attributes(quarry_dump_local_99a8954)['add_line'](f'Name: [{quarry_name_local_63a40d3}]', 6)
                        else:
                            _name_boundary.attributes(quarry_dump_local_99a8954)['add_line'](f"Id: [0x{_name_boundary.attributes(quarry_resource_id_b858765)['struct'].Id:X}]", 6)
                        _name_boundary.attributes(quarry_dump_local_99a8954)['add_lines'](_name_boundary.attributes(quarry_resource_id_b858765)['struct'].dump(), 6)
                        if _name_boundary.has_attribute(quarry_resource_id_b858765, 'directory'):
                            _name_boundary.attributes(quarry_dump_local_99a8954)['add_lines'](_name_boundary.attributes(quarry_resource_id_b858765.directory)['struct'].dump(), 8)
                            for quarry_resource_lang_d636a12 in quarry_resource_id_b858765.directory.entries:
                                if _name_boundary.has_attribute(quarry_resource_lang_d636a12, 'data'):
                                    _name_boundary.attributes(quarry_dump_local_99a8954)['add_line']('\\--- LANG [%d,%d][%s,%s]' % (quarry_resource_lang_d636a12.data.lang, quarry_resource_lang_d636a12.data.sublang, quarry_LANG.get(quarry_resource_lang_d636a12.data.lang, '*unknown*'), quarry_get_sublang_name_for_lang(quarry_resource_lang_d636a12.data.lang, quarry_resource_lang_d636a12.data.sublang)), 8)
                                    _name_boundary.attributes(quarry_dump_local_99a8954)['add_lines'](_name_boundary.attributes(quarry_resource_lang_d636a12)['struct'].dump(), 10)
                                    _name_boundary.attributes(quarry_dump_local_99a8954)['add_lines'](_name_boundary.attributes(quarry_resource_lang_d636a12.data)['struct'].dump(), 12)
                            if _name_boundary.has_attribute(quarry_resource_id_b858765.directory, 'strings') and quarry_resource_id_b858765.directory.strings:
                                _name_boundary.attributes(quarry_dump_local_99a8954)['add_line']('[STRINGS]', 10)
                                for quarry_idx_19af12c, quarry_res_string_583ecfd in sorted(quarry_resource_id_b858765.directory.strings.items()):
                                    _name_boundary.attributes(quarry_dump_local_99a8954)['add_line']('{:6d}: {}'.format(quarry_idx_19af12c, _name_boundary.attributes(quarry_res_string_583ecfd.encode('unicode-escape', 'backslashreplace'))['decode']('ascii')), 12)
                _name_boundary.attributes(quarry_dump_local_99a8954)['add_newline']()
            _name_boundary.attributes(quarry_dump_local_99a8954)['add_newline']()
        if _name_boundary.has_attribute(quarry_self_d1bc31a, 'DIRECTORY_ENTRY_TLS') and quarry_self_d1bc31a.DIRECTORY_ENTRY_TLS and _name_boundary.attributes(quarry_self_d1bc31a.DIRECTORY_ENTRY_TLS)['struct']:
            _name_boundary.attributes(quarry_dump_local_99a8954)['add_header']('TLS')
            _name_boundary.attributes(quarry_dump_local_99a8954)['add_lines'](_name_boundary.attributes(quarry_self_d1bc31a.DIRECTORY_ENTRY_TLS)['struct'].dump())
            _name_boundary.attributes(quarry_dump_local_99a8954)['add_newline']()
        if _name_boundary.has_attribute(quarry_self_d1bc31a, 'DIRECTORY_ENTRY_LOAD_CONFIG') and quarry_self_d1bc31a.DIRECTORY_ENTRY_LOAD_CONFIG and _name_boundary.attributes(quarry_self_d1bc31a.DIRECTORY_ENTRY_LOAD_CONFIG)['struct']:
            _name_boundary.attributes(quarry_dump_local_99a8954)['add_header']('LOAD_CONFIG')
            _name_boundary.attributes(quarry_dump_local_99a8954)['add_lines'](_name_boundary.attributes(quarry_self_d1bc31a.DIRECTORY_ENTRY_LOAD_CONFIG)['struct'].dump())
            _name_boundary.attributes(quarry_dump_local_99a8954)['add_newline']()
        if _name_boundary.has_attribute(quarry_self_d1bc31a, 'DIRECTORY_ENTRY_DEBUG'):
            _name_boundary.attributes(quarry_dump_local_99a8954)['add_header']('Debug information')
            for quarry_dbg_e8e6f19 in quarry_self_d1bc31a.DIRECTORY_ENTRY_DEBUG:
                _name_boundary.attributes(quarry_dump_local_99a8954)['add_lines'](_name_boundary.attributes(quarry_dbg_e8e6f19)['struct'].dump())
                try:
                    _name_boundary.attributes(quarry_dump_local_99a8954)['add_line']('Type: ' + quarry_DEBUG_TYPE[_name_boundary.attributes(quarry_dbg_e8e6f19)['struct'].Type])
                except KeyError:
                    _name_boundary.attributes(quarry_dump_local_99a8954)['add_line'](f"Type: {_name_boundary.attributes(quarry_dbg_e8e6f19)['struct'].Type:#x}(Unknown)")
                _name_boundary.attributes(quarry_dump_local_99a8954)['add_newline']()
                if quarry_dbg_e8e6f19.entry:
                    _name_boundary.attributes(quarry_dump_local_99a8954)['add_lines'](quarry_dbg_e8e6f19.entry.dump(), 4)
                    _name_boundary.attributes(quarry_dump_local_99a8954)['add_newline']()
        if _name_boundary.attributes(quarry_self_d1bc31a)['has_relocs']():
            _name_boundary.attributes(quarry_dump_local_99a8954)['add_header']('Base relocations')
            for quarry_base_reloc_f126d0a in quarry_self_d1bc31a.DIRECTORY_ENTRY_BASERELOC:
                _name_boundary.attributes(quarry_dump_local_99a8954)['add_lines'](_name_boundary.attributes(quarry_base_reloc_f126d0a)['struct'].dump())
                for quarry_reloc_d96c38c in quarry_base_reloc_f126d0a.entries:
                    try:
                        _name_boundary.attributes(quarry_dump_local_99a8954)['add_line'](f'{quarry_reloc_d96c38c.rva:08X}h {quarry_RELOCATION_TYPE[quarry_reloc_d96c38c.type][16:]}', 4)
                    except KeyError:
                        _name_boundary.attributes(quarry_dump_local_99a8954)['add_line'](f'0x{quarry_reloc_d96c38c.rva:08X} 0x{quarry_reloc_d96c38c.type:x}(Unknown)', 4)
                _name_boundary.attributes(quarry_dump_local_99a8954)['add_newline']()
        if _name_boundary.has_attribute(quarry_self_d1bc31a, 'DIRECTORY_ENTRY_EXCEPTION') and len(quarry_self_d1bc31a.DIRECTORY_ENTRY_EXCEPTION) > 0:
            _name_boundary.attributes(quarry_dump_local_99a8954)['add_header']('Unwind data for exception handling')
            for quarry_rf_903af2f in quarry_self_d1bc31a.DIRECTORY_ENTRY_EXCEPTION:
                _name_boundary.attributes(quarry_dump_local_99a8954)['add_lines'](_name_boundary.attributes(quarry_rf_903af2f)['struct'].dump())
                if _name_boundary.has_attribute(quarry_rf_903af2f, 'unwindinfo') and quarry_rf_903af2f.unwindinfo is not None:
                    _name_boundary.attributes(quarry_dump_local_99a8954)['add_lines'](quarry_rf_903af2f.unwindinfo.dump(), 4)
        return _name_boundary.attributes(quarry_dump_local_99a8954)['get_text']()

    @_name_boundary.callable_contract({'self': 'quarry_self_877c971'}, 'dump_dict')
    def quarry_dump_dict(quarry_self_877c971):
        """Dump all the PE header information into a dictionary."""
        quarry_dump_dict_8a6e28b = {}
        quarry_warnings_657e0d2 = _name_boundary.attributes(quarry_self_877c971)['get_warnings']()
        if quarry_warnings_657e0d2:
            quarry_dump_dict_8a6e28b['Parsing Warnings'] = quarry_warnings_657e0d2
        quarry_dump_dict_8a6e28b['DOS_HEADER'] = _name_boundary.attributes(_name_boundary.attributes(quarry_self_877c971)['DOS_HEADER'])['dump_dict']()
        quarry_dump_dict_8a6e28b['NT_HEADERS'] = _name_boundary.attributes(_name_boundary.attributes(quarry_self_877c971)['NT_HEADERS'])['dump_dict']()
        quarry_dump_dict_8a6e28b['FILE_HEADER'] = _name_boundary.attributes(_name_boundary.attributes(quarry_self_877c971)['FILE_HEADER'])['dump_dict']()
        quarry_image_flags_82d0dce = quarry_retrieve_flags(quarry_IMAGE_CHARACTERISTICS, 'IMAGE_FILE_')
        quarry_dump_dict_8a6e28b['Flags'] = []
        for quarry_flag_4b161bd in quarry_image_flags_82d0dce:
            if _name_boundary.read_attribute(_name_boundary.attributes(quarry_self_877c971)['FILE_HEADER'], quarry_flag_4b161bd[0]):
                quarry_dump_dict_8a6e28b['Flags'].append(quarry_flag_4b161bd[0])
        if _name_boundary.has_attribute(quarry_self_877c971, 'OPTIONAL_HEADER') and _name_boundary.attributes(quarry_self_877c971)['OPTIONAL_HEADER'] is not None:
            quarry_dump_dict_8a6e28b['OPTIONAL_HEADER'] = _name_boundary.attributes(_name_boundary.attributes(quarry_self_877c971)['OPTIONAL_HEADER'])['dump_dict']()
        quarry_dll_characteristics_flags_d14d299 = quarry_retrieve_flags(quarry_DLL_CHARACTERISTICS, 'IMAGE_DLLCHARACTERISTICS_')
        quarry_dump_dict_8a6e28b['DllCharacteristics'] = []
        for quarry_flag_4b161bd in quarry_dll_characteristics_flags_d14d299:
            if _name_boundary.read_attribute(_name_boundary.attributes(quarry_self_877c971)['OPTIONAL_HEADER'], quarry_flag_4b161bd[0]):
                quarry_dump_dict_8a6e28b['DllCharacteristics'].append(quarry_flag_4b161bd[0])
        quarry_dump_dict_8a6e28b['PE Sections'] = []
        quarry_section_flags_local_06cf59f = quarry_retrieve_flags(quarry_SECTION_CHARACTERISTICS, 'IMAGE_SCN_')
        for quarry_section_7030959 in _name_boundary.attributes(quarry_self_877c971)['sections']:
            quarry_section_dict_8880837 = _name_boundary.attributes(quarry_section_7030959)['dump_dict']()
            quarry_dump_dict_8a6e28b['PE Sections'].append(quarry_section_dict_8880837)
            quarry_section_dict_8880837['Flags'] = []
            for quarry_flag_4b161bd in quarry_section_flags_local_06cf59f:
                if _name_boundary.read_attribute(quarry_section_7030959, quarry_flag_4b161bd[0]):
                    quarry_section_dict_8880837['Flags'].append(quarry_flag_4b161bd[0])
            quarry_section_dict_8880837['Entropy'] = _name_boundary.attributes(quarry_section_7030959)['get_entropy']()
            if quarry_md5 is not None:
                quarry_section_dict_8880837['MD5'] = _name_boundary.attributes(quarry_section_7030959)['get_hash_md5']()
            if quarry_sha1 is not None:
                quarry_section_dict_8880837['SHA1'] = _name_boundary.attributes(quarry_section_7030959)['get_hash_sha1']()
            if quarry_sha256 is not None:
                quarry_section_dict_8880837['SHA256'] = _name_boundary.attributes(quarry_section_7030959)['get_hash_sha256']()
            if quarry_sha512 is not None:
                quarry_section_dict_8880837['SHA512'] = _name_boundary.attributes(quarry_section_7030959)['get_hash_sha512']()
        if _name_boundary.has_attribute(quarry_self_877c971, 'OPTIONAL_HEADER') and _name_boundary.has_attribute(_name_boundary.attributes(quarry_self_877c971)['OPTIONAL_HEADER'], 'DATA_DIRECTORY'):
            quarry_dump_dict_8a6e28b['Directories'] = []
            for quarry_idx_651b84c, quarry_directory_9e5eba3 in enumerate(_name_boundary.attributes(quarry_self_877c971)['OPTIONAL_HEADER'].DATA_DIRECTORY):
                if quarry_directory_9e5eba3 is not None:
                    quarry_dump_dict_8a6e28b['Directories'].append(_name_boundary.attributes(quarry_directory_9e5eba3)['dump_dict']())
        if _name_boundary.has_attribute(quarry_self_877c971, 'VS_VERSIONINFO'):
            quarry_dump_dict_8a6e28b['Version Information'] = []
            for quarry_idx_651b84c, quarry_vs_vinfo_95a8968 in enumerate(_name_boundary.attributes(quarry_self_877c971)['VS_VERSIONINFO']):
                quarry_version_info_89f5821 = [_name_boundary.attributes(quarry_vs_vinfo_95a8968)['dump_dict']()]
                if _name_boundary.has_attribute(quarry_self_877c971, 'VS_FIXEDFILEINFO'):
                    quarry_version_info_89f5821.append(_name_boundary.attributes(_name_boundary.attributes(quarry_self_877c971)['VS_FIXEDFILEINFO'][quarry_idx_651b84c])['dump_dict']())
                if _name_boundary.has_attribute(quarry_self_877c971, 'FileInfo') and len(_name_boundary.attributes(quarry_self_877c971)['FileInfo']) > quarry_idx_651b84c:
                    quarry_file_info_17b5d65 = []
                    quarry_version_info_89f5821.append(quarry_file_info_17b5d65)
                    for quarry_entry_3e43297 in _name_boundary.attributes(quarry_self_877c971)['FileInfo'][quarry_idx_651b84c]:
                        quarry_file_info_17b5d65.append(_name_boundary.attributes(quarry_entry_3e43297)['dump_dict']())
                        if _name_boundary.has_attribute(quarry_entry_3e43297, 'StringTable'):
                            quarry_stringtable_dict_066a37e = {}
                            for quarry_st_entry_393ba4a in quarry_entry_3e43297.StringTable:
                                quarry_file_info_17b5d65.append(_name_boundary.attributes(quarry_st_entry_393ba4a)['dump_dict']())
                                quarry_stringtable_dict_066a37e['LangID'] = quarry_st_entry_393ba4a.LangID
                                for quarry_str_entry_67ef762 in quarry_st_entry_393ba4a.entries.items():
                                    quarry_stringtable_dict_066a37e[quarry_str_entry_67ef762[0]] = quarry_str_entry_67ef762[1]
                            quarry_file_info_17b5d65.append(quarry_stringtable_dict_066a37e)
                        elif _name_boundary.has_attribute(quarry_entry_3e43297, 'Var'):
                            for quarry_var_entry_ec97111 in quarry_entry_3e43297.Var:
                                quarry_var_dict_31612c3 = {}
                                if _name_boundary.has_attribute(quarry_var_entry_ec97111, 'entry'):
                                    quarry_file_info_17b5d65.append(_name_boundary.attributes(quarry_var_entry_ec97111)['dump_dict']())
                                    quarry_var_dict_31612c3[list(quarry_var_entry_ec97111.entry.keys())[0]] = list(quarry_var_entry_ec97111.entry.values())[0]
                                    quarry_file_info_17b5d65.append(quarry_var_dict_31612c3)
                quarry_dump_dict_8a6e28b['Version Information'].append(quarry_version_info_89f5821)
        if _name_boundary.has_attribute(quarry_self_877c971, 'DIRECTORY_ENTRY_EXPORT'):
            quarry_dump_dict_8a6e28b['Exported symbols'] = []
            quarry_dump_dict_8a6e28b['Exported symbols'].append(_name_boundary.attributes(_name_boundary.attributes(quarry_self_877c971.DIRECTORY_ENTRY_EXPORT)['struct'])['dump_dict']())
            for quarry_export_492fe10 in quarry_self_877c971.DIRECTORY_ENTRY_EXPORT.symbols:
                quarry_export_dict_41a71a5 = {}
                if quarry_export_492fe10.address is not None:
                    quarry_export_dict_41a71a5.update({'Ordinal': quarry_export_492fe10.ordinal, 'RVA': quarry_export_492fe10.address, 'Name': quarry_export_492fe10.name})
                    if quarry_export_492fe10.forwarder:
                        quarry_export_dict_41a71a5['forwarder'] = quarry_export_492fe10.forwarder
                quarry_dump_dict_8a6e28b['Exported symbols'].append(quarry_export_dict_41a71a5)
        if _name_boundary.has_attribute(quarry_self_877c971, 'DIRECTORY_ENTRY_IMPORT'):
            quarry_dump_dict_8a6e28b['Imported symbols'] = []
            for quarry_module_2847b70 in quarry_self_877c971.DIRECTORY_ENTRY_IMPORT:
                quarry_import_list_6e3c728 = []
                quarry_dump_dict_8a6e28b['Imported symbols'].append(quarry_import_list_6e3c728)
                quarry_import_list_6e3c728.append(_name_boundary.attributes(_name_boundary.attributes(quarry_module_2847b70)['struct'])['dump_dict']())
                for quarry_symbol_8c4d39f in quarry_module_2847b70.imports:
                    quarry_symbol_dict_04773b8 = {}
                    if quarry_symbol_8c4d39f.import_by_ordinal is True:
                        quarry_symbol_dict_04773b8['DLL'] = quarry_module_2847b70.dll
                        quarry_symbol_dict_04773b8['Ordinal'] = quarry_symbol_8c4d39f.ordinal
                    else:
                        quarry_symbol_dict_04773b8['DLL'] = quarry_module_2847b70.dll
                        quarry_symbol_dict_04773b8['Name'] = quarry_symbol_8c4d39f.name
                        quarry_symbol_dict_04773b8['Hint'] = quarry_symbol_8c4d39f.hint
                    if quarry_symbol_8c4d39f.bound:
                        quarry_symbol_dict_04773b8['Bound'] = quarry_symbol_8c4d39f.bound
                    quarry_import_list_6e3c728.append(quarry_symbol_dict_04773b8)
        if _name_boundary.has_attribute(quarry_self_877c971, 'DIRECTORY_ENTRY_BOUND_IMPORT'):
            quarry_dump_dict_8a6e28b['Bound imports'] = []
            for quarry_bound_imp_desc_0ce5d50 in quarry_self_877c971.DIRECTORY_ENTRY_BOUND_IMPORT:
                quarry_bound_imp_desc_dict_3841514 = {}
                quarry_dump_dict_8a6e28b['Bound imports'].append(quarry_bound_imp_desc_dict_3841514)
                quarry_bound_imp_desc_dict_3841514.update(_name_boundary.attributes(_name_boundary.attributes(quarry_bound_imp_desc_0ce5d50)['struct'])['dump_dict']())
                quarry_bound_imp_desc_dict_3841514['DLL'] = quarry_bound_imp_desc_0ce5d50.name
                for quarry_bound_imp_ref_ae61880 in quarry_bound_imp_desc_0ce5d50.entries:
                    quarry_bound_imp_ref_dict_ffba7c4 = {}
                    quarry_bound_imp_ref_dict_ffba7c4.update(_name_boundary.attributes(_name_boundary.attributes(quarry_bound_imp_ref_ae61880)['struct'])['dump_dict']())
                    quarry_bound_imp_ref_dict_ffba7c4['DLL'] = quarry_bound_imp_ref_ae61880.name
        if _name_boundary.has_attribute(quarry_self_877c971, 'DIRECTORY_ENTRY_DELAY_IMPORT'):
            quarry_dump_dict_8a6e28b['Delay Imported symbols'] = []
            for quarry_module_2847b70 in quarry_self_877c971.DIRECTORY_ENTRY_DELAY_IMPORT:
                quarry_module_list_4e7caec = []
                quarry_dump_dict_8a6e28b['Delay Imported symbols'].append(quarry_module_list_4e7caec)
                quarry_module_list_4e7caec.append(_name_boundary.attributes(_name_boundary.attributes(quarry_module_2847b70)['struct'])['dump_dict']())
                for quarry_symbol_8c4d39f in quarry_module_2847b70.imports:
                    quarry_symbol_dict_04773b8 = {}
                    if quarry_symbol_8c4d39f.import_by_ordinal is True:
                        quarry_symbol_dict_04773b8['DLL'] = quarry_module_2847b70.dll
                        quarry_symbol_dict_04773b8['Ordinal'] = quarry_symbol_8c4d39f.ordinal
                    else:
                        quarry_symbol_dict_04773b8['DLL'] = quarry_module_2847b70.dll
                        quarry_symbol_dict_04773b8['Name'] = quarry_symbol_8c4d39f.name
                        quarry_symbol_dict_04773b8['Hint'] = quarry_symbol_8c4d39f.hint
                    if quarry_symbol_8c4d39f.bound:
                        quarry_symbol_dict_04773b8['Bound'] = quarry_symbol_8c4d39f.bound
                    quarry_module_list_4e7caec.append(quarry_symbol_dict_04773b8)
        if _name_boundary.has_attribute(quarry_self_877c971, 'DIRECTORY_ENTRY_RESOURCE'):
            quarry_dump_dict_8a6e28b['Resource directory'] = []
            quarry_dump_dict_8a6e28b['Resource directory'].append(_name_boundary.attributes(_name_boundary.attributes(quarry_self_877c971.DIRECTORY_ENTRY_RESOURCE)['struct'])['dump_dict']())
            for quarry_res_type_be29ee0 in quarry_self_877c971.DIRECTORY_ENTRY_RESOURCE.entries:
                quarry_resource_type_dict_c24e77a = {}
                if quarry_res_type_be29ee0.name is not None:
                    quarry_resource_type_dict_c24e77a['Name'] = quarry_res_type_be29ee0.name
                else:
                    quarry_resource_type_dict_c24e77a['Id'] = (_name_boundary.attributes(quarry_res_type_be29ee0)['struct'].Id, quarry_RESOURCE_TYPE.get(_name_boundary.attributes(quarry_res_type_be29ee0)['struct'].Id, '-'))
                quarry_resource_type_dict_c24e77a.update(_name_boundary.attributes(_name_boundary.attributes(quarry_res_type_be29ee0)['struct'])['dump_dict']())
                quarry_dump_dict_8a6e28b['Resource directory'].append(quarry_resource_type_dict_c24e77a)
                if _name_boundary.has_attribute(quarry_res_type_be29ee0, 'directory'):
                    quarry_directory_list_8618fb3 = [_name_boundary.attributes(_name_boundary.attributes(quarry_res_type_be29ee0.directory)['struct'])['dump_dict']()]
                    quarry_dump_dict_8a6e28b['Resource directory'].append(quarry_directory_list_8618fb3)
                    for quarry_resource_id_933fce8 in quarry_res_type_be29ee0.directory.entries:
                        quarry_resource_id_dict_f841ecd = {}
                        if quarry_resource_id_933fce8.name is not None:
                            quarry_resource_id_dict_f841ecd['Name'] = quarry_resource_id_933fce8.name
                        else:
                            quarry_resource_id_dict_f841ecd['Id'] = _name_boundary.attributes(quarry_resource_id_933fce8)['struct'].Id
                        quarry_resource_id_dict_f841ecd.update(_name_boundary.attributes(_name_boundary.attributes(quarry_resource_id_933fce8)['struct'])['dump_dict']())
                        quarry_directory_list_8618fb3.append(quarry_resource_id_dict_f841ecd)
                        if _name_boundary.has_attribute(quarry_resource_id_933fce8, 'directory'):
                            quarry_resource_id_list_4823f88 = [_name_boundary.attributes(_name_boundary.attributes(quarry_resource_id_933fce8.directory)['struct'])['dump_dict']()]
                            quarry_directory_list_8618fb3.append(quarry_resource_id_list_4823f88)
                            for quarry_resource_lang_af24b12 in quarry_resource_id_933fce8.directory.entries:
                                if _name_boundary.has_attribute(quarry_resource_lang_af24b12, 'data'):
                                    quarry_resource_lang_dict_6829805 = {'LANG': quarry_resource_lang_af24b12.data.lang, 'SUBLANG': quarry_resource_lang_af24b12.data.sublang, 'LANG_NAME': quarry_LANG.get(quarry_resource_lang_af24b12.data.lang, '*unknown*'), 'SUBLANG_NAME': quarry_get_sublang_name_for_lang(quarry_resource_lang_af24b12.data.lang, quarry_resource_lang_af24b12.data.sublang)}
                                    quarry_resource_lang_dict_6829805.update(_name_boundary.attributes(_name_boundary.attributes(quarry_resource_lang_af24b12)['struct'])['dump_dict']())
                                    quarry_resource_lang_dict_6829805.update(_name_boundary.attributes(_name_boundary.attributes(quarry_resource_lang_af24b12.data)['struct'])['dump_dict']())
                                    quarry_resource_id_list_4823f88.append(quarry_resource_lang_dict_6829805)
                            if _name_boundary.has_attribute(quarry_resource_id_933fce8.directory, 'strings') and quarry_resource_id_933fce8.directory.strings:
                                for quarry_idx_651b84c, quarry_res_string_9a31af6 in quarry_resource_id_933fce8.directory.strings.items():
                                    quarry_resource_id_list_4823f88.append(_name_boundary.attributes(quarry_res_string_9a31af6.encode('unicode-escape', 'backslashreplace'))['decode']('ascii'))
        if _name_boundary.has_attribute(quarry_self_877c971, 'DIRECTORY_ENTRY_TLS') and quarry_self_877c971.DIRECTORY_ENTRY_TLS and _name_boundary.attributes(quarry_self_877c971.DIRECTORY_ENTRY_TLS)['struct']:
            quarry_dump_dict_8a6e28b['TLS'] = _name_boundary.attributes(_name_boundary.attributes(quarry_self_877c971.DIRECTORY_ENTRY_TLS)['struct'])['dump_dict']()
        if _name_boundary.has_attribute(quarry_self_877c971, 'DIRECTORY_ENTRY_LOAD_CONFIG') and quarry_self_877c971.DIRECTORY_ENTRY_LOAD_CONFIG and _name_boundary.attributes(quarry_self_877c971.DIRECTORY_ENTRY_LOAD_CONFIG)['struct']:
            quarry_dump_dict_8a6e28b['LOAD_CONFIG'] = _name_boundary.attributes(_name_boundary.attributes(quarry_self_877c971.DIRECTORY_ENTRY_LOAD_CONFIG)['struct'])['dump_dict']()
        if _name_boundary.has_attribute(quarry_self_877c971, 'DIRECTORY_ENTRY_DEBUG'):
            quarry_dump_dict_8a6e28b['Debug information'] = []
            for quarry_dbg_0cacda5 in quarry_self_877c971.DIRECTORY_ENTRY_DEBUG:
                quarry_dbg_dict_11ae95f = {}
                quarry_dump_dict_8a6e28b['Debug information'].append(quarry_dbg_dict_11ae95f)
                quarry_dbg_dict_11ae95f.update(_name_boundary.attributes(_name_boundary.attributes(quarry_dbg_0cacda5)['struct'])['dump_dict']())
                quarry_dbg_dict_11ae95f['Type'] = quarry_DEBUG_TYPE.get(_name_boundary.attributes(quarry_dbg_0cacda5)['struct'].Type, _name_boundary.attributes(quarry_dbg_0cacda5)['struct'].Type)
        if _name_boundary.attributes(quarry_self_877c971)['has_relocs']():
            quarry_dump_dict_8a6e28b['Base relocations'] = []
            for quarry_base_reloc_5795b5a in quarry_self_877c971.DIRECTORY_ENTRY_BASERELOC:
                quarry_base_reloc_list_587e9ce = []
                quarry_dump_dict_8a6e28b['Base relocations'].append(quarry_base_reloc_list_587e9ce)
                quarry_base_reloc_list_587e9ce.append(_name_boundary.attributes(_name_boundary.attributes(quarry_base_reloc_5795b5a)['struct'])['dump_dict']())
                for quarry_reloc_dc437c4 in quarry_base_reloc_5795b5a.entries:
                    quarry_reloc_dict_cee8858 = {}
                    quarry_base_reloc_list_587e9ce.append(quarry_reloc_dict_cee8858)
                    quarry_reloc_dict_cee8858['RVA'] = quarry_reloc_dc437c4.rva
                    try:
                        quarry_reloc_dict_cee8858['Type'] = quarry_RELOCATION_TYPE[quarry_reloc_dc437c4.type][16:]
                    except KeyError:
                        quarry_reloc_dict_cee8858['Type'] = quarry_reloc_dc437c4.type
        return quarry_dump_dict_8a6e28b

    @_name_boundary.callable_contract({'self': 'quarry_self_3fb6305', 'rva': 'quarry_rva_bd155fd'}, 'get_physical_by_rva')
    def quarry_get_physical_by_rva(quarry_self_3fb6305, quarry_rva_bd155fd):
        """Gets the physical address in the PE file from an RVA value."""
        try:
            return _name_boundary.attributes(quarry_self_3fb6305)['get_offset_from_rva'](quarry_rva_bd155fd)
        except Exception:
            return None

    @staticmethod
    @_name_boundary.callable_contract({'dword': 'quarry_dword_fc284aa'}, 'get_data_from_dword')
    def quarry_get_data_from_dword(quarry_dword_fc284aa):
        """Return a four byte string representing the double word value (little endian)."""
        return quarry_struct.pack('<L', quarry_dword_fc284aa & 4294967295)

    @staticmethod
    @_name_boundary.callable_contract({'data': 'quarry_data_local_f0b9285', 'offset': 'quarry_offset_local_094af56'}, 'get_dword_from_data')
    def quarry_get_dword_from_data(quarry_data_local_f0b9285, quarry_offset_local_094af56):
        """Convert four bytes of data to a double word (little endian)

        'offset' is assumed to index into a dword array. So setting it to
        N will return a dword out of the data starting at offset N*4.

        Returns None if the data can't be turned into a double word.
        """
        if (quarry_offset_local_094af56 + 1) * 4 > len(quarry_data_local_f0b9285):
            return None
        return quarry_struct.unpack('<I', quarry_data_local_f0b9285[quarry_offset_local_094af56 * 4:(quarry_offset_local_094af56 + 1) * 4])[0]

    @_name_boundary.callable_contract({'self': 'quarry_self_97d1a3d', 'rva': 'quarry_rva_8559fbe'}, 'get_dword_at_rva')
    def quarry_get_dword_at_rva(quarry_self_97d1a3d, quarry_rva_8559fbe):
        """Return the double word value at the given RVA.

        Returns None if the value can't be read, i.e. the RVA can't be mapped
        to a file offset.
        """
        try:
            return _name_boundary.attributes(quarry_self_97d1a3d)['get_dword_from_data'](_name_boundary.attributes(quarry_self_97d1a3d)['get_data'](quarry_rva_8559fbe, 4), 0)
        except quarry_PEFormatError:
            return None

    @_name_boundary.callable_contract({'self': 'quarry_self_91d79d5', 'offset': 'quarry_offset_local_ae305ac'}, 'get_dword_from_offset')
    def quarry_get_dword_from_offset(quarry_self_91d79d5, quarry_offset_local_ae305ac):
        """Return the double word value at the given file offset. (little endian)"""
        if quarry_offset_local_ae305ac + 4 > len(quarry_self_91d79d5.__data__):
            return None
        return _name_boundary.attributes(quarry_self_91d79d5)['get_dword_from_data'](quarry_self_91d79d5.__data__[quarry_offset_local_ae305ac:quarry_offset_local_ae305ac + 4], 0)

    @_name_boundary.callable_contract({'self': 'quarry_self_141fd4b', 'rva': 'quarry_rva_8382e11', 'dword': 'quarry_dword_bf0b09d'}, 'set_dword_at_rva')
    def quarry_set_dword_at_rva(quarry_self_141fd4b, quarry_rva_8382e11, quarry_dword_bf0b09d):
        """Set the double word value at the file offset corresponding to the given RVA."""
        return _name_boundary.attributes(quarry_self_141fd4b)['set_bytes_at_rva'](quarry_rva_8382e11, _name_boundary.attributes(quarry_self_141fd4b)['get_data_from_dword'](quarry_dword_bf0b09d))

    @_name_boundary.callable_contract({'self': 'quarry_self_f4eb0aa', 'dword': 'quarry_dword_a98daba', 'offset': 'quarry_offset_local_55057ca'}, 'set_dword_at_offset')
    def quarry_set_dword_at_offset(quarry_self_f4eb0aa, quarry_offset_local_55057ca, quarry_dword_a98daba):
        """Set the double word value at the given file offset."""
        return _name_boundary.attributes(quarry_self_f4eb0aa)['set_bytes_at_offset'](quarry_offset_local_55057ca, _name_boundary.attributes(quarry_self_f4eb0aa)['get_data_from_dword'](quarry_dword_a98daba))

    @staticmethod
    @_name_boundary.callable_contract({'word': 'quarry_word_b82480c'}, 'get_data_from_word')
    def quarry_get_data_from_word(quarry_word_b82480c):
        """Return a two byte string representing the word value. (little endian)."""
        return quarry_struct.pack('<H', quarry_word_b82480c)

    @staticmethod
    @_name_boundary.callable_contract({'data': 'quarry_data_local_f0bec91', 'offset': 'quarry_offset_local_0581fdd'}, 'get_word_from_data')
    def quarry_get_word_from_data(quarry_data_local_f0bec91, quarry_offset_local_0581fdd):
        """Convert two bytes of data to a word (little endian)

        'offset' is assumed to index into a word array. So setting it to
        N will return a dword out of the data starting at offset N*2.

        Returns None if the data can't be turned into a word.
        """
        if (quarry_offset_local_0581fdd + 1) * 2 > len(quarry_data_local_f0bec91):
            return None
        return quarry_struct.unpack('<H', quarry_data_local_f0bec91[quarry_offset_local_0581fdd * 2:(quarry_offset_local_0581fdd + 1) * 2])[0]

    @_name_boundary.callable_contract({'self': 'quarry_self_d0561d4', 'rva': 'quarry_rva_197d618'}, 'get_word_at_rva')
    def quarry_get_word_at_rva(quarry_self_d0561d4, quarry_rva_197d618):
        """Return the word value at the given RVA.

        Returns None if the value can't be read, i.e. the RVA can't be mapped
        to a file offset.
        """
        try:
            return _name_boundary.attributes(quarry_self_d0561d4)['get_word_from_data'](_name_boundary.attributes(quarry_self_d0561d4)['get_data'](quarry_rva_197d618)[:2], 0)
        except quarry_PEFormatError:
            return None

    @_name_boundary.callable_contract({'self': 'quarry_self_366ab23', 'offset': 'quarry_offset_local_e3b9a45'}, 'get_word_from_offset')
    def quarry_get_word_from_offset(quarry_self_366ab23, quarry_offset_local_e3b9a45):
        """Return the word value at the given file offset. (little endian)"""
        if quarry_offset_local_e3b9a45 + 2 > len(quarry_self_366ab23.__data__):
            return None
        return _name_boundary.attributes(quarry_self_366ab23)['get_word_from_data'](quarry_self_366ab23.__data__[quarry_offset_local_e3b9a45:quarry_offset_local_e3b9a45 + 2], 0)

    @_name_boundary.callable_contract({'self': 'quarry_self_ad64d99', 'rva': 'quarry_rva_473fce0', 'word': 'quarry_word_d75a3b2'}, 'set_word_at_rva')
    def quarry_set_word_at_rva(quarry_self_ad64d99, quarry_rva_473fce0, quarry_word_d75a3b2):
        """Set the word value at the file offset corresponding to the given RVA."""
        return _name_boundary.attributes(quarry_self_ad64d99)['set_bytes_at_rva'](quarry_rva_473fce0, _name_boundary.attributes(quarry_self_ad64d99)['get_data_from_word'](quarry_word_d75a3b2))

    @_name_boundary.callable_contract({'self': 'quarry_self_099d520', 'word': 'quarry_word_33e04cb', 'offset': 'quarry_offset_local_4a7e5a0'}, 'set_word_at_offset')
    def quarry_set_word_at_offset(quarry_self_099d520, quarry_offset_local_4a7e5a0, quarry_word_33e04cb):
        """Set the word value at the given file offset."""
        return _name_boundary.attributes(quarry_self_099d520)['set_bytes_at_offset'](quarry_offset_local_4a7e5a0, _name_boundary.attributes(quarry_self_099d520)['get_data_from_word'](quarry_word_33e04cb))

    @staticmethod
    @_name_boundary.callable_contract({'word': 'quarry_word_9579d0c'}, 'get_data_from_qword')
    def quarry_get_data_from_qword(quarry_word_9579d0c):
        """Return an eight byte string representing the quad-word value (little endian)."""
        return quarry_struct.pack('<Q', quarry_word_9579d0c)

    @staticmethod
    @_name_boundary.callable_contract({'data': 'quarry_data_local_aae0718', 'offset': 'quarry_offset_local_ae3c3c1'}, 'get_qword_from_data')
    def quarry_get_qword_from_data(quarry_data_local_aae0718, quarry_offset_local_ae3c3c1):
        """Convert eight bytes of data to a word (little endian)

        'offset' is assumed to index into a word array. So setting it to
        N will return a dword out of the data starting at offset N*8.

        Returns None if the data can't be turned into a quad word.
        """
        if (quarry_offset_local_ae3c3c1 + 1) * 8 > len(quarry_data_local_aae0718):
            return None
        return quarry_struct.unpack('<Q', quarry_data_local_aae0718[quarry_offset_local_ae3c3c1 * 8:(quarry_offset_local_ae3c3c1 + 1) * 8])[0]

    @_name_boundary.callable_contract({'self': 'quarry_self_3f8b111', 'rva': 'quarry_rva_1e721aa'}, 'get_qword_at_rva')
    def quarry_get_qword_at_rva(quarry_self_3f8b111, quarry_rva_1e721aa):
        """Return the quad-word value at the given RVA.

        Returns None if the value can't be read, i.e. the RVA can't be mapped
        to a file offset.
        """
        try:
            return _name_boundary.attributes(quarry_self_3f8b111)['get_qword_from_data'](_name_boundary.attributes(quarry_self_3f8b111)['get_data'](quarry_rva_1e721aa)[:8], 0)
        except quarry_PEFormatError:
            return None

    @_name_boundary.callable_contract({'self': 'quarry_self_8eaced9', 'offset': 'quarry_offset_local_db5deaa'}, 'get_qword_from_offset')
    def quarry_get_qword_from_offset(quarry_self_8eaced9, quarry_offset_local_db5deaa):
        """Return the quad-word value at the given file offset. (little endian)"""
        if quarry_offset_local_db5deaa + 8 > len(quarry_self_8eaced9.__data__):
            return None
        return _name_boundary.attributes(quarry_self_8eaced9)['get_qword_from_data'](quarry_self_8eaced9.__data__[quarry_offset_local_db5deaa:quarry_offset_local_db5deaa + 8], 0)

    @_name_boundary.callable_contract({'self': 'quarry_self_7fa7801', 'rva': 'quarry_rva_2a36d48', 'qword': 'quarry_qword_6c1440d'}, 'set_qword_at_rva')
    def quarry_set_qword_at_rva(quarry_self_7fa7801, quarry_rva_2a36d48, quarry_qword_6c1440d):
        """Set the quad-word value at the file offset corresponding to the given RVA."""
        return _name_boundary.attributes(quarry_self_7fa7801)['set_bytes_at_rva'](quarry_rva_2a36d48, _name_boundary.attributes(quarry_self_7fa7801)['get_data_from_qword'](quarry_qword_6c1440d))

    @_name_boundary.callable_contract({'self': 'quarry_self_7a7b5e7', 'qword': 'quarry_qword_ee2fa94', 'offset': 'quarry_offset_local_754c47e'}, 'set_qword_at_offset')
    def quarry_set_qword_at_offset(quarry_self_7a7b5e7, quarry_offset_local_754c47e, quarry_qword_ee2fa94):
        """Set the quad-word value at the given file offset."""
        return _name_boundary.attributes(quarry_self_7a7b5e7)['set_bytes_at_offset'](quarry_offset_local_754c47e, _name_boundary.attributes(quarry_self_7a7b5e7)['get_data_from_qword'](quarry_qword_ee2fa94))

    @_name_boundary.callable_contract({'self': 'quarry_self_4559606', 'rva': 'quarry_rva_edfde98', 'data': 'quarry_data_local_dbcf8b8'}, 'set_bytes_at_rva')
    def quarry_set_bytes_at_rva(quarry_self_4559606, quarry_rva_edfde98, quarry_data_local_dbcf8b8):
        """Overwrite, with the given string, the bytes at the file offset corresponding
        to the given RVA.

        Return True if successful, False otherwise. It can fail if the
        offset is outside the file's boundaries.
        """
        if not isinstance(quarry_data_local_dbcf8b8, bytes):
            raise TypeError('data should be of type: bytes')
        quarry_offset_local_ab84a15 = _name_boundary.attributes(quarry_self_4559606)['get_physical_by_rva'](quarry_rva_edfde98)
        if quarry_offset_local_ab84a15 is None:
            return False
        return _name_boundary.attributes(quarry_self_4559606)['set_bytes_at_offset'](quarry_offset_local_ab84a15, quarry_data_local_dbcf8b8)

    @_name_boundary.callable_contract({'self': 'quarry_self_777fff4', 'offset': 'quarry_offset_local_e0d379a', 'data': 'quarry_data_local_f87710a'}, 'set_bytes_at_offset')
    def quarry_set_bytes_at_offset(quarry_self_777fff4, quarry_offset_local_e0d379a, quarry_data_local_f87710a):
        """Overwrite the bytes at the given file offset with the given string.

        Return True if successful, False otherwise. It can fail if the
        offset is outside the file's boundaries.
        """
        if not isinstance(quarry_data_local_f87710a, bytes):
            raise TypeError('data should be of type: bytes')
        if type(quarry_offset_local_e0d379a) is int and 0 <= quarry_offset_local_e0d379a <= len(quarry_self_777fff4.__data__) and len(quarry_data_local_f87710a) <= len(quarry_self_777fff4.__data__) - quarry_offset_local_e0d379a:
            _name_boundary.attributes(quarry_self_777fff4)['set_data_bytes'](quarry_offset_local_e0d379a, quarry_data_local_f87710a)
        else:
            return False
        return True

    @_name_boundary.callable_contract({'self': 'quarry_self_f6d9d8a', 'offset': 'quarry_offset_local_d98f92d', 'data': 'quarry_data_local_c4c54db'}, 'set_data_bytes')
    def quarry_set_data_bytes(quarry_self_f6d9d8a, quarry_offset_local_d98f92d: int, quarry_data_local_c4c54db: bytes):
        if not isinstance(quarry_data_local_c4c54db, bytes):
            raise TypeError('data should be of type: bytes')
        if type(quarry_offset_local_d98f92d) is not int or quarry_offset_local_d98f92d < 0 or quarry_offset_local_d98f92d > len(quarry_self_f6d9d8a.__data__) or len(quarry_data_local_c4c54db) > len(quarry_self_f6d9d8a.__data__) - quarry_offset_local_d98f92d:
            raise quarry_PEFormatError('byte edit span is outside the file')
        if not isinstance(quarry_self_f6d9d8a.__data__, bytearray):
            quarry_new_data_fc01f76 = bytearray(quarry_self_f6d9d8a.__data__)
            _name_boundary.attributes(quarry_self_f6d9d8a)['_close_data']()
            quarry_self_f6d9d8a.__data__ = quarry_new_data_fc01f76
        quarry_self_f6d9d8a.__data__[quarry_offset_local_d98f92d:quarry_offset_local_d98f92d + len(quarry_data_local_c4c54db)] = quarry_data_local_c4c54db

    @_name_boundary.callable_contract({'self': 'quarry_self_2a36c06'}, 'merge_modified_section_data')
    def quarry_merge_modified_section_data(quarry_self_2a36c06):
        """Update the PE image content with any individual section data that has been
        modified.
        """
        for quarry_section_0032159 in _name_boundary.attributes(quarry_self_2a36c06)['sections']:
            quarry_section_data_start_cd8abbe = _name_boundary.attributes(quarry_self_2a36c06)['adjust_PointerToRawData'](quarry_section_0032159.PointerToRawData)
            quarry_section_data_end_2778317 = quarry_section_data_start_cd8abbe + quarry_section_0032159.SizeOfRawData
            if quarry_section_data_start_cd8abbe < len(quarry_self_2a36c06.__data__) and quarry_section_data_end_2778317 < len(quarry_self_2a36c06.__data__):
                _name_boundary.attributes(quarry_self_2a36c06)['set_data_bytes'](quarry_section_data_start_cd8abbe, _name_boundary.attributes(quarry_section_0032159)['get_data']())

    @_name_boundary.callable_contract({'self': 'quarry_self_bc4b3eb', 'new_ImageBase': 'quarry_new_ImageBase_cb501c9'}, 'relocate_image')
    def quarry_relocate_image(quarry_self_bc4b3eb, quarry_new_ImageBase_cb501c9):
        """Apply the relocation information to the image using the provided image base.

        This method will apply the relocation information to the image. Given the new
        base, all the relocations will be processed and both the raw data and the
        section's data will be fixed accordingly.
        The resulting image can be retrieved as well through the method:

            get_memory_mapped_image()

        In order to get something that would more closely match what could be found in
        memory once the Windows loader finished its work.
        """
        quarry_relocation_difference_2b60726 = quarry_new_ImageBase_cb501c9 - _name_boundary.attributes(quarry_self_bc4b3eb)['OPTIONAL_HEADER'].ImageBase
        if len(_name_boundary.attributes(quarry_self_bc4b3eb)['OPTIONAL_HEADER'].DATA_DIRECTORY) >= 6 and _name_boundary.attributes(quarry_self_bc4b3eb)['OPTIONAL_HEADER'].DATA_DIRECTORY[5].Size:
            if not _name_boundary.has_attribute(quarry_self_bc4b3eb, 'DIRECTORY_ENTRY_BASERELOC'):
                _name_boundary.attributes(quarry_self_bc4b3eb)['parse_data_directories'](directories=[quarry_DIRECTORY_ENTRY['IMAGE_DIRECTORY_ENTRY_BASERELOC']])
            if not _name_boundary.has_attribute(quarry_self_bc4b3eb, 'DIRECTORY_ENTRY_BASERELOC'):
                _name_boundary.attributes(quarry_self_bc4b3eb)['__warnings'].append('Relocating image but PE does not have (or pefile cannot parse) a DIRECTORY_ENTRY_BASERELOC')
            else:
                for quarry_reloc_997e8bd in quarry_self_bc4b3eb.DIRECTORY_ENTRY_BASERELOC:
                    quarry_entry_idx_55a24d6 = 0
                    while quarry_entry_idx_55a24d6 < len(quarry_reloc_997e8bd.entries):
                        quarry_entry_950b510 = quarry_reloc_997e8bd.entries[quarry_entry_idx_55a24d6]
                        quarry_entry_idx_55a24d6 += 1
                        if quarry_entry_950b510.type == quarry_RELOCATION_TYPE['IMAGE_REL_BASED_ABSOLUTE']:
                            pass
                        elif quarry_entry_950b510.type == quarry_RELOCATION_TYPE['IMAGE_REL_BASED_HIGH']:
                            _name_boundary.attributes(quarry_self_bc4b3eb)['set_word_at_rva'](quarry_entry_950b510.rva, _name_boundary.attributes(quarry_self_bc4b3eb)['get_word_at_rva'](quarry_entry_950b510.rva) + quarry_relocation_difference_2b60726 >> 16 & 65535)
                        elif quarry_entry_950b510.type == quarry_RELOCATION_TYPE['IMAGE_REL_BASED_LOW']:
                            _name_boundary.attributes(quarry_self_bc4b3eb)['set_word_at_rva'](quarry_entry_950b510.rva, _name_boundary.attributes(quarry_self_bc4b3eb)['get_word_at_rva'](quarry_entry_950b510.rva) + quarry_relocation_difference_2b60726 & 65535)
                        elif quarry_entry_950b510.type == quarry_RELOCATION_TYPE['IMAGE_REL_BASED_HIGHLOW']:
                            _name_boundary.attributes(quarry_self_bc4b3eb)['set_dword_at_rva'](quarry_entry_950b510.rva, _name_boundary.attributes(quarry_self_bc4b3eb)['get_dword_at_rva'](quarry_entry_950b510.rva) + quarry_relocation_difference_2b60726)
                        elif quarry_entry_950b510.type == quarry_RELOCATION_TYPE['IMAGE_REL_BASED_HIGHADJ']:
                            if quarry_entry_idx_55a24d6 == len(quarry_reloc_997e8bd.entries):
                                break
                            quarry_next_entry_5d96d3a = quarry_reloc_997e8bd.entries[quarry_entry_idx_55a24d6]
                            quarry_entry_idx_55a24d6 += 1
                            _name_boundary.attributes(quarry_self_bc4b3eb)['set_word_at_rva'](quarry_entry_950b510.rva, ((_name_boundary.attributes(quarry_self_bc4b3eb)['get_word_at_rva'](quarry_entry_950b510.rva) << 16) + quarry_next_entry_5d96d3a.rva + quarry_relocation_difference_2b60726 & 4294901760) >> 16)
                        elif quarry_entry_950b510.type == quarry_RELOCATION_TYPE['IMAGE_REL_BASED_DIR64']:
                            _name_boundary.attributes(quarry_self_bc4b3eb)['set_qword_at_rva'](quarry_entry_950b510.rva, _name_boundary.attributes(quarry_self_bc4b3eb)['get_qword_at_rva'](quarry_entry_950b510.rva) + quarry_relocation_difference_2b60726)
            _name_boundary.attributes(quarry_self_bc4b3eb)['OPTIONAL_HEADER'].ImageBase = quarry_new_ImageBase_cb501c9
            if _name_boundary.has_attribute(quarry_self_bc4b3eb, 'DIRECTORY_ENTRY_IMPORT'):
                for quarry_dll_74e9346 in quarry_self_bc4b3eb.DIRECTORY_ENTRY_IMPORT:
                    for quarry_func_19e14ef in quarry_dll_74e9346.imports:
                        quarry_func_19e14ef.address += quarry_relocation_difference_2b60726
            if _name_boundary.has_attribute(quarry_self_bc4b3eb, 'DIRECTORY_ENTRY_TLS'):
                _name_boundary.attributes(quarry_self_bc4b3eb.DIRECTORY_ENTRY_TLS)['struct'].StartAddressOfRawData += quarry_relocation_difference_2b60726
                _name_boundary.attributes(quarry_self_bc4b3eb.DIRECTORY_ENTRY_TLS)['struct'].EndAddressOfRawData += quarry_relocation_difference_2b60726
                _name_boundary.attributes(quarry_self_bc4b3eb.DIRECTORY_ENTRY_TLS)['struct'].AddressOfIndex += quarry_relocation_difference_2b60726
                _name_boundary.attributes(quarry_self_bc4b3eb.DIRECTORY_ENTRY_TLS)['struct'].AddressOfCallBacks += quarry_relocation_difference_2b60726
            if _name_boundary.has_attribute(quarry_self_bc4b3eb, 'DIRECTORY_ENTRY_LOAD_CONFIG'):
                quarry_load_config_0af0c81 = _name_boundary.attributes(quarry_self_bc4b3eb.DIRECTORY_ENTRY_LOAD_CONFIG)['struct']
                if _name_boundary.has_attribute(quarry_load_config_0af0c81, 'LockPrefixTable') and quarry_load_config_0af0c81.LockPrefixTable:
                    quarry_load_config_0af0c81.LockPrefixTable += quarry_relocation_difference_2b60726
                if _name_boundary.has_attribute(quarry_load_config_0af0c81, 'EditList') and quarry_load_config_0af0c81.EditList:
                    quarry_load_config_0af0c81.EditList += quarry_relocation_difference_2b60726
                if _name_boundary.has_attribute(quarry_load_config_0af0c81, 'SecurityCookie') and quarry_load_config_0af0c81.SecurityCookie:
                    quarry_load_config_0af0c81.SecurityCookie += quarry_relocation_difference_2b60726
                if _name_boundary.has_attribute(quarry_load_config_0af0c81, 'SEHandlerTable') and quarry_load_config_0af0c81.SEHandlerTable:
                    quarry_load_config_0af0c81.SEHandlerTable += quarry_relocation_difference_2b60726
                if _name_boundary.has_attribute(quarry_load_config_0af0c81, 'GuardCFCheckFunctionPointer') and quarry_load_config_0af0c81.GuardCFCheckFunctionPointer:
                    quarry_load_config_0af0c81.GuardCFCheckFunctionPointer += quarry_relocation_difference_2b60726
                if _name_boundary.has_attribute(quarry_load_config_0af0c81, 'GuardCFDispatchFunctionPointer') and quarry_load_config_0af0c81.GuardCFDispatchFunctionPointer:
                    quarry_load_config_0af0c81.GuardCFDispatchFunctionPointer += quarry_relocation_difference_2b60726
                if _name_boundary.has_attribute(quarry_load_config_0af0c81, 'GuardCFFunctionTable') and quarry_load_config_0af0c81.GuardCFFunctionTable:
                    quarry_load_config_0af0c81.GuardCFFunctionTable += quarry_relocation_difference_2b60726
                if _name_boundary.has_attribute(quarry_load_config_0af0c81, 'GuardAddressTakenIatEntryTable') and quarry_load_config_0af0c81.GuardAddressTakenIatEntryTable:
                    quarry_load_config_0af0c81.GuardAddressTakenIatEntryTable += quarry_relocation_difference_2b60726
                if _name_boundary.has_attribute(quarry_load_config_0af0c81, 'GuardLongJumpTargetTable') and quarry_load_config_0af0c81.GuardLongJumpTargetTable:
                    quarry_load_config_0af0c81.GuardLongJumpTargetTable += quarry_relocation_difference_2b60726
                if _name_boundary.has_attribute(quarry_load_config_0af0c81, 'DynamicValueRelocTable') and quarry_load_config_0af0c81.DynamicValueRelocTable:
                    quarry_load_config_0af0c81.DynamicValueRelocTable += quarry_relocation_difference_2b60726
                if _name_boundary.attributes(quarry_self_bc4b3eb)['PE_TYPE'] == quarry_OPTIONAL_HEADER_MAGIC_PE_PLUS and _name_boundary.has_attribute(quarry_load_config_0af0c81, 'CHPEMetadataPointer') and quarry_load_config_0af0c81.CHPEMetadataPointer:
                    quarry_load_config_0af0c81.CHPEMetadataPointer += quarry_relocation_difference_2b60726
                if _name_boundary.has_attribute(quarry_load_config_0af0c81, 'GuardRFFailureRoutine') and quarry_load_config_0af0c81.GuardRFFailureRoutine:
                    quarry_load_config_0af0c81.GuardRFFailureRoutine += quarry_relocation_difference_2b60726
                if _name_boundary.has_attribute(quarry_load_config_0af0c81, 'GuardRFFailureRoutineFunctionPointer') and quarry_load_config_0af0c81.GuardRFFailureRoutineFunctionPointer:
                    quarry_load_config_0af0c81.GuardRFVerifyStackPointerFunctionPointer += quarry_relocation_difference_2b60726
                if _name_boundary.has_attribute(quarry_load_config_0af0c81, 'GuardRFVerifyStackPointerFunctionPointer') and quarry_load_config_0af0c81.GuardRFVerifyStackPointerFunctionPointer:
                    quarry_load_config_0af0c81.GuardRFVerifyStackPointerFunctionPointer += quarry_relocation_difference_2b60726
                if _name_boundary.has_attribute(quarry_load_config_0af0c81, 'EnclaveConfigurationPointer') and quarry_load_config_0af0c81.EnclaveConfigurationPointer:
                    quarry_load_config_0af0c81.EnclaveConfigurationPointer += quarry_relocation_difference_2b60726
                if _name_boundary.has_attribute(quarry_load_config_0af0c81, 'VolatileMetadataPointer') and quarry_load_config_0af0c81.VolatileMetadataPointer:
                    quarry_load_config_0af0c81.VolatileMetadataPointer += quarry_relocation_difference_2b60726
                if _name_boundary.has_attribute(quarry_load_config_0af0c81, 'GuardEHContinuationTable') and quarry_load_config_0af0c81.GuardEHContinuationTable:
                    quarry_load_config_0af0c81.GuardEHContinuationTable += quarry_relocation_difference_2b60726
                if _name_boundary.has_attribute(quarry_load_config_0af0c81, 'GuardXFGCheckFunctionPointer') and quarry_load_config_0af0c81.GuardXFGCheckFunctionPointer:
                    quarry_load_config_0af0c81.GuardXFGCheckFunctionPointer += quarry_relocation_difference_2b60726
                if _name_boundary.has_attribute(quarry_load_config_0af0c81, 'GuardXFGDispatchFunctionPointer') and quarry_load_config_0af0c81.GuardXFGDispatchFunctionPointer:
                    quarry_load_config_0af0c81.GuardXFGDispatchFunctionPointer += quarry_relocation_difference_2b60726
                if _name_boundary.has_attribute(quarry_load_config_0af0c81, 'GuardXFGTableDispatchFunctionPointer') and quarry_load_config_0af0c81.GuardXFGTableDispatchFunctionPointer:
                    quarry_load_config_0af0c81.GuardXFGTableDispatchFunctionPointer += quarry_relocation_difference_2b60726
                if _name_boundary.has_attribute(quarry_load_config_0af0c81, 'CastGuardOsDeterminedFailureMode') and quarry_load_config_0af0c81.CastGuardOsDeterminedFailureMode:
                    quarry_load_config_0af0c81.CastGuardOsDeterminedFailureMode += quarry_relocation_difference_2b60726
                if _name_boundary.has_attribute(quarry_load_config_0af0c81, 'GuardMemcpyFunctionPointer') and quarry_load_config_0af0c81.GuardMemcpyFunctionPointer:
                    quarry_load_config_0af0c81.GuardMemcpyFunctionPointer += quarry_relocation_difference_2b60726

    @_name_boundary.callable_contract({'self': 'quarry_self_7b4a1ab'}, 'verify_checksum')
    def quarry_verify_checksum(quarry_self_7b4a1ab):
        return _name_boundary.attributes(quarry_self_7b4a1ab)['OPTIONAL_HEADER'].CheckSum == _name_boundary.attributes(quarry_self_7b4a1ab)['generate_checksum']()

    @_name_boundary.callable_contract({'self': 'quarry_self'}, 'generate_checksum')
    def quarry_generate_checksum(quarry_self):
        """Fold explicit little-endian words, excluding the checksum field."""
        quarry_data = quarry_self.write()
        quarry_self._close_data()
        quarry_self.__data__ = quarry_data
        quarry_checksum_offset = quarry_self.OPTIONAL_HEADER.get_file_offset() + 64
        quarry_sum = 0
        for quarry_offset in range(0, len(quarry_data), 4):
            if quarry_offset // 4 == quarry_checksum_offset // 4:
                continue
            quarry_word = int.from_bytes(quarry_data[quarry_offset:quarry_offset + 4], 'little')
            quarry_sum += quarry_word
            quarry_sum = (quarry_sum & 0xffffffff) + (quarry_sum >> 32)
        quarry_sum = (quarry_sum & 0xffff) + (quarry_sum >> 16)
        quarry_sum += quarry_sum >> 16
        return (quarry_sum & 0xffff) + len(quarry_data)

    @_name_boundary.callable_contract({'self': 'quarry_self_e1e2a32'}, 'is_exe')
    def quarry_is_exe(quarry_self_e1e2a32):
        """Check whether the file is a standard executable.

        This will return true only if the file has the IMAGE_FILE_EXECUTABLE_IMAGE flag
        set and the IMAGE_FILE_DLL not set and the file does not appear to be a driver
        either.
        """
        quarry_EXE_flag_5d838e6 = quarry_IMAGE_CHARACTERISTICS['IMAGE_FILE_EXECUTABLE_IMAGE']
        return quarry_EXE_flag_5d838e6 & _name_boundary.attributes(quarry_self_e1e2a32)['FILE_HEADER'].Characteristics and (not _name_boundary.attributes(quarry_self_e1e2a32)['is_dll']()) and (not _name_boundary.attributes(quarry_self_e1e2a32)['is_driver']())

    @_name_boundary.callable_contract({'self': 'quarry_self_0e09977'}, 'is_dll')
    def quarry_is_dll(quarry_self_0e09977):
        """Check whether the file is a standard DLL.

        This will return true only if the image has the IMAGE_FILE_DLL flag set.
        """
        quarry_DLL_flag_3f30edf = quarry_IMAGE_CHARACTERISTICS['IMAGE_FILE_DLL']
        return bool(quarry_DLL_flag_3f30edf & _name_boundary.attributes(quarry_self_0e09977)['FILE_HEADER'].Characteristics)

    @_name_boundary.callable_contract({'self': 'quarry_self_c4564e3'}, 'is_driver')
    def quarry_is_driver(quarry_self_c4564e3):
        """Check whether the file is a Windows driver.

        This will return true only if there are reliable indicators of the image
        being a driver.
        """
        if not _name_boundary.has_attribute(quarry_self_c4564e3, 'DIRECTORY_ENTRY_IMPORT'):
            _name_boundary.attributes(quarry_self_c4564e3)['parse_data_directories'](directories=[quarry_DIRECTORY_ENTRY['IMAGE_DIRECTORY_ENTRY_IMPORT']])
        if not _name_boundary.has_attribute(quarry_self_c4564e3, 'DIRECTORY_ENTRY_IMPORT'):
            return False
        quarry_system_DLLs_0cc9308 = {b'ntoskrnl.exe', b'hal.dll', b'ndis.sys', b'bootvid.dll', b'kdcom.dll'}
        if quarry_system_DLLs_0cc9308.intersection({quarry_imp_ec63d75.dll.lower() for quarry_imp_ec63d75 in quarry_self_c4564e3.DIRECTORY_ENTRY_IMPORT}):
            return True
        quarry_driver_like_section_names_85520ea = {b'page', b'paged'}
        return quarry_driver_like_section_names_85520ea.intersection({quarry_section_7e91897.Name.lower().rstrip(b'\x00') for quarry_section_7e91897 in _name_boundary.attributes(quarry_self_c4564e3)['sections']}) and _name_boundary.attributes(quarry_self_c4564e3)['OPTIONAL_HEADER'].Subsystem in (quarry_SUBSYSTEM_TYPE['IMAGE_SUBSYSTEM_NATIVE'], quarry_SUBSYSTEM_TYPE['IMAGE_SUBSYSTEM_NATIVE_WINDOWS'])

    @_name_boundary.callable_contract({'self': 'quarry_self_32bdfba'}, 'get_overlay_data_start_offset')
    def quarry_get_overlay_data_start_offset(quarry_self_32bdfba):
        """Get the offset of data appended to the file and not contained within
        the area described in the headers."""
        quarry_largest_offset_and_size_dcd9cfa = (0, 0)

        @_name_boundary.callable_contract({'offset_and_size': 'quarry_offset_and_size_fd95be3', 'file_size': 'quarry_file_size_1b5121a'}, 'update_if_sum_is_larger_and_within_file')
        def quarry_update_if_sum_is_larger_and_within_file_406d955(quarry_offset_and_size_fd95be3, quarry_file_size_1b5121a=len(quarry_self_32bdfba.__data__)):
            if sum(quarry_largest_offset_and_size_dcd9cfa) < sum(quarry_offset_and_size_fd95be3) <= quarry_file_size_1b5121a:
                return quarry_offset_and_size_fd95be3
            return quarry_largest_offset_and_size_dcd9cfa
        if _name_boundary.has_attribute(quarry_self_32bdfba, 'OPTIONAL_HEADER'):
            quarry_largest_offset_and_size_dcd9cfa = quarry_update_if_sum_is_larger_and_within_file_406d955((_name_boundary.attributes(_name_boundary.attributes(quarry_self_32bdfba)['OPTIONAL_HEADER'])['get_file_offset'](), _name_boundary.attributes(quarry_self_32bdfba)['FILE_HEADER'].SizeOfOptionalHeader))
        for quarry_section_654e997 in _name_boundary.attributes(quarry_self_32bdfba)['sections']:
            quarry_largest_offset_and_size_dcd9cfa = quarry_update_if_sum_is_larger_and_within_file_406d955((quarry_section_654e997.PointerToRawData, quarry_section_654e997.SizeOfRawData))
        quarry_skip_directories_91e8d35 = [quarry_DIRECTORY_ENTRY['IMAGE_DIRECTORY_ENTRY_SECURITY']]
        for quarry_idx_168ce51, quarry_directory_92c98db in enumerate(_name_boundary.attributes(quarry_self_32bdfba)['OPTIONAL_HEADER'].DATA_DIRECTORY):
            if quarry_idx_168ce51 in quarry_skip_directories_91e8d35:
                continue
            try:
                quarry_largest_offset_and_size_dcd9cfa = quarry_update_if_sum_is_larger_and_within_file_406d955((_name_boundary.attributes(quarry_self_32bdfba)['get_offset_from_rva'](quarry_directory_92c98db.VirtualAddress), quarry_directory_92c98db.Size))
            except quarry_PEFormatError:
                continue
        if len(quarry_self_32bdfba.__data__) > sum(quarry_largest_offset_and_size_dcd9cfa):
            return sum(quarry_largest_offset_and_size_dcd9cfa)
        return None

    @_name_boundary.callable_contract({'self': 'quarry_self_a8a008b'}, 'get_overlay')
    def quarry_get_overlay(quarry_self_a8a008b):
        """Get the data appended to the file and not contained within the area described
        in the headers."""
        quarry_overlay_data_offset_8e7a291 = _name_boundary.attributes(quarry_self_a8a008b)['get_overlay_data_start_offset']()
        if quarry_overlay_data_offset_8e7a291 is not None:
            return quarry_self_a8a008b.__data__[quarry_overlay_data_offset_8e7a291:]
        return None

    @_name_boundary.callable_contract({'self': 'quarry_self_d88f816'}, 'trim')
    def quarry_trim(quarry_self_d88f816):
        """Return just the data defined by the PE headers, removing any overlaid data."""
        quarry_overlay_data_offset_91a644d = _name_boundary.attributes(quarry_self_d88f816)['get_overlay_data_start_offset']()
        if quarry_overlay_data_offset_91a644d is not None:
            return quarry_self_d88f816.__data__[:quarry_overlay_data_offset_91a644d]
        return quarry_self_d88f816.__data__[:]

    @_name_boundary.callable_contract({'self': 'quarry_self_62c749d', 'val': 'quarry_val_8c45959'}, 'adjust_PointerToRawData')
    def quarry_adjust_PointerToRawData(quarry_self_62c749d, quarry_val_8c45959):
        if _name_boundary.attributes(quarry_self_62c749d)['OPTIONAL_HEADER'].FileAlignment >= quarry_MIN_VALID_FILE_ALIGNMENT:
            if not quarry_power_of_two(_name_boundary.attributes(quarry_self_62c749d)['OPTIONAL_HEADER'].FileAlignment) and _name_boundary.attributes(quarry_self_62c749d)['FileAlignment_Warning'] is False:
                _name_boundary.attributes(quarry_self_62c749d)['__warnings'].append(f"If FileAlignment > 0x200 it should be a power of 2. Value: {_name_boundary.attributes(quarry_self_62c749d)['OPTIONAL_HEADER'].FileAlignment:#x}")
                _name_boundary.attributes(quarry_self_62c749d)['FileAlignment_Warning'] = True
        return quarry_val_8c45959 & ~511

    @_name_boundary.callable_contract({'self': 'quarry_self_0eb4287', 'val': 'quarry_val_34424cd', 'section_alignment': 'quarry_section_alignment_42f527b', 'file_alignment': 'quarry_file_alignment_ee58346'}, 'adjust_SectionAlignment')
    def quarry_adjust_SectionAlignment(quarry_self_0eb4287, quarry_val_34424cd, quarry_section_alignment_42f527b, quarry_file_alignment_ee58346):
        if quarry_section_alignment_42f527b < 4096:
            if quarry_file_alignment_ee58346 != quarry_section_alignment_42f527b and _name_boundary.attributes(quarry_self_0eb4287)['SectionAlignment_Warning'] is False:
                _name_boundary.attributes(quarry_self_0eb4287)['__warnings'].append(f'If SectionAlignment ({quarry_section_alignment_42f527b:#x}) < 0x1000 it should equal FileAlignment ({quarry_file_alignment_ee58346:#x})')
                _name_boundary.attributes(quarry_self_0eb4287)['SectionAlignment_Warning'] = True
        return quarry_cache_adjust_SectionAlignment(quarry_val_34424cd, quarry_section_alignment_42f527b, quarry_file_alignment_ee58346)

@_name_boundary.callable_contract({}, 'main')
def quarry_main():
    import sys as quarry_sys_ba231c9
    if not quarry_sys_ba231c9.argv[1:]:
        print('pefile.py <filename>', 'pefile.py exports <filename>', sep='\n')
    elif quarry_sys_ba231c9.argv[1] == 'exports':
        if not quarry_sys_ba231c9.argv[2:]:
            quarry_sys_ba231c9.exit('error: <filename> required')
        quarry_pe_local_a36b03f = quarry_PE(quarry_sys_ba231c9.argv[2])
        for quarry_exp_712fbf3 in quarry_pe_local_a36b03f.DIRECTORY_ENTRY_EXPORT.symbols:
            print(hex(_name_boundary.attributes(quarry_pe_local_a36b03f)['OPTIONAL_HEADER'].ImageBase + quarry_exp_712fbf3.address), quarry_exp_712fbf3.name, quarry_exp_712fbf3.ordinal)
    else:
        print(_name_boundary.attributes(quarry_PE(quarry_sys_ba231c9.argv[1]))['dump_info']())
if __name__ == '__main__':
    quarry_main()
_name_boundary.module_contract(globals(), {'MAX_DLL_LENGTH': 'quarry_MAX_DLL_LENGTH', 'two_way_dict': 'quarry_two_way_dict', 'SUBSYSTEM_TYPE': 'quarry_SUBSYSTEM_TYPE', 'Structure': 'quarry_Structure', 'fast_load': 'quarry_fast_load', 'TlsData': 'quarry_TlsData', 'IMAGE_LX_SIGNATURE': 'quarry_IMAGE_LX_SIGNATURE', 'PrologEpilogOpSaveXMMFar': 'quarry_PrologEpilogOpSaveXMMFar', 'MAX_IMPORT_SYMBOLS': 'quarry_MAX_IMPORT_SYMBOLS', 'IMAGE_ORDINAL_FLAG': 'quarry_IMAGE_ORDINAL_FLAG', 'ResourceDataEntryData': 'quarry_ResourceDataEntryData', 'image_characteristics': 'quarry_image_characteristics', 'sha512': 'quarry_sha512', 'debug_types': 'quarry_debug_types', 'section_characteristics': 'quarry_section_characteristics', 'cache_adjust_SectionAlignment': 'quarry_cache_adjust_SectionAlignment', 'lru_cache_copy': 'quarry_lru_cache_copy', 'PE': 'quarry_PE', 'allowed_filename': 'quarry_allowed_filename', 'DebugData': 'quarry_DebugData', 'LANG': 'quarry_LANG', 'IMAGE_TE_SIGNATURE': 'quarry_IMAGE_TE_SIGNATURE', 'SECTION_CHARACTERISTICS': 'quarry_SECTION_CHARACTERISTICS', 'UnwindInfo': 'quarry_UnwindInfo', 'human_readable_size': 'quarry_human_readable_size', 'UWOP_PUSH_NONVOL': 'quarry_UWOP_PUSH_NONVOL', 'UWOP_SET_FPREG': 'quarry_UWOP_SET_FPREG', 'set_flags': 'quarry_set_flags', 'lru_cache': 'quarry_lru_cache', 'Dump': 'quarry_Dump', 'registers': 'quarry_registers', 'IMAGE_DOSZM_SIGNATURE': 'quarry_IMAGE_DOSZM_SIGNATURE', 'ImportData': 'quarry_ImportData', 'MACHINE_TYPE': 'quarry_MACHINE_TYPE', 'count_zeroes': 'quarry_count_zeroes', 'relocation_types': 'quarry_relocation_types', 'UWOP_ALLOC_LARGE': 'quarry_UWOP_ALLOC_LARGE', 'os': 'quarry_os', 'ResourceDirData': 'quarry_ResourceDirData', 'DIRECTORY_ENTRY': 'quarry_DIRECTORY_ENTRY', 'SECTOR_SIZE': 'quarry_SECTOR_SIZE', 'FunctionOverrideData': 'quarry_FunctionOverrideData', 'uuid': 'quarry_uuid', 'OPTIONAL_HEADER_MAGIC_PE': 'quarry_OPTIONAL_HEADER_MAGIC_PE', 'allowed_function_name': 'quarry_allowed_function_name', 'Counter': 'quarry_Counter', 'ExceptionsDirEntryData': 'quarry_ExceptionsDirEntryData', 'PrologEpilogOpSaveRegFar': 'quarry_PrologEpilogOpSaveRegFar', 'dll_characteristics': 'quarry_dll_characteristics', 'IMAGE_NT_SIGNATURE': 'quarry_IMAGE_NT_SIGNATURE', 'mmap': 'quarry_mmap', 'string': 'quarry_string', 'machine_types': 'quarry_machine_types', 'IMAGE_NUMBEROF_DIRECTORY_ENTRIES': 'quarry_IMAGE_NUMBEROF_DIRECTORY_ENTRIES', 'PrologEpilogOpPushFrame': 'quarry_PrologEpilogOpPushFrame', 'IMAGE_ORDINAL_FLAG64': 'quarry_IMAGE_ORDINAL_FLAG64', 'EX_DLL_CHARACTERISTICS': 'quarry_EX_DLL_CHARACTERISTICS', 'PrologEpilogOpsFactory': 'quarry_PrologEpilogOpsFactory', 'unwind_info_flags': 'quarry_unwind_info_flags', 'BoundImportRefData': 'quarry_BoundImportRefData', 'power_of_two': 'quarry_power_of_two', 'math': 'quarry_math', 'UWOP_SAVE_NONVOL': 'quarry_UWOP_SAVE_NONVOL', 'IMAGE_CHARACTERISTICS': 'quarry_IMAGE_CHARACTERISTICS', 'UWOP_ALLOC_SMALL': 'quarry_UWOP_ALLOC_SMALL', 'DynamicRelocationData': 'quarry_DynamicRelocationData', 'DEBUG_TYPE': 'quarry_DEBUG_TYPE', 'md5': 'quarry_md5', 'MAX_RESOURCE_ENTRIES': 'quarry_MAX_RESOURCE_ENTRIES', 'sha1': 'quarry_sha1', 'subsystem_types': 'quarry_subsystem_types', 'PrologEpilogOpAllocSmall': 'quarry_PrologEpilogOpAllocSmall', 'is_valid_dos_filename': 'quarry_is_valid_dos_filename', 'StructureWithBitfields': 'quarry_StructureWithBitfields', 'get_sublang_name_for_lang': 'quarry_get_sublang_name_for_lang', 'sublang': 'quarry_sublang', 'ExportData': 'quarry_ExportData', 'UWOP_PUSH_MACHFRAME': 'quarry_UWOP_PUSH_MACHFRAME', 'ex_dll_characteristics': 'quarry_ex_dll_characteristics', 'parse_strings': 'quarry_parse_strings', 'IMAGE_DOS_SIGNATURE': 'quarry_IMAGE_DOS_SIGNATURE', 'IMAGE_NE_SIGNATURE': 'quarry_IMAGE_NE_SIGNATURE', 'MAX_SECTIONS': 'quarry_MAX_SECTIONS', 'ImportDescData': 'quarry_ImportDescData', 'time': 'quarry_time', 'UWOP_EPILOG': 'quarry_UWOP_EPILOG', 'OPTIONAL_HEADER_MAGIC_PE_PLUS': 'quarry_OPTIONAL_HEADER_MAGIC_PE_PLUS', 'LoadConfigData': 'quarry_LoadConfigData', 'ordlookup': 'quarry_ordlookup', 'MAX_SYMBOL_EXPORT_COUNT': 'quarry_MAX_SYMBOL_EXPORT_COUNT', 'BaseRelocationData': 'quarry_BaseRelocationData', 'RESOURCE_TYPE': 'quarry_RESOURCE_TYPE', 'set_bitfields_format': 'quarry_set_bitfields_format', 'sha256': 'quarry_sha256', 'PrologEpilogOpAllocLarge': 'quarry_PrologEpilogOpAllocLarge', 'defaultdict': 'quarry_defaultdict', 'set_format': 'quarry_set_format', 'PrologEpilogOpPushReg': 'quarry_PrologEpilogOpPushReg', 'UWOP_SAVE_NONVOL_FAR': 'quarry_UWOP_SAVE_NONVOL_FAR', 'directory_entry_types': 'quarry_directory_entry_types', 'BddDynamicRelocationData': 'quarry_BddDynamicRelocationData', 'STRUCT_SIZEOF_TYPES': 'quarry_STRUCT_SIZEOF_TYPES', 'ExportDirData': 'quarry_ExportDirData', 'main': 'quarry_main', 'DLL_CHARACTERISTICS': 'quarry_DLL_CHARACTERISTICS', 'ResourceDirEntryData': 'quarry_ResourceDirEntryData', 'SUBLANG': 'quarry_SUBLANG', 'struct': 'quarry_struct', 'resource_type': 'quarry_resource_type', 'lang': 'quarry_lang', 'UnicodeStringWrapperPostProcessor': 'quarry_UnicodeStringWrapperPostProcessor', 'codecs': 'quarry_codecs', 'wraps': 'quarry_wraps', 'PrologEpilogOp': 'quarry_PrologEpilogOp', 'PrologEpilogOpSetFP': 'quarry_PrologEpilogOpSetFP', 'MAX_SYMBOL_NAME_LENGTH': 'quarry_MAX_SYMBOL_NAME_LENGTH', 'PEFormatError': 'quarry_PEFormatError', 'RELOCATION_TYPE': 'quarry_RELOCATION_TYPE', 'is_valid_function_name': 'quarry_is_valid_function_name', 'MAX_IMPORT_NAME_LENGTH': 'quarry_MAX_IMPORT_NAME_LENGTH', 'UNWIND_INFO_FLAGS': 'quarry_UNWIND_INFO_FLAGS', 'MAX_STRING_LENGTH': 'quarry_MAX_STRING_LENGTH', 'PrologEpilogOpSaveXMM': 'quarry_PrologEpilogOpSaveXMM', 'PrologEpilogOpEpilogMarker': 'quarry_PrologEpilogOpEpilogMarker', 'RelocationData': 'quarry_RelocationData', 'retrieve_flags': 'quarry_retrieve_flags', 'BoundImportDescData': 'quarry_BoundImportDescData', 'MAX_RESOURCE_DEPTH': 'quarry_MAX_RESOURCE_DEPTH', 'REGISTERS': 'quarry_REGISTERS', 'copy': 'quarry_copy', 'UWOP_SAVE_XMM128': 'quarry_UWOP_SAVE_XMM128', 'sizeof_type': 'quarry_sizeof_type', 'PrologEpilogOpSaveReg': 'quarry_PrologEpilogOpSaveReg', 'UWOP_SAVE_XMM128_FAR': 'quarry_UWOP_SAVE_XMM128_FAR', 'DataContainer': 'quarry_DataContainer', 'MIN_VALID_FILE_ALIGNMENT': 'quarry_MIN_VALID_FILE_ALIGNMENT', 'FunctionOverrideDynamicRelocationData': 'quarry_FunctionOverrideDynamicRelocationData', 'IMAGE_LE_SIGNATURE': 'quarry_IMAGE_LE_SIGNATURE', 'AddressSet': 'quarry_AddressSet', 'SectionStructure': 'quarry_SectionStructure', 'sublang_name': 'quarry_sublang_name', 'sublang_value': 'quarry_sublang_value'})
