# Derived from tests/pefile_test.py; original copyright and license retained in ORIGIN.md.
import pequarry.api_contract as _name_boundary
import difflib as quarry_difflib
import os as quarry_os
import struct as quarry_struct
import sys as quarry_sys
import unittest as quarry_unittest
from hashlib import sha256 as quarry_sha256
import pequarry.image_reader as quarry_pefile
quarry_REGRESSION_TESTS_DIR = 'tests/test_files'

@_name_boundary.class_contract('TestPEFile', {'_load_test_files': 'quarry__load_test_files', 'test_pe_image_regression_test': 'quarry_test_pe_image_regression_test', 'test_get_rich_header_hash': 'quarry_test_get_rich_header_hash', 'test_selective_loading_integrity': 'quarry_test_selective_loading_integrity', 'test_imphash': 'quarry_test_imphash', 'test_exphash': 'quarry_test_exphash', 'test_write_header_fields': 'quarry_test_write_header_fields', 'test_nt_headers_exception': 'quarry_test_nt_headers_exception', 'test_dos_header_exception_large_data': 'quarry_test_dos_header_exception_large_data', 'test_dos_header_exception_small_data': 'quarry_test_dos_header_exception_small_data', 'test_empty_file_exception': 'quarry_test_empty_file_exception', 'test_virtual_size_less_than_raw_size': 'quarry_test_virtual_size_less_than_raw_size', 'test_virtual_size_greater_than_raw_size': 'quarry_test_virtual_size_greater_than_raw_size', 'test_relocated_memory_mapped_image': 'quarry_test_relocated_memory_mapped_image', 'test_entry_point_retrieval_with_overlapping_sections': 'quarry_test_entry_point_retrieval_with_overlapping_sections', 'test_entry_point_retrieval_with_unusual_aligments': 'quarry_test_entry_point_retrieval_with_unusual_aligments', 'test_entry_point_retrieval_with_unusual_PointerToRawData_values': 'quarry_test_entry_point_retrieval_with_unusual_PointerToRawData_values', 'test_low_alignment_section_pointer_to_raw_data': 'quarry_test_low_alignment_section_pointer_to_raw_data', 'test_VS_VERSIONINFO_dword_aligment': 'quarry_test_VS_VERSIONINFO_dword_aligment', 'test_overlay_github_issue_104': 'quarry_test_overlay_github_issue_104', 'test_get_overlay_and_trimming': 'quarry_test_get_overlay_and_trimming', 'test_unable_to_read_file': 'quarry_test_unable_to_read_file', 'test_driver_check': 'quarry_test_driver_check', 'test_rebased_image': 'quarry_test_rebased_image', 'test_checksum': 'quarry_test_checksum', 'test_files': 'quarry_test_files'})
class quarry_TestPEFile(quarry_unittest.TestCase):
    maxDiff = None

    @_name_boundary.callable_contract({'self': 'quarry_self_c96ddcf'}, 'setUp')
    def setUp(quarry_self_c96ddcf):
        _name_boundary.attributes(quarry_self_c96ddcf)['test_files'] = _name_boundary.attributes(quarry_self_c96ddcf)['_load_test_files']()

    @_name_boundary.callable_contract({'self': 'quarry_self_eb53f14'}, '_load_test_files')
    def quarry__load_test_files(quarry_self_eb53f14):
        """Load all the test files to be processed"""
        quarry_test_files_ad6cfac = list()
        for quarry_dirpath_f6c5fa6, quarry_dirname_974e2fe, quarry_filenames_61ca47b in quarry_os.walk(quarry_REGRESSION_TESTS_DIR):
            for quarry_filename_19e3588 in (quarry_f_12ccc8f for quarry_f_12ccc8f in quarry_filenames_61ca47b if not quarry_f_12ccc8f.endswith('.dmp')):
                quarry_test_files_ad6cfac.append(quarry_os.path.join(quarry_dirpath_f6c5fa6, quarry_filename_19e3588))
        return quarry_test_files_ad6cfac

    @_name_boundary.callable_contract({'self': 'quarry_self_0db5bab'}, 'test_pe_image_regression_test')
    def quarry_test_pe_image_regression_test(quarry_self_0db5bab):
        """Run through all the test files and make sure they run correctly"""
        quarry_failed_c2785c2 = False
        for quarry_idx_13f3bac, quarry_pe_filename_dadf134 in enumerate(_name_boundary.attributes(quarry_self_0db5bab)['test_files']):
            if quarry_pe_filename_dadf134.endswith('fake_PE_no_read_permissions_issue_53'):
                continue
            if quarry_pe_filename_dadf134.endswith('empty_file'):
                continue
            try:
                quarry_pe_local_1600ca2 = _name_boundary.attributes(quarry_pefile)['PE'](quarry_pe_filename_dadf134)
                quarry_pe_file_data_c002845 = _name_boundary.attributes(quarry_pe_local_1600ca2)['dump_info']()
                quarry_pe_file_dict_data_10ec7ab = _name_boundary.attributes(quarry_pe_local_1600ca2)['dump_dict']()
                quarry_pe_file_data_c002845 = quarry_pe_file_data_c002845.replace('\n\r', '\n')
            except Exception as quarry_excp_1ba59de:
                print(f'Failed processing [{quarry_os.path.basename(quarry_pe_filename_dadf134)}] ({quarry_excp_1ba59de})')
                quarry_failed_c2785c2 = True
                continue
            quarry_control_data_filename_869834d = f'{quarry_pe_filename_dadf134}.dmp'
            if not quarry_os.path.exists(quarry_control_data_filename_869834d):
                print('Could not find control data file [%s]. Assuming first run and generating...' % quarry_os.path.basename(quarry_control_data_filename_869834d))
                quarry_control_data_f_3b74b27 = open(quarry_control_data_filename_869834d, 'wb')
                _name_boundary.attributes(quarry_control_data_f_3b74b27)['write'](quarry_pe_file_data_c002845.encode('utf-8', 'backslashreplace'))
                continue
            quarry_control_data_f_3b74b27 = open(quarry_control_data_filename_869834d, 'rb')
            quarry_control_data_8ce079f = quarry_control_data_f_3b74b27.read()
            _name_boundary.attributes(quarry_control_data_f_3b74b27)['close']()
            quarry_pe_file_data_hash_b03d76d = quarry_sha256(quarry_pe_file_data_c002845.encode('utf-8', 'backslashreplace')).hexdigest()
            quarry_control_data_hash_33e7eae = quarry_sha256(quarry_control_data_8ce079f).hexdigest()
            quarry_diff_lines_added_count_9757833 = 0
            quarry_diff_lines_removed_count_b279aab = 0
            quarry_lines_to_ignore_dfe4dd8 = 0
            if quarry_control_data_hash_33e7eae != quarry_pe_file_data_hash_b03d76d:
                print(f'\nHash differs for [{quarry_os.path.basename(quarry_pe_filename_dadf134)}]')
                quarry_control_file_lines_49aefe2 = [quarry_l_df47d67 for quarry_l_df47d67 in _name_boundary.attributes(quarry_control_data_8ce079f)['decode']('utf-8').splitlines()]
                quarry_pefile_lines_611dfd3 = quarry_pe_file_data_c002845.splitlines()
                quarry_diff_7b58276 = quarry_difflib.ndiff(quarry_control_file_lines_49aefe2, quarry_pefile_lines_611dfd3)
                for quarry_line_b6bba3a in quarry_diff_7b58276:
                    if quarry_line_b6bba3a.startswith('+ '):
                        quarry_diff_lines_added_count_9757833 += 1
                        if 'TimeDateStamp' in quarry_line_b6bba3a:
                            quarry_lines_to_ignore_dfe4dd8 += 1
                    if quarry_line_b6bba3a.startswith('- '):
                        quarry_diff_lines_removed_count_b279aab += 1
                        if 'TimeDateStamp' in quarry_line_b6bba3a:
                            quarry_lines_to_ignore_dfe4dd8 += 1
                if quarry_diff_lines_removed_count_b279aab == quarry_diff_lines_added_count_9757833 and quarry_lines_to_ignore_dfe4dd8 == quarry_diff_lines_removed_count_b279aab + quarry_diff_lines_added_count_9757833:
                    print('Differences are in TimeDateStamp formatting, ignoring...')
                else:
                    print('Lines added: %d, lines removed: %d, lines with TimeDateStamp: %d' % (quarry_diff_lines_added_count_9757833, quarry_diff_lines_removed_count_b279aab, quarry_lines_to_ignore_dfe4dd8))
                    quarry_diff_7b58276 = list(quarry_difflib.unified_diff(quarry_control_file_lines_49aefe2, quarry_pefile_lines_611dfd3, fromfile='expected', tofile='new'))
                    quarry_error_diff_f_7e8039f = open('error_diff.txt', 'ab')
                    _name_boundary.attributes(quarry_error_diff_f_7e8039f)['write'](b'\n________________________________________\n')
                    _name_boundary.attributes(quarry_error_diff_f_7e8039f)['write'](f'Errors for file "{quarry_pe_filename_dadf134}":\n'.encode('utf-8', 'backslashreplace'))
                    _name_boundary.attributes(quarry_error_diff_f_7e8039f)['write']('\n'.join([quarry_l_15e62bf for quarry_l_15e62bf in quarry_diff_7b58276 if not quarry_l_15e62bf.startswith(' ')]).encode('utf-8', 'backslashreplace'))
                    _name_boundary.attributes(quarry_error_diff_f_7e8039f)['close']()
                    print('\n'.join(quarry_diff_7b58276))
                    print('Diff saved to: error_diff.txt')
                    quarry_failed_c2785c2 = True
            _name_boundary.attributes(quarry_sys.stdout)['write']('[%d]' % (len(_name_boundary.attributes(quarry_self_0db5bab)['test_files']) - quarry_idx_13f3bac))
            quarry_sys.stdout.flush()
        if quarry_failed_c2785c2:
            raise AssertionError('One or more errors occurred')

    @_name_boundary.callable_contract({'self': 'quarry_self_7f0885d'}, 'test_get_rich_header_hash')
    def quarry_test_get_rich_header_hash(quarry_self_7f0885d):
        """Verify the RICH_HEADER hashes."""
        quarry_control_file_2e97d2c = quarry_os.path.join(quarry_REGRESSION_TESTS_DIR, 'kernel32.dll')
        quarry_pe_local_db64cf7 = _name_boundary.attributes(quarry_pefile)['PE'](quarry_control_file_2e97d2c)
        quarry_self_7f0885d.assertEqual(_name_boundary.attributes(quarry_pe_local_db64cf7)['get_rich_header_hash'](), 'b855b76450d1cd0dc4716bb129962b6d')
        quarry_self_7f0885d.assertEqual(_name_boundary.attributes(quarry_pe_local_db64cf7)['get_rich_header_hash']('md5'), 'b855b76450d1cd0dc4716bb129962b6d')
        quarry_self_7f0885d.assertEqual(_name_boundary.attributes(quarry_pe_local_db64cf7)['get_rich_header_hash'](algorithm='sha1'), '5113650e24988e658e40e6dfb4dcefbe62c1e1a5')
        quarry_self_7f0885d.assertEqual(_name_boundary.attributes(quarry_pe_local_db64cf7)['get_rich_header_hash'](algorithm='sha256'), '3a5f34064c2add746936f0a9cff5c02212e625e52c74dc7872409ae508cd6efb')
        quarry_self_7f0885d.assertEqual(_name_boundary.attributes(quarry_pe_local_db64cf7)['get_rich_header_hash'](algorithm='sha512'), '3efff532bf25870c4757c7fce6b1812b86e9518b885dc3860de4716cdd78d6ba5147a6261442c61f13158d439681a9ff50767676b49b0a06a3f618e0526e084f')
        quarry_self_7f0885d.assertRaises(Exception, _name_boundary.attributes(quarry_pe_local_db64cf7)['get_rich_header_hash'], algorithm='badalgo')

    @_name_boundary.callable_contract({'self': 'quarry_self_9c7a5f9'}, 'test_selective_loading_integrity')
    def quarry_test_selective_loading_integrity(quarry_self_9c7a5f9):
        """Verify integrity of loading the separate elements of the file as
        opposed to do a single pass.
        """
        quarry_control_file_18c13c8 = quarry_os.path.join(quarry_REGRESSION_TESTS_DIR, 'MSVBVM60.DLL')
        quarry_pe_local_765d0fc = _name_boundary.attributes(quarry_pefile)['PE'](quarry_control_file_18c13c8, fast_load=True)
        _name_boundary.attributes(quarry_pe_local_765d0fc)['parse_data_directories'](directories=list(range(16)))
        quarry_pe_full_28b2d93 = _name_boundary.attributes(quarry_pefile)['PE'](quarry_control_file_18c13c8, fast_load=False)
        quarry_self_9c7a5f9.assertEqual(_name_boundary.attributes(quarry_pe_full_28b2d93)['dump_info'](), _name_boundary.attributes(quarry_pe_local_765d0fc)['dump_info']())
        _name_boundary.attributes(quarry_pe_local_765d0fc)['close']()
        _name_boundary.attributes(quarry_pe_full_28b2d93)['close']()

    @_name_boundary.callable_contract({'self': 'quarry_self_209ed12'}, 'test_imphash')
    def quarry_test_imphash(quarry_self_209ed12):
        """Test imphash values."""
        quarry_self_209ed12.assertEqual(_name_boundary.attributes(_name_boundary.attributes(quarry_pefile)['PE'](quarry_os.path.join(quarry_REGRESSION_TESTS_DIR, 'mfc40.dll')))['get_imphash'](), 'ef3d32741141a9ffde06721c65ea07b6')
        quarry_self_209ed12.assertEqual(_name_boundary.attributes(_name_boundary.attributes(quarry_pefile)['PE'](quarry_os.path.join(quarry_REGRESSION_TESTS_DIR, 'kernel32.dll')))['get_imphash'](), '239b8e3d4f9d1860d6ce5efb07b02e2a')
        quarry_self_209ed12.assertEqual(_name_boundary.attributes(_name_boundary.attributes(quarry_pefile)['PE'](quarry_os.path.join(quarry_REGRESSION_TESTS_DIR, '66c74e4c9dbd1d33b22f63cd0318b72dea88f9dbb4d36a3383d3da20b037d42e')))['get_imphash'](), 'a781de574e0567285ee1233bf6a57cc0')
        quarry_self_209ed12.assertEqual(_name_boundary.attributes(_name_boundary.attributes(quarry_pefile)['PE'](quarry_os.path.join(quarry_REGRESSION_TESTS_DIR, '64bit_Binaries/cmd.exe')))['get_imphash'](), 'd0058544e4588b1b2290b7f4d830eb0a')

    @_name_boundary.callable_contract({'self': 'quarry_self_58bc265'}, 'test_exphash')
    def quarry_test_exphash(quarry_self_58bc265):
        """Test exphash values."""
        quarry_self_58bc265.assertEqual(_name_boundary.attributes(_name_boundary.attributes(quarry_pefile)['PE'](quarry_os.path.join(quarry_REGRESSION_TESTS_DIR, 'mfc40.dll')))['get_exphash'](), '62d630f6941ad56df3b0a079873a82bc')
        quarry_self_58bc265.assertEqual(_name_boundary.attributes(_name_boundary.attributes(quarry_pefile)['PE'](quarry_os.path.join(quarry_REGRESSION_TESTS_DIR, 'kernel32.dll')))['get_exphash'](), 'ce0e98011116b41414acebc1e8c411c9')
        quarry_self_58bc265.assertEqual(_name_boundary.attributes(_name_boundary.attributes(quarry_pefile)['PE'](quarry_os.path.join(quarry_REGRESSION_TESTS_DIR, '66c74e4c9dbd1d33b22f63cd0318b72dea88f9dbb4d36a3383d3da20b037d42e')))['get_exphash'](), '1f00d8a63daedf9970feb050bad38030')
        quarry_self_58bc265.assertEqual(_name_boundary.attributes(_name_boundary.attributes(quarry_pefile)['PE'](quarry_os.path.join(quarry_REGRESSION_TESTS_DIR, '64bit_Binaries/cmd.exe')))['get_exphash'](), '')

    @_name_boundary.callable_contract({'self': 'quarry_self_6873f64'}, 'test_write_header_fields')
    def quarry_test_write_header_fields(quarry_self_6873f64):
        """Verify correct field data modification."""
        quarry_control_file_a9589fa = quarry_os.path.join(quarry_REGRESSION_TESTS_DIR, 'MSVBVM60.DLL')
        quarry_pe_local_43d04e0 = _name_boundary.attributes(quarry_pefile)['PE'](quarry_control_file_a9589fa, fast_load=True)
        _name_boundary.attributes(quarry_pe_local_43d04e0)['parse_data_directories'](directories=[quarry_pefile.DIRECTORY_ENTRY['IMAGE_DIRECTORY_ENTRY_RESOURCE']])
        quarry_original_data_c99a2da = _name_boundary.attributes(quarry_pe_local_43d04e0)['write']()
        quarry_str1_fa820d4 = b'string1'
        quarry_str2_dc9a081 = b'str2'
        quarry_str3_bc4b511 = b'string3'
        _name_boundary.attributes(quarry_pe_local_43d04e0)['FileInfo'][0][0].StringTable[0].entries[b'FileDescription'] = quarry_str1_fa820d4
        _name_boundary.attributes(quarry_pe_local_43d04e0)['FileInfo'][0][0].StringTable[0].entries[b'FileVersion'] = quarry_str2_dc9a081
        _name_boundary.attributes(quarry_pe_local_43d04e0)['FileInfo'][0][0].StringTable[0].entries[b'InternalName'] = quarry_str3_bc4b511
        quarry_new_data_644dcef = _name_boundary.attributes(quarry_pe_local_43d04e0)['write']()
        quarry_diff_c9bc58c, quarry_differences_9e5a5b7 = (0, list())
        for quarry_idx_2b9bf97 in range(len(quarry_original_data_c99a2da)):
            if quarry_original_data_c99a2da and quarry_new_data_644dcef and (quarry_original_data_c99a2da[quarry_idx_2b9bf97] != quarry_new_data_644dcef[quarry_idx_2b9bf97]):
                quarry_diff_c9bc58c += 1
                if quarry_new_data_644dcef[quarry_idx_2b9bf97] != 0:
                    quarry_differences_9e5a5b7.append(chr(quarry_new_data_644dcef[quarry_idx_2b9bf97]))
        quarry_self_6873f64.assertEqual(''.join(quarry_differences_9e5a5b7).encode('utf-8', 'backslashreplace'), quarry_str1_fa820d4 + quarry_str2_dc9a081 + quarry_str3_bc4b511)
        _name_boundary.attributes(quarry_pe_local_43d04e0)['close']()

    @_name_boundary.callable_contract({'self': 'quarry_self_3db2143'}, 'test_nt_headers_exception')
    def quarry_test_nt_headers_exception(quarry_self_3db2143):
        """pefile should fail parsing invalid data (missing NT headers)"""
        quarry_control_file_30b4b95 = quarry_os.path.join(quarry_REGRESSION_TESTS_DIR, 'MSVBVM60.DLL')
        quarry_pe_local_83ced13 = _name_boundary.attributes(quarry_pefile)['PE'](quarry_control_file_30b4b95, fast_load=True)
        quarry_pe_header_offest_a931c76 = _name_boundary.attributes(quarry_pe_local_83ced13)['DOS_HEADER'].e_lfanew
        quarry_self_3db2143.assertIsNotNone(quarry_pe_local_83ced13.__data__)
        if quarry_pe_local_83ced13.__data__:
            quarry_corrupted_data_6009a8a = quarry_pe_local_83ced13.__data__[:quarry_pe_header_offest_a931c76] + b'\x00' * (1024 * 10)
            quarry_self_3db2143.assertRaises(_name_boundary.attributes(quarry_pefile)['PEFormatError'], _name_boundary.attributes(quarry_pefile)['PE'], data=quarry_corrupted_data_6009a8a)

    @_name_boundary.callable_contract({'self': 'quarry_self_e64b313'}, 'test_dos_header_exception_large_data')
    def quarry_test_dos_header_exception_large_data(quarry_self_e64b313):
        """pefile should fail parsing 10KiB of invalid data
        (missing DOS header).
        """
        quarry_data_local_b6b2dd4 = b'\x00' * (1024 * 10)
        quarry_self_e64b313.assertRaises(_name_boundary.attributes(quarry_pefile)['PEFormatError'], _name_boundary.attributes(quarry_pefile)['PE'], data=quarry_data_local_b6b2dd4)

    @_name_boundary.callable_contract({'self': 'quarry_self_757a9fb'}, 'test_dos_header_exception_small_data')
    def quarry_test_dos_header_exception_small_data(quarry_self_757a9fb):
        """pefile should fail parsing 64 bytes of invalid data
        (missing DOS header).
        """
        quarry_data_local_da581b9 = b'\x00' * 64
        quarry_self_757a9fb.assertRaises(_name_boundary.attributes(quarry_pefile)['PEFormatError'], _name_boundary.attributes(quarry_pefile)['PE'], data=quarry_data_local_da581b9)

    @_name_boundary.callable_contract({'self': 'quarry_self_2671651'}, 'test_empty_file_exception')
    def quarry_test_empty_file_exception(quarry_self_2671651):
        """pefile should fail parsing empty files."""
        quarry_control_file_fa49a40 = quarry_os.path.join(quarry_REGRESSION_TESTS_DIR, 'empty_file')
        quarry_self_2671651.assertRaises(_name_boundary.attributes(quarry_pefile)['PEFormatError'], _name_boundary.attributes(quarry_pefile)['PE'], quarry_control_file_fa49a40)

    @_name_boundary.callable_contract({'self': 'quarry_self_22f26c8'}, 'test_virtual_size_less_than_raw_size')
    def quarry_test_virtual_size_less_than_raw_size(quarry_self_22f26c8):
        """File-alignment padding must not bleed into the memory-mapped image.

        When VirtualSize < SizeOfRawData the bytes beyond VirtualSize are
        disk padding that the OS loader never maps.  The memory-mapped image
        must end at VirtualAddress + VirtualSize, not VirtualAddress + SizeOfRawData.
        """
        quarry_vsize_02bd37f = 2048
        quarry_raw_size_125cd9f = 4096
        quarry_pe_local_49aa4b8 = _name_boundary.attributes(quarry_pefile)['PE'](data=quarry__create_pe(quarry_vsize_02bd37f, quarry_raw_size_125cd9f))
        quarry_image_fb7e7cc = _name_boundary.attributes(quarry_pe_local_49aa4b8)['get_memory_mapped_image']()
        quarry_va_412508e = _name_boundary.attributes(quarry_pe_local_49aa4b8)['sections'][0].VirtualAddress
        quarry_self_22f26c8.assertEqual(quarry_image_fb7e7cc[quarry_va_412508e:quarry_va_412508e + quarry_vsize_02bd37f], b'\xcc' * quarry_vsize_02bd37f, 'section content must be preserved up to VirtualSize')
        quarry_self_22f26c8.assertEqual(len(quarry_image_fb7e7cc), quarry_va_412508e + quarry_vsize_02bd37f, 'mapped image must not include raw file-padding past VirtualSize')

    @_name_boundary.callable_contract({'self': 'quarry_self_46f91e3'}, 'test_virtual_size_greater_than_raw_size')
    def quarry_test_virtual_size_greater_than_raw_size(quarry_self_46f91e3):
        """Uninitialized BSS region must be zero-padded in the memory-mapped image.

        When SizeOfRawData < VirtualSize the bytes from SizeOfRawData up to
        VirtualSize represent BSS and must be zero in the mapped view.
        """
        quarry_vsize_9d58125 = 5376
        quarry_raw_size_e091347 = 4096
        quarry_pe_local_a1c0331 = _name_boundary.attributes(quarry_pefile)['PE'](data=quarry__create_pe(quarry_vsize_9d58125, quarry_raw_size_e091347))
        quarry_image_110c81c = _name_boundary.attributes(quarry_pe_local_a1c0331)['get_memory_mapped_image']()
        quarry_va_5cd4c91 = _name_boundary.attributes(quarry_pe_local_a1c0331)['sections'][0].VirtualAddress
        quarry_self_46f91e3.assertEqual(quarry_image_110c81c[quarry_va_5cd4c91:quarry_va_5cd4c91 + quarry_raw_size_e091347], b'\xcc' * quarry_raw_size_e091347, 'raw section content must be preserved')
        quarry_self_46f91e3.assertEqual(quarry_image_110c81c[quarry_va_5cd4c91 + quarry_raw_size_e091347:quarry_va_5cd4c91 + quarry_vsize_9d58125], b'\x00' * (quarry_vsize_9d58125 - quarry_raw_size_e091347), 'BSS region (VirtualSize - SizeOfRawData) must be zero-padded')

    @_name_boundary.callable_contract({'self': 'quarry_self_f8801c3'}, 'test_relocated_memory_mapped_image')
    def quarry_test_relocated_memory_mapped_image(quarry_self_f8801c3):
        """Test different rebasing methods produce the same image"""
        quarry_control_file_1c44c57 = quarry_os.path.join(quarry_REGRESSION_TESTS_DIR, 'MSVBVM60.DLL')
        quarry_pe_local_09bb477 = _name_boundary.attributes(quarry_pefile)['PE'](quarry_control_file_1c44c57)

        @_name_boundary.callable_contract({'data1': 'quarry_data1_a6d69a6', 'data2': 'quarry_data2_51783e8'}, 'count_differences')
        def quarry_count_differences_fbeca46(quarry_data1_a6d69a6, quarry_data2_51783e8):
            quarry_diff_1f94a33 = 0
            for quarry_idx_3972d3e in range(len(quarry_data1_a6d69a6)):
                if quarry_data1_a6d69a6[quarry_idx_3972d3e] != quarry_data2_51783e8[quarry_idx_3972d3e]:
                    quarry_diff_1f94a33 += 1
            return quarry_diff_1f94a33
        quarry_original_image_1_ce79e57 = _name_boundary.attributes(quarry_pe_local_09bb477)['get_memory_mapped_image']()
        quarry_rebased_image_1_0121d2c = _name_boundary.attributes(quarry_pe_local_09bb477)['get_memory_mapped_image'](ImageBase=16777216)
        quarry_differences_1_3b018d0 = quarry_count_differences_fbeca46(quarry_original_image_1_ce79e57, quarry_rebased_image_1_0121d2c)
        quarry_self_f8801c3.assertEqual(quarry_differences_1_3b018d0, 60624)
        quarry_pe_local_09bb477 = _name_boundary.attributes(quarry_pefile)['PE'](quarry_control_file_1c44c57)
        quarry_original_image_2_131bda5 = _name_boundary.attributes(quarry_pe_local_09bb477)['get_memory_mapped_image']()
        _name_boundary.attributes(quarry_pe_local_09bb477)['relocate_image'](16777216)
        quarry_rebased_image_2_368e059 = _name_boundary.attributes(quarry_pe_local_09bb477)['get_memory_mapped_image']()
        quarry_differences_2_0ed8fd5 = quarry_count_differences_fbeca46(quarry_original_image_2_131bda5, quarry_rebased_image_2_368e059)
        quarry_self_f8801c3.assertEqual(quarry_differences_2_0ed8fd5, 60624)
        quarry_self_f8801c3.assertEqual(quarry_original_image_1_ce79e57, quarry_original_image_2_131bda5)
        quarry_control_file_1c44c57 = quarry_os.path.join(quarry_REGRESSION_TESTS_DIR, 'crash-8499a0bb33aeba8f59a172584abc7ca0ab82a78c')
        quarry_pe_local_09bb477 = _name_boundary.attributes(quarry_pefile)['PE'](quarry_control_file_1c44c57)

    @_name_boundary.callable_contract({'self': 'quarry_self_e2fa260'}, 'test_entry_point_retrieval_with_overlapping_sections')
    def quarry_test_entry_point_retrieval_with_overlapping_sections(quarry_self_e2fa260):
        quarry_control_file_9e7c91f = quarry_os.path.join(quarry_REGRESSION_TESTS_DIR, '924C62EF97E0B4939E9047B866037BB5BDDA92F9DA6D22F5DEEFC540856CDC0D.bin__aleph_overlapping_sections')
        quarry_pe_local_b599301 = _name_boundary.attributes(quarry_pefile)['PE'](quarry_control_file_9e7c91f)
        quarry_entry_point_data_6037339 = _name_boundary.attributes(quarry_pe_local_b599301)['get_data'](_name_boundary.attributes(quarry_pe_local_b599301)['OPTIONAL_HEADER'].AddressOfEntryPoint, 10)
        quarry_good_ep_data_cac6e28 = b'U\x8b\xec\x83\xecp\x83e\xcc\x00'
        quarry_self_e2fa260.assertEqual(quarry_entry_point_data_6037339, quarry_good_ep_data_cac6e28)

    @_name_boundary.callable_contract({'self': 'quarry_self_64ddc7f'}, 'test_entry_point_retrieval_with_unusual_aligments')
    def quarry_test_entry_point_retrieval_with_unusual_aligments(quarry_self_64ddc7f):
        quarry_control_file_fca8b08 = quarry_os.path.join(quarry_REGRESSION_TESTS_DIR, 'BackDoor.Poison.ex_bad_section_and_file_aligments_broke_pefile_1.2.10-93')
        quarry_pe_local_e7f3dea = _name_boundary.attributes(quarry_pefile)['PE'](quarry_control_file_fca8b08)
        quarry_self_64ddc7f.assertEqual(_name_boundary.attributes(quarry_pe_local_e7f3dea)['get_data'](_name_boundary.attributes(quarry_pe_local_e7f3dea)['OPTIONAL_HEADER'].AddressOfEntryPoint, 32), bytes.fromhex('B800044000FFD06A00E800000000FF2500024000440200000000000000000000'))

    @_name_boundary.callable_contract({'self': 'quarry_self_0e43434'}, 'test_entry_point_retrieval_with_unusual_PointerToRawData_values')
    def quarry_test_entry_point_retrieval_with_unusual_PointerToRawData_values(quarry_self_0e43434):
        quarry_control_file_0ea58d9 = quarry_os.path.join(quarry_REGRESSION_TESTS_DIR, 'unconventional_PointerToRawData_values')
        quarry_pe_local_c5d96ff = _name_boundary.attributes(quarry_pefile)['PE'](quarry_control_file_0ea58d9)
        quarry_self_0e43434.assertEqual(_name_boundary.attributes(quarry_pe_local_c5d96ff)['get_data'](_name_boundary.attributes(quarry_pe_local_c5d96ff)['OPTIONAL_HEADER'].AddressOfEntryPoint, 32), bytes.fromhex('BEE0114000FF36E9C300000048010F010B014B45524E454C33322E444C4C0000'))
        quarry_self_0e43434.assertEqual(_name_boundary.attributes(quarry_pe_local_c5d96ff)['get_data'](_name_boundary.attributes(quarry_pe_local_c5d96ff)['OPTIONAL_HEADER'].AddressOfEntryPoint, 32), quarry_pe_local_c5d96ff.__data__[24:24 + 32])
        quarry_fname_c189682 = 'pe-bear_issue_11/packed.exe'
        if quarry_os.path.exists(quarry_os.path.join(quarry_REGRESSION_TESTS_DIR, quarry_fname_c189682)):
            quarry_control_file_0ea58d9 = quarry_os.path.join(quarry_REGRESSION_TESTS_DIR, quarry_fname_c189682)
            quarry_pe_local_c5d96ff = _name_boundary.attributes(quarry_pefile)['PE'](quarry_control_file_0ea58d9)
            quarry_self_0e43434.assertEqual(_name_boundary.attributes(quarry_pe_local_c5d96ff)['get_data'](_name_boundary.attributes(quarry_pe_local_c5d96ff)['OPTIONAL_HEADER'].AddressOfEntryPoint, 10), bytes.fromhex('55f3499ca68cc9e57b9d'))
        quarry_control_file_0ea58d9 = quarry_os.path.join(quarry_REGRESSION_TESTS_DIR, 'tiny-1.exe')
        quarry_pe_local_c5d96ff = _name_boundary.attributes(quarry_pefile)['PE'](quarry_control_file_0ea58d9)
        quarry_self_0e43434.assertEqual(_name_boundary.attributes(quarry_pe_local_c5d96ff)['get_data'](_name_boundary.attributes(quarry_pe_local_c5d96ff)['OPTIONAL_HEADER'].AddressOfEntryPoint, 10), bytes.fromhex('6a2a58c3000000000000'))
        quarry_control_file_0ea58d9 = quarry_os.path.join(quarry_REGRESSION_TESTS_DIR, 'corkami_ange_testfiles/whole_pe_section.exe')
        quarry_pe_local_c5d96ff = _name_boundary.attributes(quarry_pefile)['PE'](quarry_control_file_0ea58d9)
        quarry_self_0e43434.assertEqual(_name_boundary.attributes(quarry_pe_local_c5d96ff)['get_data'](8192, 10), quarry_pe_local_c5d96ff.__data__[0:10])

    @_name_boundary.callable_contract({'self': 'quarry_self_01853e1'}, 'test_low_alignment_section_pointer_to_raw_data')
    def quarry_test_low_alignment_section_pointer_to_raw_data(quarry_self_01853e1):
        quarry_pe_local_662c12a = _name_boundary.attributes(quarry_pefile)['PE'](data=quarry__low_alignment_resource_pe())
        quarry_self_01853e1.assertEqual(_name_boundary.attributes(quarry_pe_local_662c12a)['get_offset_from_rva'](416), 352)
        quarry_self_01853e1.assertTrue(_name_boundary.has_attribute(quarry_pe_local_662c12a, 'DIRECTORY_ENTRY_RESOURCE'))
        quarry_self_01853e1.assertEqual([quarry_e_ec1172e.id for quarry_e_ec1172e in quarry_pe_local_662c12a.DIRECTORY_ENTRY_RESOURCE.entries], [3])

    @_name_boundary.callable_contract({'self': 'quarry_self_9c752e7'}, 'test_VS_VERSIONINFO_dword_aligment')
    def quarry_test_VS_VERSIONINFO_dword_aligment(quarry_self_9c752e7):
        quarry_control_file_8ba18d7 = quarry_os.path.join(quarry_REGRESSION_TESTS_DIR, '031.vxe_pefile_1.2.10-95_dword_alignment_was_not_ok_for_VS_VERSIONINFO')
        quarry_pe_local_4235a69 = _name_boundary.attributes(quarry_pefile)['PE'](quarry_control_file_8ba18d7)
        quarry_vs_fixedfileinfo_signature_cf55ee5 = _name_boundary.attributes(quarry_pe_local_4235a69)['VS_FIXEDFILEINFO'][0].Signature
        quarry_good_vs_fixedfileinfo_signature_90e2ded = 4277077181
        quarry_self_9c752e7.assertEqual(quarry_vs_fixedfileinfo_signature_cf55ee5, quarry_good_vs_fixedfileinfo_signature_90e2ded)

    @_name_boundary.callable_contract({'self': 'quarry_self_8c2ffa8'}, 'test_overlay_github_issue_104')
    def quarry_test_overlay_github_issue_104(quarry_self_8c2ffa8):
        quarry_control_file_pe_df4a4e7 = quarry_os.path.join(quarry_REGRESSION_TESTS_DIR, '307a69414b203f1116db677b8bc07130ae2b72cf33cf2ae5a39bf1bd484b587c_overlay_issue_104')
        quarry_pe_local_504943b = _name_boundary.attributes(quarry_pefile)['PE'](quarry_control_file_pe_df4a4e7)
        quarry_overlay_offset_5bc2f04 = _name_boundary.attributes(quarry_pe_local_504943b)['get_overlay_data_start_offset']()
        quarry_self_8c2ffa8.assertEqual(quarry_overlay_offset_5bc2f04, 14848)
        quarry_control_file_pe_df4a4e7 = quarry_os.path.join(quarry_REGRESSION_TESTS_DIR, '3096e39df63c0be68746ea3bbe528c067b6eb45e2d61cc167712c3b1e0966be3_overlay_issue_104')
        quarry_pe_local_504943b = _name_boundary.attributes(quarry_pefile)['PE'](quarry_control_file_pe_df4a4e7)
        quarry_overlay_offset_5bc2f04 = _name_boundary.attributes(quarry_pe_local_504943b)['get_overlay_data_start_offset']()
        quarry_self_8c2ffa8.assertEqual(quarry_overlay_offset_5bc2f04, 93696)

    @_name_boundary.callable_contract({'self': 'quarry_self_5e384f4'}, 'test_get_overlay_and_trimming')
    def quarry_test_get_overlay_and_trimming(quarry_self_5e384f4):
        """Test method to retrieve overlay data and trim the PE"""
        quarry_control_file_pe_498e2df = quarry_os.path.join(quarry_REGRESSION_TESTS_DIR, '0x90_with_overlay_data.exe')
        quarry_pe_local_75391bd = _name_boundary.attributes(quarry_pefile)['PE'](quarry_control_file_pe_498e2df)
        quarry_overlay_data_2f018d8 = _name_boundary.attributes(quarry_pe_local_75391bd)['get_overlay']()
        quarry_trimmed_data_811cd30 = _name_boundary.attributes(quarry_pe_local_75391bd)['trim']()
        quarry_self_5e384f4.assertEqual(quarry_overlay_data_2f018d8, bytes(b'A' * 186 + b'\n'))
        quarry_self_5e384f4.assertEqual(_name_boundary.attributes(quarry_pe_local_75391bd)['get_overlay_data_start_offset'](), 294912)
        quarry_self_5e384f4.assertEqual(len(quarry_trimmed_data_811cd30), 294912)
        quarry_control_file_pe_498e2df = quarry_os.path.join(quarry_REGRESSION_TESTS_DIR, '0x90.exe')
        quarry_pe_local_75391bd = _name_boundary.attributes(quarry_pefile)['PE'](quarry_control_file_pe_498e2df)
        quarry_self_5e384f4.assertIsNone(_name_boundary.attributes(quarry_pe_local_75391bd)['get_overlay']())
        quarry_trimmed_data_811cd30 = _name_boundary.attributes(quarry_pe_local_75391bd)['trim']()
        quarry_self_5e384f4.assertEqual(len(quarry_trimmed_data_811cd30), 294912)
        quarry_control_file_pe_498e2df = quarry_os.path.join(quarry_REGRESSION_TESTS_DIR, 'sectionless.exe_corkami_issue_51')
        quarry_pe_local_75391bd = _name_boundary.attributes(quarry_pefile)['PE'](quarry_control_file_pe_498e2df)
        quarry_self_5e384f4.assertIsNone(_name_boundary.attributes(quarry_pe_local_75391bd)['get_overlay']())

    @_name_boundary.callable_contract({'self': 'quarry_self_4632a14'}, 'test_unable_to_read_file')
    def quarry_test_unable_to_read_file(quarry_self_4632a14):
        """Attempting to open a file without read permission for the user
        should result in an error message.
        """
        quarry_control_file_pe_cdf84b5 = quarry_os.path.join(quarry_REGRESSION_TESTS_DIR, 'fake_PE_no_read_permissions_issue_53')
        quarry_self_4632a14.assertRaises(Exception, _name_boundary.attributes(quarry_pefile)['PE'], quarry_control_file_pe_cdf84b5)

    @_name_boundary.callable_contract({'self': 'quarry_self_f0a26ec'}, 'test_driver_check')
    def quarry_test_driver_check(quarry_self_f0a26ec):
        """Test the is_driver check"""
        quarry_control_file_pe_ce3b66c = quarry_os.path.join(quarry_REGRESSION_TESTS_DIR, '075356de51afac92d1c20ba53c966fa145172897a96cfdb1b3bb369edb376a77_driver')
        quarry_pe_fast_3aeed62 = _name_boundary.attributes(quarry_pefile)['PE'](quarry_control_file_pe_ce3b66c, fast_load=True)
        quarry_pe_full_b02e2df = _name_boundary.attributes(quarry_pefile)['PE'](quarry_control_file_pe_ce3b66c, fast_load=False)
        quarry_self_f0a26ec.assertEqual(_name_boundary.attributes(quarry_pe_fast_3aeed62)['is_driver'](), _name_boundary.attributes(quarry_pe_full_b02e2df)['is_driver']())
        quarry_control_file_pe_ce3b66c = quarry_os.path.join(quarry_REGRESSION_TESTS_DIR, 'issue_322_plaso_test_driver.sys')
        quarry_pe_local_64a56f4 = _name_boundary.attributes(quarry_pefile)['PE'](quarry_control_file_pe_ce3b66c, fast_load=False)
        quarry_self_f0a26ec.assertTrue(_name_boundary.attributes(quarry_pe_local_64a56f4)['is_driver']())

    @_name_boundary.callable_contract({'self': 'quarry_self_3c610cb'}, 'test_rebased_image')
    def quarry_test_rebased_image(quarry_self_3c610cb):
        """Test correctness of rebased images"""
        quarry_control_file_8a86f6c = quarry_os.path.join(quarry_REGRESSION_TESTS_DIR, 'pefile_unittest_data__resurrel_malware_rebased_0x400000')
        quarry_control_file_f_d37c2d9 = open(quarry_control_file_8a86f6c, 'rb')
        quarry_control_file_data_b708704 = quarry_control_file_f_d37c2d9.read()
        _name_boundary.attributes(quarry_control_file_f_d37c2d9)['close']()
        quarry_control_file_pe_92ddf59 = quarry_os.path.join(quarry_REGRESSION_TESTS_DIR, 'e05916.ex_')
        quarry_pe_local_78900cd = _name_boundary.attributes(quarry_pefile)['PE'](quarry_control_file_pe_92ddf59)
        quarry_rebased_data_77006e9 = _name_boundary.attributes(quarry_pe_local_78900cd)['get_memory_mapped_image'](ImageBase=4194304)
        quarry_self_3c610cb.assertEqual(quarry_rebased_data_77006e9, quarry_control_file_data_b708704)

    @_name_boundary.callable_contract({'self': 'quarry_self_623143e'}, 'test_checksum')
    def quarry_test_checksum(quarry_self_623143e):
        """Verify correct calculation of checksum"""
        quarry_control_file_adfb71c = quarry_os.path.join(quarry_REGRESSION_TESTS_DIR, 'MSVBVM60.DLL')
        quarry_pe_local_e2905e8 = _name_boundary.attributes(quarry_pefile)['PE'](quarry_control_file_adfb71c)
        quarry_self_623143e.assertTrue(_name_boundary.attributes(quarry_pe_local_e2905e8)['verify_checksum']())
        quarry_control_file_adfb71c = quarry_os.path.join(quarry_REGRESSION_TESTS_DIR, 'checksum/0031709440C539B47E34B524AF3900248DD35274_bad_checksum')
        quarry_pe_local_e2905e8 = _name_boundary.attributes(quarry_pefile)['PE'](quarry_control_file_adfb71c)
        quarry_self_623143e.assertFalse(_name_boundary.attributes(quarry_pe_local_e2905e8)['verify_checksum']())
        quarry_self_623143e.assertEqual(_name_boundary.attributes(quarry_pe_local_e2905e8)['generate_checksum'](), 93241)
        quarry_control_file_adfb71c = quarry_os.path.join(quarry_REGRESSION_TESTS_DIR, 'checksum/009763E904C053C1803B26EC0D817AF497DA1BB2_bad_checksum')
        quarry_pe_local_e2905e8 = _name_boundary.attributes(quarry_pefile)['PE'](quarry_control_file_adfb71c)
        quarry_self_623143e.assertFalse(_name_boundary.attributes(quarry_pe_local_e2905e8)['verify_checksum']())
        quarry_self_623143e.assertEqual(_name_boundary.attributes(quarry_pe_local_e2905e8)['generate_checksum'](), 150007)
        quarry_control_file_adfb71c = quarry_os.path.join(quarry_REGRESSION_TESTS_DIR, 'checksum/00499E3A70A324160A3FE935F10BFB699ACB0954')
        quarry_pe_local_e2905e8 = _name_boundary.attributes(quarry_pefile)['PE'](quarry_control_file_adfb71c)
        quarry_self_623143e.assertTrue(_name_boundary.attributes(quarry_pe_local_e2905e8)['verify_checksum']())
        quarry_control_file_adfb71c = quarry_os.path.join(quarry_REGRESSION_TESTS_DIR, 'checksum/0011FEECD53D06A6C68C531E0DA7A61C692E76BF')
        quarry_pe_local_e2905e8 = _name_boundary.attributes(quarry_pefile)['PE'](quarry_control_file_adfb71c)
        quarry_self_623143e.assertTrue(_name_boundary.attributes(quarry_pe_local_e2905e8)['verify_checksum']())

@_name_boundary.callable_contract({}, '_low_alignment_resource_pe')
def quarry__low_alignment_resource_pe():
    """Minimal PE32 with SectionAlignment == FileAlignment == 0x10 and a single
    .rsrc section whose PointerToRawData (0x160) differs from its VirtualAddress
    (0x1a0), mirroring the resource-only DLL reported in issue #465."""
    quarry_va_ec6b9e7, quarry_ptr_raw_2925fdb = (416, 352)
    quarry_res_8b4e3a9 = b''
    quarry_res_8b4e3a9 += quarry_struct.pack('<IIHHHH', 0, 0, 0, 0, 0, 1)
    quarry_res_8b4e3a9 += quarry_struct.pack('<II', 3, 2147483648 | 24)
    quarry_res_8b4e3a9 += quarry_struct.pack('<IIHHHH', 0, 0, 0, 0, 0, 1)
    quarry_res_8b4e3a9 += quarry_struct.pack('<II', 1, 2147483648 | 48)
    quarry_res_8b4e3a9 += quarry_struct.pack('<IIHHHH', 0, 0, 0, 0, 0, 1)
    quarry_res_8b4e3a9 += quarry_struct.pack('<II', 1033, 72)
    quarry_res_8b4e3a9 += quarry_struct.pack('<IIII', quarry_va_ec6b9e7 + 88, 4, 0, 0)
    quarry_res_8b4e3a9 += b'TEST'
    quarry_dos_b973035 = b'MZ' + b'\x00' * 58 + quarry_struct.pack('<I', 64)
    quarry_coff_41fe05b = quarry_struct.pack('<HHIIIHH', 332, 1, 0, 0, 0, 224, 8450)
    quarry_size_of_image_f59f387 = quarry_va_ec6b9e7 + len(quarry_res_8b4e3a9) + 15 & ~15
    quarry_opt_c8d52a3 = quarry_struct.pack('<HBBIIIIII', 267, 0, 0, 0, 0, 0, 0, 0, 0)
    quarry_opt_c8d52a3 += quarry_struct.pack('<III', 4194304, 16, 16)
    quarry_opt_c8d52a3 += quarry_struct.pack('<HHHHHH', 4, 0, 0, 0, 4, 0)
    quarry_opt_c8d52a3 += quarry_struct.pack('<I', 0)
    quarry_opt_c8d52a3 += quarry_struct.pack('<II', quarry_size_of_image_f59f387, quarry_ptr_raw_2925fdb)
    quarry_opt_c8d52a3 += quarry_struct.pack('<IHH', 0, 2, 0)
    quarry_opt_c8d52a3 += quarry_struct.pack('<IIII', 0, 0, 0, 0)
    quarry_opt_c8d52a3 += quarry_struct.pack('<II', 0, 16)
    quarry_dirs_086bf47 = [(0, 0)] * 16
    quarry_dirs_086bf47[2] = (quarry_va_ec6b9e7, len(quarry_res_8b4e3a9))
    for quarry_rva_e3339dc, quarry_sz_431a8b0 in quarry_dirs_086bf47:
        quarry_opt_c8d52a3 += quarry_struct.pack('<II', quarry_rva_e3339dc, quarry_sz_431a8b0)
    quarry_section_f8c2bcf = quarry_struct.pack('<8sIIIIIIHHI', b'.rsrc\x00\x00\x00', len(quarry_res_8b4e3a9), quarry_va_ec6b9e7, len(quarry_res_8b4e3a9), quarry_ptr_raw_2925fdb, 0, 0, 0, 0, 1073741888)
    return quarry_dos_b973035 + b'PE\x00\x00' + quarry_coff_41fe05b + quarry_opt_c8d52a3 + quarry_section_f8c2bcf + quarry_res_8b4e3a9

@_name_boundary.callable_contract({'virtual_size': 'quarry_virtual_size_0eaf3ce', 'size_of_raw_data': 'quarry_size_of_raw_data_6ca0ed1'}, '_create_pe')
def quarry__create_pe(quarry_virtual_size_0eaf3ce, quarry_size_of_raw_data_6ca0ed1):
    """Build a minimal PE32 with one section whose VirtualSize and SizeOfRawData differ.

    Reused by the memory-mapped-image tests below.
    """
    quarry_dos_header_06c0c53 = bytearray(64)
    quarry_dos_header_06c0c53[0:2] = b'MZ'
    quarry_dos_header_06c0c53[60:64] = quarry_struct.pack('<I', 64)
    quarry_file_header_15ec4d5 = quarry_struct.pack('<H', 332) + quarry_struct.pack('<H', 1) + quarry_struct.pack('<I', 0) + quarry_struct.pack('<I', 0) + quarry_struct.pack('<I', 0) + quarry_struct.pack('<H', 224) + quarry_struct.pack('<H', 258)
    quarry_section_alignment_d18ffbf = 4096
    quarry_pointer_to_raw_data_c517ca8 = 1024
    quarry_va_0974891 = 4096
    quarry_size_of_image_54d7002 = quarry_va_0974891 + max(quarry_virtual_size_0eaf3ce, quarry_size_of_raw_data_6ca0ed1)
    quarry_size_of_image_54d7002 = quarry_size_of_image_54d7002 + quarry_section_alignment_d18ffbf - 1 & ~(quarry_section_alignment_d18ffbf - 1)
    quarry_opt_header_dd5159b = quarry_struct.pack('<H', 267) + quarry_struct.pack('<BB', 14, 0) + quarry_struct.pack('<I', quarry_size_of_raw_data_6ca0ed1) + quarry_struct.pack('<II', 0, 0) + quarry_struct.pack('<I', quarry_va_0974891) + quarry_struct.pack('<II', quarry_va_0974891, 0) + quarry_struct.pack('<I', 4194304) + quarry_struct.pack('<II', quarry_section_alignment_d18ffbf, 512) + quarry_struct.pack('<HHHHHH', 6, 0, 0, 0, 6, 0) + quarry_struct.pack('<I', 0) + quarry_struct.pack('<I', quarry_size_of_image_54d7002) + quarry_struct.pack('<I', 512) + quarry_struct.pack('<I', 0) + quarry_struct.pack('<H', 2) + quarry_struct.pack('<H', 33024) + quarry_struct.pack('<IIII', 1048576, 4096, 1048576, 4096) + quarry_struct.pack('<II', 0, 16) + b'\x00' * 128
    assert len(quarry_opt_header_dd5159b) == 224
    quarry_section_header_50b413d = b'.text\x00\x00\x00' + quarry_struct.pack('<I', quarry_virtual_size_0eaf3ce) + quarry_struct.pack('<I', quarry_va_0974891) + quarry_struct.pack('<I', quarry_size_of_raw_data_6ca0ed1) + quarry_struct.pack('<I', quarry_pointer_to_raw_data_c517ca8) + quarry_struct.pack('<IIHHI', 0, 0, 0, 0, 1610612768)
    quarry_headers_4cf3128 = bytes(quarry_dos_header_06c0c53) + b'PE\x00\x00' + quarry_file_header_15ec4d5 + quarry_opt_header_dd5159b + quarry_section_header_50b413d
    quarry_headers_4cf3128 = quarry_headers_4cf3128.ljust(quarry_pointer_to_raw_data_c517ca8, b'\x00')
    quarry_section_data_ebebf2f = b'\xcc' * quarry_size_of_raw_data_6ca0ed1
    return bytes(quarry_headers_4cf3128) + quarry_section_data_ebebf2f
_name_boundary.module_contract(globals(), {'sha256': 'quarry_sha256', 'pefile': 'quarry_pefile', 'sys': 'quarry_sys', '_create_pe': 'quarry__create_pe', 'difflib': 'quarry_difflib', 'struct': 'quarry_struct', 'TestPEFile': 'quarry_TestPEFile', '_low_alignment_resource_pe': 'quarry__low_alignment_resource_pe', 'os': 'quarry_os', 'REGRESSION_TESTS_DIR': 'quarry_REGRESSION_TESTS_DIR', 'unittest': 'quarry_unittest'})
