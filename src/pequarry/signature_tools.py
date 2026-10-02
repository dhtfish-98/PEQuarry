# Derived from peutils.py; original copyright and license retained in ORIGIN.md.
"""peutils, Portable Executable utilities module


Copyright (c) 2005-2024 Ero Carrera <ero.carrera@gmail.com>

All rights reserved.
"""
import pequarry.api_contract as _name_boundary
import os as quarry_os
import re as quarry_re
import string as quarry_string
import urllib.request as _boundary_import_urllib_request
import urllib as quarry_urllib
import pequarry.image_reader as quarry_pefile
__author__ = 'Ero Carrera'
__version__ = quarry_pefile.__version__
__contact__ = 'ero.carrera@gmail.com'

@_name_boundary.class_contract('SignatureDatabase', {'generate_section_signatures': 'quarry_generate_section_signatures', 'generate_ep_signature': 'quarry_generate_ep_signature', '__generate_signature': 'quarry___generate_signature', 'match': 'quarry_match', 'match_all': 'quarry_match_all', '__match': 'quarry___match', 'match_data': 'quarry_match_data', '__match_signature_tree': 'quarry___match_signature_tree', 'load': 'quarry_load', '__load': 'quarry___load', 'parse_sig': 'quarry_parse_sig', 'signature_tree_eponly_false': 'quarry_signature_tree_eponly_false', 'signature_tree_eponly_true': 'quarry_signature_tree_eponly_true', 'signature_tree_section_start': 'quarry_signature_tree_section_start', 'signature_count_eponly_false': 'quarry_signature_count_eponly_false', 'signature_count_eponly_true': 'quarry_signature_count_eponly_true', 'signature_count_section_start': 'quarry_signature_count_section_start', 'max_depth': 'quarry_max_depth'})
class quarry_SignatureDatabase:
    """This class loads and keeps a parsed PEiD signature database.

    Usage:

        signatures = SignatureDatabase('/path/to/signature/file')

    and/or

        signatures = SignatureDatabase()
        signatures.load('/path/to/signature/file')

    Signature databases can be combined by performing multiple loads.

    The filename parameter can be a URL too. In that case the
    signature database will be downloaded from that location.
    """

    @_name_boundary.callable_contract({'self': 'quarry_self_b5950de', 'filename': 'quarry_filename_11b963b', 'data': 'quarry_data_local_2d72823'}, '__init__')
    def __init__(quarry_self_b5950de, quarry_filename_11b963b=None, quarry_data_local_2d72823=None):
        _name_boundary.attributes(quarry_self_b5950de)['parse_sig'] = quarry_re.compile('\\[(.*?)\\]\\s+?signature\\s*=\\s*(.*?)(\\s+\\?\\?)*\\s*ep_only\\s*=\\s*(\\w+)(?:\\s*section_start_only\\s*=\\s*(\\w+)|)', quarry_re.DOTALL)
        _name_boundary.attributes(quarry_self_b5950de)['signature_tree_eponly_false'] = {}
        _name_boundary.attributes(quarry_self_b5950de)['signature_tree_eponly_true'] = {}
        _name_boundary.attributes(quarry_self_b5950de)['signature_tree_section_start'] = {}
        _name_boundary.attributes(quarry_self_b5950de)['signature_count_eponly_false'] = 0
        _name_boundary.attributes(quarry_self_b5950de)['signature_count_eponly_true'] = 0
        _name_boundary.attributes(quarry_self_b5950de)['signature_count_section_start'] = 0
        _name_boundary.attributes(quarry_self_b5950de)['max_depth'] = 0
        _name_boundary.attributes(quarry_self_b5950de)['__load'](filename=quarry_filename_11b963b, data=quarry_data_local_2d72823)

    @_name_boundary.callable_contract({'self': 'quarry_self_af16e98', 'sig_length': 'quarry_sig_length_610ca79', 'pe': 'quarry_pe_local_527be8e', 'name': 'quarry_name_local_aa1ff42'}, 'generate_section_signatures')
    def quarry_generate_section_signatures(quarry_self_af16e98, quarry_pe_local_527be8e, quarry_name_local_aa1ff42, quarry_sig_length_610ca79=512):
        """Generates signatures for all the sections in a PE file.

        If the section contains any data a signature will be created
        for it. The signature name will be a combination of the
        parameter 'name' and the section number and its name.
        """
        quarry_section_signatures_d8d7d79 = []
        for quarry_idx_3688a53, quarry_section_881ea3d in enumerate(_name_boundary.attributes(quarry_pe_local_527be8e)['sections'], start=1):
            if quarry_section_881ea3d.SizeOfRawData < quarry_sig_length_610ca79:
                continue
            quarry_offset_local_bf94f32 = quarry_section_881ea3d.PointerToRawData
            quarry_sig_name_0201d47 = '%s Section(%d/%d,%s)' % (quarry_name_local_aa1ff42, quarry_idx_3688a53, len(_name_boundary.attributes(quarry_pe_local_527be8e)['sections']), ''.join((quarry_c_27feb15 for quarry_c_27feb15 in quarry_section_881ea3d.Name if quarry_c_27feb15 in quarry_string.printable)))
            quarry_section_signatures_d8d7d79.append(_name_boundary.attributes(quarry_self_af16e98)['__generate_signature'](quarry_pe_local_527be8e, quarry_offset_local_bf94f32, quarry_sig_name_0201d47, ep_only=False, section_start_only=True, sig_length=quarry_sig_length_610ca79))
        return '\n'.join(quarry_section_signatures_d8d7d79) + '\n'

    @_name_boundary.callable_contract({'self': 'quarry_self_821c607', 'sig_length': 'quarry_sig_length_883ac68', 'pe': 'quarry_pe_local_5528f36', 'name': 'quarry_name_local_e7879f8'}, 'generate_ep_signature')
    def quarry_generate_ep_signature(quarry_self_821c607, quarry_pe_local_5528f36, quarry_name_local_e7879f8, quarry_sig_length_883ac68=512):
        """Generate signatures for the entry point of a PE file.

        Creates a signature whose name will be the parameter 'name'
        and the section number and its name.
        """
        quarry_offset_local_706f55e = _name_boundary.attributes(quarry_pe_local_5528f36)['get_offset_from_rva'](_name_boundary.attributes(quarry_pe_local_5528f36)['OPTIONAL_HEADER'].AddressOfEntryPoint)
        return _name_boundary.attributes(quarry_self_821c607)['__generate_signature'](quarry_pe_local_5528f36, quarry_offset_local_706f55e, quarry_name_local_e7879f8, ep_only=True, sig_length=quarry_sig_length_883ac68)

    @staticmethod
    @_name_boundary.callable_contract({'ep_only': 'quarry_ep_only_8d1c5cd', 'section_start_only': 'quarry_section_start_only_124ecff', 'sig_length': 'quarry_sig_length_873b760', 'pe': 'quarry_pe_local_24b54a3', 'offset': 'quarry_offset_local_12ab4f0', 'name': 'quarry_name_local_7cf8fbb'}, '__generate_signature')
    def quarry___generate_signature(quarry_pe_local_24b54a3, quarry_offset_local_12ab4f0, quarry_name_local_7cf8fbb, quarry_ep_only_8d1c5cd=False, quarry_section_start_only_124ecff=False, quarry_sig_length_873b760=512):
        quarry_data_local_977428e = quarry_pe_local_24b54a3.__data__[quarry_offset_local_12ab4f0:quarry_offset_local_12ab4f0 + quarry_sig_length_873b760]
        quarry_signature_bytes_48375d2 = ' '.join((f'{ord(quarry_c_46afac6):02x}' for quarry_c_46afac6 in quarry_data_local_977428e))
        if quarry_ep_only_8d1c5cd:
            quarry_ep_only_8d1c5cd = 'true'
        else:
            quarry_ep_only_8d1c5cd = 'false'
        if quarry_section_start_only_124ecff:
            quarry_section_start_only_124ecff = 'true'
        else:
            quarry_section_start_only_124ecff = 'false'
        quarry_signature_16b75bd = f'[{quarry_name_local_7cf8fbb}]\nsignature = {quarry_signature_bytes_48375d2}\nep_only = {quarry_ep_only_8d1c5cd}\nsection_start_only = {quarry_section_start_only_124ecff}\n'
        return quarry_signature_16b75bd

    @_name_boundary.callable_contract({'self': 'quarry_self_568f711', 'ep_only': 'quarry_ep_only_e17dc43', 'section_start_only': 'quarry_section_start_only_6e7bb0a', 'pe': 'quarry_pe_local_0e6dc4d'}, 'match')
    def quarry_match(quarry_self_568f711, quarry_pe_local_0e6dc4d, quarry_ep_only_e17dc43=True, quarry_section_start_only_6e7bb0a=False):
        """Matches and returns the exact match(es).

        If ep_only is True the result will be a string with
        the packer name. Otherwise it will be a list of the
        form (file_offset, packer_name) specifying where
        in the file the signature was found.
        """
        quarry_matches_9f036f3 = _name_boundary.attributes(quarry_self_568f711)['__match'](quarry_pe_local_0e6dc4d, quarry_ep_only_e17dc43, quarry_section_start_only_6e7bb0a)
        if quarry_matches_9f036f3:
            if not quarry_ep_only_e17dc43:
                return [(quarry_match_261681d[0], quarry_match_261681d[1][-1]) for quarry_match_261681d in quarry_matches_9f036f3]
            return quarry_matches_9f036f3[1][-1]
        return None

    @_name_boundary.callable_contract({'self': 'quarry_self_10839db', 'ep_only': 'quarry_ep_only_7717807', 'section_start_only': 'quarry_section_start_only_af2a9be', 'pe': 'quarry_pe_local_76c1cc9'}, 'match_all')
    def quarry_match_all(quarry_self_10839db, quarry_pe_local_76c1cc9, quarry_ep_only_7717807=True, quarry_section_start_only_af2a9be=False):
        """Matches and returns all the likely matches."""
        quarry_matches_f6e71c1 = _name_boundary.attributes(quarry_self_10839db)['__match'](quarry_pe_local_76c1cc9, quarry_ep_only_7717807, quarry_section_start_only_af2a9be)
        if quarry_matches_f6e71c1:
            if not quarry_ep_only_7717807:
                return quarry_matches_f6e71c1
            return quarry_matches_f6e71c1[1]
        return None

    @_name_boundary.callable_contract({'self': 'quarry_self_8839f4b', 'ep_only': 'quarry_ep_only_87e4b65', 'section_start_only': 'quarry_section_start_only_057f869', 'pe': 'quarry_pe_local_b4d7ddd'}, '__match')
    def quarry___match(quarry_self_8839f4b, quarry_pe_local_b4d7ddd, quarry_ep_only_87e4b65, quarry_section_start_only_057f869):
        if quarry_section_start_only_057f869 is True:
            try:
                quarry_data_local_128e552 = quarry_pe_local_b4d7ddd.__data__
            except Exception:
                raise
            quarry_signatures_8ec888c = _name_boundary.attributes(quarry_self_8839f4b)['signature_tree_section_start']
            quarry_scan_addresses_5ba05df = [quarry_section_381a5cf.PointerToRawData for quarry_section_381a5cf in _name_boundary.attributes(quarry_pe_local_b4d7ddd)['sections']]
        elif quarry_ep_only_87e4b65 is True:
            try:
                quarry_data_local_128e552 = _name_boundary.attributes(quarry_pe_local_b4d7ddd)['get_memory_mapped_image']()
            except Exception:
                raise
            quarry_signatures_8ec888c = _name_boundary.attributes(quarry_self_8839f4b)['signature_tree_eponly_true']
            quarry_ep_0931c1c = _name_boundary.attributes(quarry_pe_local_b4d7ddd)['OPTIONAL_HEADER'].AddressOfEntryPoint
            quarry_scan_addresses_5ba05df = [quarry_ep_0931c1c]
        else:
            quarry_data_local_128e552 = quarry_pe_local_b4d7ddd.__data__
            quarry_signatures_8ec888c = _name_boundary.attributes(quarry_self_8839f4b)['signature_tree_eponly_false']
            quarry_scan_addresses_5ba05df = range(len(quarry_data_local_128e552))
        quarry_matches_6005420 = []
        for quarry_idx_e9d6b2d in quarry_scan_addresses_5ba05df:
            quarry_result_9120c2f = _name_boundary.attributes(quarry_self_8839f4b)['__match_signature_tree'](quarry_signatures_8ec888c, quarry_data_local_128e552[quarry_idx_e9d6b2d:quarry_idx_e9d6b2d + _name_boundary.attributes(quarry_self_8839f4b)['max_depth']])
            if quarry_result_9120c2f:
                quarry_matches_6005420.append((quarry_idx_e9d6b2d, quarry_result_9120c2f))
        if quarry_ep_only_87e4b65 is True and quarry_matches_6005420:
            return quarry_matches_6005420[0]
        return quarry_matches_6005420

    @_name_boundary.callable_contract({'self': 'quarry_self_9740fef', 'code_data': 'quarry_code_data_5586232', 'ep_only': 'quarry_ep_only_d94a154', 'section_start_only': 'quarry_section_start_only_79f1b54'}, 'match_data')
    def quarry_match_data(quarry_self_9740fef, quarry_code_data_5586232, quarry_ep_only_d94a154=True, quarry_section_start_only_79f1b54=False):
        quarry_data_local_00b4a96 = quarry_code_data_5586232
        quarry_scan_addresses_7e85b34 = [0]
        if quarry_section_start_only_79f1b54:
            quarry_signatures_86d0471 = _name_boundary.attributes(quarry_self_9740fef)['signature_tree_section_start']
        elif quarry_ep_only_d94a154:
            quarry_signatures_86d0471 = _name_boundary.attributes(quarry_self_9740fef)['signature_tree_eponly_true']
        quarry_matches_ad3da93 = []
        for quarry_idx_f1d59cb in quarry_scan_addresses_7e85b34:
            quarry_result_85846fe = _name_boundary.attributes(quarry_self_9740fef)['__match_signature_tree'](quarry_signatures_86d0471, quarry_data_local_00b4a96[quarry_idx_f1d59cb:quarry_idx_f1d59cb + _name_boundary.attributes(quarry_self_9740fef)['max_depth']])
            if quarry_result_85846fe:
                quarry_matches_ad3da93.append((quarry_idx_f1d59cb, quarry_result_85846fe))
        if quarry_ep_only_d94a154 and quarry_matches_ad3da93:
            return quarry_matches_ad3da93[0]
        return quarry_matches_ad3da93

    @_name_boundary.callable_contract({'self': 'quarry_self_492fd40', 'signature_tree': 'quarry_signature_tree_ed7f878', 'depth': 'quarry_depth_625d3ea', 'data': 'quarry_data_local_04ccef2'}, '__match_signature_tree')
    def quarry___match_signature_tree(quarry_self_492fd40, quarry_signature_tree_ed7f878, quarry_data_local_04ccef2, quarry_depth_625d3ea=0):
        """Recursive function to find matches along the signature tree.

        signature_tree  is the part of the tree left to walk
        data    is the data being checked against the signature tree
        depth   keeps track of how far we have gone down the tree
        """
        quarry_matched_names_433cdd1 = []
        quarry_match_af6d5c1 = quarry_signature_tree_ed7f878
        for quarry_idx_0ac29b4, quarry_byte_6c81555 in enumerate([quarry_b_1270bdd if isinstance(quarry_b_1270bdd, int) else ord(quarry_b_1270bdd) for quarry_b_1270bdd in quarry_data_local_04ccef2]):
            if quarry_match_af6d5c1 is None:
                break
            quarry_match_next_09df9b2 = quarry_match_af6d5c1.get(quarry_byte_6c81555, None)
            if None in list(quarry_match_af6d5c1.values()):
                quarry_names_82f6afc = []
                for quarry_item_e1ebbfa in quarry_match_af6d5c1.items():
                    if quarry_item_e1ebbfa[1] is None:
                        quarry_names_82f6afc.append(quarry_item_e1ebbfa[0])
                quarry_matched_names_433cdd1.append(quarry_names_82f6afc)
            if '??' in quarry_match_af6d5c1:
                quarry_match_tree_alternate_0067620 = quarry_match_af6d5c1.get('??', None)
                quarry_data_remaining_24a2e83 = quarry_data_local_04ccef2[quarry_idx_0ac29b4 + 1:]
                if quarry_data_remaining_24a2e83:
                    quarry_matched_names_433cdd1.extend(_name_boundary.attributes(quarry_self_492fd40)['__match_signature_tree'](quarry_match_tree_alternate_0067620, quarry_data_remaining_24a2e83, quarry_idx_0ac29b4 + quarry_depth_625d3ea + 1))
            quarry_match_af6d5c1 = quarry_match_next_09df9b2
        if quarry_match_af6d5c1 is not None and None in list(quarry_match_af6d5c1.values()):
            quarry_names_82f6afc = []
            for quarry_item_e1ebbfa in quarry_match_af6d5c1.items():
                if quarry_item_e1ebbfa[1] is None:
                    quarry_names_82f6afc.append(quarry_item_e1ebbfa[0])
            quarry_matched_names_433cdd1.append(quarry_names_82f6afc)
        return quarry_matched_names_433cdd1

    @_name_boundary.callable_contract({'self': 'quarry_self_a2e866e', 'filename': 'quarry_filename_0865f0c', 'data': 'quarry_data_local_323dc7c'}, 'load')
    def quarry_load(quarry_self_a2e866e, quarry_filename_0865f0c=None, quarry_data_local_323dc7c=None):
        """Load a PEiD signature file.

        Invoking this method on different files combines the signatures.
        """
        _name_boundary.attributes(quarry_self_a2e866e)['__load'](filename=quarry_filename_0865f0c, data=quarry_data_local_323dc7c)

    @_name_boundary.callable_contract({'self': 'quarry_self_de218fb', 'filename': 'quarry_filename_363b0a6', 'data': 'quarry_data_local_2ca9083'}, '__load')
    def quarry___load(quarry_self_de218fb, quarry_filename_363b0a6=None, quarry_data_local_2ca9083=None):
        if quarry_filename_363b0a6 is not None:
            if not quarry_os.path.exists(quarry_filename_363b0a6):
                try:
                    quarry_sig_f_dac1393 = quarry_urllib.request.urlopen(quarry_filename_363b0a6)
                    quarry_sig_data_ed6de08 = quarry_sig_f_dac1393.read()
                    _name_boundary.attributes(quarry_sig_f_dac1393)['close']()
                except OSError:
                    raise
            else:
                try:
                    with open(quarry_filename_363b0a6, 'r') as quarry_f_8fdc727:
                        quarry_sig_data_ed6de08 = quarry_f_8fdc727.read()
                except OSError:
                    raise
        else:
            quarry_sig_data_ed6de08 = quarry_data_local_2ca9083
        if not quarry_sig_data_ed6de08:
            return

        @_name_boundary.callable_contract({'value': 'quarry_value_895c8ad'}, 'to_byte')
        def quarry_to_byte_1531848(quarry_value_895c8ad):
            if '?' in quarry_value_895c8ad:
                return quarry_value_895c8ad
            return int(quarry_value_895c8ad, 16)
        quarry_matches_6e5b5d3 = _name_boundary.attributes(quarry_self_de218fb)['parse_sig'].findall(quarry_sig_data_ed6de08)
        for quarry_packer_name_5fb3da6, quarry_signature_d33ce95, quarry_superfluous_wildcards_36aa04f, quarry_ep_only_619d4ad, quarry_section_start_only_06a788a in quarry_matches_6e5b5d3:
            quarry_ep_only_619d4ad = quarry_ep_only_619d4ad.strip().lower()
            quarry_signature_d33ce95 = quarry_signature_d33ce95.replace('\\n', '').strip()
            quarry_signature_bytes_aba38ab = [quarry_to_byte_1531848(quarry_b_14922c8) for quarry_b_14922c8 in quarry_signature_d33ce95.split()]
            if quarry_ep_only_619d4ad == 'true':
                quarry_ep_only_619d4ad = True
            else:
                quarry_ep_only_619d4ad = False
            if quarry_section_start_only_06a788a == 'true':
                quarry_section_start_only_06a788a = True
            else:
                quarry_section_start_only_06a788a = False
            quarry_depth_a72ebf6 = 0
            if quarry_section_start_only_06a788a:
                quarry_tree_7955e28 = _name_boundary.attributes(quarry_self_de218fb)['signature_tree_section_start']
                _name_boundary.attributes(quarry_self_de218fb)['signature_count_section_start'] += 1
            elif quarry_ep_only_619d4ad:
                quarry_tree_7955e28 = _name_boundary.attributes(quarry_self_de218fb)['signature_tree_eponly_true']
                _name_boundary.attributes(quarry_self_de218fb)['signature_count_eponly_true'] += 1
            else:
                quarry_tree_7955e28 = _name_boundary.attributes(quarry_self_de218fb)['signature_tree_eponly_false']
                _name_boundary.attributes(quarry_self_de218fb)['signature_count_eponly_false'] += 1
            for quarry_idx_352bfee, quarry_byte_e4accd7 in enumerate(quarry_signature_bytes_aba38ab, start=1):
                if quarry_idx_352bfee == len(quarry_signature_bytes_aba38ab):
                    quarry_tree_7955e28[quarry_byte_e4accd7] = quarry_tree_7955e28.get(quarry_byte_e4accd7, {})
                    quarry_tree_7955e28[quarry_byte_e4accd7][quarry_packer_name_5fb3da6] = None
                else:
                    quarry_tree_7955e28[quarry_byte_e4accd7] = quarry_tree_7955e28.get(quarry_byte_e4accd7, {})
                quarry_tree_7955e28 = quarry_tree_7955e28[quarry_byte_e4accd7]
                quarry_depth_a72ebf6 += 1
            _name_boundary.attributes(quarry_self_de218fb)['max_depth'] = max(_name_boundary.attributes(quarry_self_de218fb)['max_depth'], quarry_depth_a72ebf6)

@_name_boundary.callable_contract({'pe': 'quarry_pe_local_5eb6582'}, 'is_valid')
def quarry_is_valid(quarry_pe_local_5eb6582):
    """"""

@_name_boundary.callable_contract({'pe': 'quarry_pe_local_3161c85'}, 'is_suspicious')
def quarry_is_suspicious(quarry_pe_local_3161c85):
    """
    Unusual locations of import tables
    Non-recognized section names
    Presence of long ASCII strings
    """
    quarry_relocations_overlap_entry_point_491055f = False
    quarry_sequential_relocs_6127803 = 0
    if _name_boundary.has_attribute(quarry_pe_local_3161c85, 'DIRECTORY_ENTRY_BASERELOC'):
        for quarry_base_reloc_13d3f9f in quarry_pe_local_3161c85.DIRECTORY_ENTRY_BASERELOC:
            quarry_last_reloc_rva_8cca70c = None
            for quarry_reloc_50d6625 in quarry_base_reloc_13d3f9f.entries:
                if quarry_reloc_50d6625.rva <= _name_boundary.attributes(quarry_pe_local_3161c85)['OPTIONAL_HEADER'].AddressOfEntryPoint <= quarry_reloc_50d6625.rva + 4:
                    quarry_relocations_overlap_entry_point_491055f = True
                if quarry_last_reloc_rva_8cca70c is not None and quarry_last_reloc_rva_8cca70c <= quarry_reloc_50d6625.rva <= quarry_last_reloc_rva_8cca70c + 4:
                    quarry_sequential_relocs_6127803 += 1
                quarry_last_reloc_rva_8cca70c = quarry_reloc_50d6625.rva
    quarry_warnings_while_parsing_d812de0 = False
    quarry_warnings_cf3d501 = _name_boundary.attributes(quarry_pe_local_3161c85)['get_warnings']()
    if quarry_warnings_cf3d501:
        quarry_warnings_while_parsing_d812de0

@_name_boundary.callable_contract({'section_entropy': 'quarry_section_entropy_c313583', 'packed_threshold': 'quarry_packed_threshold_8fb8eb8', 'pe': 'quarry_pe_local_6c84d8f'}, 'is_probably_packed')
def quarry_is_probably_packed(quarry_pe_local_6c84d8f, quarry_section_entropy_c313583=7.4, quarry_packed_threshold_8fb8eb8=0.2):
    """
    The entropy of sections are analyzed to determine if they likely contain
    compressed data (default > 7.4). The proportion of the total size of these
    (probably) compressed sections to the total file size (excluding any
    overlay) is calculated. If this proportion is greater than a threshold
    (default > 0.2) the PE file is likely packed or compressed.

    The section entropy default of 7.4 is empirical, based on looking at a few
    files packed by different packers. This and the packed threshold can be user
    specified.

    Args:
        pe: An instance of class PE.
        section_entropy: Threshold of a section being considered packed / compressed.
        packed_threshold: The proportion of the size of high-entropy sections to
            total file size, above which it is assumed that it could be an installer
            or a packed file.

    Returns:
        True if file is probably packed or contains compressed data, False otherwise.
    """
    quarry_total_pe_data_length_2d04246 = len(_name_boundary.attributes(quarry_pe_local_6c84d8f)['trim']())
    if not quarry_total_pe_data_length_2d04246:
        return True
    quarry_total_compressed_data_9dfc290 = 0
    for quarry_section_bac9308 in _name_boundary.attributes(quarry_pe_local_6c84d8f)['sections']:
        quarry_s_entropy_bf67d65 = _name_boundary.attributes(quarry_section_bac9308)['get_entropy']()
        if quarry_s_entropy_bf67d65 > quarry_section_entropy_c313583:
            quarry_total_compressed_data_9dfc290 += len(_name_boundary.attributes(quarry_section_bac9308)['get_data']())
    quarry_has_significant_amount_of_compressed_data_7543ac5 = False
    if quarry_total_compressed_data_9dfc290 / quarry_total_pe_data_length_2d04246 > quarry_packed_threshold_8fb8eb8:
        quarry_has_significant_amount_of_compressed_data_7543ac5 = True
    return quarry_has_significant_amount_of_compressed_data_7543ac5
_name_boundary.module_contract(globals(), {'pefile': 'quarry_pefile', 'SignatureDatabase': 'quarry_SignatureDatabase', 'is_valid': 'quarry_is_valid', 're': 'quarry_re', 'is_probably_packed': 'quarry_is_probably_packed', 'is_suspicious': 'quarry_is_suspicious', 'os': 'quarry_os', 'urllib': 'quarry_urllib', 'string': 'quarry_string'})
