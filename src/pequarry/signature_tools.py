# Derived from peutils.py; original copyright and MIT license retained.
"""Static signature utilities; bounded parsing and iterative matching.

Copyright (c) 2005-2024 Ero Carrera <ero.carrera@gmail.com>
All rights reserved. PEQuarry maintenance preserves attribution in ORIGIN.md.
"""
import re as quarry_re
import urllib.request as quarry_request
import urllib.parse as quarry_urlparse
import math as quarry_math
import pequarry.api_contract as _name_boundary
import pequarry.image_reader as quarry_pefile
from pequarry.bounded_io import quarry_LimitError, quarry_SIGNATURE_LIMIT, quarry_positive_limit, quarry_read_regular
__author__ = 'Ero Carrera'
__version__ = quarry_pefile.__version__
__contact__ = 'ero.carrera@gmail.com'

@_name_boundary.class_contract('SignatureDatabase', {'generate_section_signatures': 'quarry_generate_section_signatures', 'generate_ep_signature': 'quarry_generate_ep_signature', '__generate_signature': 'quarry___generate_signature', 'match': 'quarry_match', 'match_all': 'quarry_match_all', '__match': 'quarry___match', 'match_data': 'quarry_match_data', '__match_signature_tree': 'quarry___match_signature_tree', 'load': 'quarry_load', '__load': 'quarry___load', 'parse_sig': 'quarry_parse_sig', 'signature_tree_eponly_false': 'quarry_signature_tree_eponly_false', 'signature_tree_eponly_true': 'quarry_signature_tree_eponly_true', 'signature_tree_section_start': 'quarry_signature_tree_section_start', 'signature_count_eponly_false': 'quarry_signature_count_eponly_false', 'signature_count_eponly_true': 'quarry_signature_count_eponly_true', 'signature_count_section_start': 'quarry_signature_count_section_start', 'max_depth': 'quarry_max_depth', 'load_url': 'quarry_load_url'})
class quarry_SignatureDatabase:
    """Local PEiD signature database. URL retrieval requires explicit load_url().

    Successful loads combine signatures. A malformed or over-limit load leaves
    the existing trees and counts unchanged. Matching is static and finite;
    reaching a budget raises LimitError rather than reporting a negative match.
    """
    def __init__(quarry_self, filename=None, data=None, *, max_bytes=quarry_SIGNATURE_LIMIT,
                 max_signatures=65536, max_depth=4096, max_nodes=1048576,
                 max_match_steps=4194304, max_matches=65536):
        quarry_self._quarry_limits = tuple(quarry_positive_limit(quarry_v, quarry_n) for quarry_v, quarry_n in (
            (max_bytes, 'max_bytes'), (max_signatures, 'max_signatures'),
            (max_depth, 'max_depth'), (max_nodes, 'max_nodes'),
            (max_match_steps, 'max_match_steps'), (max_matches, 'max_matches')))
        # Retained compatibility attribute; the actual parser is line based.
        quarry_self.parse_sig = quarry_re.compile(r'\[(.*?)\]\s+?signature\s*=\s*(.*?)(\s+\?\?)*\s*ep_only\s*=\s*(\w+)(?:\s*section_start_only\s*=\s*(\w+)|)', quarry_re.DOTALL)
        quarry_self.signature_tree_eponly_false = {}
        quarry_self.signature_tree_eponly_true = {}
        quarry_self.signature_tree_section_start = {}
        quarry_self.signature_count_eponly_false = 0
        quarry_self.signature_count_eponly_true = 0
        quarry_self.signature_count_section_start = 0
        quarry_self.max_depth = 0
        quarry_self._quarry_nodes = 0
        quarry_self._quarry_loaded_bytes = 0
        quarry_self.quarry_load(filename, data)

    def quarry_load(quarry_self, filename=None, data=None):
        if filename is not None and data is not None:
            raise ValueError('supply filename or data, not both')
        if filename is not None:
            # Missing paths remain missing paths. No URL or file:// fallback.
            quarry_source = quarry_read_regular(filename, quarry_self._quarry_limits[0], quarry_allow_empty=True)
        elif data is None:
            return
        else:
            quarry_source = data
        quarry_self.quarry___load(data=quarry_source)

    def quarry_load_url(quarry_self, url, *, timeout=10.0):
        """Explicit HTTPS retrieval; redirects and embedded credentials rejected.

        The caller owns destination authorization. This opt-in method makes an
        outbound request. The normal constructor/load path never does so.
        """
        if not isinstance(url, str) or any(ord(quarry_c) < 33 for quarry_c in url):
            raise ValueError('URL must be an HTTPS string without controls')
        quarry_parts = quarry_urlparse.urlsplit(url)
        if quarry_parts.scheme != 'https' or not quarry_parts.hostname or quarry_parts.username is not None or quarry_parts.password is not None or quarry_parts.fragment:
            raise ValueError('URL must use HTTPS without credentials or fragments')
        if isinstance(timeout, bool) or not isinstance(timeout, (int, float)) or not quarry_math.isfinite(timeout) or timeout <= 0 or timeout > 60:
            raise ValueError('timeout must be finite and between 0 and 60 seconds')
        class quarry_NoRedirect(quarry_request.HTTPRedirectHandler):
            def redirect_request(quarry_handler, quarry_req, quarry_fp, quarry_code, quarry_msg, quarry_headers, quarry_newurl):
                quarry_fp.close()
                raise ValueError('signature download redirects are not permitted')
        quarry_opener = quarry_request.build_opener(quarry_NoRedirect)
        quarry_limit = quarry_self._quarry_limits[0]
        with quarry_opener.open(url, timeout=timeout) as quarry_response:
            quarry_chunks = []
            quarry_total = 0
            while True:
                quarry_chunk = quarry_response.read(min(65536, quarry_limit - quarry_total + 1))
                if not quarry_chunk:
                    break
                quarry_total += len(quarry_chunk)
                if quarry_total > quarry_limit:
                    raise quarry_LimitError('signature download exceeds byte limit')
                quarry_chunks.append(quarry_chunk)
        quarry_self.quarry___load(data=b''.join(quarry_chunks))

    def quarry___load(quarry_self, filename=None, data=None):
        if filename is not None:
            return quarry_self.quarry_load(filename, data)
        if data is None:
            return
        if isinstance(data, bytes):
            quarry_size = len(data)
            if quarry_size > quarry_self._quarry_limits[0]:
                raise quarry_LimitError('signature input exceeds byte limit')
            quarry_text = data.decode('utf-8-sig')
        elif isinstance(data, str):
            if len(data) > quarry_self._quarry_limits[0]:
                raise quarry_LimitError('signature input exceeds byte limit')
            quarry_size = len(data.encode('utf-8'))
            quarry_text = data.lstrip('\ufeff')
        else:
            raise TypeError('signature data must be str or UTF-8 bytes')
        if quarry_size > quarry_self._quarry_limits[0] or quarry_size + quarry_self._quarry_loaded_bytes > quarry_self._quarry_limits[0]:
            raise quarry_LimitError('combined signature input exceeds byte limit')
        quarry_records = quarry_self._quarry_parse_records(quarry_text)
        quarry_count = sum((quarry_self.signature_count_eponly_false, quarry_self.signature_count_eponly_true, quarry_self.signature_count_section_start))
        if quarry_count + len(quarry_records) > quarry_self._quarry_limits[1]:
            raise quarry_LimitError('signature count exceeds limit')
        # Plan fresh nodes against all current trees, then mutate only after the
        # entire input has been accepted. No recursive deepcopy is needed.
        quarry_pending = {}
        quarry_additions = []
        quarry_new_nodes = 0
        for quarry_name, quarry_tokens, quarry_kind in quarry_records:
            quarry_tree = quarry_self._quarry_tree(quarry_kind)
            for quarry_token in quarry_tokens:
                quarry_key = (id(quarry_tree), quarry_token)
                quarry_next = quarry_tree.get(quarry_token)
                if quarry_next is None:
                    quarry_next = quarry_pending.get(quarry_key)
                if quarry_next is None:
                    quarry_next = {}
                    quarry_pending[quarry_key] = quarry_next
                    quarry_additions.append((quarry_tree, quarry_token, quarry_next))
                    quarry_new_nodes += 1
                    if quarry_self._quarry_nodes + quarry_new_nodes > quarry_self._quarry_limits[3]:
                        raise quarry_LimitError('signature tree nodes exceed limit')
                quarry_tree = quarry_next
            quarry_additions.append((quarry_tree, quarry_name, None))
        for quarry_tree, quarry_key, quarry_value in quarry_additions:
            quarry_tree[quarry_key] = quarry_value
        quarry_self._quarry_nodes += quarry_new_nodes
        quarry_self._quarry_loaded_bytes += quarry_size
        for quarry_name, quarry_tokens, quarry_kind in quarry_records:
            quarry_field = ('signature_count_eponly_false', 'signature_count_eponly_true', 'signature_count_section_start')[quarry_kind]
            setattr(quarry_self, quarry_field, getattr(quarry_self, quarry_field) + 1)
            quarry_self.max_depth = max(quarry_self.max_depth, len(quarry_tokens))

    def _quarry_parse_records(quarry_self, quarry_text):
        quarry_records = []
        quarry_name = None
        quarry_fields = {}
        quarry_last_key = None
        for quarry_line in quarry_text.splitlines() + ['[__PEQUARRY_END__]']:
            quarry_line = quarry_line.strip()
            if not quarry_line or quarry_line.startswith((';', '#')):
                continue
            if quarry_line.startswith('[') and quarry_line.endswith(']'):
                if quarry_name is not None:
                    if not quarry_fields.get('signature') or 'ep_only' not in quarry_fields:
                        raise ValueError('signature record requires signature and ep_only')
                    quarry_words = quarry_fields['signature'].replace('\\n', '').split()
                    if len(quarry_words) > quarry_self._quarry_limits[2]:
                        raise quarry_LimitError('signature depth exceeds limit')
                    quarry_tokens = []
                    for quarry_word in quarry_words:
                        if quarry_word == '??':
                            quarry_tokens.append('??')
                        elif len(quarry_word) == 2 and all(quarry_c in '0123456789abcdefABCDEF' for quarry_c in quarry_word):
                            quarry_tokens.append(int(quarry_word, 16))
                        else:
                            raise ValueError('signature token must be two hexadecimal digits or ??')
                    quarry_flags = []
                    for quarry_flag in ('ep_only', 'section_start_only'):
                        quarry_value = quarry_fields.get(quarry_flag, 'false').lower()
                        if quarry_value not in ('true', 'false'):
                            raise ValueError('signature flags must be true or false')
                        quarry_flags.append(quarry_value == 'true')
                    quarry_kind = 2 if quarry_flags[1] else int(quarry_flags[0])
                    quarry_records.append((quarry_name, quarry_tokens, quarry_kind))
                    if len(quarry_records) > quarry_self._quarry_limits[1]:
                        raise quarry_LimitError('signature count exceeds limit')
                quarry_name = quarry_line[1:-1].strip()
                if not quarry_name or len(quarry_name) > 1024 or quarry_name == '??' or any(ord(quarry_c) < 32 or quarry_c in '[]' for quarry_c in quarry_name):
                    raise ValueError('invalid signature name')
                quarry_fields = {}
                quarry_last_key = None
            elif '=' in quarry_line:
                if quarry_name is None:
                    raise ValueError('signature fields require a record name')
                quarry_key, quarry_value = (quarry_piece.strip() for quarry_piece in quarry_line.split('=', 1))
                quarry_key = quarry_key.lower()
                if quarry_key not in ('signature', 'ep_only', 'section_start_only') or quarry_key in quarry_fields:
                    raise ValueError('unknown or duplicate signature field')
                quarry_fields[quarry_key] = quarry_value
                quarry_last_key = quarry_key
            elif quarry_last_key == 'signature':
                quarry_fields['signature'] += ' ' + quarry_line
            else:
                raise ValueError('malformed signature record line')
        return quarry_records

    def _quarry_tree(quarry_self, quarry_kind):
        return (quarry_self.signature_tree_eponly_false, quarry_self.signature_tree_eponly_true, quarry_self.signature_tree_section_start)[quarry_kind]

    def quarry___match_signature_tree(quarry_self, signature_tree, data, depth=0, *, _quarry_budget=None):
        if not isinstance(data, (bytes, bytearray, memoryview)):
            raise TypeError('match data must be bytes, bytearray or memoryview')
        quarry_byte_size = data.nbytes if isinstance(data, memoryview) else len(data)
        if quarry_byte_size > quarry_self._quarry_limits[0]:
            raise quarry_LimitError('signature match input exceeds byte limit')
        # Byte-oriented semantics for signed, multi-byte, multidimensional and
        # strided buffer views. Check nbytes before copying the stable snapshot.
        data = bytes(data)
        if type(depth) is not int or depth < 0:
            raise ValueError('depth must be a nonnegative integer')
        quarry_budget = _quarry_budget if _quarry_budget is not None else [0, 0]
        quarry_stack = [(signature_tree, 0)]
        quarry_results = []
        while quarry_stack:
            quarry_node, quarry_index = quarry_stack.pop()
            quarry_budget[0] += 1
            if quarry_budget[0] > quarry_self._quarry_limits[4]:
                raise quarry_LimitError('signature matching step budget exceeded')
            if not isinstance(quarry_node, dict):
                raise ValueError('invalid signature tree')
            quarry_names = [quarry_key for quarry_key, quarry_value in quarry_node.items() if quarry_value is None]
            if quarry_names:
                quarry_budget[1] += len(quarry_names)
                if quarry_budget[1] > quarry_self._quarry_limits[5]:
                    raise quarry_LimitError('signature matches exceed limit')
                quarry_results.append(quarry_names)
            if quarry_index >= len(data) or quarry_index >= quarry_self.max_depth:
                continue
            quarry_byte = data[quarry_index]
            if not isinstance(quarry_byte, int):
                raise TypeError('match data must use byte-sized elements')
            if quarry_byte in quarry_node:
                quarry_stack.append((quarry_node[quarry_byte], quarry_index + 1))
            if '??' in quarry_node:
                quarry_stack.append((quarry_node['??'], quarry_index + 1))
        return quarry_results

    def quarry___match(quarry_self, pe, ep_only=True, section_start_only=False):
        if section_start_only:
            quarry_data = pe.__data__
            quarry_addresses = [quarry_section.PointerToRawData for quarry_section in pe.sections]
            quarry_kind = 2
        elif ep_only:
            quarry_data = pe.get_memory_mapped_image()
            quarry_addresses = [pe.OPTIONAL_HEADER.AddressOfEntryPoint]
            quarry_kind = 1
        else:
            quarry_data = pe.__data__
            quarry_addresses = range(len(quarry_data))
            quarry_kind = 0
        if not ep_only and not section_start_only and len(quarry_data) > quarry_self._quarry_limits[4]:
            raise quarry_LimitError('signature scan input exceeds step budget')
        quarry_matches = []
        quarry_budget = [0, 0]
        quarry_tree = quarry_self._quarry_tree(quarry_kind)
        if not quarry_tree:
            return []
        for quarry_offset in quarry_addresses:
            if type(quarry_offset) is not int or not 0 <= quarry_offset < len(quarry_data):
                continue
            quarry_result = quarry_self.quarry___match_signature_tree(quarry_tree, memoryview(quarry_data)[quarry_offset:quarry_offset + quarry_self.max_depth], _quarry_budget=quarry_budget)
            if quarry_result:
                quarry_matches.append((quarry_offset, quarry_result))
        return quarry_matches[0] if ep_only and quarry_matches else quarry_matches

    def quarry_match_all(quarry_self, pe, ep_only=True, section_start_only=False):
        quarry_matches = quarry_self.quarry___match(pe, ep_only, section_start_only)
        if not quarry_matches:
            return None
        return quarry_matches[1] if ep_only else quarry_matches

    def quarry_match(quarry_self, pe, ep_only=True, section_start_only=False):
        quarry_matches = quarry_self.quarry___match(pe, ep_only, section_start_only)
        if not quarry_matches:
            return None
        return quarry_matches[1][-1] if ep_only else [(quarry_offset, quarry_groups[-1]) for quarry_offset, quarry_groups in quarry_matches]

    def quarry_match_data(quarry_self, code_data, ep_only=True, section_start_only=False):
        quarry_kind = 2 if section_start_only else int(bool(ep_only))
        quarry_result = quarry_self.quarry___match_signature_tree(quarry_self._quarry_tree(quarry_kind), code_data)
        quarry_matches = [(0, quarry_result)] if quarry_result else []
        return quarry_matches[0] if ep_only and quarry_matches else quarry_matches

    @staticmethod
    def quarry___generate_signature(pe, offset, name, ep_only=False, section_start_only=False, sig_length=512):
        quarry_positive_limit(sig_length, 'sig_length')
        if sig_length > 4096:
            raise quarry_LimitError('signature generation length exceeds limit')
        if not isinstance(name, str) or not name or len(name) > 1024 or name == '??' or any(ord(quarry_c) < 32 or quarry_c in '[]' for quarry_c in name):
            raise ValueError('invalid signature name')
        if type(offset) is not int or offset < 0 or offset > len(pe.__data__) or sig_length > len(pe.__data__) - offset:
            raise ValueError('signature generation span is outside the file')
        quarry_data = bytes(pe.__data__[offset:offset + sig_length])
        quarry_hex = ' '.join(f'{quarry_byte:02x}' for quarry_byte in quarry_data)
        return f'[{name}]\nsignature = {quarry_hex}\nep_only = {str(bool(ep_only)).lower()}\nsection_start_only = {str(bool(section_start_only)).lower()}\n'

    def quarry_generate_ep_signature(quarry_self, pe, name, sig_length=512):
        quarry_offset = pe.get_offset_from_rva(pe.OPTIONAL_HEADER.AddressOfEntryPoint)
        return quarry_self.quarry___generate_signature(pe, quarry_offset, name, ep_only=True, sig_length=sig_length)

    def quarry_generate_section_signatures(quarry_self, pe, name, sig_length=512):
        quarry_positive_limit(sig_length, 'sig_length')
        quarry_records = []
        quarry_output_bytes = 1
        for quarry_index, quarry_section in enumerate(pe.sections, start=1):
            if quarry_section.SizeOfRawData < sig_length:
                continue
            quarry_label = bytes(quarry_section.Name).decode('ascii', 'backslashreplace').rstrip('\x00')
            quarry_label = ''.join(quarry_c if 32 <= ord(quarry_c) < 127 and quarry_c not in '[]' else '_' for quarry_c in quarry_label)
            quarry_name = f'{name} Section({quarry_index}/{len(pe.sections)},{quarry_label})'
            quarry_record = quarry_self.quarry___generate_signature(pe, quarry_section.PointerToRawData, quarry_name, section_start_only=True, sig_length=sig_length)
            quarry_output_bytes += len(quarry_record.encode('utf-8')) + 1
            if quarry_output_bytes > quarry_self._quarry_limits[0]:
                raise quarry_LimitError('generated signatures exceed byte limit')
            quarry_records.append(quarry_record)
            if len(quarry_records) > quarry_self._quarry_limits[1]:
                raise quarry_LimitError('generated signature count exceeds limit')
        return '\n'.join(quarry_records) + '\n'


def quarry_is_valid(quarry_pe):
    """Retained upstream placeholder: returns None, not a validity verdict."""
    return None


def quarry_is_suspicious(quarry_pe):
    """Retained upstream placeholder: returns None, not a suspicion verdict."""
    return None


def quarry_is_probably_packed(quarry_pe, section_entropy=7.4, packed_threshold=0.2):
    """Empirical entropy heuristic; does not establish maliciousness."""
    quarry_total = len(quarry_pe.trim())
    if not quarry_total:
        return True
    quarry_compressed = sum(len(quarry_section.get_data()) for quarry_section in quarry_pe.sections if quarry_section.get_entropy() > section_entropy)
    return quarry_compressed / quarry_total > packed_threshold

_name_boundary.module_contract(globals(), {'pefile': 'quarry_pefile', 'SignatureDatabase': 'quarry_SignatureDatabase', 'is_valid': 'quarry_is_valid', 'is_probably_packed': 'quarry_is_probably_packed', 'is_suspicious': 'quarry_is_suspicious'})
