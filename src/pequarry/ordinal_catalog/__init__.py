# Derived from ordlookup/__init__.py; original copyright and license retained in ORIGIN.md.
import pequarry.api_contract as _name_boundary
__boundary_names__ = {'oleaut32': 'automation_names', 'ws2_32': 'winsock2_names', 'wsock32': 'winsock1_names', 'imphash_oleaut32': 'automation_hash_names', 'imphash_ws2_32': 'winsock_hash_names'}
from pequarry.ordinal_catalog import automation_hash_names as quarry_imphash_oleaut32, winsock_hash_names as quarry_imphash_ws2_32, automation_names as quarry_oleaut32, winsock2_names as quarry_ws2_32, winsock1_names as quarry_wsock32
'\nA small module containing a database of ordinal to symbol mappings for DLLs\nwhich frequently get linked without symbolic information.\n'
quarry_ords = {b'oleaut32.dll': quarry_oleaut32.ord_names, b'ws2_32.dll': quarry_ws2_32.ord_names, b'wsock32.dll': quarry_wsock32.ord_names}

@_name_boundary.callable_contract({'ord_val': 'quarry_ord_val_a2f2977'}, 'format_ordinal')
def quarry_format_ordinal(quarry_ord_val_a2f2977):
    return f'ord{quarry_ord_val_a2f2977}'.encode()

@_name_boundary.callable_contract({'libname': 'quarry_libname_115c5c0', 'ord_val': 'quarry_ord_val_33165e2', 'make_name': 'quarry_make_name_fb9cc50'}, 'ordinal_lookup')
def quarry_ordinal_lookup(quarry_libname_115c5c0, quarry_ord_val_33165e2, quarry_make_name_fb9cc50=False):
    """
    Lookup a name for the given ordinal if it's in our database.
    """
    quarry_names_696ebe3 = quarry_ords.get(quarry_libname_115c5c0.lower())
    if quarry_names_696ebe3 is None:
        if quarry_make_name_fb9cc50 is True:
            return quarry_format_ordinal(quarry_ord_val_33165e2)
        return None
    quarry_name_local_ed068be = quarry_names_696ebe3.get(quarry_ord_val_33165e2)
    if quarry_name_local_ed068be is None:
        return quarry_format_ordinal(quarry_ord_val_33165e2)
    return quarry_name_local_ed068be
quarry_imphash_ords = {b'oleaut32.dll': quarry_imphash_oleaut32.ord_names, b'ws2_32.dll': quarry_imphash_ws2_32.ord_names, b'wsock32.dll': quarry_imphash_ws2_32.ord_names}

@_name_boundary.callable_contract({'ord_val': 'quarry_ord_val_8f6176f'}, 'imphash_format_ordinal')
def quarry_imphash_format_ordinal(quarry_ord_val_8f6176f):
    return f'ord{quarry_ord_val_8f6176f}'.encode()

@_name_boundary.callable_contract({'libname': 'quarry_libname_020bdbe', 'ord_val': 'quarry_ord_val_ad376e4', 'make_name': 'quarry_make_name_2dfb4c6'}, 'imphash_ordinal_lookup')
def quarry_imphash_ordinal_lookup(quarry_libname_020bdbe, quarry_ord_val_ad376e4, quarry_make_name_2dfb4c6=False):
    """
    Lookup a name for the given ordinal using the imphash-specific database.

    This uses ordinal tables that are frozen to the state when the original
    implementation was written so that imphash values remain compatible with
    YARA, YARA-X, VirusTotal, and other tools based on the original pefile
    implementation.
    """
    quarry_names_464ae50 = quarry_imphash_ords.get(quarry_libname_020bdbe.lower())
    if quarry_names_464ae50 is None:
        if quarry_make_name_2dfb4c6 is True:
            return quarry_imphash_format_ordinal(quarry_ord_val_ad376e4)
        return None
    quarry_name_local_5872c68 = quarry_names_464ae50.get(quarry_ord_val_ad376e4)
    if quarry_name_local_5872c68 is None:
        return quarry_imphash_format_ordinal(quarry_ord_val_ad376e4)
    return quarry_name_local_5872c68
_name_boundary.module_contract(globals(), {'imphash_format_ordinal': 'quarry_imphash_format_ordinal', 'imphash_oleaut32': 'automation_hash_names', 'imphash_ords': 'quarry_imphash_ords', 'ordinal_lookup': 'quarry_ordinal_lookup', 'imphash_ws2_32': 'winsock_hash_names', 'ws2_32': 'winsock2_names', 'imphash_ordinal_lookup': 'quarry_imphash_ordinal_lookup', 'format_ordinal': 'quarry_format_ordinal', 'ords': 'quarry_ords', 'wsock32': 'winsock1_names', 'oleaut32': 'automation_names'})
