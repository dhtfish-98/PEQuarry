"""Lossless comparable JSON for dumps containing both byte and text keys."""
import json


def typed(value):
    if isinstance(value, dict):
        items = [(typed(key), typed(item)) for key, item in value.items()]
        items.sort(key=lambda item: json.dumps(item[0], sort_keys=True, ensure_ascii=True))
        return {'dict': items}
    if isinstance(value, bytes):
        return {'bytes': value.hex()}
    if isinstance(value, (tuple, list)):
        return {'tuple' if isinstance(value, tuple) else 'list': [typed(item) for item in value]}
    if value is None or isinstance(value, (bool, int, float, str)):
        return {'type': type(value).__name__, 'value': value}
    return {'type': type(value).__name__.removeprefix('quarry_'), 'value': str(value)}


def dumps(value):
    return json.dumps(typed(value), sort_keys=True, ensure_ascii=True)
