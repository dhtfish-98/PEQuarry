"""A comparison must retain mixed key types without masking parser fields."""
import json
import pytest
from checks.observation_json import dumps


@pytest.mark.parametrize('pair', [(b'entry','entry'), (1,'1'), (False,'False'), ((1,2),'(1, 2)')])
def test_typed_keys_survive_sorting_and_retain_distinct_fields(pair):
    first, second = pair
    value = {first: {'translation': [(0,0)], 'data': b'\xff'}, second: {'translation': [(1033,1200)], 'data': b'\0'}}
    encoded = dumps(value)
    assert encoded == dumps(dict(reversed(list(value.items()))))
    assert len(json.loads(encoded)['dict']) == 2
    changed = dict(value);changed[second] = {'translation': [(0,1200)], 'data': b'\0'}
    assert dumps(changed) != encoded
    assert dumps({first: value[first]}) != dumps({second: value[first]})
