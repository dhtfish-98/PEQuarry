"""Observe available historical cases; known fixture gaps stay visible."""
import contextlib as history_context
import importlib.util as history_import
import io as history_io
import json as history_json
import sys as history_sys
import unittest as history_unittest

history_source, history_data, history_variant = history_sys.argv[1:]
history_spec = history_import.spec_from_file_location('historical_fixture_observation',history_source)
history_module = history_import.module_from_spec(history_spec)
history_sys.modules[history_spec.name] = history_module
history_spec.loader.exec_module(history_module)
history_module.REGRESSION_TESTS_DIR = history_data
history_class = history_module.quarry_TestPEFile if history_variant=='rewritten' else history_module.TestPEFile
history_results = []
for history_method in history_unittest.defaultTestLoader.getTestCaseNames(history_class):
    if history_method=='test_pe_image_regression_test':
        continue  # This old test generates controls in its input dataset.
    history_instance = history_class(history_method)
    history_item = {'case':history_method}
    try:
        with history_context.redirect_stdout(history_io.StringIO()):
            history_instance.setUp()
            getattr(history_instance,history_method)()
        history_item['outcome'] = 'PASS'
    except Exception as history_error:
        history_item.update(outcome='BASELINE_FAILURE',exception_type=type(history_error).__name__.removeprefix('quarry_'),message=str(history_error))
    history_results.append(history_item)
print(history_json.dumps(history_results,sort_keys=True))
