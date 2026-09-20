import pytest
from coboleval.execution import execution_request
from test_scoring import record




def test_cobol_exact_compile_and_filename_protocol():
    r = record()
    r['entry_point'] = 'has_close_elements'
    request = execution_request('CANDIDATE', r, r['tests'][0])
    assert request['argv'] == ['cobc', '-w', '-fformat=variable', '-x', 'call.cbl', 'solution.cbl']
    assert request['run_argv'] == ['./call']
    assert request['output_file'] == 'HAS-CLOSE-ELEMENTS.TXT'
    assert set(request['files']) == {'call.cbl', 'solution.cbl'}
    assert 'result' not in request


@pytest.mark.parametrize('name', ['../secret', 'bad/name', 'x;echo'])
def test_unsafe_entry_points_fail_closed(name):
    r = record()
    r['entry_point'] = name
    with pytest.raises(ValueError):
        execution_request('code', r, r['tests'][0])
