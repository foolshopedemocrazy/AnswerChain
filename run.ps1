Set-Location "$PSScriptRoot"
$env:PYTHONPATH = 'src'
python .\examples\example_usage.py
pytest -q
