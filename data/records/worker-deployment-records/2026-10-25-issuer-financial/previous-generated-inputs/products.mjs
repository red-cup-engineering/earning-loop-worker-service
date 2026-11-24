// Generated from the selected Public product map (--products). No account or contract state.
export default {
  "flat-json-to-csv-python": {
    "name": "Python flat JSON to CSV executable",
    "artifactUrl": "https://github.com/red-cup-engineering/csv-engineering-services-section/releases/download/v0.1.2/red-cup-engineering-csv-services-section-0.1.2.tgz",
    "artifactSha256": "96f323ddf8b2d6200b5e2edf5a94bc3734c9b00242d0d4284a777149edfae9f1",
    "sourceCommit": "d9ea3253c6e877aa9128526ff318ddc4b71d52c5",
    "sourceUrl": "https://github.com/red-cup-engineering/csv-engineering-services-section/tree/d9ea3253c6e877aa9128526ff318ddc4b71d52c5",
    "runtime": "Python 3.10+; standard library only for conversion; pytest for the supplied tests",
    "verificationInstructions": "Verify the archive SHA-256 is 96f323ddf8b2d6200b5e2edf5a94bc3734c9b00242d0d4284a777149edfae9f1. Extract it, enter package/, run python3 -m pytest -q test/test_json_to_csv.py, then run python3 scripts/json_to_csv.py input.json output.csv. The source producer observed 18 passing Python cases and 3 passing existing JavaScript tests; buyer acceptance remains independent.",
    "criteriaEvidence": {
      "Need a Python 3.10+ script that reads a JSON file (array of flat objects) and converts it to a CSV file. Should handle missing keys gracefully (fill with empty string). Include a README with usage instructions and at least one test using pytest.": "The frozen archive contains scripts/json_to_csv.py, README.md with the executable command, and test/test_json_to_csv.py with 18 observed passing cases. The converter uses the first-seen union of object keys and writes missing or null values as empty cells; the tests cover differing keys, quoting, UTF-8 and rejection of nested inputs before output replacement.",
      "Python 3.10+": "scripts/json_to_csv.py uses Python 3.10-compatible syntax and standard-library modules; the producer ran the tests under Python 3.12.3. A Python 3.10 runtime was not independently exercised.",
      "missing keys": "The first-seen union of keys defines CSV columns; absent fields serialize as empty strings. test/test_json_to_csv.py exercises differing keys and missing values.",
      "README": "README.md in the frozen archive documents python3 scripts/json_to_csv.py input.json output.csv, supported input shape, scalar formatting and failure behavior.",
      "pytest": "test/test_json_to_csv.py is included in the frozen archive. The source producer observed 18 passing tests with python3 -m pytest -q test/test_json_to_csv.py."
    },
    "maximumInputBytes": 1048576
  }
};
