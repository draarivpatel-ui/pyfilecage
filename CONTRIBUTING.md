# Contributing

Contributions are welcome. This project is a security boundary, so correctness
and adversarial tests matter more than convenience features.

## Ground rules

- Keep runtime dependencies at zero. The Python standard library is the only
  permitted runtime dependency.
- Keep Python 3.9 compatibility. Do not use `match`/`case`, `tomllib`, or newer
  syntax that cannot parse on Python 3.9.
- Never use `libmagic`, Pillow, subprocess-based file identification, or an
  image decoder in the library.
- Add regression tests for every security fix. Include the hostile input and at
  least one false-positive control when the change affects scanning.
- Do not weaken a default to make a test pass. Opt-in escape hatches must be
  explicit and documented.
- Do not commit secrets, tokens, private paths, or real personal data.

## Local verification

```sh
python3 -m unittest discover -s tests
python3 -m build
pyfilecage --help
```

A pull request should state which tests were run and whether the wheel contents
were checked. The wheel must contain `pyfilecage/py.typed` and must not contain
tests, `__pycache__`, or `.pyc` files.

## Security reports

Do not open a public issue for an exploitable vulnerability. Follow
`SECURITY.md`.
