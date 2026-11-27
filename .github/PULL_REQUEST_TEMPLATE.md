## Summary

<!-- What changed and why? Keep runtime dependencies at zero. -->

## Security impact

<!-- Describe attack surface, default behavior, and any opt-in escape hatch. -->

## Tests

- [ ] `python3 -m unittest discover -s tests`
- [ ] Wheel contents checked for `py.typed` and absence of tests and bytecode
- [ ] New hostile-input regression test added
- [ ] False-positive control added

## Compatibility

- [ ] Python 3.9 syntax compatibility preserved
- [ ] No runtime dependency added
- [ ] Public API behavior is documented when changed
