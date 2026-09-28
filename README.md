# libeezo

The Eezo runtime library: terms, the bit-coded lambda calculus (BCL/XBCL) and Jomplement encodings, bignums, the x86
native back end. Linked by [eezo](https://github.com/Levalicious/eezo), [eezoc](https://github.com/Levalicious/eezoc)
and [eezott](https://github.com/Levalicious/eezott); its headers are included as `../libeezo/*.h`, so it sits beside
them in a workspace (the [umbrella](https://github.com/Levalicious/umbrella) repository lays one out).

Build: `mk` (Plan 9 mk with the [mkroot](https://github.com/Levalicious/mkroot) proto files; see
[mk](https://github.com/Levalicious/mk)). Depends on nothing. CI builds it at the mk/mkroot commits its workflow pins.
