# String-Var Dynamic Values

**WIP!**

Currently, the best guide is from the **XMT Matcher Verb Guide**, which is copied
below.

## Matcher Verb Guide

- `<N>` indicates a non-negative number value that is **REQUIRED**.
- `[N]` indicated a non-negative number value that is **OPTIONAL**.
   If omitted, a random positive 8 to 32bit value will be used.

If the number is followed by a `f`, this will **FORCE** the count and will use it
directly instead of a range to `N`. Otherwise, a `[1, N] (inclusive)` value will
be generated to be used instead.

_In both cases, the `<`, `[`, `]`, and `>` are only used to indicate usage,_
_and are not actually used in the string value._

| Verb   | Description                                         | RegEx            |
| ------ | --------------------------------------------------- | ---------------- |
| %<N>n  | 1 to N count of random single-digit numbers         | [0-9]{1,N}       |
| %<N>fn | N count of random single-digit numbers              | [0-9]{N}         |
| %<N>c  | 1 to N count of random ASCII non-number characters  | [a-zA-Z]{1,N}    |
| %<N>fc | N count of random ASCII non-number characters       | [a-zA-Z]{N}      |
| %<N>u  | 1 to N count of random ASCII uppercase characters   | [A-Z]{1,N}       |
| %<N>fu | N count of random ASCII uppercase characters        | [A-Z]{N}         |
| %<N>l  | 1 to N count of random ASCII lowercase characters   | [a-z]{1,N}       |
| %<N>fl | N count of random ASCII lowercase characters        | [a-z]{n}         |
| %s     | Random 1 to 256 count of random ASCII characters    | ([a-zA-Z0-9]+)   |
| %[N]s  | 1 to N (or random) count of random ASCII characters | [a-zA-Z0-9]{1,N} |
| %<N>fs | N count of random ASCII characters                  | [a-zA-Z0-9]{N}   |
| %d     | String literal number 0 to 4,294,967,296            | ([0-9]+)         |
| %<N>d  | String literal number 0 to N                        | ([0-9]+)         |
| %<N>fd | String literal number N                             | ([0-9]+)         |
| %h     | Hex string literal number 0 to 4,294,967,296        | ([a-fA-F0-9]+)   |
| %<N>h  | Hex string literal number 0 to N                    | ([a-fA-F0-9]+)   |
| %<N>fh | Hex string literal number N                         | ([a-fA-F0-9]+)   |

All other values are ignored and directly added to the resulting string value.
