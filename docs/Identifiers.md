# Data Specification Identifiers

What are **Data Values** and **Data Specification Identifiers**?

**Data Values** (usually identified by `data`) are a method of describing a resource
so it can be parsed properly. Data can come in the form of:

- Strings
- Raw Bytes
- Raw Strings (Not Escaped)
- Base64 Encoded Strings
- Local File Paths
- Remote File Paths

Each of these options might be able to be the source of data used in a
particular command.

By default, each command that uses a **Data Value** will attempt to automatically
determine the type of data described. Many times this comes down to **Strings**
and **File Paths** and some commands will attempt to autodetect **Base64** strings.
In order to explicitly tell the command what the data type is, we can use
**Data Specification Identifiers** to assist.

Many commands may take multiple **Data Value** types in order to augment their
runtime.

## Identifiers

**Data Specification Identifiers** are a type declariation added to the beginning
of a string to indicate what type it represents.

There are two ways to use **Data Specification Identifiers**:

- `<type>$<data>`
- `<type>"<data>"`

The `type` value is a single character that indicates the type. Here are the
type indicators supported:

- `r` **Raw Strings or Raw Bytes**:
    Data will be **DIRECTLY** interpreted as it's explicit form, meaning that
    newlines `\n` and other control chars DO NOT need to be escaped and will
    act like they were un-escaped. This indication also can be used with the
    `b` indicator interchangeably.
- `b` **Raw Bytes**:
    Data will be **DIRECTLY** interpreted as a sequence of bytes. You do not need
    to escape any values and may also use hex codes to signify other data
    values, such as `\xFF` and `\x40`.
- `x` **Remote File Path**:
    Data will be **DIRECTLY** interpreted as a raw **REMOTE (on client)** path. This
    path will **NOT** be parsed and instead will be expanded on the client side.
- `p` **Local File Path**:
    Data will be **DIRECTLY** interpreted as a raw **LOCAL** path. This will cause any
    environment variables to be resolved and will result in an error if it
    does not exist.
- `e` **Base64 Encoded String**:
    Data will be **DIRECTLY** interpreted as a Base64 encoded string value. It will
    be decoded directly into bytes. This will result in an error if the Base64
    encoding is invalid or incorrect.

As long as the Data Value begins with one of these characters and is either
surrounded in double quotes `""` or has a single dollar sign `$` after the type
character, it will be evaluated.

## Examples

```text
r"Hello\\nWorld!"
```

Raw String, this will result in:

```text
Hello
World!
```

```text
e"c3VwZXJzZWNyZXQK"
```

Base64 Encoded String, this will result in:

```text
supersecret
(Note the newline at the end).
```

```text
b$\x41\x42\x43\x44\x45\x46
```

Raw Bytes, this will result in:

```text
ABCDEF
```
