# Build

## Install maturin

```
pip install maturin
```

## Build

Debug:

```
maturin build --manylinux off
```

Release:

```
maturin build --manylinux off --release --strip
```
