# Static Sign Analysis using Angr

### To Run Sign Analysis on a Binary:
```
sign.py -b <path to binary> -f <function name in the binary>
sign.py -b <path to binary>
```

### Examples
```
sign.py -b test -f main
sign.py -b test
```

### To Compile C code:
```
gcc -o <output name> <name of code>.c -m32
```

### Example
```
gcc -o test test.c -m32
```
