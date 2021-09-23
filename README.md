# PEParser
A **SMALL** library I wrote for reading module exports.

# How to use
import the library into your C++ project

```c++
#include "PEParser.hpp"
```

Next instantiate the class
```c++
auto parsed_dll = pe_parser("kernel32.dll");
```
and... you're done!
You can use the member functions as you wish!

# More info

Feel free to take a look at the Source.cpp file to reference
