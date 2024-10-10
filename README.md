
[![Build (linux64)](https://github.com/subreption/yara-java/actions/workflows/build_linux64.yml/badge.svg)](https://github.com/subreption/yara-java/actions/workflows/build_linux64.yml) [![Build (multiplatform)](https://github.com/subreption/yara-java/actions/workflows/build_multi.yml/badge.svg)](https://github.com/subreption/yara-java/actions/workflows/build_multi.yml) [![Build (osx64)](https://github.com/subreption/yara-java/actions/workflows/build_macos.yml/badge.svg)](https://github.com/subreption/yara-java/actions/workflows/build_macos.yml) [![Nightly Release (multiplatform)](https://github.com/subreption/yara-java/actions/workflows/ci_nightly.yml/badge.svg)](https://github.com/subreption/yara-java/actions/workflows/ci_nightly.yml) [![Stable Release multiplatform](https://github.com/subreption/yara-java/actions/workflows/ci_release.yml/badge.svg)](https://github.com/subreption/yara-java/actions/workflows/ci_release.yml)

## Introduction

This is Subreption's fork of the original `yara-java` project, with improvements, fixes and ongoing maintenance.
The original bindings were created by Paul Apostolescu circa 2015, and eventually fell out of maintenance with
significant issues creeping up.

The main motivation is the development of a Ghidra extension (analyzer) providing YARA signature matching capabilities.
In addition, libyara was forked to include Kevin Weatherman's `area` module to provide optimized scanning for 32-bit
and 64-bit cryptographic constants, resurrecting the famed signature database from Luigi Auriemma's `signsrch` tool
(originally a standalone tool and subsequently re-implemented as plugins for IDA and other RE tools).

Please review the source code prior to integrating these bindings in your own tools and projects. The cleanup is still
ongoing, and ideally, a Panama/FFM version will be created, eliminating the necessity of using JNI via `hawtjni`.

 - Subreption's yara fork: https://github.com/subreption/yara

## Highlights

- Self-contained.
- Both JNI (native) and *external* operation modes supported. The latter can use environment variables to use existent external YARA scanner and compiler binaries.
- Rules can be added (and compiled) as raw strings, from files and from archives (ZIP format).
- Matches are returned with identifier, metadata and tags.
- Negate match and constraints (timeout and limit) supported.
- Supports the latest libyara 4.5.2 (2024)

### Differences with the original fork

 - Fixed a TOCTOU/file permissions vulnerability in the `external` variants of the compiler and scanner implementations.
 - Updated to the latest available Maven components.
 - Revised the logging logic.
 - Revised all unit tests.
 - The broken retrieval of match-specific data was fixed to work with buffers containing NULL bytes. The original method in `YaraMatch` is still supported but the `byte[]` variant should be used instead.
 - Isolated test units providing repeatable results, especially for the embedded implementations.
 - Supports linking against a specific libyara build via the `YARA_HOME` environment variable.

## Building

### Obtain libyara

Example (building from 4.5.2 version):

```
git clone https://github.com/subreption/yara.git
cd yara
git checkout tags/v4.5.2-subreption
./bootstrap.sh
./configure --disable-shared --enable-area --without-crypto CFLAGS=-fPIC
make
export YARA_HOME=$PWD
```

### Obtain yara-java

Example (in "yara" folder):

```
git clone https://github.com/subreption/yara-java.git
cd yara-java
mvn clean install
```

### Building in hardened environments

It is preferable, especially in hardened environments (where `/tmp` might not be executable or even
normally writable), to use the `YARA_BINARY_PATH` and `YARAC_BINARY_PATH` environment variables,
pointing at working `yara` and `yarac` (compiler) installations, respectively.

The library will attempt to use these whenever the external variant of the scanner or compiler classes are used.

Support for the "external" operating mode might be removed in the future. Therefore we cannot make promises for
extended support.

## Releases

We have added CI workflows to generate *jars* for the supported platforms upon every stable *tag* in this
repository.

## Using the library

The unit tests are a good reference for using the bindings. However, a basic use case is not more
complicated than the code below:


``` java
public void scanBytesWithYara(byte[] mysteryBytes) throws Exception
{
  YaraImpl yara = null;

  try {
    yara = new YaraImpl();
  } catch (Exception e) {
    System.err.println("Failed to create Yara instance: " + e.getMessage());
    return;
  }

  // ...
  YaraCompilationCallback compileCallback = (errorLevel, fileName, lineNumber, message) -> {
    System.err.printf("ErrorLevel: %s, File: %s, Line: %d, Message: %s%n",
      errorLevel, fileName, lineNumber, message);
  };

  YaraScanCallback scanCallback = v -> {
    // Handle the meta-data in the v.getMetadata() collection...
    // Handle the actual matched data in the v.getStrings() collection...
    // Refer to the YaraMatch type
  };

  try (YaraCompiler compiler = yara.createCompiler()) {
      // Set the compilation callback for handling errors
      compiler.setCallback(compileCallback);

      // Add Yara rules file to the compiler (you can customize the namespace if needed)
      compiler.addRulesFile("./rules/foobar.yar", "foobar.yar", null);

      // Create the scanner instance
      try (YaraScanner scanner = compiler.createScanner()) {
          // Set the scan callback
          scanner.setCallback(scanCallback);

          // Scan the provided bytes (mysteryBytes)
          scanner.scan(mysteryBytes);
      }
  } catch (YaraException e) {
      System.err.println("Yara scanning error: " + e.getMessage());
  }

  try {
    yara.close();
  } catch (Exception e) {
    System.err.println("Failed to close Yara instance: " + e.getMessage());
    return;
  }
}
```

## Caveats

Refer to the libyara documentation (C API) for low-level details. Avoid destroying or releasing instances of the YaraScanner
more than once, and preferably use it in context (as done in the example above).

## Reporting bugs

Please file an issue, or even better, provide a **tested** and **documented** PR. :-)

## Licensing

```
   Copyright (c) 2024 Subreption LLC. All rights reserved.
   Copyright (c) 2015-2022 Paul Apostolescu. All rights reserved.

   Licensed under the Apache License, Version 2.0 (the "License");
   you may not use this file except in compliance with the License.
   You may obtain a copy of the License at

       http://www.apache.org/licenses/LICENSE-2.0

   Unless required by applicable law or agreed to in writing, software
   distributed under the License is distributed on an "AS IS" BASIS,
   WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
   See the License for the specific language governing permissions and
   limitations under the License.
```

This library and source code are distributed under the terms described in the `LICENSE` file.
