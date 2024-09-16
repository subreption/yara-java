[![Build Status](https://travis-ci.org/p8a/yara-java.svg)](https://travis-ci.org/p8a/yara-java)

Highlights
------------
- Does not require yara to be deployed (embeds all needed native dependencies)
- Supports two modes of operation:
  - External: yara/yarac binary installed, or extracted and executed as a child process
  - Embedded: yara jnilib runs embedded in the java process
- Rules can be loaded as strings, files or archives; for archives will recursively look for and load all yara rule files
- Matches are returned with identifier, metadata and tags
- Negate, timeout and limit supported
- Supports yara 4.5.2 (2024)
- Vulnerabilities and other developer "quality of life" issues present in the original fork fixed.
- Isolated test units providing repeatable results, especially for the embedded implementations.

How to build
------------

### Get and build yara source code

Example (building from 4.5.2 version)

```
git clone https://github.com/virustotal/yara.git
cd yara
git checkout tags/v4.5.2
./bootstrap.sh
./configure --disable-shared --without-crypto CFLAGS=-fPIC
make
export YARA_HOME=/path/to/compiled/yara
```

### Get and build yara-java

Example (in "yara" folder):

```
git clone https://github.com/p8a/yara-java.git
cd yara-java
mvn clean install
```

It is preferable, especially in hardened environments (where `/tmp` might not be executable or even normally writable), to
use the YARA_BINARY_PATH and YARAC_BINARY_PATH environment variables, pointing at working yara and yarac (compiler) installations, respectively.
The library will attempt to use these whenever the external variant of the scanner or compiler classes are used.

In the future, it is possible those might be removed entirely.

Usage and examples
------------------

See the unit tests


Notes
----
After you successfully added some sources you can get the compiled rules using the yr_compiler_get_rules() function. You'll get a pointer to a YR_RULES structure which can be used to scan your data as described in Scanning data. Once yr_compiler_get_rules() is invoked you can not add more sources to the compiler, but you can call yr_compiler_get_rules() multiple times. Each time this function is called it returns a pointer to the same YR_RULES structure. Notice that this behaviour is new in YARA 4.0.0, in YARA 3.X and 2.X yr_compiler_get_rules() returned a new copy the YR_RULES structure.Instances of YR_RULES must be destroyed with yr_rules_destroy().

When you call YaraCompilerImpl.createScanner() multiple times. the return YaraScanner will point to the same YR_RULES structure. so, you cann't destroy YaraScanner multiple times!!!
