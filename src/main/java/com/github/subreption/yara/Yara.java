package com.github.subreption.yara;

/**
 * Yara wrapper
 */
public interface Yara extends AutoCloseable {
    YaraCompiler createCompiler();
  
}
