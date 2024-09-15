package com.github.subreption.yara.embedded;

import com.github.subreption.yara.Yara;
import com.github.subreption.yara.YaraCompiler;
import com.github.subreption.yara.YaraException;

/**
 * Yara component
 *
 * @apiNote There should be only one component instance per process
 */
public class YaraImpl implements Yara {
    private static final YaraLibrary library;

    static {
        library = new YaraLibrary();
        library.initialize();
    }

    /**
     * Create compiler
     *
     * @return
     */
    public YaraCompiler createCompiler() {
        long compiler[] = new long[1];

        int ret = library.compilerCreate(compiler);
        if (ret != 0) {
            throw new YaraException(ret);
        }

        return new YaraCompilerImpl(this.library, compiler[0]);
    }

    @Override
    public void close() throws Exception {
    }
}
