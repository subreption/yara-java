package com.github.subreption.yara.external;


import com.github.subreption.yara.Yara;
import com.github.subreption.yara.YaraCompiler;

public class YaraImpl implements Yara {
    @Override
    public YaraCompiler createCompiler() {
        return new YaraCompilerImpl();
    }

    @Override
    public void close() throws Exception {
    }
}
