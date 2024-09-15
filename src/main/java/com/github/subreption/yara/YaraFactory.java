package com.github.subreption.yara;

import com.github.subreption.yara.embedded.YaraImpl;

/**
 * Yara factory
 */
public class YaraFactory {
    public enum Mode {
        EMBEDDED,
        EXTERNAL
    }

    public static Yara create(Mode mode) {
        switch (mode) {
            case EMBEDDED:
                return new YaraImpl();
            case EXTERNAL:
                return new com.github.subreption.yara.external.YaraImpl();
            default:
                throw new UnsupportedOperationException();
        }
    }
}
