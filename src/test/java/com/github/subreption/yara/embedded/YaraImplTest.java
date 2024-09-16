package com.github.subreption.yara.embedded;

import org.junit.jupiter.api.Test;
import com.github.subreption.yara.YaraCompiler;

import static org.junit.jupiter.api.Assertions.assertNotNull;

/**
 * User: pba
 * Date: 6/9/15
 * Time: 6:51 PM
 */
public class YaraImplTest {
    @Test
    public void testCreateClose() throws Exception {
        try (YaraImpl yara = new YaraImpl()) {
        }
    }

    @Test
    public void testCreateCompiler() throws Exception {
        try (YaraImpl yara = new YaraImpl()) {
            try (YaraCompiler compiler = yara.createCompiler())  {
                assertNotNull(compiler);
            }
        }
    }
}