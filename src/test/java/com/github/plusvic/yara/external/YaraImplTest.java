package com.github.plusvic.yara.external;

import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.assertNotNull;

/**
 * User: pba
 * Date: 6/16/15
 * Time: 6:11 PM
 */
public class YaraImplTest {
    @Test
    public void testCreate() {
        new YaraImpl();
    }

    @Test
    public void testCreateCompiler() {
        assertNotNull(new YaraImpl().createCompiler());
    }
}
