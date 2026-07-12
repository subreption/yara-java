/*
 * Copyright (c) 2024 Subreption LLC. All rights reserved.
 * Copyright (c) 2015-2022 Paul Apostolescu. All rights reserved.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package com.github.subreption.yara.embedded;

import java.io.File;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.nio.file.StandardOpenOption;
import java.util.HashMap;
import java.util.HashSet;
import java.util.Map;
import java.util.Set;
import java.util.UUID;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.concurrent.atomic.AtomicLong;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.junit.jupiter.api.Assertions.fail;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import com.github.subreption.yara.YaraCompilationCallback;
import com.github.subreption.yara.YaraCompiler;
import com.github.subreption.yara.YaraMatch;
import com.github.subreption.yara.YaraMeta;
import com.github.subreption.yara.YaraScanCallback;
import com.github.subreption.yara.YaraScanner;

/**
 * area module tests. Rules are taken from subreption/ghidra_yara's signsrch_le_be.yar.
 * Scan buffers must be at least (value_count + 1) * value_size bytes or area.scan returns 0.
 */
public class YaraAreaModuleTest {

    private static final String DES_RULE =
            "import \"area\"\n" +
            "rule DES : AND {\n" +
            "  strings:\n" +
            "    $first = { 0F0F0F0F }\n" +
            "  condition:\n" +
            "    $first and area.scan(@first, 32, 5, 640,\n" +
            "      \"\\xFF\\xFF\\x00\\x00\\x33\\x33\\x33\\x33\\xFF\\x00\\xFF\\x00\\x55\\x55\\x55\\x55\")\n" +
            "}\n";

    // $first + the four area values + one value_size of padding (24 == (5 + 1) * 4).
    private static final byte[] DES_BUFFER = {
            0x0F, 0x0F, 0x0F, 0x0F,
            (byte) 0xFF, (byte) 0xFF, 0x00, 0x00,
            0x33, 0x33, 0x33, 0x33,
            (byte) 0xFF, 0x00, (byte) 0xFF, 0x00,
            0x55, 0x55, 0x55, 0x55,
            0x00, 0x00, 0x00, 0x00
    };

    private YaraImpl yara;

    @BeforeEach
    public void setup() {
        this.yara = new YaraImpl();
    }

    @AfterEach
    public void teardown() throws Exception {
        yara.close();
    }

    private static File tempFileWith(byte[] data) throws Exception {
        File temp = File.createTempFile(UUID.randomUUID().toString(), ".tmp");
        Files.write(Paths.get(temp.getAbsolutePath()), data, StandardOpenOption.WRITE);
        return temp;
    }

    private boolean scan(String rules, byte[] buffer, String expectedId) throws Exception {
        File temp = tempFileWith(buffer);
        YaraCompilationCallback compileCallback =
                (errorLevel, fileName, lineNumber, message) -> fail("compile error: " + message);
        final AtomicBoolean matched = new AtomicBoolean(false);
        YaraScanCallback scanCallback = v -> {
            if (expectedId.equals(v.getIdentifier())) {
                matched.set(true);
            }
        };

        try (YaraCompiler compiler = yara.createCompiler()) {
            compiler.setCallback(compileCallback);
            compiler.addRulesContent(rules, null);
            try (YaraScanner scanner = compiler.createScanner()) {
                scanner.setCallback(scanCallback);
                scanner.scan(temp);
            }
        }
        return matched.get();
    }

    @Test
    public void testAreaModuleIsCompiledIn() throws Exception {
        String rules = "import \"area\"\nrule AreaModulePresent { condition: true }\n";
        YaraCompilationCallback compileCallback =
                (errorLevel, fileName, lineNumber, message) -> fail("area import failed: " + message);

        try (YaraCompiler compiler = yara.createCompiler()) {
            compiler.setCallback(compileCallback);
            compiler.addRulesContent(rules, null);
            try (YaraScanner scanner = compiler.createScanner()) {
                assertNotNull(scanner);
            }
        }
    }

    @Test
    public void testAreaScanDes32BitMatches() throws Exception {
        assertTrue(scan(DES_RULE, DES_BUFFER, "DES"));
    }

    @Test
    public void testAreaScanRc564BitMatches() throws Exception {
        String rules =
                "import \"area\"\n" +
                "rule RC5_RC5_64_P_and_RC5_64_Q : AND {\n" +
                "  strings:\n" +
                "    $first = { 6B2AED8A6251E1B7 }\n" +
                "  condition:\n" +
                "    $first and area.scan(@first, 64, 2, 512,\n" +
                "      \"\\x15\\x7C\\x4A\\x7F\\xB9\\x79\\x37\\x9E\")\n" +
                "}\n";
        byte[] buffer = {
                0x6B, 0x2A, (byte) 0xED, (byte) 0x8A, 0x62, 0x51, (byte) 0xE1, (byte) 0xB7,
                0x15, 0x7C, 0x4A, 0x7F, (byte) 0xB9, 0x79, 0x37, (byte) 0x9E,
                0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00
        };
        assertTrue(scan(rules, buffer, "RC5_RC5_64_P_and_RC5_64_Q"));
    }

    @Test
    public void testAreaScanDoesNotFalseMatch() throws Exception {
        byte[] buffer = {                                 // $first present, area values absent
                0x0F, 0x0F, 0x0F, 0x0F,
                0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
                0, 0, 0, 0, 0, 0, 0, 0
        };
        assertFalse(scan(DES_RULE, buffer, "DES"));
    }

    @Test
    public void testAreaScanBufferOneUnderGuardDoesNotMatchOrCrash() throws Exception {
        byte[] buffer = {                                 // 23 bytes, one under (5 + 1) * 4
                0x0F, 0x0F, 0x0F, 0x0F,
                (byte) 0xFF, (byte) 0xFF, 0x00, 0x00,
                0x33, 0x33, 0x33, 0x33,
                (byte) 0xFF, 0x00, (byte) 0xFF, 0x00,
                0x55, 0x55, 0x55, 0x55,
                0x00, 0x00, 0x00
        };
        assertFalse(scan(DES_RULE, buffer, "DES"));
    }

    @Test
    public void testAreaMatchExposesCorrectRuleData() throws Exception {
        String rules =
                "import \"area\"\n" +
                "rule AreaMatchData : AND CRYPTO {\n" +
                "  meta:\n" +
                "    description = \"DES init constants\"\n" +
                "    author = \"Luigi Auriemma\"\n" +
                "    value_count = 5\n" +
                "  strings:\n" +
                "    $first = { 0F0F0F0F }\n" +
                "  condition:\n" +
                "    $first and area.scan(@first, 32, 5, 640,\n" +
                "      \"\\xFF\\xFF\\x00\\x00\\x33\\x33\\x33\\x33\\xFF\\x00\\xFF\\x00\\x55\\x55\\x55\\x55\")\n" +
                "}\n";

        final AtomicBoolean verified = new AtomicBoolean(false);
        YaraScanCallback scanCallback = v -> {
            assertEquals("AreaMatchData", v.getIdentifier());

            Set<String> tags = new HashSet<>();
            v.getTags().forEachRemaining(tags::add);
            assertTrue(tags.contains("AND") && tags.contains("CRYPTO"));

            Map<String, YaraMeta> metas = new HashMap<>();
            v.getMetadata().forEachRemaining(m -> metas.put(m.getIdentifier(), m));
            assertEquals("DES init constants", metas.get("description").getString());
            assertEquals("Luigi Auriemma", metas.get("author").getString());
            assertEquals(5, metas.get("value_count").getInteger());

            YaraMatch m = v.getStrings().next().getMatches().next();
            assertArrayEquals(new byte[] { 0x0F, 0x0F, 0x0F, 0x0F }, m.getBytes());
            assertEquals(0L, m.getOffset());

            verified.set(true);
        };

        try (YaraCompiler compiler = yara.createCompiler()) {
            compiler.setCallback((errorLevel, fileName, lineNumber, message) -> fail("compile error: " + message));
            compiler.addRulesContent(rules, null);
            try (YaraScanner scanner = compiler.createScanner()) {
                scanner.setCallback(scanCallback);
                scanner.scan(DES_BUFFER);
            }
        }
        assertTrue(verified.get());
    }

    @Test
    public void testAreaScanLargeBufferReportsCorrectOffset() throws Exception {
        final int matchOffset = 8_000_000;
        byte[] buffer = new byte[16_000_000];
        System.arraycopy(DES_BUFFER, 0, buffer, matchOffset, DES_BUFFER.length);

        final AtomicBoolean matched = new AtomicBoolean(false);
        final AtomicLong reportedOffset = new AtomicLong(-1);
        YaraScanCallback scanCallback = v -> {
            if ("DES".equals(v.getIdentifier())) {
                reportedOffset.set(v.getStrings().next().getMatches().next().getOffset());
                matched.set(true);
            }
        };

        try (YaraCompiler compiler = yara.createCompiler()) {
            compiler.setCallback((errorLevel, fileName, lineNumber, message) -> fail("compile error: " + message));
            compiler.addRulesContent(DES_RULE, null);
            try (YaraScanner scanner = compiler.createScanner()) {
                scanner.setCallback(scanCallback);
                scanner.scan(buffer);
            }
        }
        assertTrue(matched.get());
        assertEquals(matchOffset, reportedOffset.get());
    }

    // One scan, one rule present and one absent: guards against a build that silently never matches.
    @Test
    public void testAreaScanMatchesAndRejectsInOneScan() throws Exception {
        String rules =
                "import \"area\"\n" +
                "rule DES : AND {\n" +
                "  strings: $first = { 0F0F0F0F }\n" +
                "  condition: $first and area.scan(@first, 32, 5, 640,\n" +
                "    \"\\xFF\\xFF\\x00\\x00\\x33\\x33\\x33\\x33\\xFF\\x00\\xFF\\x00\\x55\\x55\\x55\\x55\")\n" +
                "}\n" +
                "rule DecoyAbsent : AND {\n" +
                "  strings: $first = \"foobar\"\n" +
                "  condition: $first and area.scan(@first, 32, 2, 256, \"\\x11\\x22\\x33\\x44\")\n" +
                "}\n";

        Set<String> matched = new HashSet<>();
        try (YaraCompiler compiler = yara.createCompiler()) {
            compiler.setCallback((errorLevel, fileName, lineNumber, message) -> fail("compile error: " + message));
            compiler.addRulesContent(rules, null);
            try (YaraScanner scanner = compiler.createScanner()) {
                scanner.setCallback(v -> matched.add(v.getIdentifier()));
                scanner.scan(DES_BUFFER);
            }
        }
        assertTrue(matched.contains("DES"));
        assertFalse(matched.contains("DecoyAbsent"));
    }
}
