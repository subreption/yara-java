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

import java.util.ArrayList;
import java.util.HashSet;
import java.util.Iterator;
import java.util.List;
import java.util.Set;
import java.util.concurrent.atomic.AtomicBoolean;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.junit.jupiter.api.Assertions.fail;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import com.github.subreption.yara.YaraCompiler;
import com.github.subreption.yara.YaraMatch;
import com.github.subreption.yara.YaraScanner;

/**
 * Match-behavior edge cases: no-match variety, multiple matches, and match-instance iteration.
 */
public class YaraMatchEdgeCasesTest {

    private YaraImpl yara;

    @BeforeEach
    public void setup() {
        this.yara = new YaraImpl();
    }

    @AfterEach
    public void teardown() throws Exception {
        yara.close();
    }

    private static final String DES_BODY =
            "rule DES : AND {\n" +
            "  strings:\n" +
            "    $first = { 0F0F0F0F }\n" +
            "  condition:\n" +
            "    $first and area.scan(@first, 32, 5, 640,\n" +
            "      \"\\xFF\\xFF\\x00\\x00\\x33\\x33\\x33\\x33\\xFF\\x00\\xFF\\x00\\x55\\x55\\x55\\x55\")\n" +
            "}\n";

    private static final String RC5_BODY =
            "rule RC5_RC5_64_P_and_RC5_64_Q : AND {\n" +
            "  strings:\n" +
            "    $first = { 6B2AED8A6251E1B7 }\n" +
            "  condition:\n" +
            "    $first and area.scan(@first, 64, 2, 512, \"\\x15\\x7C\\x4A\\x7F\\xB9\\x79\\x37\\x9E\")\n" +
            "}\n";

    private static final byte[] DES_BLOCK = {
            0x0F, 0x0F, 0x0F, 0x0F,
            (byte) 0xFF, (byte) 0xFF, 0x00, 0x00,
            0x33, 0x33, 0x33, 0x33,
            (byte) 0xFF, 0x00, (byte) 0xFF, 0x00,
            0x55, 0x55, 0x55, 0x55,
            0x00, 0x00, 0x00, 0x00
    };
    private static final byte[] RC5_BLOCK = {
            0x6B, 0x2A, (byte) 0xED, (byte) 0x8A, 0x62, 0x51, (byte) 0xE1, (byte) 0xB7,
            0x15, 0x7C, 0x4A, 0x7F, (byte) 0xB9, 0x79, 0x37, (byte) 0x9E,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00
    };

    private static String areaRules(String... bodies) {
        StringBuilder sb = new StringBuilder("import \"area\"\n");
        for (String b : bodies) {
            sb.append(b);
        }
        return sb.toString();
    }

    private List<String> matchedIds(String rules, byte[] buffer) throws Exception {
        final List<String> ids = new ArrayList<>();
        try (YaraCompiler compiler = yara.createCompiler()) {
            compiler.setCallback((errorLevel, fileName, lineNumber, message) -> fail("compile error: " + message));
            compiler.addRulesContent(rules, null);
            try (YaraScanner scanner = compiler.createScanner()) {
                scanner.setCallback(v -> ids.add(v.getIdentifier()));
                scanner.scan(buffer);
            }
        }
        return ids;
    }

    @Test
    public void noMatchWhenPatternAbsent() throws Exception {
        assertTrue(matchedIds(areaRules(DES_BODY), new byte[64]).isEmpty());
    }

    @Test
    public void noMatchWhenAreaValuesOutOfRange() throws Exception {
        byte[] buffer = new byte[6000];
        System.arraycopy(DES_BLOCK, 0, buffer, 0, 4);       // $first at offset 0
        System.arraycopy(DES_BLOCK, 4, buffer, 5000, 16);   // values well past scan_range (640)
        assertTrue(matchedIds(areaRules(DES_BODY), buffer).isEmpty());
    }

    @Test
    public void multipleDistinctRulesMatchOneBuffer() throws Exception {
        byte[] buffer = new byte[200];
        System.arraycopy(DES_BLOCK, 0, buffer, 0, DES_BLOCK.length);
        System.arraycopy(RC5_BLOCK, 0, buffer, 100, RC5_BLOCK.length);

        List<String> ids = matchedIds(areaRules(DES_BODY, RC5_BODY), buffer);
        assertTrue(ids.contains("DES"), "got " + ids);
        assertTrue(ids.contains("RC5_RC5_64_P_and_RC5_64_Q"), "got " + ids);
    }

    @Test
    public void stringMatchInstancesIteratedExactly() throws Exception {
        final int n = 64;
        final int stride = 8;                          // 4-byte pattern + 4-byte gap, non-overlapping
        final byte[] pattern = { 'M', 'A', 'R', 'K' };

        byte[] buffer = new byte[n * stride];
        Set<Long> expectedOffsets = new HashSet<>();
        for (int i = 0; i < n; i++) {
            System.arraycopy(pattern, 0, buffer, i * stride, pattern.length);
            expectedOffsets.add((long) (i * stride));
        }
        String rule = "rule Marks { strings: $a = \"MARK\" condition: #a == " + n + " }";

        final Set<Long> seenOffsets = new HashSet<>();
        final AtomicBoolean fired = new AtomicBoolean(false);
        try (YaraCompiler compiler = yara.createCompiler()) {
            compiler.setCallback((errorLevel, fileName, lineNumber, message) -> fail("compile error: " + message));
            compiler.addRulesContent(rule, null);
            try (YaraScanner scanner = compiler.createScanner()) {
                scanner.setCallback(v -> {
                    fired.set(true);
                    for (Iterator<YaraMatch> it = v.getStrings().next().getMatches(); it.hasNext(); ) {
                        seenOffsets.add(it.next().getOffset());
                    }
                });
                scanner.scan(buffer);
            }
        }
        assertTrue(fired.get());
        assertEquals(expectedOffsets, seenOffsets);
    }
}
