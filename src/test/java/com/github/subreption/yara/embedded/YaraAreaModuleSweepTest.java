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

import java.net.URL;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.util.ArrayList;
import java.util.HashSet;
import java.util.List;
import java.util.Set;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.regex.Matcher;
import java.util.regex.Pattern;
import java.util.stream.Stream;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.junit.jupiter.api.Assertions.fail;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.Arguments;
import org.junit.jupiter.params.provider.MethodSource;

import com.github.subreption.yara.YaraCompilationCallback;
import com.github.subreption.yara.YaraCompiler;
import com.github.subreption.yara.YaraScanCallback;
import com.github.subreption.yara.YaraScanner;

/**
 * area module breadth and repeated-scan safety, driven by real rules from the
 * /rules/signsrch-area-sample.yar fixture. Each rule's scan buffer is rebuilt from its own
 * signature and scanned via scan(byte[]).
 */
public class YaraAreaModuleSweepTest {

    private YaraImpl yara;

    @BeforeEach
    public void setup() {
        this.yara = new YaraImpl();
    }

    @AfterEach
    public void teardown() throws Exception {
        yara.close();
    }

    static final class AreaRule {
        final String name;
        final String ruleText;
        final byte[] buffer;
        AreaRule(String name, String ruleText, byte[] buffer) {
            this.name = name; this.ruleText = ruleText; this.buffer = buffer;
        }
        @Override public String toString() { return name; }
    }

    private static final Pattern RULE_BLOCK = Pattern.compile("(?s)rule\\s+\\w+\\b.*?\\n\\}");
    private static final Pattern RULE_NAME  = Pattern.compile("rule\\s+(\\w+)");
    private static final Pattern FIRST_HEX  = Pattern.compile("\\$first\\s*=\\s*\\{\\s*([0-9A-Fa-f]+)\\s*\\}");
    private static final Pattern AREA_SCAN  =
            Pattern.compile("area\\.scan\\(@first,\\s*(\\d+),\\s*(\\d+),\\s*(\\d+),\\s*\"([^\"]*)\"");
    private static final Pattern HEX_ESCAPE = Pattern.compile("\\\\x([0-9A-Fa-f]{2})");

    static List<AreaRule> loadFixtureRules() throws Exception {
        URL url = YaraAreaModuleSweepTest.class.getResource("/rules/signsrch-area-sample.yar");
        assertNotNull(url, "signsrch-area-sample.yar not on the test classpath");
        String text = new String(Files.readAllBytes(Paths.get(url.toURI())), StandardCharsets.UTF_8);

        List<AreaRule> rules = new ArrayList<>();
        Matcher blocks = RULE_BLOCK.matcher(text);
        while (blocks.find()) {
            String block = blocks.group();

            Matcher nm = RULE_NAME.matcher(block);
            Matcher fm = FIRST_HEX.matcher(block);
            Matcher sm = AREA_SCAN.matcher(block);
            assertTrue(nm.find() && fm.find() && sm.find(), "unparseable rule block:\n" + block);

            int valueSize = Integer.parseInt(sm.group(1)) / 8;
            byte[] first = hexToBytes(fm.group(1));
            byte[] hexData = escapedToBytes(sm.group(4));

            // $first + hex_data values + one value_size of padding == (value_count + 1) * value_size.
            byte[] buffer = new byte[first.length + hexData.length + valueSize];
            System.arraycopy(first, 0, buffer, 0, first.length);
            System.arraycopy(hexData, 0, buffer, first.length, hexData.length);

            rules.add(new AreaRule(nm.group(1), "import \"area\"\n" + block + "\n", buffer));
        }
        return rules;
    }

    private static byte[] hexToBytes(String hex) {
        int n = hex.length() / 2;
        byte[] out = new byte[n];
        for (int i = 0; i < n; i++) {
            out[i] = (byte) Integer.parseInt(hex.substring(i * 2, i * 2 + 2), 16);
        }
        return out;
    }

    private static byte[] escapedToBytes(String escaped) {
        Matcher m = HEX_ESCAPE.matcher(escaped);
        List<Byte> bytes = new ArrayList<>();
        while (m.find()) {
            bytes.add((byte) Integer.parseInt(m.group(1), 16));
        }
        byte[] out = new byte[bytes.size()];
        for (int i = 0; i < out.length; i++) {
            out[i] = bytes.get(i);
        }
        return out;
    }

    static Stream<Arguments> areaRules() throws Exception {
        return loadFixtureRules().stream().map(r -> Arguments.of(r));
    }

    private boolean scanForMatch(String ruleText, byte[] buffer, String expectedId) throws Exception {
        YaraCompilationCallback compileCallback =
                (errorLevel, fileName, lineNumber, message) -> fail("compile error [" + expectedId + "]: " + message);
        final AtomicBoolean matched = new AtomicBoolean(false);
        YaraScanCallback scanCallback = v -> {
            if (expectedId.equals(v.getIdentifier())) {
                matched.set(true);
            }
        };
        try (YaraCompiler compiler = yara.createCompiler()) {
            compiler.setCallback(compileCallback);
            compiler.addRulesContent(ruleText, null);
            try (YaraScanner scanner = compiler.createScanner()) {
                scanner.setCallback(scanCallback);
                scanner.scan(buffer);
            }
        }
        return matched.get();
    }

    @Test
    public void fixtureParsesAllRules() throws Exception {
        assertEquals(7, loadFixtureRules().size());
    }

    @ParameterizedTest(name = "{0}")
    @MethodSource("areaRules")
    public void realAreaRuleMatchesItsSignature(AreaRule rule) throws Exception {
        assertTrue(scanForMatch(rule.ruleText, rule.buffer, rule.name), rule.name);
    }

    // One scanner, reused across many setCallback+scan(byte[]) calls (the analyzer's block loop).
    @Test
    public void reusedScannerRepeatedScansDoNotCrash() throws Exception {
        List<AreaRule> rules = loadFixtureRules();

        StringBuilder allRules = new StringBuilder("import \"area\"\n");
        for (AreaRule r : rules) {
            allRules.append(r.ruleText.replaceFirst("(?s)import \"area\"\\n", ""));
        }

        final int rounds = 200;
        try (YaraCompiler compiler = yara.createCompiler()) {
            compiler.setCallback((errorLevel, fileName, lineNumber, message) -> fail("compile error: " + message));
            compiler.addRulesContent(allRules.toString(), null);

            try (YaraScanner scanner = compiler.createScanner()) {
                for (int round = 0; round < rounds; round++) {
                    for (AreaRule r : rules) {
                        final Set<String> matchedIds = new HashSet<>();
                        scanner.setCallback(v -> matchedIds.add(v.getIdentifier()));
                        scanner.scan(r.buffer);
                        assertTrue(matchedIds.contains(r.name), r.name + " round " + round + ": " + matchedIds);
                    }
                }
            }
        }
    }

    @Test
    public void compilerScannerLifecycleChurnDoesNotCrash() throws Exception {
        AreaRule rule = loadFixtureRules().get(0);
        for (int i = 0; i < 100; i++) {
            assertTrue(scanForMatch(rule.ruleText, rule.buffer, rule.name), rule.name);
        }
    }
}
