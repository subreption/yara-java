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
import java.util.Iterator;
import java.util.Map;
import java.util.UUID;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.concurrent.atomic.AtomicInteger;

import org.junit.jupiter.api.AfterEach;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.junit.jupiter.api.Assertions.fail;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import static org.mockito.Mockito.mock;

import com.github.subreption.yara.YaraCompilationCallback;
import com.github.subreption.yara.YaraCompiler;
import com.github.subreption.yara.YaraMatch;
import com.github.subreption.yara.YaraMeta;
import com.github.subreption.yara.YaraScanCallback;
import com.github.subreption.yara.YaraScanner;
import com.github.subreption.yara.YaraString;
import com.github.subreption.yara.TestUtils;

import net.jcip.annotations.NotThreadSafe;


/**
 * User: pba
 * Date: 6/7/15
 * Time: 6:38 PM
 */
@NotThreadSafe
public class YaraScannerImplTest {
    private static final String YARA_RULES = "import \"pe\"\n" +
            "rule HelloWorld : Hello World\n"+
            "{\n"+
            "\tmeta:\n" +
            "   my_identifier_1 = \"Some string data\"\n" +
            "   my_identifier_2 = 24\n" +
            "   my_identifier_3 = true\n" +
            "\tstrings:\n"+
            "\t\t$a = \"Hello world\"\n"+
            "\n"+
            "\tcondition:\n"+
            "\t\t$a\n"+
            "}" +
            "rule NoMatch \n"+
            "{\n"+
            "\tmeta:\n" +
            "	my_identifier_1 = \"Some string data\"\n" +
            "	my_identifier_2 = 24\n" +
            "	my_identifier_3 = true\n" +
            "\tstrings:\n"+
            "\t\t$a = \"nomatch\"\n"+
            "\n"+
            "\tcondition:\n"+
            "\t\t$a\n"+
            "}";

    private YaraImpl yara;

    @BeforeEach
    public void setup() {
        this.yara = new YaraImpl();
    }

    @AfterEach
    public void teardown() throws Exception {
        yara.close();
    }


    @Test
    public void testCreateNoRules() {
        assertThrows(IllegalArgumentException.class, () -> new YaraScannerImpl(mock(YaraLibrary.class), 0));
    }

    @Test
    public void testCreateNoLibrary() {
        assertThrows(IllegalArgumentException.class, () -> new YaraScannerImpl(null, 1));
    }

    @Test
    public void testCreate() {
        new YaraScannerImpl(mock(YaraLibrary.class), 1);
    }

    @Test
    public void testWrongTimeout() {
        YaraScannerImpl impl = new YaraScannerImpl(mock(YaraLibrary.class), 1);
        assertThrows(IllegalArgumentException.class, () -> impl.setTimeout(-1));
    }

    @Test
    public void testSetCallback() throws Exception {
        //
        YaraCompilationCallback compileCallback = (errorLevel, fileName, lineNumber, message) -> fail();
        YaraScanCallback scanCallback = v -> {};

        // Create compiler and get scanner
        try (YaraCompiler compiler = yara.createCompiler()) {
            compiler.setCallback(compileCallback);
            compiler.addRulesContent(YARA_RULES, null);

            try (YaraScanner scanner = compiler.createScanner()) {
                assertNotNull(scanner);

                scanner.setCallback(scanCallback);
            }
        }
    }

    @Test
    public void testScanMatch() throws Exception {
        // Write test file
        File temp = File.createTempFile(UUID.randomUUID().toString(), ".tmp");
        Files.write(Paths.get(temp.getAbsolutePath()), "Hello world".getBytes(), StandardOpenOption.WRITE);


        //
        YaraCompilationCallback compileCallback = (errorLevel, fileName, lineNumber, message) -> fail();

        final AtomicBoolean match = new AtomicBoolean();

        YaraScanCallback scanCallback = v -> {
            assertEquals("HelloWorld", v.getIdentifier());
            assertMetas(v.getMetadata());
            assertStrings(v.getStrings());
            assertTags(v.getTags());

            match.set(true);
        };

        // Create compiler and get scanner
        try (YaraCompiler compiler = yara.createCompiler()) {
            compiler.setCallback(compileCallback);
            compiler.addRulesContent(YARA_RULES, null);

            try (YaraScanner scanner = compiler.createScanner()) {
                assertNotNull(scanner);

                scanner.setCallback(scanCallback);
                scanner.scan(temp);
            }
        }

        assertTrue(match.get());
    }

    @Test
    public void testScanNegateMatch() throws Exception {
        /*
            Negate and try matching on an UUID, we should have two matches
         */
        // Write test file
        File temp = File.createTempFile(UUID.randomUUID().toString(), ".tmp");
        Files.write(Paths.get(temp.getAbsolutePath()), UUID.randomUUID().toString().getBytes(),
                StandardOpenOption.WRITE);


        //
        YaraCompilationCallback compileCallback = (errorLevel, fileName, lineNumber, message) -> fail();

        final AtomicInteger match = new AtomicInteger();

        YaraScanCallback scanCallback = v -> {
            assertMetas(v.getMetadata());
            assertFalse(v.getStrings().next().getMatches().hasNext());

            match.incrementAndGet();
        };

        // Create compiler and get scanner
        try (YaraCompiler compiler = yara.createCompiler()) {
            compiler.setCallback(compileCallback);
            compiler.addRulesContent(YARA_RULES, null);

            try (YaraScanner scanner = compiler.createScanner()) {
                scanner.setNotSatisfiedOnly(true);
                assertNotNull(scanner);

                scanner.setCallback(scanCallback);
                scanner.scan(temp);
            }
        }

        assertEquals(2, match.get());
    }

    @Test
    public void testScanNegateLimitMatch() throws Exception {
         /*
            Negate and try matching on an UUID with limit one,
            we should have a single match
         */
        // Write test file
        File temp = File.createTempFile(UUID.randomUUID().toString(), ".tmp");
        Files.write(Paths.get(temp.getAbsolutePath()), UUID.randomUUID().toString().getBytes(),
                StandardOpenOption.WRITE);


        //
        YaraCompilationCallback compileCallback = (errorLevel, fileName, lineNumber, message) -> fail();

        final AtomicInteger match = new AtomicInteger();

        YaraScanCallback scanCallback = v -> {
            assertMetas(v.getMetadata());
            assertFalse(v.getStrings().next().getMatches().hasNext());
            match.incrementAndGet();
        };

        // Create compiler and get scanner
        try (YaraCompiler compiler = yara.createCompiler()) {
            compiler.setCallback(compileCallback);
            compiler.addRulesContent(YARA_RULES, null);

            try (YaraScanner scanner = compiler.createScanner()) {
                scanner.setNotSatisfiedOnly(true);
                scanner.setMaxRules(1);
                assertNotNull(scanner);

                scanner.setCallback(scanCallback);
                scanner.scan(temp);
            }
        }

        assertEquals(1, match.get());
    }

    @Test
    public void testScanNoMatch() throws Exception {
        // Write test file
        File temp = File.createTempFile(UUID.randomUUID().toString(), ".tmp");
        Files.write(Paths.get(temp.getAbsolutePath()), UUID.randomUUID().toString().getBytes(),
                StandardOpenOption.WRITE);


        //
        YaraCompilationCallback compileCallback = (errorLevel, fileName, lineNumber, message) -> fail();

        final AtomicBoolean match = new AtomicBoolean();

        YaraScanCallback scanCallback = v -> match.set(true);

        // Create compiler and get scanner
        try (YaraCompiler compiler = yara.createCompiler()) {
            compiler.setCallback(compileCallback);
            compiler.addRulesContent(YARA_RULES, null);

            try (YaraScanner scanner = compiler.createScanner()) {
                assertNotNull(scanner);

                scanner.setCallback(scanCallback);
                scanner.scan(temp);
            }
        }

        assertFalse(match.get());
    }

    @Test
    public void testScanModule() throws Exception {
        // Write test file
        File temp = File.createTempFile(UUID.randomUUID().toString(), ".tmp");
        Files.write(Paths.get(temp.getAbsolutePath()), "Hello world".getBytes(), StandardOpenOption.WRITE);

        Map<String, String> args = new HashMap<>();
        args.put("pe", temp.getAbsolutePath());

        YaraCompilationCallback compileCallback = (errorLevel, fileName, lineNumber, message) -> fail();

        final AtomicBoolean match = new AtomicBoolean();

        YaraScanCallback scanCallback = v -> match.set(true);

        // Create compiler and get scanner
        try (YaraCompiler compiler = yara.createCompiler()) {
            compiler.setCallback(compileCallback);
            compiler.addRulesContent(YARA_RULES, null);

            try (YaraScanner scanner = compiler.createScanner()) {
                assertNotNull(scanner);

                scanner.setCallback(scanCallback);
                scanner.scan(temp, args);
            }
        }

        assertTrue(match.get());
    }

    @Test
    public void testScanMemMatch() throws Exception {
        // Make test buffer
        byte[] buffer = "Hello world".getBytes();

        YaraCompilationCallback compileCallback = (errorLevel, fileName, lineNumber, message) -> fail();

        final AtomicBoolean match = new AtomicBoolean();

        YaraScanCallback scanCallback = v -> {
            assertEquals("HelloWorld", v.getIdentifier());
            assertMetas(v.getMetadata());
            assertStrings(v.getStrings());
            assertTags(v.getTags());
            match.set(true);
        };

        // Create compiler and get scanner
        try (YaraCompiler compiler = yara.createCompiler()) {
            compiler.setCallback(compileCallback);
            compiler.addRulesContent(YARA_RULES, null);

            try (YaraScanner scanner = compiler.createScanner()) {
                assertNotNull(scanner);
                scanner.setCallback(scanCallback);
                scanner.scan(buffer);
            }
        }

        assertTrue(match.get());
    }

    private void assertMetas(Iterator<YaraMeta> metas) {
        assertNotNull(metas);

        YaraMeta meta = metas.next();
        assertEquals(YaraMeta.Type.STRING, meta.getType());
        assertEquals("my_identifier_1", meta.getIdentifier());
        assertEquals("Some string data", meta.getString());

        meta = metas.next();
        assertEquals(YaraMeta.Type.INTEGER, meta.getType());
        assertEquals("my_identifier_2", meta.getIdentifier());
        assertEquals(24, meta.getInteger());

        meta = metas.next();
        assertEquals(YaraMeta.Type.BOOLEAN, meta.getType());
        assertEquals("my_identifier_3", meta.getIdentifier());
        assertEquals(1, meta.getInteger());

        assertFalse(metas.hasNext());
    }

    private void assertStrings(Iterator<YaraString> strings) {
        String helloWorld = "Hello world";
        byte[] helloWorldBytes = helloWorld.getBytes();

        assertNotNull(strings);

        YaraString string = strings.next();

        assertEquals("$a", string.getIdentifier());

        Iterator<YaraMatch> matches = string.getMatches();
        assertTrue(matches.hasNext());

        YaraMatch match = matches.next();
        assertEquals(0, match.getOffset());
        assertEquals(helloWorld, match.getValue());
        assertEquals(TestUtils.bytesToHex(helloWorldBytes), TestUtils.bytesToHex(match.getBytes()));
        assertEquals(helloWorldBytes.length, match.getBytes().length);
        assertFalse(matches.hasNext());

        assertFalse(strings.hasNext());
    }

    private void assertTags(Iterator<String> tags) {
        assertNotNull(tags);

        assertEquals("Hello", tags.next());
        assertEquals("World", tags.next());
        assertFalse(tags.hasNext());
    }
}
