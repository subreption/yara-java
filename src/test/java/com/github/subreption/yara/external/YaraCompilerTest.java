package com.github.subreption.yara.external;

import java.io.File;
import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.nio.file.StandardOpenOption;
import java.util.UUID;
import java.util.concurrent.atomic.AtomicBoolean;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.junit.jupiter.api.Assertions.fail;
import org.junit.jupiter.api.Test;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import com.github.subreption.yara.TestUtils;
import com.github.subreption.yara.YaraCompilationCallback;
import com.github.subreption.yara.YaraCompiler;
import com.github.subreption.yara.YaraException;
import com.github.subreption.yara.YaraScanner;

/**
 * User: pba
 * Date: 6/16/15
 * Time: 6:12 PM
 */
public class YaraCompilerTest {
    private final static Logger logger = LoggerFactory.getLogger(YaraCompilerTest.class.getName());

    private static final String YARA_RULE_HELLO = "rule HelloWorld\n"+
            "{\n"+
            "\tstrings:\n"+
            "\t\t$a = \"Hello world\"\n"+
            "\n"+
            "\tcondition:\n"+
            "\t\t$a\n"+
            "}";

    private static final String YARA_RULE_NOOP = "rule Noop\n"+
            "{\n"+
            "\tstrings:\n"+
            "\t\t$a = \"\"\n"+
            "\n"+
            "\tcondition:\n"+
            "\t\t$a\n"+
            "}";

    private static final String YARA_RULE_FAIL = "rule HelloWorld\n"+
            "{\n"+
            "\tstrings:\n"+
            "\t\t$a = \"Hello world\"\n"+
            "\n"+
            "\tcondition:\n"+
            "\t\t$a or $b\n"+
            "}";

    @Test
    public void testCreate() {
        new YaraCompilerImpl();
    }

    @Test
    public void testSetNullCallback() {
        YaraCompilerImpl impl = new YaraCompilerImpl();
        assertThrows(IllegalArgumentException.class, () -> impl.setCallback(null));
    }

    @Test
    public void testAddNullRule() {
        YaraCompilerImpl yaraCompiler = new YaraCompilerImpl();
        assertThrows(IllegalArgumentException.class, () -> yaraCompiler.addRulesContent(null, null));
    }

    @Test
    public void testSetCallback() throws Exception {
        try (YaraCompiler compiler = new YaraCompilerImpl()) {
            compiler.setCallback((errorLevel, fileName, lineNumber, message) -> {});
        }
    }

    @Test
    public void testAddRulesContentSucceeds() throws Exception {
        YaraCompilationCallback callback = (errorLevel, fileName, lineNumber, message) -> fail();

        try (YaraCompiler compiler = new YaraCompilerImpl()) {
            compiler.setCallback(callback);
            compiler.addRulesContent(YARA_RULE_HELLO, null);
        }
    }

    @Test
    public void testAddRulesContentFails() throws Exception {
        final AtomicBoolean called = new AtomicBoolean();
        YaraCompilationCallback callback = new YaraCompilationCallback() {
            @Override
            public void onError(ErrorLevel errorLevel, String fileName, long lineNumber, String message) {
                called.set(true);
                logger.info(String.format("Compilation failed in %s at %d: %s", fileName, lineNumber, message));
            }
        };

        try (YaraCompiler compiler = new YaraCompilerImpl()) {
            compiler.setCallback(callback);
            compiler.addRulesContent(YARA_RULE_FAIL, null);

            try {
                assertNotNull(compiler.createScanner());
            }
            catch (YaraException ye) {
            }
        }

        assertTrue(called.get());
    }

    @Test
    public void testAddRulesFileSucceeds() throws Exception {
        YaraCompilationCallback callback = (errorLevel, fileName, lineNumber, message) -> fail();


        Path rule = File.createTempFile(UUID.randomUUID().toString(), "yara")
                .toPath();

        Files.write(rule, YARA_RULE_HELLO.getBytes(), StandardOpenOption.WRITE);

        try (YaraCompiler compiler = new YaraCompilerImpl()) {
            compiler.setCallback(callback);
            compiler.addRulesFile(rule.toString(), null, null);
        }
    }

    @Test
    public void testAddRulesFileFails() throws Exception {
        YaraCompilationCallback callback = (errorLevel, fileName, lineNumber, message) -> {};

        String rule = UUID.randomUUID().toString();

        try (YaraCompiler compiler = new YaraCompilerImpl()) {
            compiler.setCallback(callback);
            assertThrows(IllegalArgumentException.class, () -> compiler.addRulesFile(rule, rule, null));
        }
    }

    @Test
    public void testAddRulePackageSucceeds() throws Exception {
        final AtomicBoolean called = new AtomicBoolean();

        YaraCompilationCallback callback = (errorLevel, fileName, lineNumber, message) -> fail();


        try (YaraCompiler compiler = new YaraCompilerImpl()) {
            compiler.setCallback(callback);
            compiler.addRulesPackage(TestUtils.getResource("rules/one-level.zip").toString(), null);

            // Write test file
            File temp = File.createTempFile(UUID.randomUUID().toString(), ".tmp");
            Files.write(Paths.get(temp.getAbsolutePath()), "Hello world".getBytes(), StandardOpenOption.WRITE);

            try (YaraScanner scanner = compiler.createScanner()) {
                scanner.setCallback(rule -> {});
                scanner.scan(temp);
            }

            if (temp != null) {
                try {
                    Files.deleteIfExists(Paths.get(temp.getAbsolutePath()));
                } catch (IOException e) {
                    logger.error(String.format("Failed to delete temporary file: {0}", e.getMessage()));
                }
            }

            assertFalse(called.get());
        }
    }

    @Test
    public void testAddRuleMultiLevelPackageSucceeds() throws Exception {
        final AtomicBoolean called = new AtomicBoolean();

        YaraCompilationCallback callback = (errorLevel, fileName, lineNumber, message) -> fail();


        try (YaraCompiler compiler = new YaraCompilerImpl()) {
            compiler.setCallback(callback);
            compiler.addRulesPackage(TestUtils.getResource("rules/two-levels.zip").toString(), null);

            // Write test file
            File temp = File.createTempFile(UUID.randomUUID().toString(), ".tmp");
            Files.write(Paths.get(temp.getAbsolutePath()), "Hello world".getBytes(), StandardOpenOption.WRITE);

            try (YaraScanner scanner = compiler.createScanner()) {
                scanner.setCallback(rule -> {});
                scanner.scan(temp);
            }

            assertFalse(called.get());
        }
    }

    @Test
    public void testAddRulePackageFails() throws Exception {
        final AtomicBoolean called = new AtomicBoolean();
        YaraCompilationCallback callback = new YaraCompilationCallback() {
            @Override
            public void onError(ErrorLevel errorLevel, String fileName, long lineNumber, String message) {
                called.set(true);
                //logger.warn(String.format("Compilation failed in %s at %d: %s", fileName, lineNumber, message));
            }
        };

        // Write test file
        File temp = File.createTempFile(UUID.randomUUID().toString(), ".tmp");
        Files.write(Paths.get(temp.getAbsolutePath()), "Hello world".getBytes(), StandardOpenOption.WRITE);

        try (YaraCompiler compiler = new YaraCompilerImpl()) {
            compiler.setCallback(callback);
            compiler.addRulesPackage(TestUtils.getResource("rules/one-level.zip").toString(), null);
            compiler.addRulesPackage(TestUtils.getResource("rules/two-levels.zip").toString(), null);

            try (YaraScanner scanner = compiler.createScanner()) {
                scanner.setCallback(rule -> {});
                scanner.scan(temp);
            }

            assertTrue(called.get());
        }
        catch(YaraException e) {
        }
        finally {
            if (temp != null) {
                if (! temp.delete()) {
                    logger.warn(String.format("Failed to delete tmp file %s", temp));
                }
            }
        }

        assertTrue(called.get());
    }


    @Test
    public void testCreateScanner() throws Exception {
        YaraCompilationCallback callback = (errorLevel, fileName, lineNumber, message) -> fail();

        try (YaraCompiler compiler = new YaraCompilerImpl()) {
            compiler.setCallback(callback);
            compiler.addRulesContent(YARA_RULE_HELLO, null);

            try (YaraScanner scanner = compiler.createScanner()) {
                assertNotNull(scanner);
            }
        }
    }

    @Test
    public void testAddRulesAfterScannerCreate() throws Exception {
        final AtomicBoolean called = new AtomicBoolean();
        YaraCompilationCallback callback = (errorLevel, fileName, lineNumber, message) -> {
            called.set(true);
            logger.warn(String.format("testAddRulesAfterScannerCreate: compilation failed in %s at %d: %s", fileName, lineNumber, message));
        };

        try (YaraCompiler compiler = new YaraCompilerImpl()) {
            compiler.setCallback(callback);
            compiler.addRulesContent(YARA_RULE_HELLO, null);

            logger.info("testAddRulesAfterScannerCreate: added YARA_RULE_HELLO, creating scanner.");

            // Get scanner
            try (YaraScanner scanner = compiler.createScanner()) {
                logger.info(String.format("scanner = %s", scanner.toString()));
                assertNotNull(scanner);
            }

            if (called.get()) {
                logger.warn(String.format("testAddRulesAfterScannerCreate: premature/unexpected failure, verify!"));
                fail();
            }

            logger.info("testAddRulesAfterScannerCreate: adding NOOP rule, expecting failure");

            // Subsequent add rule should fail
            try {
                compiler.addRulesContent(YARA_RULE_NOOP, null);
                fail();
            }
            catch (YaraException e) {
                logger.warn(String.format("testAddRulesAfterScannerCreate: got YaraException, %s", e.toString()));
                assertEquals(1L, e.getNativeCode());
            }
        }
    }

}
