package com.github.subreption.yara.embedded;

import java.io.File;
import java.math.BigInteger;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.StandardOpenOption;
import java.security.SecureRandom;
import java.util.concurrent.atomic.AtomicBoolean;

import org.junit.jupiter.api.AfterEach;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.junit.jupiter.api.Assertions.fail;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Disabled;
import org.junit.jupiter.api.Test;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import com.github.subreption.yara.TestUtils;
import com.github.subreption.yara.YaraCompilationCallback;
import com.github.subreption.yara.YaraCompiler;
import com.github.subreption.yara.YaraException;
import com.github.subreption.yara.YaraScanner;

import net.jcip.annotations.NotThreadSafe;

/**
 * User: pba
 * Date: 6/5/15
 * Time: 6:58 PM
 */
@NotThreadSafe
public class YaraCompilerImplTest {
    private final static Logger logger = LoggerFactory.getLogger(YaraCompilerImplTest.class.getName());
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

    private YaraImpl yara;

    private String randomString(String prefix) {
        SecureRandom random = new SecureRandom();

        // Generate a random filename with high entropy
        String randomStr = new BigInteger(130, random).toString(32);

        return String.format("%s_%s", prefix, randomStr);
    }

    @BeforeEach
    public void setup()
    {
        ProcessHandle currentProcess = ProcessHandle.current();

        logger.debug(String.format("Creating instance of Yara library (native), pid %d, thread %s.",
            currentProcess.pid(), Thread.currentThread().getName()));

        this.yara = new YaraImpl();
    }

    @AfterEach
    public void teardown() throws Exception {
        ProcessHandle currentProcess = ProcessHandle.current();

        logger.debug(String.format("Closing instance of Yara library (native), pid %d, thread %s.",
            currentProcess.pid(), Thread.currentThread().getName()));

        this.yara.close();
    }


    @Test
    public void testCreate() throws Exception {
        try (YaraCompiler compiler = yara.createCompiler()) {
            assertNotNull(compiler);
        }
    }

    @Test
    public void testSetCallback() throws Exception {
        try (YaraCompiler compiler = yara.createCompiler()) {
            compiler.setCallback(new YaraCompilationCallback() {
                @Override
                public void onError(ErrorLevel errorLevel, String fileName, long lineNumber, String message) {
                }
            });
        }
    }

    @Test
    public void testAddRulesContentSucceeds() throws Exception {
        YaraCompilationCallback callback = (errorLevel, fileName, lineNumber, message) -> fail();

        try (YaraCompiler compiler = yara.createCompiler()) {
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
                logger.debug(String.format("Compilation failed in %s at %d: %s", fileName, lineNumber, message));
            }
        };

        try (YaraCompiler compiler = yara.createCompiler()) {
            compiler.setCallback(callback);
            compiler.addRulesContent(YARA_RULE_FAIL, null);

            fail();
        }
        catch (YaraException e) {
        }

        assertTrue(called.get());
    }

    @Test
    public void testAddRulePackageSucceeds() throws Exception {
        YaraCompilationCallback callback = new YaraCompilationCallback() {
            @Override
            public void onError(ErrorLevel errorLevel, String fileName, long lineNumber, String message) {
                fail();
            }
        };
        String rulePath = TestUtils.getResource("rules/one-level.zip").toString();


        try (YaraCompiler compiler = yara.createCompiler()) {
            compiler.setCallback(callback);
            compiler.addRulesPackage(rulePath, null);
        }
    }

    @Test
    public void testAddRuleMultiLevelPackageSucceeds() throws Exception {
        YaraCompilationCallback callback = new YaraCompilationCallback() {
            @Override
            public void onError(ErrorLevel errorLevel, String fileName, long lineNumber, String message) {
                fail();
            }
        };


        try (YaraCompiler compiler = yara.createCompiler()) {
            compiler.setCallback(callback);
            compiler.addRulesPackage(TestUtils.getResource("rules/two-levels.zip").toString(), null);
        }
    }

    @Test
    public void testAddRulePackageFails() throws Exception {
        final AtomicBoolean called = new AtomicBoolean();
        YaraCompilationCallback callback = new YaraCompilationCallback() {
            @Override
            public void onError(ErrorLevel errorLevel, String fileName, long lineNumber, String message) {
                called.set(true);
                logger.debug(String.format("Compilation failed in %s at %d: %s", fileName, lineNumber, message));
            }
        };

        try (YaraCompiler compiler = yara.createCompiler()) {
            compiler.setCallback(callback);
            compiler.addRulesPackage(TestUtils.getResource("rules/one-level.zip").toString(), null);
            compiler.addRulesPackage(TestUtils.getResource("rules/two-levels.zip").toString(), null);

            fail();
        }
        catch(YaraException e) {
            logger.debug(String.format("YaraException %s", e.toString()));
        }

        assertTrue(called.get());
    }

    @Test
    public void testAddRulesFileSucceeds() throws Exception {
        YaraCompilationCallback callback = new YaraCompilationCallback() {
            @Override
            public void onError(ErrorLevel errorLevel, String fileName, long lineNumber, String message) {
                logger.debug(String.format("Compilation failed in %s at %d: %s", fileName, lineNumber, message));
                fail();
            }
        };


        Path rule = File.createTempFile(randomString("testAddRulesFileSucceeds"), "yara")
                .toPath();

        Files.write(rule, YARA_RULE_HELLO.getBytes(), StandardOpenOption.WRITE);

        try (YaraCompiler compiler = yara.createCompiler()) {
            compiler.setCallback(callback);
            compiler.addRulesFile(rule.toString(), null, null);
        } finally {
            if (rule != null) {
                Files.deleteIfExists(rule);
            }
        }
    }


    @Test
    public void testAddRulesFileFails() throws Exception {
        final AtomicBoolean called = new AtomicBoolean();
        YaraCompilationCallback callback = new YaraCompilationCallback() {
            @Override
            public void onError(ErrorLevel errorLevel, String fileName, long lineNumber, String message) {
                called.set(true);
                logger.debug(String.format("Compilation failed in %s at %d: %s", fileName, lineNumber, message));
            }
        };

        Path rule = File.createTempFile(randomString("testAddRulesFileFails"), "yara")
                .toPath();

        Files.write(rule, YARA_RULE_FAIL.getBytes(), StandardOpenOption.WRITE);

        try (YaraCompiler compiler = yara.createCompiler()) {
            compiler.setCallback(callback);
            compiler.addRulesFile(rule.toString(), rule.toString(), null);

            fail();
        }
        catch(YaraException e) {
            logger.debug(String.format("YaraException on testAddRulesFileFails: %s", e.getMessage()));
        } finally {
            if (rule != null) {
                Files.deleteIfExists(rule);
            }
        }

        assertTrue(called.get());
    }


    @Test
    public void testCreateScanner() throws Exception {
        YaraCompilationCallback callback = (errorLevel, fileName, lineNumber, message) -> fail();

        try (YaraCompiler compiler = yara.createCompiler()) {
            compiler.setCallback(callback);
            compiler.addRulesContent(YARA_RULE_HELLO, null);

            try (YaraScanner scanner = compiler.createScanner()) {
                assertNotNull(scanner);
            }
        }
    }

    @Test
    @Disabled("yara asserts which stops execution")
    public void testAddRulesAfterScannerCreate() throws Exception {
        YaraCompilationCallback callback = (errorLevel, fileName, lineNumber, message) -> fail();

        try (YaraCompiler compiler = yara.createCompiler()) {
            compiler.setCallback(callback);
            compiler.addRulesContent(YARA_RULE_HELLO, null);

            // Get scanner
            try (YaraScanner scanner = compiler.createScanner()) {
                assertNotNull(scanner);
            }

            // Subsequent add rule should fail
            try {
                compiler.addRulesContent(YARA_RULE_NOOP, null);
            }
            catch (YaraException e) {
                assertEquals(1L, e.getNativeCode());
            }
        }
    }
}
