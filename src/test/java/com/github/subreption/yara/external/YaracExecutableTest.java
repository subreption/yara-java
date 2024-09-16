package com.github.subreption.yara.external;

import com.github.subreption.yara.TestUtils;
import com.github.subreption.yara.YaraCompilationCallback;
import org.junit.jupiter.api.Test;

import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.util.concurrent.atomic.AtomicBoolean;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.junit.jupiter.api.Assertions.fail;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.times;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;


/**
 * User: pba
 * Date: 6/15/15
 * Time: 3:36 PM
 */
public class YaracExecutableTest {
    private final static Logger logger = LoggerFactory.getLogger(YaracExecutableTest.class.getName());

    @Test
    public void testCreate() {
        new YaracExecutable();
    }

    @Test
    public void testCreateNull() {
        assertThrows(IllegalArgumentException.class, () -> new YaracExecutable(null));
    }

    @Test
    public void testCreateNativeExec() {
        NativeExecutable exec = mock(NativeExecutable.class);
        when(exec.load(null)).thenReturn(true);

        new YaracExecutable(exec);

        verify(exec, times(1)).load(System.getenv("YARAC_BINARY_PATH"));
    }

    @Test
    public void testRuleNullNamespace() {
        YaracExecutable exec = new YaracExecutable();
        Path tempdir = Paths.get(System.getProperty("java.io.tmpdir"));
        assertThrows(IllegalArgumentException.class, () -> exec.addRule(null, tempdir));
    }


    @Test
    public void testRule() {
        YaracExecutable exec = new YaracExecutable();
        assertEquals(exec, exec.addRule(Paths.get(System.getProperty("java.io.tmpdir"))));
    }

    @Test
    public void testExecuteNoArgs() throws Exception {
        final AtomicBoolean failure = new AtomicBoolean();

        YaraCompilationCallback callback = (errorLevel, fileName, lineNumber, message) -> failure.set(true);

        Path output = new YaracExecutable().compile(callback);
        assertNotNull(output);
        assertTrue(failure.get());
    }

    @Test
    public void testExecuteOK() throws Exception {
        YaraCompilationCallback callback = (errorLevel, fileName, lineNumber, message) -> {
            logger.info(String.format("errorLevel %s, message %s", errorLevel, message));
        };

        Path output = new YaracExecutable()
                                .addRule(TestUtils.getResource("rules/hello.yara"))
                                .addRule(TestUtils.getResource("rules/test.yara"))
                                .compile(callback);

        logger.info(String.format("output %s", output));

        assertNotNull(output);
        assertTrue(Files.exists(output));
    }

    @Test
    public void testExecuteError() throws Exception {
        final AtomicBoolean failure = new AtomicBoolean();

        YaraCompilationCallback callback = (errorLevel, fileName, lineNumber, message) -> {
            logger.info(String.format("errorLevel %s, message %s", errorLevel, message));
            assertEquals(YaraCompilationCallback.ErrorLevel.WARNING, errorLevel);
            assertTrue(fileName.endsWith("error.yara"));
            assertEquals(13, lineNumber);
            assertTrue(message.endsWith("$b\""));
            failure.set(true);
        };

        Path output = new YaracExecutable()
                            .addRule(TestUtils.getResource("rules/error.yara"))
                            .compile(callback);

        assertNotNull(output);
        assertTrue(failure.get());
    }
}
