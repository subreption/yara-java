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

package com.github.subreption.yara.external;

import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.util.concurrent.atomic.AtomicBoolean;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;
import org.junit.jupiter.api.Test;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.times;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import com.github.subreption.yara.TestUtils;
import com.github.subreption.yara.YaraCompilationCallback;


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
