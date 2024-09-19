
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

import java.util.UUID;

import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;
import org.junit.jupiter.api.Test;


/**
 * User: pba
 * Date: 6/13/15
 * Time: 8:55 AM
 */
public class NativeExecutableTest {
    @Test
    public void testCreateNoName() {
        assertThrows(IllegalArgumentException.class, () -> new NativeExecutable(""));
    }

    @Test
    public void testCreateNullName() {
        assertThrows(IllegalArgumentException.class,
            () -> new NativeExecutable(null, NativeExecutableTest.class.getClassLoader()));
    }

    @Test
    public void testCreate() {
        new NativeExecutable("yara");
    }

    @Test
    public void testLoadNotFound() {
        NativeExecutable exe = new NativeExecutable(UUID.randomUUID().toString());
        assertFalse(exe.load(null));
    }

    @Test
    public void testLoadYara() {
        NativeExecutable exe = new NativeExecutable("yara");
        assertTrue(exe.load(System.getenv("YARA_BINARY_PATH")));
    }

    @Test
    public void testLoadYarac() {
        NativeExecutable exe = new NativeExecutable("yarac");
        assertTrue(exe.load(System.getenv("YARAC_BINARY_PATH")));
    }
}
