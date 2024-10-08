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

import java.io.IOException;

import org.junit.jupiter.api.Test;

import net.jcip.annotations.NotThreadSafe;

/**
 * User: pba
 * Date: 6/5/15
 * Time: 3:01 PM
 */
@NotThreadSafe
public class YaraLibraryTest {
    @Test
    public void testCreate() {
        new YaraLibrary();
    }

    @Test
    public void testInitialize() {
        YaraLibrary library = new YaraLibrary();
        library.initialize();
    }

    @Test
    public void testFinalize() throws IOException {
        YaraLibrary library = new YaraLibrary();
        library.initialize();
    }
}
