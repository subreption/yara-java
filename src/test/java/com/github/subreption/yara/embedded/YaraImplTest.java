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

import static org.junit.jupiter.api.Assertions.assertNotNull;
import org.junit.jupiter.api.Test;

import com.github.subreption.yara.YaraCompiler;

/**
 * User: pba
 * Date: 6/9/15
 * Time: 6:51 PM
 */
public class YaraImplTest {
    @Test
    public void testCreateClose() throws Exception {
        try (YaraImpl yara = new YaraImpl()) {
        }
    }

    @Test
    public void testCreateCompiler() throws Exception {
        try (YaraImpl yara = new YaraImpl()) {
            try (YaraCompiler compiler = yara.createCompiler())  {
                assertNotNull(compiler);
            }
        }
    }
}
