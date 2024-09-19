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

package com.github.subreption.yara;

import java.nio.file.Path;
import java.nio.file.Paths;

/**
 * User: pba
 * Date: 6/15/15
 * Time: 4:18 PM
 */
public class TestUtils {
    public static Path getResource(String path) {
        try {
            return Paths.get(TestUtils.class.getClassLoader().getResource(path).toURI());
        }
        catch (Throwable t) {
            throw new RuntimeException(t);
        }
    }
}
