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

/**
 * Yara executable manager
 */
public class YaraExecutableManager {
    private static final Object yaraLock = new Object();
    private static volatile NativeExecutable yara;

    private static final Object yaracLock = new Object();
    private static volatile NativeExecutable yarac;

    public static NativeExecutable getYara() {
        if (yara == null) {
            synchronized (yaraLock) {
                if (yara == null) {
                    yara = new NativeExecutable("yara");
                    String yaraBinaryPath = System.getenv("YARA_BINARY_PATH");
                    yara.load(yaraBinaryPath);
                }
            }
        }
        return yara;
    }

    public static NativeExecutable getYarac() {
        if (yarac == null) {
            synchronized (yaracLock) {
                if (yarac == null) {
                    yarac = new NativeExecutable("yarac");
                    String yaracBinaryPath = System.getenv("YARAC_BINARY_PATH");
                    yarac.load(yaracBinaryPath);
                }
            }
        }
        return yarac;
    }
}
