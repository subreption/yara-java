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

import com.github.subreption.yara.Yara;
import com.github.subreption.yara.YaraCompiler;
import com.github.subreption.yara.YaraException;

/**
 * Yara component
 *
 * @apiNote There should be only one component instance per process
 */
public class YaraImpl implements Yara {
    private static final YaraLibrary library;

    static {
        library = new YaraLibrary();
        library.initialize();
    }

    /**
     * Create compiler
     *
     * @return
     */
    public YaraCompiler createCompiler() {
        long compiler[] = new long[1];

        int ret = library.compilerCreate(compiler);
        if (ret != 0) {
            throw new YaraException(ret);
        }

        return new YaraCompilerImpl(this.library, compiler[0]);
    }

    @Override
    public void close() throws Exception {
    }
}
