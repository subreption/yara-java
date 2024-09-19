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

import static com.github.subreption.yara.Preconditions.checkArgument;

/**
 * Yara module
 */
public class YaraModule implements  AutoCloseable {
    private final YaraLibrary library;
    private final long peer;
    private long dp;

    YaraModule(YaraLibrary library, long peer) {
        checkArgument(library != null);
        checkArgument(peer != 0);

        this.library = library;
        this.peer = peer;
    }

    public String getName() {
        return library.moduleName(peer);
    }

    public boolean loadData(String data) {
        unloadData();

        dp = library.moduleLoadData(peer, data);
        return dp != 0;
    }

    public void unloadData() {
        if (dp != 0) {
            library.moduleUnloadData(dp);
            dp = 0;
        }
    }

    @Override
    public void close() throws Exception {
        unloadData();
    }
}
