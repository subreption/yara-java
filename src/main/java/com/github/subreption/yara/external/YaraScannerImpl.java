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

import java.io.File;
import java.nio.file.Path;
import java.util.Map;

import com.github.subreption.yara.ErrorCode;
import static com.github.subreption.yara.Preconditions.checkArgument;
import com.github.subreption.yara.YaraException;
import com.github.subreption.yara.YaraScanCallback;
import com.github.subreption.yara.YaraScanner;


public class YaraScannerImpl implements YaraScanner {
    private YaraExecutable yara;
    private YaraScanCallback callback;

    public YaraScannerImpl(Path rules) {
        checkArgument(rules != null);
        this.yara = new YaraExecutable();
        this.yara.addRule(rules);
    }

    @Override
    public void setTimeout(int timeout) {
        this.yara.setTimeout(timeout);
    }

    @Override
    public void setMaxRules(int count) {
        yara.setMaxRules(count);
    }

    @Override
    public void setNotSatisfiedOnly(boolean value) {
        yara.setNegate(value);
    }

    @Override
    public void setCallback(YaraScanCallback cbk) {
        checkArgument(cbk != null);
        this.callback = cbk;
    }

    @Override
    public void scan(File file) {
        scan(file, null);
    }

    @Override
    public void scan(File file, Map<String, String> moduleArgs) {
        scan(file, moduleArgs, this.callback);
    }
    @Override
    public void scan(File file, Map<String, String> moduleArgs, YaraScanCallback yaraScanCallback) {
        checkArgument(file != null);

        if (!file.exists()) {
            throw new YaraException(ErrorCode.COULD_NOT_OPEN_FILE.getValue());
        }

        try {
            yara.match(file.toPath(), moduleArgs, yaraScanCallback);
        } catch (Exception e) {
            throw new YaraException(e.getMessage());
        }

    }

    @Override
    public void scan(byte[] buffer) {
        scan(buffer, null);
    }

    @Override
    public void scan(byte[] buffer, Map<String, String> moduleArgs) {
        scan(buffer, moduleArgs, this.callback);
    }

    @Override
    public void scan(byte[] buffer, Map<String, String> moduleArgs, YaraScanCallback yaraScanCallback) {
        checkArgument(buffer != null);

        try {
            yara.match(buffer, moduleArgs, yaraScanCallback);
        } catch (Exception e) {
            throw new YaraException(e.getMessage());
        }
    }

    @Override
    public void close() throws Exception {
    }
}
