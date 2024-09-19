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

import static com.github.subreption.yara.Preconditions.checkArgument;
import com.github.subreption.yara.Utils;
import com.github.subreption.yara.YaraMeta;

public class YaraMetaImpl implements YaraMeta {
    private String identifier;
    private Type type;
    private String string;
    private int integer;

    public YaraMetaImpl(String identifier, String value) {
        checkArgument(!Utils.isNullOrEmpty(identifier));
        this.identifier = identifier;
        this.type = Type.STRING;
        this.string = value;
    }

    public YaraMetaImpl(String identifier, int value) {
        checkArgument(!Utils.isNullOrEmpty(identifier));
        this.identifier = identifier;
        this.type = Type.INTEGER;
        this.integer = value;
    }

    public YaraMetaImpl(String identifier, boolean value) {
        checkArgument(!Utils.isNullOrEmpty(identifier));
        this.identifier = identifier;
        this.type = Type.BOOLEAN;
        this.integer = value ? 1 : 0;
    }

    @Override
    public Type getType() {
        return type;
    }

    @Override
    public String getIdentifier() {
        return identifier;
    }

    @Override
    public String getString() {
        return string;
    }

    @Override
    public int getInteger() {
        return integer;
    }
}
