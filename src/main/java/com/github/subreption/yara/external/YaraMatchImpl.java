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


import com.github.subreption.yara.YaraMatch;

public class YaraMatchImpl implements YaraMatch {
    private String value;
    private long offset;

    public YaraMatchImpl(long offset, String value) {
        this.offset = offset;
        this.value = value;
    }

    @Override
    public String getValue() {
        return value;
    }

    @Override
    public long getOffset() {
        return offset;
    }
}
