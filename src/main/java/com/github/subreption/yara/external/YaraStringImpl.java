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

import java.util.ArrayList;
import java.util.Iterator;
import java.util.List;

import static com.github.subreption.yara.Preconditions.checkArgument;
import com.github.subreption.yara.Utils;
import com.github.subreption.yara.YaraMatch;
import com.github.subreption.yara.YaraString;

public class YaraStringImpl implements YaraString {
    private String identifier;
    private List<YaraMatch> matches = new ArrayList<>();

    public YaraStringImpl(String identifier) {
        checkArgument(!Utils.isNullOrEmpty(identifier));
        this.identifier = identifier;
    }

    public void addMatch(long offset, String value) {
        this.matches.add(new YaraMatchImpl(offset, value));
    }

    @Override
    public String getIdentifier() {
        return identifier;
    }

    @Override
    public Iterator<YaraMatch> getMatches() {
        return matches.iterator();
    }
}
