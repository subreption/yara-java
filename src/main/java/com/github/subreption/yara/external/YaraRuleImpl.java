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
import com.github.subreption.yara.YaraMeta;
import com.github.subreption.yara.YaraRule;
import com.github.subreption.yara.YaraString;

public class YaraRuleImpl implements YaraRule {
    private String identifier;
    private List<String> tags = new ArrayList<>();
    private List<YaraMeta> metas = new ArrayList<>();
    private List<YaraString> strings = new ArrayList<>();

    public YaraRuleImpl(String identifier) {
        checkArgument(!Utils.isNullOrEmpty(identifier));

        this.identifier = identifier;
    }

    public void addTag(String tag) {
        this.tags.add(tag);
    }

    public void addMeta(YaraMeta meta) {
        this.metas.add(meta);
    }

    public void addString(YaraString string) {
        this.strings.add(string);
    }

    @Override
    public String getIdentifier() {
        return identifier;
    }

    @Override
    public Iterator<String> getTags() {
        return tags.iterator();
    }

    @Override
    public Iterator<YaraMeta> getMetadata() {
        return metas.iterator();
    }

    @Override
    public Iterator<YaraString> getStrings() {
        return strings.iterator();
    }
}
