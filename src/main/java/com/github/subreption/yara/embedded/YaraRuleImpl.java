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

import com.github.subreption.yara.*;

import java.util.Iterator;

import static com.github.subreption.yara.Preconditions.checkArgument;

/**
 * Yara rule
 */
public class YaraRuleImpl implements YaraRule {
    private final YaraLibrary library;
    private final long context;
    private final long peer;

    YaraRuleImpl(YaraLibrary library, long context, long peer) {
        checkArgument(library != null);
        checkArgument(context != 0);
        checkArgument(peer != 0);

        this.library = library;
        this.context = context;
        this.peer = peer;
    }

    /**
     * Rule identifier
     *
     * @return
     */
    public String getIdentifier() {
        return library.ruleIdentifier(peer);
    }

    /**
     * Rule tags
     *
     * @return
     */
    public Iterator<String> getTags() {
        return new GenericIterator<String>() {
            private long index = library.ruleTags(peer);

            @Override
            protected String getNext() {
                long last = index;
                index = library.ruleTagNext(index);

                if (index == 0 || last == 0) {
                    return null;
                }

                return library.tagString(last);
            }
        };
    }

    /**
     * Rule metadata
     *
     * @return
     */
    public Iterator<YaraMeta> getMetadata() {
        return new GenericIterator<YaraMeta>() {
            private long index = library.ruleMetas(peer);

            @Override
            protected YaraMetaImpl getNext() {
                if (index == 0){
                    return null;
                }

                long last = index;
                index = library.ruleMetaNext(index);

                return new YaraMetaImpl(library, last);
            }
        };
    }

    /**
     * Rule strings
     *
     * @return
     */
    public Iterator<YaraString> getStrings() {
        return new GenericIterator<YaraString>() {
            private long index = library.ruleStrings(peer);

            @Override
            protected YaraStringImpl getNext() {
                if (index == 0){
                    return null;
                }

                long last = index;
                index = library.ruleStringNext(index);

                return new YaraStringImpl(library, context, last);
            }
        };
    }
}
