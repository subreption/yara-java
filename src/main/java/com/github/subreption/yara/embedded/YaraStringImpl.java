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

import java.util.Iterator;

import com.github.subreption.yara.GenericIterator;
import static com.github.subreption.yara.Preconditions.checkArgument;
import com.github.subreption.yara.YaraMatch;
import com.github.subreption.yara.YaraString;

/**
 * Yara rule strings
 */
public class YaraStringImpl implements YaraString {
    private final YaraLibrary library;
    private final long context;
    private final long peer;

    YaraStringImpl(YaraLibrary library, long context, long peer) {
        checkArgument(library != null);
        checkArgument(context != 0);
        checkArgument(peer != 0);

        this.library = library;
        this.context = context;
        this.peer = peer;
    }

    /**
     * Get identifier
     *
     * @return
     */
    public String getIdentifier() {
        return library.stringIdentifier(peer);
    }

    /**
     * Get matches for the string
     *
     * @return
     */
    public Iterator<YaraMatch> getMatches() {
        return new GenericIterator<YaraMatch>() {
            private long index = library.stringMatches(context, peer);

            @Override
            protected YaraMatchImpl getNext() {
                if (index == 0) {
                    return null;
                }

                long last = index;
                index = library.stringMatchNext(index);

                return new YaraMatchImpl(library, last);
            }
        };
    }
}
