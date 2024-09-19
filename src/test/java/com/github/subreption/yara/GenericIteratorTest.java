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

package com.github.subreption.yara;

import java.util.NoSuchElementException;
import java.util.UUID;

import org.junit.jupiter.api.Assertions;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertTrue;
import org.junit.jupiter.api.Test;

/**
 * User: pba
 * Date: 6/12/15
 * Time: 10:43 AM
 */
public class GenericIteratorTest {
    @Test
    public void testEmpty() {
        GenericIterator<String> it = new GenericIterator<String>() {
            @Override
            protected String getNext() {
                return null;
            }
        };
        assertFalse(it.hasNext());
    }

    @Test
    public void testOne() {
        GenericIterator<String> it = new GenericIterator<String>() {
            private boolean used = false;

            @Override
            protected String getNext() {
                if (!used) {
                    used = true;
                    return UUID.randomUUID().toString();
                }
                return null;
            }
        };
        assertTrue(it.hasNext());
        assertNotNull(it.next());
        assertFalse(it.hasNext());
    }

    @Test
    public void testTwo() {
        GenericIterator<String> it = new GenericIterator<String>() {
            private String values[] = new String[] { "one", "two"};
            private int pos = 0;

            @Override
            protected String getNext() {
                if (pos  < values.length) {
                    return values[pos++];
                }
                return null;
            }
        };

        assertTrue(it.hasNext());
        assertNotNull(it.next());
        assertTrue(it.hasNext());
        assertNotNull(it.next());
        assertFalse(it.hasNext());
    }

    @Test
    public void testN() {
        final int size = 10;

        GenericIterator<String> it = new GenericIterator<String>() {
            private String values[];
            private int pos = 0;

            @Override
            protected String getNext() {
                if (values == null) {
                    values = new String[size];
                    for (int i = 0; i < size; ++i) {
                        values[i] = UUID.randomUUID().toString();
                    }
                }
                if (pos  < values.length) {
                    return values[pos++];
                }
                return null;
            }
        };

        int count = 0;
        while (it.hasNext()) {
            count++;
            assertNotNull(it.next());
        }

        assertEquals(size, count);
    }

    @Test
    public void testNextFirst() {
        GenericIterator<String> it = new GenericIterator<String>() {
            private boolean used = false;

            @Override
            protected String getNext() {
                if (!used) {
                    used = true;
                    return UUID.randomUUID().toString();
                }
                return null;
            }
        };

        assertNotNull(it.next());
        Assertions.assertThrows(NoSuchElementException.class, it::next);
    }

    @Test
    public void testNextFirstMultiple() {
        GenericIterator<String> it = new GenericIterator<String>() {
            private final String[] values = new String[] { "one", "two"};
            private int pos = 0;

            @Override
            protected String getNext() {
                if (pos  < values.length) {
                    return values[pos++];
                }
                return null;
            }
        };

        assertNotNull(it.next());
        assertNotNull(it.next());
        assertFalse(it.hasNext());
    }
}
