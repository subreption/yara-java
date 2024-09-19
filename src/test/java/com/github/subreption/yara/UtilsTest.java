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

import static org.junit.jupiter.api.Assertions.assertEquals;
import org.junit.jupiter.api.Test;


/**
 * User: pba
 * Date: 6/16/15
 * Time: 5:17 PM
 */
public class UtilsTest {
    @Test
    public void testUnescapeEmpty() {
        String value = "";
        assertEquals(value, Utils.unescape(value));
    }
    @Test
    public void testUnescapeNull() {
        String value = null;
        assertEquals(value, Utils.unescape(value));
    }
    @Test
    public void testUnescapeClean() {
        String value = "123123 1231ad   112312 1230ipokxlcmzlkdcm928349082fnsdkfnjkshdf";
        assertEquals(value, Utils.unescape(value));
    }

    @Test
    public void testUnescapeSlash() {
        String value = "123\\\\123";
        assertEquals("123\\123", Utils.unescape(value));
    }
    @Test
    public void testUnescapeDoubleQuote() {
        String value = "123\\\"123";
        assertEquals("123\"123", Utils.unescape(value));
    }
    @Test
    public void testUnescapeQuote() {
        String value = "123\\\'123";
        assertEquals("123\'123", Utils.unescape(value));
    }
    @Test
    public void testUnescapeTab() {
        String value = "123\\\t123";
        assertEquals("123\t123", Utils.unescape(value));
    }
    @Test
    public void testUnescapeNewline() {
        String value = "123\\\n123";
        assertEquals("123\n123", Utils.unescape(value));
    }
}
