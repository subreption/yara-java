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

import java.nio.file.Files;
import java.nio.file.Path;

public class Utils {
    /**
     * Check string is null or empty
     *
     * @param value
     * @return
     */
    public static boolean isNullOrEmpty(String value) {
        return (value == null || value.length() <= 0) ? true : false;
    }

    /**
     * Check path exists
     *
     * @param value
     * @return
     */
    public static boolean exists(Path value) {
        return (value == null || !Files.exists(value)) ? false : true;
    }

    /**
     * Unescape string
     *
     * @param value
     * @return
     */
    public static String unescape(String value) {
        if (value == null || value.length() == 0) {
            return value;
        }

        StringBuffer buffer = new StringBuffer();

        int pos = 0, max = value.length();

        while (pos < max) {
            Character current = (Character) value.charAt(pos);

            if (current == '\\' && (pos + 1) < max) {
                switch (value.charAt(pos + 1)) {
                    case '\"':
                        buffer.append('\"');
                        pos += 2;
                        break;
                    case '\'':
                        buffer.append('\'');
                        pos += 2;
                        break;
                    case '\\':
                        buffer.append('\\');
                        pos += 2;
                        break;
                    case '\n':
                        buffer.append('\n');
                        pos += 2;
                        break;
                    case '\t':
                        buffer.append('\t');
                        pos += 2;
                        break;
                    default:
                        buffer.append(current);
                        pos++;
                        break;
                }
            } else {
                buffer.append(current);
                pos++;
            }
        }


        return buffer.toString();
    }

    public static String compiledRuleIdentifier = "yaracc";
}
