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

import java.io.File;
import java.util.Map;

/**
 * Yara scanner
 */
public interface YaraScanner extends AutoCloseable {
    /**
     * Set scan timeout
     */
    void setTimeout(int timeout);

    /**
     * Set maximum rules to match
     * @param count
     */
    void setMaxRules(int count);

    /**
     * Return only rules that do not match (negate)
     * @param value
     */
    void setNotSatisfiedOnly(boolean value);

    /**
     * Set scan callback
     *
     * @param cbk
     */
    void setCallback(YaraScanCallback cbk);

    /**
     * Scan file
     *
     * @param file File to scan
     */
    void scan(File file);

    /**
     * Scan file
     *
     * @param file
     * @param moduleArgs Module arguments (-x)
     */
    void scan(File file, Map<String, String> moduleArgs);

   /**
     * Scan file
     *
     * @param file
     * @param moduleArgs Module arguments (-x)
     */
    void scan(File file, Map<String, String> moduleArgs, YaraScanCallback cbk);

    /**
     * Scan memory
     *
     * @param buffer
     */
    void scan(byte[] buffer);

    /**
     * Scan memory
     *
     * @param buffer
     * @param moduleArgs Module arguments (-x)
     */
    void scan(byte[] buffer, Map<String, String> moduleArgs);

   /**
     * Scan memory
     *
     * @param buffer
     * @param moduleArgs Module arguments (-x)
     */
    void scan(byte[] buffer, Map<String, String> moduleArgs, YaraScanCallback cbk);

}
