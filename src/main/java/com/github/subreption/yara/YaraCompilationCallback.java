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

/**
 * Compilation callback
 */
public interface YaraCompilationCallback {
    /**
     * Compilation error level
     */
    enum ErrorLevel {
        ERROR(0),
        WARNING(1);

        private int value;

        ErrorLevel(int value) {
            this.value = value;
        }

        public static ErrorLevel from(int value) {
            for (ErrorLevel t : ErrorLevel.values()) {
                if (t.value == value) {
                    return t;
                }
            }

            throw new IllegalArgumentException();
        }
    }

    /**
     * Compilation error occured
     * @param errorLevel    Error level
     * @param fileName      File name being compiled (empty if string)
     * @param lineNumber    Line number
     * @param message       Error message
     */
    void onError(ErrorLevel errorLevel, String fileName, long lineNumber, String message);
}
