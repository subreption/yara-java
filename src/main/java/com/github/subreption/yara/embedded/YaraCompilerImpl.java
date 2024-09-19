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
import org.fusesource.hawtjni.runtime.Callback;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStreamReader;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.util.Enumeration;
import java.util.zip.ZipEntry;
import java.util.zip.ZipFile;

import static com.github.subreption.yara.Preconditions.checkArgument;
import static com.github.subreption.yara.Preconditions.checkState;

/**
 * Yara compiler
 */
public class YaraCompilerImpl implements YaraCompiler {
    private static final Logger logger = LoggerFactory.getLogger(com.github.subreption.yara.embedded.YaraCompilerImpl.class);


    /**
     * Native compilation callback wrapper
     */
    private class NativeCompilationCallback {
        private final YaraLibrary library;
        private final YaraCompilationCallback callback;

        public NativeCompilationCallback(YaraLibrary library, YaraCompilationCallback callback) {
            this.library = library;
            this.callback = callback;
        }

        long nativeOnError(long errorLevel, long fileName, long lineNumber, long rule, long message, long data) {
            callback.onError(YaraCompilationCallback.ErrorLevel.from((int) errorLevel),
                    library.toString(fileName),
                    lineNumber,
                    library.toString(message));
            return 0;
        }
    }

    private YaraLibrary library;
    private long        peer;
    private Callback    callback;

    YaraCompilerImpl(YaraLibrary library, long compiler) {
        checkArgument(library != null);
        checkArgument(compiler != 0);

        this.library = library;
        this.peer = compiler;
    }

    @Override
    protected void finalize() throws Throwable {
        close();
        super.finalize();
    }

    /**
     * Set compilation callback
     * @param cbk
     */
    public void setCallback(YaraCompilationCallback cbk) {
        checkArgument(cbk != null);
        checkState(callback == null);

        callback = new Callback(new NativeCompilationCallback(library, cbk), "nativeOnError", 6);
        final long callBackAddress = callback.getAddress();
        if(callBackAddress == 0) {
          throw new IllegalStateException("Too many concurent callbacks, unable to create.");
        }
        library.compilerSetCallback(peer, callBackAddress, 0);
    }

    /**
     * Release compiler instance
     * @throws Exception
     */
    public void close() throws Exception {
        if (callback != null) {
            callback.dispose();
            callback = null;
        }

        if (peer != 0) {
            library.compilerDestroy(peer);
            peer = 0;
        }

        library = null;
    }

    /**
     * Add rules content
     * @param content
     * @param namespace
     * @return
     */
    public void addRulesContent(String content, String namespace) {
        int ret  = library.compilerAddString(peer, content, namespace);
        if (ret != ErrorCode.SUCCESS.getValue()) {
            throw new YaraException(ret);
        }
    }

    /** Add rules file
     * @param filePath
     * @param fileName
     * @param namespace
     */
    public void addRulesFile(String filePath, String fileName, String namespace) {
        int ret  = library.compilerAddFile(peer, filePath, namespace, fileName);
        if (ret != ErrorCode.SUCCESS.getValue()) {
            throw new YaraException(ret);
        }
    }

    /**
     * Add rules from package
     * @param packagePath
     * @param namespace
     */
    @Override
    public void addRulesPackage(String packagePath, String namespace) {
        checkArgument(!Utils.isNullOrEmpty(packagePath));
        checkArgument(Files.exists(Paths.get(packagePath)));

        logger.info("Loading package: " + packagePath);

        try (ZipFile zf = new ZipFile(packagePath)) {

            for (Enumeration e = zf.entries(); e.hasMoreElements();) {
                ZipEntry entry = (ZipEntry) e.nextElement();

                // Check yara rule
                String iname = entry.getName().toLowerCase();
                if (!(iname.endsWith(".yar") || iname.endsWith(".yara") || iname.endsWith(".yr"))) {
                    continue;
                }

                // Read content
                logger.debug("Loading package entry: " + entry.getName());
                StringBuilder content = new StringBuilder();

                try (BufferedReader bsr = new BufferedReader(new InputStreamReader(zf.getInputStream(entry)))) {
                    String line;

                    while (null != (line = bsr.readLine())) {
                        content.append(line).append("\n");
                    }
                }

                // Add content
                addRulesContent(content.toString(), namespace);
            }
        }
        catch (IOException ioe) {
            throw new RuntimeException("Failed to load rule package", ioe);
        }
        catch(YaraException yex) {
            throw yex;
        }
    }

    /**
     * Create scanner
     * @return
     */
    public YaraScanner createScanner() {
        int ret = 0;

        long rules[] = new long[1];
        if (0 != (ret = library.compilerGetRules(peer, rules))) {
            throw new YaraException(ret);
        }

        return new YaraScannerImpl(library, rules[0]);
    }
}
