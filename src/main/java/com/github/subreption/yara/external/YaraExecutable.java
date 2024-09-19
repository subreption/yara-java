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

import java.io.BufferedReader;
import java.io.File;
import java.io.FileOutputStream;
import java.io.InputStreamReader;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.concurrent.TimeUnit;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import static com.github.subreption.yara.Preconditions.checkArgument;
import com.github.subreption.yara.Utils;
import com.github.subreption.yara.YaraException;
import com.github.subreption.yara.YaraScanCallback;

public class YaraExecutable {
    private static final Logger logger = LoggerFactory.getLogger(YaraExecutable.class);

    private int timeout = 60;
    private boolean negate = false;
    private int maxRules = 0;
    private NativeExecutable executable;
    private Set<Path> rules = new HashSet<>();

    public YaraExecutable() {
        this.executable = YaraExecutableManager.getYara();
    }

    public YaraExecutable(NativeExecutable executable) {
        if (executable == null) {
            throw new IllegalArgumentException();
        }
        this.executable = executable;
        String yaraBinaryPath = System.getenv("YARA_BINARY_PATH");
        this.executable.load(yaraBinaryPath);
    }

    public YaraExecutable addRule(Path file) {
        if (!Utils.exists(file)) {
            throw new IllegalArgumentException();
        }

        rules.add(file);
        return this;
    }

    public YaraExecutable setTimeout(int timeout) {
        checkArgument(timeout > 0);
        this.timeout = timeout;

        return this;
    }

    public YaraExecutable setMaxRules(int count) {
        checkArgument(count > 0);
        this.maxRules = count;

        return this;
    }

    public YaraExecutable setNegate(boolean value) {
        this.negate = value;
        return this;
    }

    private String[] getCommandLine(Path target, Map<String, String> moduleArgs) {
        List<String> args = new ArrayList<>();
        args.add("-g"); // tags
        args.add("-m"); // meta
        args.add("-s"); // strings

        if (negate) {
            args.add("-n");
        }

        if (maxRules > 0) {
            args.add("-l");
            args.add(Integer.toString(maxRules));
        }

        // module initialization
        if (moduleArgs != null && moduleArgs.size() > 0) {
            moduleArgs.forEach( (k, v) -> {
                args.add("-x");
                args.add(String.format("%s=%s", k, v));
            });
        }

        // rules
        if (rules.size() == 1 && rules.iterator().next().toAbsolutePath().toString().endsWith(Utils.compiledRuleIdentifier)) {
            // -C flag is required when scanning with a compiled rule
            args.add("-C");
        }

        for (Path path : rules) {
            args.add(path.toAbsolutePath().toString());
        }

        // sample
        args.add(target.toAbsolutePath().toString());

        return args.toArray(new String[]{});
    }

    public boolean match(Path target, Map<String, String> moduleArgs, YaraScanCallback callback) throws Exception {
        if (target == null || callback == null) {
            throw new IllegalArgumentException();
        }

        try {
            Process process = executable.execute(getCommandLine(target, moduleArgs));
            process.waitFor(timeout, TimeUnit.SECONDS);

            try (BufferedReader pout = new BufferedReader(new InputStreamReader(process.getInputStream()));
                 BufferedReader perr  = new BufferedReader(new InputStreamReader(process.getErrorStream())))
            {
                String line;
                while(null != (line = perr.readLine())) {
                    processError(line);
                }

                YaraOutputProcessor outputProcessor = new YaraOutputProcessor(callback);

                outputProcessor.onStart();
                while (null != (line = pout.readLine())) {
                    outputProcessor.onLine(line);
                }
                outputProcessor.onComplete();
            }

            return true;
        }
        catch (Throwable t) {
            logger.warn(String.format("Failed to match rules: %s", t.getMessage()));
            throw t;
        }
    }

    public boolean match(byte buffer[], Map<String, String> moduleArgs, YaraScanCallback callback) throws Exception {
        if (buffer == null || callback == null) {
            throw new IllegalArgumentException();
        }

        File ftmp = File.createTempFile("yara-",".dat");
        try (FileOutputStream fos = new FileOutputStream(ftmp)) {
            fos.write(buffer);
        }

        Path target = ftmp.toPath();
        try {
            Process process = executable.execute(getCommandLine(target, moduleArgs));
            process.waitFor(timeout, TimeUnit.SECONDS);

            try (BufferedReader pout = new BufferedReader(new InputStreamReader(process.getInputStream()));
                 BufferedReader perr  = new BufferedReader(new InputStreamReader(process.getErrorStream())))
            {
                String line;
                while(null != (line = perr.readLine())) {
                    processError(line);
                }

                YaraOutputProcessor outputProcessor = new YaraOutputProcessor(callback);

                outputProcessor.onStart();
                while (null != (line = pout.readLine())) {
                    outputProcessor.onLine(line);
                }
                outputProcessor.onComplete();
            }

            return true;
        }
        catch (Throwable t) {
            logger.warn(String.format("Failed to match rules: %s", t.getMessage()));
            throw t;
        } finally {
            if (ftmp != null) {
                if (! ftmp.delete()) {
                    logger.warn(String.format("Failed to delete tmp file %s", ftmp));
                }
            }
        }
    }

    private void processError(String line) {
        throw new YaraException(line);
    }
}
