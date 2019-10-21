package com.github.plusvic.yara.external;

import com.github.plusvic.yara.Utils;
import com.github.plusvic.yara.YaraException;
import com.github.plusvic.yara.YaraScanCallback;

import java.io.BufferedReader;
import java.io.File;
import java.io.FileOutputStream;
import java.io.InputStreamReader;
import java.nio.file.Path;
import java.util.*;
import java.util.concurrent.TimeUnit;
import java.util.logging.Level;
import java.util.logging.Logger;

import static com.github.plusvic.yara.Preconditions.checkArgument;

public class YaraExecutable {
    private static final Logger LOGGER = Logger.getLogger(YaraExecutable.class.getName());

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
        this.executable.load();
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
            LOGGER.log(Level.WARNING, "Failed to match rules: {0}", t.getMessage());
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
            LOGGER.log(Level.WARNING, "Failed to match rules: {0}", t.getMessage());
            throw t;
        } finally {
            if (ftmp != null) {
                if (! ftmp.delete()) {
                    LOGGER.log(Level.WARNING, "Failed to delete tmp file {0}", ftmp);
                }
            }
        }
    }

    private void processError(String line) {
        throw new YaraException(line);
    }
}
