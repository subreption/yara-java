package com.github.subreption.yara.external;

import java.io.BufferedReader;
import java.io.File;
import java.io.InputStreamReader;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.UUID;
import java.util.concurrent.TimeUnit;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import static com.github.subreption.yara.Preconditions.checkArgument;
import com.github.subreption.yara.Utils;
import com.github.subreption.yara.YaraCompilationCallback;

/**
 * User: pba
 * Date: 6/15/15
 * Time: 9:50 AM
 */
public class YaracExecutable {
    private static final Logger logger = LoggerFactory.getLogger(YaracExecutable.class);

    public static final String GLOBAL_NAMESPACE = "";

    private int timeout = 60;
    private NativeExecutable executable;
    private Map<String, Set<Path>> rules = new HashMap<>();

    public YaracExecutable() {
        this.executable = YaraExecutableManager.getYarac();
    }

    public YaracExecutable(NativeExecutable executable) {
        if (executable == null) {
            throw new IllegalArgumentException();
        }
        this.executable = executable;
        String yaracBinaryPath = System.getenv("YARAC_BINARY_PATH");
        this.executable.load(yaracBinaryPath);
    }


    public YaracExecutable addRule(Path file) {
        return addRule(GLOBAL_NAMESPACE, file);
    }

    public YaracExecutable addRule(String namespace, Path file) {
        if (namespace == null || !Utils.exists(file)) {
            throw new IllegalArgumentException();
        }

        Set<Path> paths = rules.get(namespace);
        if (paths == null) {
            paths = new HashSet<>();
            rules.put(namespace, paths);
        }

        logger.debug(String.format("Adding rule from %s", file));
        paths.add(file);

        return this;
    }

    public YaracExecutable setTimeout(int timeout) {
        checkArgument(timeout > 0);
        this.timeout = timeout;

        return this;
    }

    private String[] getCommandLine(Path output) {
        List<String> args = new ArrayList<>();

        for (Map.Entry<String, Set<Path>> kv : rules.entrySet()) {
            for (Path path : kv.getValue()) {
                String prefix = Utils.isNullOrEmpty(kv.getKey()) ?
                        "" : kv.getKey() + ":";
                args.add(prefix + path.toAbsolutePath().toString());
            }
        }

        args.add(output.toAbsolutePath().toString());

        return args.toArray(new String[args.size()]);
    }

    public Path compile(YaraCompilationCallback callback) throws Exception {
        if (callback == null) {
            logger.error("compiler called with no callback defined!");
            throw new IllegalArgumentException();
        }

        try {
            Path output = File.createTempFile(UUID.randomUUID().toString(), Utils.compiledRuleIdentifier).toPath();

            Process process = executable.execute(getCommandLine(output));
            process.waitFor(timeout, TimeUnit.SECONDS);

            try (BufferedReader pout = new BufferedReader(new InputStreamReader(process.getInputStream()));
                 BufferedReader perr = new BufferedReader(new InputStreamReader(process.getErrorStream()))) {
                String line;
                while (null != (line = perr.readLine())) {
                    processError(callback, line);
                }
                while (null != (line = pout.readLine())) {
                    logger.debug(line);
                }
            }

            return output;
        } catch (Throwable t) {
            logger.warn(String.format("Failed to compile rules: %s", t.toString()));
            throw t;
        }
    }

    private void processError(YaraCompilationCallback callback, String line) {
        int lineNumber = 0;
        String filename = null;
        StringBuffer temp = new StringBuffer();
        YaraCompilationCallback.ErrorLevel level = YaraCompilationCallback.ErrorLevel.WARNING;

        /**
         * 0 - reading file
         * 1 - reading line
         * 2 - reading level
         * 3 - reading message
         */
        int state = 0;

        for (int i = 0; i < line.length(); ++i) {
            Character c = line.charAt(i);

            switch (state) {
                case 0:
                    if (c == '(') {
                        filename = temp.toString().trim();
                        temp = new StringBuffer();
                        state = 1;
                    } else {
                        temp.append(c);
                    }
                    break;
                case 1:
                    if (c == ')')
                        break;
                    if (c == ':') {
                        lineNumber = Integer.valueOf(temp.toString().trim());
                        temp = new StringBuffer();
                        state = 2;
                    } else {
                        temp.append(c);
                    }
                    break;
                case 2:
                    if (c == ':') {
                        String v = temp.toString().trim().toLowerCase();
                        if (v.startsWith("err")) {
                            level = YaraCompilationCallback.ErrorLevel.ERROR;
                        } else {
                            level = YaraCompilationCallback.ErrorLevel.WARNING;
                        }
                        state = 3;
                    } else {
                        temp.append(c);
                    }
                    break;
                case 3:
                default:
                    temp.append(c);
                    break;
            }
        }

        logger.warn(String.format("Compilation failed at line %d in %s: %s", lineNumber, filename, temp.toString().trim()));

        callback.onError(level, filename, lineNumber, temp.toString().trim());
    }
}
