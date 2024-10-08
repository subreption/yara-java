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

import java.io.File;
import java.io.IOException;
import java.io.InputStream;
import java.net.URL;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.nio.file.StandardCopyOption;
import java.nio.file.attribute.PosixFilePermission;
import java.util.ArrayList;
import java.util.HashSet;
import java.util.List;
import java.util.Set;
import java.util.UUID;

import org.fusesource.hawtjni.runtime.Library;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * Native executable dependency
 */
public class NativeExecutable {
    private static final Logger logger = LoggerFactory.getLogger(NativeExecutable.class);
    private static final Set<PosixFilePermission> EXECUTABLE_PERMISSIONS = new HashSet<>();

    static {
        EXECUTABLE_PERMISSIONS.add(PosixFilePermission.GROUP_EXECUTE);
        EXECUTABLE_PERMISSIONS.add(PosixFilePermission.GROUP_READ);
        EXECUTABLE_PERMISSIONS.add(PosixFilePermission.OWNER_EXECUTE);
        EXECUTABLE_PERMISSIONS.add(PosixFilePermission.OWNER_READ);
        EXECUTABLE_PERMISSIONS.add(PosixFilePermission.OWNER_WRITE);
        EXECUTABLE_PERMISSIONS.add(PosixFilePermission.OTHERS_EXECUTE);
        EXECUTABLE_PERMISSIONS.add(PosixFilePermission.OTHERS_READ);
    }

    private final String name;
    private final ClassLoader classLoader;
    private Path localPath;

    public NativeExecutable(String name) {
        this(name, (ClassLoader) null);
    }

    public NativeExecutable(String name, Class<?> clazz) {
        this(name, clazz.getClassLoader());
    }

    public NativeExecutable(String name, ClassLoader classLoader) {
        if (name == null || name.length() == 0) {
            throw new IllegalArgumentException();
        } else {
            this.name = name;
            this.classLoader = classLoader != null ?
                    classLoader :
                    NativeExecutable.class.getClassLoader();
        }
    }

    public synchronized boolean load(String localFallback) {
        if (localFallback != null) {
            Path fallbackPath = Paths.get(localFallback);

            // Check if the path exists and is executable
            if (!Files.exists(fallbackPath)) {
                logger.warn("The fallback path does not exist: " + localFallback);
                return false;
            }

            if (!Files.isExecutable(fallbackPath)) {
                logger.warn("The fallback path is not executable: " + localFallback);
                return false;
            }

            // If the path exists and is executable, set localPath to it
            localPath = fallbackPath;
        }

        if (localPath == null) {
            localPath = doLoad();
        }
        return localPath != null;
    }

    private static String version(Class<?> clazz) {
        try {
            return clazz.getPackage().getImplementationVersion();
        } catch (Throwable var2) {
            return null;
        }
    }

    private static String getEmbeddedPath(String name) {
        String platform = Library.getOperatingSystem();

        if ("osx".equals(platform)) {
            return String.format("META-INF/native/%s/%s", platform, name);
        }

        return String.format("META-INF/native/%s/%s", Library.getPlatform(), name);
    }

    private Path doLoad() {
        String resourcePath = getEmbeddedPath(name);

        try {
            Path tempPath = File.createTempFile(name, Integer.toString(UUID.randomUUID().hashCode())).toPath();

            URL resource = this.classLoader.getResource(resourcePath);
            if (resource != null) {
                try (InputStream is = resource.openStream()) {
                    Files.copy(is, tempPath, StandardCopyOption.REPLACE_EXISTING);
                }
                Files.setPosixFilePermissions(tempPath, EXECUTABLE_PERMISSIONS);

                return tempPath;
            }
        } catch (IOException ioe) {
            logger.warn("Failed to write executable to {0}: {1}", localPath, ioe.toString());
        }

        return null;
    }

    /**
     * Run executable
     *
     * @param args
     * @return
     * @throws Exception
     */
    public Process execute(String... args) throws Exception {
        if (localPath == null) {
            throw new IllegalStateException();
        }

        List<String> command = new ArrayList<>();
        command.add(localPath.toString());

        if (args != null) {
            for (String arg : args) {
                command.add(arg);
            }
        }

        return new ProcessBuilder(command).start();
    }
}
