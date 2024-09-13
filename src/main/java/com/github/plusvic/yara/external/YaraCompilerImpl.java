package com.github.plusvic.yara.external;

import com.github.plusvic.yara.*;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.*;
import java.nio.file.attribute.BasicFileAttributes;
import java.util.ArrayList;
import java.util.List;
import java.util.UUID;
import java.util.zip.ZipEntry;
import java.util.zip.ZipInputStream;

import static com.github.plusvic.yara.Preconditions.checkArgument;

public class YaraCompilerImpl implements YaraCompiler {
    private static final Logger logger = LoggerFactory.getLogger(com.github.plusvic.yara.embedded.YaraCompilerImpl.class);

    private YaraCompilationCallback callback;
    private List<Path> packages = new ArrayList<>();
    private YaracExecutable yarac;
    private Path   rules;

    public YaraCompilerImpl() {
        this.rules = null;
        this.yarac = new YaracExecutable();
    }

    @Override
    public void setCallback(YaraCompilationCallback cbk) {
        checkArgument(cbk != null);
        this.callback = cbk;
    }

    @Override
    public void addRulesContent(String content, String namespace) {
        checkArgument(!Utils.isNullOrEmpty(content));

        if (rules != null) {
            // Mimic embedded behavior
            throw new YaraException(ErrorCode.INSUFFICIENT_MEMORY.getValue());
        }

        Path rule = null;
        try {
            String ns = (namespace != null ? namespace : YaracExecutable.GLOBAL_NAMESPACE);
            rule = Files.createTempFile(UUID.randomUUID().toString(), ".yara");

            Files.write(rule, content.getBytes(StandardCharsets.UTF_8), StandardOpenOption.WRITE);
            yarac.addRule(ns, rule);
        } catch (IOException e) {
            logger.warn("Failed to add rule content: {0}", e.getMessage());
            throw new RuntimeException(e);
        } finally {
            // Ensure the temporary file is deleted
            if (rule != null) {
                try {
                    Files.deleteIfExists(rule);
                } catch (IOException e) {
                    logger.warn("Failed to delete temporary rule file: {0}", e.getMessage());
                }
            }
        }
    }

    @Override
    public void addRulesFile(String filePath, String fileName, String namespace) {
        checkArgument(!Utils.isNullOrEmpty(filePath));
        checkArgument(Files.exists(Paths.get(filePath)));

        if (rules != null) {
            // Mimic embedded behavior
            throw new YaraException(ErrorCode.INSUFFICIENT_MEMORY.getValue());
        }

        try {
            String ns = (namespace != null ? namespace : YaracExecutable.GLOBAL_NAMESPACE);
            Path rulePath = Paths.get(filePath);

            // Log information about the rule being added
            logger.debug(String.format("Adding rule file: %s to namespace: %s", filePath, ns));

            // Add the rule using yarac
            yarac.addRule(ns, rulePath);
        } catch (Exception e) {
            logger.warn("Failed to add rules file {}: {}", filePath, e.getMessage());
            throw new RuntimeException(e);
        }
    }

    @Override
    public void addRulesPackage(String packagePath, String namespace) {
        checkArgument(!Utils.isNullOrEmpty(packagePath));
        checkArgument(Files.exists(Paths.get(packagePath)));

        logger.debug(String.format("Loading package: %s", packagePath));

        try {
            Path unpackedFolder = Files.createTempDirectory(UUID.randomUUID().toString());
            packages.add(unpackedFolder);

            try (ZipInputStream zis = new ZipInputStream(new FileInputStream(packagePath))) {

                for (ZipEntry ze = zis.getNextEntry(); ze != null; ze = zis.getNextEntry()) {
                    // Check yara rule
                    String iname = ze.getName().toLowerCase();
                    if (!(iname.endsWith(".yar") || iname.endsWith(".yara") || iname.endsWith(".yr"))) {
                        continue;
                    }

                    // Resolve the normalized path
                    Path resolvedPath = unpackedFolder.resolve(ze.getName()).normalize();

                    // Ensure the resolved path is within the unpacked folder
                    if (!resolvedPath.startsWith(unpackedFolder)) {
                        throw new IOException("Zip entry is outside of the target dir: " + ze.getName());
                    }

                    // Read content
                    logger.debug(String.format("Loading package entry: %s", ze.getName()));
                    File ruleFile = resolvedPath.toFile();

                    new File(ruleFile.getParent()).mkdirs();

                    byte[] buffer = new byte[1024];

                    try (FileOutputStream fos = new FileOutputStream(ruleFile)) {
                        int len;
                        while ((len = zis.read(buffer)) > 0) {
                            fos.write(buffer, 0, len);
                        }
                    }

                    // Load file
                    addRulesFile(ruleFile.toString(), ze.getName(), namespace);
                }

                zis.closeEntry();
                zis.close();
            }

        } catch(IOException ioe) {
            throw new RuntimeException(ioe);
        }
    }

    @Override
    public YaraScanner createScanner() {
        try {
            if (rules == null) {
                rules = yarac.compile(callback);
            }
            return new YaraScannerImpl(rules);
        }
        catch (Exception e) {
            throw new YaraException(e.getMessage());
        }
    }

    @Override
    public void close() throws Exception {
        for (Path p : packages) {
            try {
                Files.walkFileTree(p, new SimpleFileVisitor<Path>() {
                    @Override
                    public FileVisitResult visitFile(Path file, BasicFileAttributes attrs) throws IOException {
                        Files.delete(file);
                        return FileVisitResult.CONTINUE;
                    }

                    @Override
                    public FileVisitResult visitFileFailed(Path file, IOException exc) throws IOException {
                        Files.delete(file);
                        return FileVisitResult.CONTINUE;
                    }

                    @Override
                    public FileVisitResult postVisitDirectory(Path dir, IOException exc) throws IOException {
                        if (exc == null) {
                            Files.delete(dir);
                            return FileVisitResult.CONTINUE;
                        }
                        return FileVisitResult.CONTINUE;
                    }
                });
            }
            catch (IOException ioe) {
                logger.warn(String.format("Failed to delete package %s: %s", p, ioe.getMessage()));
            }
        }
    }
}
