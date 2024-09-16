package com.github.subreption.yara.external;

import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.FileVisitResult;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.nio.file.SimpleFileVisitor;
import java.nio.file.StandardOpenOption;
import java.nio.file.attribute.BasicFileAttributes;
import java.util.ArrayList;
import java.util.List;
import java.util.UUID;
import java.util.zip.ZipEntry;
import java.util.zip.ZipInputStream;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import com.github.subreption.yara.ErrorCode;
import static com.github.subreption.yara.Preconditions.checkArgument;
import com.github.subreption.yara.Utils;
import com.github.subreption.yara.YaraCompilationCallback;
import com.github.subreption.yara.YaraCompiler;
import com.github.subreption.yara.YaraException;
import com.github.subreption.yara.YaraScanner;

public class YaraCompilerImpl implements YaraCompiler {
    private static final Logger logger = LoggerFactory.getLogger(com.github.subreption.yara.embedded.YaraCompilerImpl.class);

    private YaraCompilationCallback callback;
    private List<Path> packages = new ArrayList<>();
    private YaracExecutable yarac;
    private Path rules;
    private List<Path> tempFiles;

    public YaraCompilerImpl() {
        this.rules = null;
        this.tempFiles = new ArrayList<>();
        this.yarac = new YaracExecutable();
    }

    @Override
    public void setCallback(YaraCompilationCallback cbk) {
        checkArgument(cbk != null);
        this.callback = cbk;
    }

    @Override
    public void addRulesContent(String content, String namespace) {
        Boolean deleteImmediately = false;

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
            logger.debug(String.format("calling addRule: %s", rule.toString()));
            yarac.addRule(ns, rule);
        } catch (IOException e) {
            logger.warn(String.format("IOException while adding rule content: %s", e.getMessage()));
            deleteImmediately = true;
            throw new RuntimeException(e);
        } catch (YaraException e) {
            logger.warn(String.format("YaraException while adding rule content: %s", e.getMessage()));
            deleteImmediately = true;
            throw new RuntimeException(e);
        } finally {
            // Ensure the temporary file is deleted
            if (rule != null) {
                if (deleteImmediately)
                {
                    try {
                        logger.debug(String.format("Deleting %s", rule.toString()));
                        Files.deleteIfExists(rule);
                    } catch (IOException e) {
                        logger.warn(String.format("Failed to delete temporary rule file: %s", e.getMessage()));
                    }
                } else {
                    // Delay deletion on close()
                    tempFiles.add(rule);
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
            logger.error("rules is null");
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
            logger.warn(String.format("Failed to add rules file %s: %s", filePath, e.getMessage()));
            throw new RuntimeException(e);
        }
    }

    @Override
    public void addRulesPackage(String packagePath, String namespace) {
        checkArgument(!Utils.isNullOrEmpty(packagePath));
        checkArgument(Files.exists(Paths.get(packagePath)));

        logger.info("Loading package: " + packagePath);

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
                        logger.error("Zip entry is outside of the target dir: " + ze.getName());
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

        // Iterate through the list of paths and delete files if they exist
        for (Path path : tempFiles) {
            try {
                if (Files.exists(path)) {
                    Files.delete(path);
                    logger.debug(String.format("Deleted %s", path.toString()));
                }
            } catch (IOException e) {
                logger.warn(String.format("Failed to delete %s: %s", path.toString(), e.getMessage()));
            }
        }
    }
}
