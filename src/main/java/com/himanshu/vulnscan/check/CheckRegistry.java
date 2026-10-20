package com.himanshu.vulnscan.check;

import com.himanshu.vulnscan.check.builtin.AnonymousFtpCheck;
import com.himanshu.vulnscan.check.builtin.BlueKeepCheck;
import com.himanshu.vulnscan.check.builtin.DefaultCredsCheck;
import com.himanshu.vulnscan.check.builtin.DirectoryListingCheck;
import com.himanshu.vulnscan.check.builtin.HttpSecurityHeadersCheck;
import com.himanshu.vulnscan.check.builtin.Log4ShellCheck;
import com.himanshu.vulnscan.check.builtin.MongoOpenCheck;
import com.himanshu.vulnscan.check.builtin.RedisUnauthCheck;
import com.himanshu.vulnscan.check.builtin.SshWeakAlgoCheck;
import com.himanshu.vulnscan.check.builtin.SslTlsCheck;
import com.himanshu.vulnscan.model.Finding;
import com.himanshu.vulnscan.model.ServiceFingerprint;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.IOException;
import java.net.URL;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.util.*;
import java.util.concurrent.ConcurrentHashMap;
import java.util.jar.JarFile;
import java.util.stream.Collectors;
import java.util.stream.Stream;

public final class CheckRegistry {

    private static final Logger log = LoggerFactory.getLogger(CheckRegistry.class);

    private final Map<String, VulnerabilityCheck> checks = new ConcurrentHashMap<>();
    private final Set<String> enabledChecks = ConcurrentHashMap.newKeySet();
    private final Set<String> disabledChecks = ConcurrentHashMap.newKeySet();

    public CheckRegistry() {
        loadBuiltInChecks();
        loadExternalChecks();
    }

    private void loadBuiltInChecks() {
        register(new Log4ShellCheck());
        register(new BlueKeepCheck());
        register(new AnonymousFtpCheck());
        register(new DefaultCredsCheck());
        register(new RedisUnauthCheck());
        register(new MongoOpenCheck());
        register(new SslTlsCheck());
        register(new SshWeakAlgoCheck());
        register(new HttpSecurityHeadersCheck());
        register(new DirectoryListingCheck());

        log.info("Loaded {} built-in vulnerability checks", checks.size());
    }

    private void loadExternalChecks() {
        String userHome = System.getProperty("user.home");
        Path checksDir = Paths.get(userHome, ".vulnscan", "checks");

        if (!Files.exists(checksDir)) {
            return;
        }

        try (Stream<Path> jars = Files.list(checksDir).filter(p -> p.toString().endsWith(".jar"))) {
            jars.forEach(this::loadChecksFromJar);
        } catch (IOException e) {
            log.warn("Failed to load external checks: {}", e.getMessage());
        }
    }

    private void loadChecksFromJar(Path jarPath) {
        try (JarFile jar = new JarFile(jarPath.toFile())) {
            URL[] urls = {jarPath.toUri().toURL()};
            var loader = new java.net.URLClassLoader(urls, getClass().getClassLoader());

            var services = loader.getResources("META-INF/services/com.himanshu.vulnscan.check.VulnerabilityCheck");
            while (services.hasMoreElements()) {
                URL url = services.nextElement();
                try (var reader = new java.io.BufferedReader(
                        new java.io.InputStreamReader(url.openStream(), StandardCharsets.UTF_8))) {
                    String line;
                    while ((line = reader.readLine()) != null) {
                        line = line.trim();
                        if (!line.isEmpty() && !line.startsWith("#")) {
                            try {
                                Class<?> clazz = loader.loadClass(line);
                                if (VulnerabilityCheck.class.isAssignableFrom(clazz)) {
                                    VulnerabilityCheck check = (VulnerabilityCheck) clazz.getDeclaredConstructor().newInstance();
                                    register(check);
                                    log.info("Loaded external check: {} from {}", check.metadata().id(), jarPath.getFileName());
                                }
                            } catch (ReflectiveOperationException | RuntimeException e) {
                                log.warn("Failed to load check class {}: {}", line, e.getMessage());
                            }
                        }
                    }
                }
            }
        } catch (IOException e) {
            log.warn("Failed to load checks from {}: {}", jarPath, e.getMessage());
        }
    }

    public void register(VulnerabilityCheck check) {
        String id = check.metadata().id();
        if (checks.containsKey(id)) {
            log.warn("Check {} already registered, skipping", id);
            return;
        }
        checks.put(id, check);
        enabledChecks.add(id);
    }

    public void unregister(String checkId) {
        checks.remove(checkId);
        enabledChecks.remove(checkId);
        disabledChecks.remove(checkId);
    }

    public void enableCheck(String checkId) {
        if (checks.containsKey(checkId)) {
            enabledChecks.add(checkId);
            disabledChecks.remove(checkId);
        }
    }

    public void disableCheck(String checkId) {
        enabledChecks.remove(checkId);
        disabledChecks.add(checkId);
    }

    public void enableOnly(Collection<String> checkIds) {
        enabledChecks.clear();
        enabledChecks.addAll(checkIds);
    }

    public void disableAll(Collection<String> checkIds) {
        disabledChecks.addAll(checkIds);
        enabledChecks.removeAll(checkIds);
    }

    public List<VulnerabilityCheck> getEnabledChecks() {
        return enabledChecks.stream()
                .map(checks::get)
                .filter(Objects::nonNull)
                .filter(VulnerabilityCheck::isEnabled)
                .toList();
    }

    public List<VulnerabilityCheck> getAllChecks() {
        return new ArrayList<>(checks.values());
    }

    public Optional<VulnerabilityCheck> getCheck(String checkId) {
        return Optional.ofNullable(checks.get(checkId));
    }

    public List<Finding> executeChecks(ServiceFingerprint fingerprint) {
        return getEnabledChecks().stream()
                .filter(check -> check.matches(fingerprint))
                .flatMap(check -> check.execute(fingerprint).stream())
                .toList();
    }

    public Map<String, VulnerabilityCheck> getChecksByTag(String tag) {
        return checks.entrySet().stream()
                .filter(e -> e.getValue().metadata().tags().contains(tag))
                .collect(Collectors.toMap(Map.Entry::getKey, Map.Entry::getValue));
    }

    public int getTotalCount() { return checks.size(); }
    public int getEnabledCount() { return enabledChecks.size(); }
    public int getDisabledCount() { return disabledChecks.size(); }
}
