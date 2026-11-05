/*
 * Copyright 2026 the original author or authors.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package org.cloudfoundry.security;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.security.Security;
import java.util.List;
import java.util.function.Supplier;
import java.util.regex.Pattern;

/**
 * Describes, for logging, which system trust store the JVM uses and which certificates the JDK blocks or distrusts.
 */
final class TrustStoreDiagnostics {

    private static final Pattern FINGERPRINT = Pattern.compile("[0-9A-Fa-f]{40,}=?");

    private TrustStoreDiagnostics() {
    }

    // Reports the configuration as set, without interpreting it: the JDK does not expose which store it loaded, and its rules
    // (defaults, empty or special values, store types) are internal. The certificate count shows what was actually loaded.
    static String systemTrustStore() {
        return bestEffort(() -> {
            String store = System.getProperty("javax.net.ssl.trustStore");
            if (store == null) {
                return "default JVM configuration (javax.net.ssl.trustStore not set)";
            }

            String type = System.getProperty("javax.net.ssl.trustStoreType");
            return String.format("default JVM configuration (javax.net.ssl.trustStore=%s, javax.net.ssl.trustStoreType=%s)",
                    store, type != null ? type : "not set");
        });
    }

    static String blocked() {
        return bestEffort(() -> blocked(Paths.get(System.getProperty("java.home", ""), "lib", "security")));
    }

    // Diagnostics must never prevent TLS setup, for example when a SecurityManager denies a property or file read or a path is malformed.
    static String bestEffort(Supplier<String> diagnostic) {
        try {
            return diagnostic.get();
        } catch (SecurityException e) {
            return "unavailable (access denied)";
        } catch (RuntimeException e) {
            return "unavailable (" + e.getClass().getSimpleName() + ")";
        }
    }

    static Supplier<String> safe(Supplier<String> message) {
        return () -> bestEffort(message);
    }

    static String blocked(Path security) {
        String distrust = Security.getProperty("jdk.security.caDistrustPolicies");
        String policies = distrust == null || distrust.isEmpty() ? "none" : distrust;
        Integer count = countBlockedCertificates(security);
        return count == null
                ? String.format("unknown (no readable blocked.certs or blacklisted.certs), caDistrustPolicies=%s", policies)
                : String.format("%d blocked certificates, caDistrustPolicies=%s", count, policies);
    }

    // Java 8 names the file blacklisted.certs; newer JDKs use blocked.certs. Returns null when neither is readable.
    private static Integer countBlockedCertificates(Path security) {
        for (String name : new String[]{"blocked.certs", "blacklisted.certs"}) {
            try {
                List<String> lines = Files.readAllLines(security.resolve(name));
                return (int) lines.stream().filter(TrustStoreDiagnostics::isFingerprintLine).count();
            } catch (IOException e) {
                // try the next name
            }
        }

        return null;
    }

    // The blocklist holds one hex fingerprint per line (optionally with an empty "=" value), mixed with comments and blank lines.
    private static boolean isFingerprintLine(String line) {
        return FINGERPRINT.matcher(line.trim()).matches();
    }

}
