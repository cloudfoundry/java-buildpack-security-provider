/*
 * Copyright 2017-2019 the original author or authors.
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

import org.junit.Test;

import javax.net.ssl.TrustManager;
import java.io.IOException;
import java.lang.reflect.Constructor;
import java.lang.reflect.Method;
import java.net.URL;
import java.net.URLClassLoader;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.cert.CertificateException;
import java.util.ArrayList;
import java.util.List;
import java.util.logging.Level;
import java.util.logging.LogRecord;

import static org.assertj.core.api.Assertions.assertThat;

public final class CloudFoundryContainerTrustManagerFactoryTest extends AbstractLoggingTest {

    @Test
    public void customTrustManager() throws NoSuchProviderException, NoSuchAlgorithmException, CertificateException, KeyStoreException, IOException {
        CloudFoundryContainerTrustManagerFactory.PKIXFactory factory = new CloudFoundryContainerTrustManagerFactory.PKIXFactory(Paths.get("src/test/resources/server-certificates-48.pem"));
        factory.engineInit(getKeyStore());

        TrustManager trustManager = factory.engineGetTrustManagers()[0];
        assertThat(trustManager).isInstanceOf(DelegatingX509ExtendedTrustManager.class);
        assertThat(((DelegatingX509ExtendedTrustManager) trustManager).size()).isEqualTo(2);
    }

    @Test
    public void defaultTrustManagerForNullCertificatesLocation() throws CertificateException, NoSuchAlgorithmException, KeyStoreException, IOException, NoSuchProviderException {
        CloudFoundryContainerTrustManagerFactory.PKIXFactory factory = new CloudFoundryContainerTrustManagerFactory.PKIXFactory(null);
        factory.engineInit(getKeyStore());

        TrustManager trustManager = factory.engineGetTrustManagers()[0];
        assertThat(trustManager).isInstanceOf(DelegatingX509ExtendedTrustManager.class);
        assertThat(((DelegatingX509ExtendedTrustManager) trustManager).size()).isEqualTo(1);
    }

    // Logging the summary at INFO for every factory init (e.g. per new connection) was the problem fixed in #17.
    @Test
    public void logsSummaryAtInfoOnceThenAtFine() throws Exception {
        String store = System.getProperty("javax.net.ssl.trustStore");
        String type = System.getProperty("javax.net.ssl.trustStoreType");
        System.clearProperty("javax.net.ssl.trustStore");
        System.clearProperty("javax.net.ssl.trustStoreType");
        List<LogRecord> records;
        try {
            records = recordSummaryOfTwoInitsInIsolatedClassLoader();
        } finally {
            restoreProperty("javax.net.ssl.trustStore", store);
            restoreProperty("javax.net.ssl.trustStoreType", type);
        }

        // With the default configuration there is no trust store line: only the count and the blocklist.
        assertThat(records).extracting(LogRecord::getMessage).noneMatch(m -> m.startsWith("System trust store:"));
        assertThat(records).extracting(LogRecord::getLevel).containsExactly(Level.INFO, Level.INFO, Level.FINE, Level.FINE);
    }

    @Test
    public void systemSummaryContainsCertificateCount() throws Exception {

        assertThat(recordSystemSummary()).extracting(LogRecord::getMessage).anyMatch(m -> m.matches("Adding System TrustManager \\(PKIX\\) with \\d+ trusted certificates"));
    }

    @Test
    public void logsSuppliedKeyStoreAsSystemTrustStoreSource() throws Exception {
        List<LogRecord> records = LogRecorder.record(CloudFoundryContainerTrustManagerFactory.PKIXFactory.class, () -> {
            CloudFoundryContainerTrustManagerFactory.PKIXFactory factory = new CloudFoundryContainerTrustManagerFactory.PKIXFactory(null);
            factory.engineInit(getKeyStore());
            factory.engineGetTrustManagers();
        });

        assertThat(records).extracting(LogRecord::getMessage).contains("System trust store: KeyStore passed to init");
    }

    @Test
    public void systemTrustStoreSourceIsCapturedAtInit() throws Exception {
        String original = System.getProperty("javax.net.ssl.trustStore");
        String cacerts = Paths.get(System.getProperty("java.home"), "lib", "security", "cacerts").toString();

        List<LogRecord> records = LogRecorder.record(CloudFoundryContainerTrustManagerFactory.PKIXFactory.class, () -> {
            CloudFoundryContainerTrustManagerFactory.PKIXFactory factory = new CloudFoundryContainerTrustManagerFactory.PKIXFactory(null);
            System.setProperty("javax.net.ssl.trustStore", cacerts);
            try {
                factory.engineInit((KeyStore) null);
            } finally {
                restoreProperty("javax.net.ssl.trustStore", original);
            }
            factory.engineGetTrustManagers();
        });

        assertThat(records).extracting(LogRecord::getMessage)
                .contains("System trust store: javax.net.ssl.trustStore=" + cacerts + ", javax.net.ssl.trustStoreType=not set");
    }

    @Test
    public void summaryFailureDoesNotBreakInit() throws Exception {
        String javaHome = System.getProperty("java.home");
        System.setProperty("java.home", "bad\0path");
        try {
            List<LogRecord> records = LogRecorder.record(CloudFoundryContainerTrustManagerFactory.PKIXFactory.class, () -> {
                CloudFoundryContainerTrustManagerFactory.PKIXFactory factory = new CloudFoundryContainerTrustManagerFactory.PKIXFactory(null);
                factory.engineInit((KeyStore) null);
                assertThat(factory.engineGetTrustManagers()).isNotEmpty();
            });

            assertThat(records).extracting(LogRecord::getMessage).contains("Blocked: unavailable (InvalidPathException)");
        } finally {
            System.setProperty("java.home", javaHome);
        }
    }

    // The once-per-JVM state is static, so a fresh class loader gives every run a clean state without test hooks in the main code.
    private List<LogRecord> recordSummaryOfTwoInitsInIsolatedClassLoader() throws Exception {
        URL classes = Paths.get("target/classes").toUri().toURL();
        try (URLClassLoader isolated = new URLClassLoader(new URL[]{classes}, ClassLoader.getSystemClassLoader().getParent())) {
            Class<?> factoryClass = isolated.loadClass(CloudFoundryContainerTrustManagerFactory.PKIXFactory.class.getName());
            Constructor<?> constructor = factoryClass.getDeclaredConstructor(Path.class);
            constructor.setAccessible(true);
            Method init = factoryClass.getSuperclass().getDeclaredMethod("engineInit", KeyStore.class);
            init.setAccessible(true);
            Method getTrustManagers = factoryClass.getSuperclass().getDeclaredMethod("engineGetTrustManagers");
            getTrustManagers.setAccessible(true);

            return filterSummary(LogRecorder.record(CloudFoundryContainerTrustManagerFactory.PKIXFactory.class, () -> {
                for (int i = 0; i < 2; i++) {
                    Object factory = constructor.newInstance((Path) null);
                    init.invoke(factory, new Object[]{null});
                    getTrustManagers.invoke(factory);
                }
            }));
        }
    }

    private static void restoreProperty(String key, String value) {
        if (value == null) {
            System.clearProperty(key);
        } else {
            System.setProperty(key, value);
        }
    }

    private List<LogRecord> recordSystemSummary() throws Exception {
        List<LogRecord> records = LogRecorder.record(CloudFoundryContainerTrustManagerFactory.PKIXFactory.class, () -> {
            CloudFoundryContainerTrustManagerFactory.PKIXFactory factory = new CloudFoundryContainerTrustManagerFactory.PKIXFactory(null);
            factory.engineInit(getKeyStore());
            factory.engineGetTrustManagers();
        });

        return filterSummary(records);
    }

    private static List<LogRecord> filterSummary(List<LogRecord> records) {
        List<LogRecord> summary = new ArrayList<>();
        for (LogRecord record : records) {
            String message = record.getMessage();
            if (message.startsWith("Adding System TrustManager") || message.startsWith("System trust store:")
                    || message.startsWith("Blocked:")) {
                summary.add(record);
            }
        }

        return summary;
    }

    private KeyStore getKeyStore() throws KeyStoreException, CertificateException, NoSuchAlgorithmException, IOException {
        KeyStore keyStore = KeyStore.getInstance(KeyStore.getDefaultType());
        keyStore.load(null);
        return keyStore;
    }

}