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

import javax.net.ssl.KeyManagerFactory;
import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.nio.file.StandardCopyOption;
import java.security.NoSuchAlgorithmException;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.time.Instant;
import java.util.Collections;
import java.util.List;
import java.util.concurrent.atomic.AtomicReference;
import java.util.logging.Level;
import java.util.logging.LogRecord;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.assertj.core.api.Assertions.fail;

// The client-certificates-*.pem fixtures are Diego-issued and expired in 2017 (CA in 2018). That is fine: loading and
// matching never check validity dates, only a TLS handshake would. The expired-chain warning is logged but not asserted.
public final class FileWatchingX509ExtendedKeyManagerTest extends AbstractLoggingTest {

    @Test
    public void initializedWithWatchedFile() throws IOException, NoSuchAlgorithmException {
        Path watchedCertificates = getWatchedCertificatesFile();
        Files.copy(Paths.get("src/test/resources/client-certificates-1.pem"), watchedCertificates);

        Path watchedPrivateKey = getWatchedPrivateKeyFile();
        Files.copy(Paths.get("src/test/resources/client-private-key-1.pem"), watchedPrivateKey);

        FileWatchingX509ExtendedKeyManager keyManager = new FileWatchingX509ExtendedKeyManager(watchedCertificates, watchedPrivateKey, KeyManagerFactory.getInstance("SunX509"));

        assertThat(keyManager.getClientAliases("RSA", null)).hasSize(1);
    }

    @Test
    public void watchesWatchedFile() throws IOException, InterruptedException, NoSuchAlgorithmException {
        Path watchedCertificates = getWatchedCertificatesFile();
        Files.copy(Paths.get("src/test/resources/client-certificates-1.pem"), watchedCertificates);

        Path watchedPrivateKey = getWatchedPrivateKeyFile();
        Files.copy(Paths.get("src/test/resources/client-private-key-1.pem"), watchedPrivateKey);

        FileWatchingX509ExtendedKeyManager keyManager = new FileWatchingX509ExtendedKeyManager(watchedCertificates, watchedPrivateKey, KeyManagerFactory.getInstance("SunX509"));

        String alias = keyManager.getClientAliases("RSA", null)[0];

        Thread.sleep(5_000);
        // Same as Diego: each file is replaced atomically, as a rename, the private key before the certificate,
        // so no update sees a half-written file.
        replace(Paths.get("src/test/resources/client-private-key-2.pem"), watchedPrivateKey);
        replace(Paths.get("src/test/resources/client-certificates-2.pem"), watchedCertificates);

        long timeout = System.currentTimeMillis() + 30_000;
        for (; ; ) {
            if (System.currentTimeMillis() > timeout) {
                fail("Failed to update within timeout");
            }

            if (!keyManager.getClientAliases("RSA", null)[0].equals(alias)) {
                return;
            }

            Thread.sleep(1_000);
        }
    }

    @Test
    public void initializedWithWarningWhenPrivateKeyDoesNotMatchCertificate() throws Exception {
        Path watchedCertificates = getWatchedCertificatesFile();
        Files.copy(Paths.get("src/test/resources/client-certificates-2.pem"), watchedCertificates);

        Path watchedPrivateKey = getWatchedPrivateKeyFile();
        Files.copy(Paths.get("src/test/resources/client-private-key-1.pem"), watchedPrivateKey);

        AtomicReference<FileWatchingX509ExtendedKeyManager> keyManager = new AtomicReference<>();
        List<LogRecord> records = LogRecorder.record(FileWatchingX509ExtendedKeyManager.class, () ->
            keyManager.set(new FileWatchingX509ExtendedKeyManager(watchedCertificates, watchedPrivateKey, KeyManagerFactory.getInstance("SunX509"))));

        assertThat(keyManager.get().getClientAliases("RSA", null)).hasSize(1);
        assertThat(records).filteredOn(r -> r.getLevel() == Level.WARNING && r.getMessage().startsWith("Private key " + watchedPrivateKey + " does not match certificate"))
            .hasSize(1);
    }

    @Test
    public void initializationFailsWhenCertificatesAreEmpty() throws IOException {
        Path watchedCertificates = getWatchedCertificatesFile();
        Files.write(watchedCertificates, new byte[0]);

        Path watchedPrivateKey = getWatchedPrivateKeyFile();
        Files.copy(Paths.get("src/test/resources/client-private-key-1.pem"), watchedPrivateKey);

        assertThatThrownBy(() -> new FileWatchingX509ExtendedKeyManager(watchedCertificates, watchedPrivateKey, KeyManagerFactory.getInstance("SunX509")))
            .isInstanceOf(IllegalArgumentException.class);
    }

    @Test
    public void updatesWhenPrivateKeyMatchesCertificate() throws IOException, CertificateException, NoSuchAlgorithmException {
        Path watchedCertificates = getWatchedCertificatesFile();
        Files.copy(Paths.get("src/test/resources/client-certificates-1.pem"), watchedCertificates);

        Path watchedPrivateKey = getWatchedPrivateKeyFile();
        Files.copy(Paths.get("src/test/resources/client-private-key-1.pem"), watchedPrivateKey);

        FileWatchingX509ExtendedKeyManager keyManager = new FileWatchingX509ExtendedKeyManager(watchedCertificates, watchedPrivateKey, KeyManagerFactory.getInstance("SunX509"));

        Files.copy(Paths.get("src/test/resources/client-private-key-2.pem"), watchedPrivateKey, StandardCopyOption.REPLACE_EXISTING);
        Files.copy(Paths.get("src/test/resources/client-certificates-2.pem"), watchedCertificates, StandardCopyOption.REPLACE_EXISTING);
        keyManager.update();

        assertThat(getLeafCertificate(keyManager)).isEqualTo(X509CertificateFactory.generate(Paths.get("src/test/resources/client-certificates-2.pem")).get(0));
    }

    @Test
    public void keepsCurrentWhenPrivateKeyDoesNotMatchCertificate() throws IOException, CertificateException, NoSuchAlgorithmException {
        Path watchedCertificates = getWatchedCertificatesFile();
        Files.copy(Paths.get("src/test/resources/client-certificates-1.pem"), watchedCertificates);

        Path watchedPrivateKey = getWatchedPrivateKeyFile();
        Files.copy(Paths.get("src/test/resources/client-private-key-1.pem"), watchedPrivateKey);

        FileWatchingX509ExtendedKeyManager keyManager = new FileWatchingX509ExtendedKeyManager(watchedCertificates, watchedPrivateKey, KeyManagerFactory.getInstance("SunX509"));

        Files.copy(Paths.get("src/test/resources/client-certificates-2.pem"), watchedCertificates, StandardCopyOption.REPLACE_EXISTING);
        keyManager.update();

        assertThat(getLeafCertificate(keyManager)).isEqualTo(X509CertificateFactory.generate(Paths.get("src/test/resources/client-certificates-1.pem")).get(0));
    }

    @Test
    public void keepsCurrentWhenCertificatesAreEmpty() throws IOException, CertificateException, NoSuchAlgorithmException {
        Path watchedCertificates = getWatchedCertificatesFile();
        Files.copy(Paths.get("src/test/resources/client-certificates-1.pem"), watchedCertificates);

        Path watchedPrivateKey = getWatchedPrivateKeyFile();
        Files.copy(Paths.get("src/test/resources/client-private-key-1.pem"), watchedPrivateKey);

        FileWatchingX509ExtendedKeyManager keyManager = new FileWatchingX509ExtendedKeyManager(watchedCertificates, watchedPrivateKey, KeyManagerFactory.getInstance("SunX509"));

        Files.write(watchedCertificates, new byte[0]);
        keyManager.update();

        assertThat(getLeafCertificate(keyManager)).isEqualTo(X509CertificateFactory.generate(Paths.get("src/test/resources/client-certificates-1.pem")).get(0));
    }

    @Test
    public void notAfterIsEarliestInChain() throws IOException, CertificateException {
        List<X509Certificate> certificates = X509CertificateFactory.generate(Paths.get("src/test/resources/client-certificates-1.pem"));
        Collections.reverse(certificates);

        assertThat(FileWatchingX509ExtendedKeyManager.notAfter(certificates)).isEqualTo(Instant.parse("2017-05-19T17:58:20Z"));
    }

    // The file watcher can install a new KeyManager between the two calls; aliases change on every load, so retry.
    private X509Certificate getLeafCertificate(FileWatchingX509ExtendedKeyManager keyManager) {
        for (int i = 0; i < 100; i++) {
            X509Certificate[] chain = keyManager.getCertificateChain(keyManager.getClientAliases("RSA", null)[0]);
            if (chain != null) {
                return chain[0];
            }
        }
        throw new IllegalStateException("No stable certificate chain");
    }

    private void replace(Path source, Path target) throws IOException {
        Path replacement = Files.createTempFile(target.getParent(), "replacement-", ".tmp");
        Files.copy(source, replacement, StandardCopyOption.REPLACE_EXISTING);
        Files.move(replacement, target, StandardCopyOption.ATOMIC_MOVE);
    }

    private Path getWatchedCertificatesFile() throws IOException {
        Path workDirectory = Files.createTempDirectory("file-watching-key-manager-test-");
        return workDirectory.resolve("certificates.pem");
    }

    private Path getWatchedPrivateKeyFile() throws IOException {
        Path workDirectory = Files.createTempDirectory("file-watching-key-manager-test-");
        return workDirectory.resolve("private-key.pem");
    }

}