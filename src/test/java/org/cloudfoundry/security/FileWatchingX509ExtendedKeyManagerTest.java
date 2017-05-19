/*
 * Copyright 2017 the original author or authors.
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
import java.security.NoSuchProviderException;

import static org.assertj.core.api.Assertions.assertThat;

public final class FileWatchingX509ExtendedKeyManagerTest {

    @Test
    public void initializedWithWatchedFile() throws IOException, NoSuchProviderException, NoSuchAlgorithmException {
        Path watchedCertificates = getWatchedCertificatesFile();
        Files.copy(Paths.get("src/test/resources/client-certificates-1.pem"), watchedCertificates);

        Path watchedPrivateKey = getWatchedPrivateKeyFile();
        Files.copy(Paths.get("src/test/resources/client-private-key-1.pem"), watchedPrivateKey);

        FileWatchingX509ExtendedKeyManager keyManager = new FileWatchingX509ExtendedKeyManager(watchedCertificates, watchedPrivateKey, KeyManagerFactory.getInstance("SunX509"));

        assertThat(keyManager.getClientAliases("RSA", null)).hasSize(1);
    }

    @Test
    public void watchesWatchedFile() throws IOException, InterruptedException, NoSuchProviderException, NoSuchAlgorithmException {
        Path watchedCertificates = getWatchedCertificatesFile();
        Files.copy(Paths.get("src/test/resources/client-certificates-1.pem"), watchedCertificates);

        Path watchedPrivateKey = getWatchedPrivateKeyFile();
        Files.copy(Paths.get("src/test/resources/client-private-key-1.pem"), watchedPrivateKey);

        FileWatchingX509ExtendedKeyManager keyManager = new FileWatchingX509ExtendedKeyManager(watchedCertificates, watchedPrivateKey, KeyManagerFactory.getInstance("SunX509"));

        String alias = keyManager.getClientAliases("RSA", null)[0];

        Thread.sleep(5_000);
        Files.copy(Paths.get("src/test/resources/client-certificates-2.pem"), watchedCertificates, StandardCopyOption.REPLACE_EXISTING);
        Files.copy(Paths.get("src/test/resources/client-private-key-2.pem"), watchedPrivateKey, StandardCopyOption.REPLACE_EXISTING);
        Thread.sleep(11_000);

        assertThat(keyManager.getClientAliases("RSA", null)[0]).isNotEqualTo(alias);
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