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

import javax.net.ssl.TrustManagerFactory;
import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.nio.file.StandardCopyOption;
import java.security.NoSuchAlgorithmException;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.fail;

public final class FileWatchingX509ExtendedTrustManagerTest extends AbstractLoggingTest {

    @Test
    public void initializedWithWatchedFile() throws IOException, NoSuchAlgorithmException {
        Path watchedCertificates = getWatchedFile();
        Files.copy(Paths.get("src/test/resources/server-certificates-48.pem"), watchedCertificates);

        FileWatchingX509ExtendedTrustManager trustManager = new FileWatchingX509ExtendedTrustManager(watchedCertificates, TrustManagerFactory.getInstance("PKIX"));

        assertThat(trustManager.getAcceptedIssuers()).hasSize(48);
    }

    @Test
    public void watchesWatchedFile() throws IOException, InterruptedException, NoSuchAlgorithmException {
        Path watchedCertificates = getWatchedFile();
        Files.copy(Paths.get("src/test/resources/server-certificates-48.pem"), watchedCertificates);

        FileWatchingX509ExtendedTrustManager trustManager = new FileWatchingX509ExtendedTrustManager(watchedCertificates, TrustManagerFactory.getInstance("PKIX"));

        assertThat(trustManager.getAcceptedIssuers()).hasSize(48);

        Thread.sleep(5_000);
        Files.copy(Paths.get("src/test/resources/server-certificates-173.pem"), watchedCertificates, StandardCopyOption.REPLACE_EXISTING);

        long timeout = System.currentTimeMillis() + 300_000;
        for (; ; ) {
            if (System.currentTimeMillis() > timeout) {
                fail("Failed to update within timeout");
            }

            if (trustManager.getAcceptedIssuers().length == 173) {
                return;
            }

            Thread.sleep(1_000);
        }
    }

    private Path getWatchedFile() throws IOException {
        Path workDirectory = Files.createTempDirectory("file-watching-trust-manager-test-");
        return workDirectory.resolve("certificates.pem");
    }

}