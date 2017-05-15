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

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.nio.file.StandardCopyOption;

import static org.assertj.core.api.Assertions.assertThat;

public final class FileWatchingX509TrustManagerTest {

    @Test
    public void initializedWithWatchedFile() throws IOException {
        Path watchedFile = getWatchedFile();
        Files.copy(Paths.get("src/test/resources/darwin-48.pem"), watchedFile);

        FileWatchingX509TrustManager trustManager = new FileWatchingX509TrustManager("PKIX", watchedFile);

        assertThat(trustManager.getAcceptedIssuers()).hasSize(48);
    }

    @Test
    public void watchesWatchedFile() throws IOException, InterruptedException {
        Path watchedFile = getWatchedFile();
        Files.copy(Paths.get("src/test/resources/darwin-48.pem"), watchedFile);

        FileWatchingX509TrustManager trustManager = new FileWatchingX509TrustManager("PKIX", watchedFile);

        assertThat(trustManager.getAcceptedIssuers()).hasSize(48);

        Thread.sleep(5_000);
        Files.copy(Paths.get("src/test/resources/unix-173.pem"), watchedFile, StandardCopyOption.REPLACE_EXISTING);
        Thread.sleep(11_000);

        assertThat(trustManager.getAcceptedIssuers()).hasSize(173);
    }

    private Path getWatchedFile() throws IOException {
        Path workDirectory = Files.createTempDirectory("file-watching-trust-manager-test-");
        return workDirectory.resolve("certificates.pem");
    }

}