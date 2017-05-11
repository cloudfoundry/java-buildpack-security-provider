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

import java.nio.file.Files;
import java.nio.file.Path;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;

import static org.assertj.core.api.Assertions.assertThat;

public final class CloudFoundryContainerTrustManagerFactoryTest {

    @Test
    public void addsAdditionalTrustManagers() throws NoSuchAlgorithmException, KeyStoreException {
        int expected = 1;

        for (Path certificateFile : CloudFoundryContainerTrustManagerFactory.OPENSSL_CERTIFICATE_FILES) {
            if (Files.exists(certificateFile)) {
                expected++;
            }
        }

        CloudFoundryContainerTrustManagerFactory.PKIXFactory factory = new CloudFoundryContainerTrustManagerFactory.PKIXFactory();
        factory.engineInit(KeyStore.getInstance(KeyStore.getDefaultType()));

        assertThat(factory.engineGetTrustManagers()).hasSize(expected);
    }

}