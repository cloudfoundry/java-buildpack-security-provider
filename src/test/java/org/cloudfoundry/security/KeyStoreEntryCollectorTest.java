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

import java.io.IOException;
import java.nio.file.Paths;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.cert.Certificate;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.util.List;

import static org.assertj.core.api.Assertions.assertThat;

public final class KeyStoreEntryCollectorTest {

    @Test
    public void certificate() throws CertificateException, NoSuchAlgorithmException, KeyStoreException, IOException {
        X509Certificate certificate = X509CertificateFactory.generate(Paths.get("src/test/resources/client-certificates-1.pem")).get(0);

        KeyStore keyStore = KeyStoreEntryCollector.identity();
        KeyStoreEntryCollector.accumulate(keyStore, certificate);

        assertThat(keyStore.size()).isEqualTo(1);
    }

    @Test
    public void privateKey() throws CertificateException, NoSuchAlgorithmException, KeyStoreException, IOException {
        PrivateKey privateKey = PrivateKeyFactory.generate(Paths.get("src/test/resources/client-private-key-1.pem"));
        List<X509Certificate> certificates = X509CertificateFactory.generate(Paths.get("src/test/resources/client-certificates-1.pem"));

        KeyStore keyStore = KeyStoreEntryCollector.identity();
        KeyStoreEntryCollector.accumulate(keyStore, privateKey, new char[0], certificates.toArray(new Certificate[certificates.size()]));

        assertThat(keyStore.size()).isEqualTo(1);
    }

}