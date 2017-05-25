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

import javax.net.ssl.TrustManager;
import java.io.IOException;
import java.nio.file.Paths;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.cert.CertificateException;

import static org.assertj.core.api.Assertions.assertThat;

public final class CloudFoundryContainerTrustManagerFactoryTest {

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

    private KeyStore getKeyStore() throws KeyStoreException, CertificateException, NoSuchAlgorithmException, IOException {
        KeyStore keyStore = KeyStore.getInstance(KeyStore.getDefaultType());
        keyStore.load(null);
        return keyStore;
    }

}