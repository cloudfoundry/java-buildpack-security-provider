/*
 * Copyright 2017-2018 the original author or authors.
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

import org.junit.After;
import org.junit.Test;

import javax.net.ssl.KeyManagerFactory;
import javax.net.ssl.TrustManagerFactory;
import java.security.NoSuchAlgorithmException;
import java.security.Security;

import static org.assertj.core.api.Assertions.assertThat;
import static org.cloudfoundry.security.CloudFoundryContainerProvider.KEY_MANAGER_ENABLED;
import static org.cloudfoundry.security.CloudFoundryContainerProvider.TRUST_MANAGER_ENABLED;

public final class CloudFoundryContainerProviderTest {

    @Test
    public void doesNotProvideKeyManagerDisabled() throws NoSuchAlgorithmException {
        System.setProperty(KEY_MANAGER_ENABLED, "false");
        Security.insertProviderAt(new CloudFoundryContainerProvider(), 2);

        assertThat(KeyManagerFactory.getInstance("SunX509").getProvider()).isNotInstanceOf(CloudFoundryContainerProvider.class);
        assertThat(KeyManagerFactory.getInstance("NewSunX509").getProvider()).isNotInstanceOf(CloudFoundryContainerProvider.class);
        assertThat(KeyManagerFactory.getInstance("PKIX").getProvider()).isNotInstanceOf(CloudFoundryContainerProvider.class);
    }

    @Test
    public void doesNotProviderTrustManagerFactoryDisabled() throws NoSuchAlgorithmException {
        System.setProperty(TRUST_MANAGER_ENABLED, "false");
        Security.insertProviderAt(new CloudFoundryContainerProvider(), 2);

        assertThat(TrustManagerFactory.getInstance("SunX509").getProvider()).isNotInstanceOf(CloudFoundryContainerProvider.class);
        assertThat(TrustManagerFactory.getInstance("PKIX").getProvider()).isNotInstanceOf(CloudFoundryContainerProvider.class);
        assertThat(TrustManagerFactory.getInstance("SunPKIX").getProvider()).isNotInstanceOf(CloudFoundryContainerProvider.class);
        assertThat(TrustManagerFactory.getInstance("X509").getProvider()).isNotInstanceOf(CloudFoundryContainerProvider.class);
        assertThat(TrustManagerFactory.getInstance("X.509").getProvider()).isNotInstanceOf(CloudFoundryContainerProvider.class);
    }

    @Test
    public void providesKeyManagerFactory() throws NoSuchAlgorithmException {
        Security.insertProviderAt(new CloudFoundryContainerProvider(), 2);

        assertThat(KeyManagerFactory.getInstance("SunX509").getProvider()).isInstanceOf(CloudFoundryContainerProvider.class);
        assertThat(KeyManagerFactory.getInstance("NewSunX509").getProvider()).isInstanceOf(CloudFoundryContainerProvider.class);
        assertThat(KeyManagerFactory.getInstance("PKIX").getProvider()).isInstanceOf(CloudFoundryContainerProvider.class);
    }

    @Test
    public void providesKeyManagerFactoryEmpty() throws NoSuchAlgorithmException {
        System.setProperty(KEY_MANAGER_ENABLED, "");
        Security.insertProviderAt(new CloudFoundryContainerProvider(), 2);

        assertThat(KeyManagerFactory.getInstance("SunX509").getProvider()).isInstanceOf(CloudFoundryContainerProvider.class);
        assertThat(KeyManagerFactory.getInstance("NewSunX509").getProvider()).isInstanceOf(CloudFoundryContainerProvider.class);
        assertThat(KeyManagerFactory.getInstance("PKIX").getProvider()).isInstanceOf(CloudFoundryContainerProvider.class);
    }

    @Test
    public void providesKeyManagerFactoryEnabled() throws NoSuchAlgorithmException {
        System.setProperty(KEY_MANAGER_ENABLED, "true");
        Security.insertProviderAt(new CloudFoundryContainerProvider(), 2);

        assertThat(KeyManagerFactory.getInstance("SunX509").getProvider()).isInstanceOf(CloudFoundryContainerProvider.class);
        assertThat(KeyManagerFactory.getInstance("NewSunX509").getProvider()).isInstanceOf(CloudFoundryContainerProvider.class);
        assertThat(KeyManagerFactory.getInstance("PKIX").getProvider()).isInstanceOf(CloudFoundryContainerProvider.class);
    }

    @Test
    public void providesTrustManagerFactory() throws NoSuchAlgorithmException {
        Security.insertProviderAt(new CloudFoundryContainerProvider(), 2);

        assertThat(TrustManagerFactory.getInstance("SunX509").getProvider()).isInstanceOf(CloudFoundryContainerProvider.class);
        assertThat(TrustManagerFactory.getInstance("PKIX").getProvider()).isInstanceOf(CloudFoundryContainerProvider.class);
        assertThat(TrustManagerFactory.getInstance("SunPKIX").getProvider()).isInstanceOf(CloudFoundryContainerProvider.class);
        assertThat(TrustManagerFactory.getInstance("X509").getProvider()).isInstanceOf(CloudFoundryContainerProvider.class);
        assertThat(TrustManagerFactory.getInstance("X.509").getProvider()).isInstanceOf(CloudFoundryContainerProvider.class);
    }

    @Test
    public void providesTrustManagerFactoryEmpty() throws NoSuchAlgorithmException {
        System.setProperty(TRUST_MANAGER_ENABLED, "");
        Security.insertProviderAt(new CloudFoundryContainerProvider(), 2);

        assertThat(TrustManagerFactory.getInstance("SunX509").getProvider()).isInstanceOf(CloudFoundryContainerProvider.class);
        assertThat(TrustManagerFactory.getInstance("PKIX").getProvider()).isInstanceOf(CloudFoundryContainerProvider.class);
        assertThat(TrustManagerFactory.getInstance("SunPKIX").getProvider()).isInstanceOf(CloudFoundryContainerProvider.class);
        assertThat(TrustManagerFactory.getInstance("X509").getProvider()).isInstanceOf(CloudFoundryContainerProvider.class);
        assertThat(TrustManagerFactory.getInstance("X.509").getProvider()).isInstanceOf(CloudFoundryContainerProvider.class);
    }

    @Test
    public void providesTrustManagerFactoryEnabled() throws NoSuchAlgorithmException {
        System.setProperty(TRUST_MANAGER_ENABLED, "true");
        Security.insertProviderAt(new CloudFoundryContainerProvider(), 2);

        assertThat(TrustManagerFactory.getInstance("SunX509").getProvider()).isInstanceOf(CloudFoundryContainerProvider.class);
        assertThat(TrustManagerFactory.getInstance("PKIX").getProvider()).isInstanceOf(CloudFoundryContainerProvider.class);
        assertThat(TrustManagerFactory.getInstance("SunPKIX").getProvider()).isInstanceOf(CloudFoundryContainerProvider.class);
        assertThat(TrustManagerFactory.getInstance("X509").getProvider()).isInstanceOf(CloudFoundryContainerProvider.class);
        assertThat(TrustManagerFactory.getInstance("X.509").getProvider()).isInstanceOf(CloudFoundryContainerProvider.class);
    }

    @After
    public void removeProvider() {
        Security.removeProvider("Cloud Foundry Container");
        System.clearProperty(KEY_MANAGER_ENABLED);
        System.clearProperty(TRUST_MANAGER_ENABLED);
    }

}