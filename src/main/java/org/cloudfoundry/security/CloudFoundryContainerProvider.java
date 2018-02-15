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

import javax.net.ssl.KeyManagerFactory;
import javax.net.ssl.TrustManagerFactory;
import java.security.Provider;
import java.util.logging.Logger;

/**
 * An security {@link Provider} that exposes a {@link KeyManagerFactory} and {@link TrustManagerFactory} based on artifacts within a Cloud Foundry application container.
 */
public final class CloudFoundryContainerProvider extends Provider {

    static final String KEY_MANAGER_ENABLED = "org.cloudfoundry.security.keymanager.enabled";

    static final String TRUST_MANAGER_ENABLED = "org.cloudfoundry.security.trustmanager.enabled";

    private static final long serialVersionUID = -2667509590306131953L;

    private final Logger logger = Logger.getLogger(this.getClass().getName());

    /**
     * Creates a new instance of the provider.  This registers the following components
     * <ul>
     * <li>{@code KeyManagerFactory.PKIX}: {@link CloudFoundryContainerKeyManagerFactory}</li>
     * <li>{@code TrustManagerFactory.PKIX}: {@link CloudFoundryContainerTrustManagerFactory}</li>
     * </ul>
     */
    public CloudFoundryContainerProvider() {
        super("Cloud Foundry Container", 1.0, "KeyManagerFactory and TrustManagerFactory based on artifacts within a Cloud Foundry application container");

        if (get(KEY_MANAGER_ENABLED)) {
            this.logger.fine("KeyManager enabled");

            put("KeyManagerFactory.SunX509", "org.cloudfoundry.security.CloudFoundryContainerKeyManagerFactory$SunX509");
            put("KeyManagerFactory.NewSunX509", "org.cloudfoundry.security.CloudFoundryContainerKeyManagerFactory$X509");
            put("Alg.Alias.KeyManagerFactory.PKIX", "NewSunX509");
        }

        if (get(TRUST_MANAGER_ENABLED)) {
            this.logger.fine("TrustManager enabled");

            put("TrustManagerFactory.SunX509", "org.cloudfoundry.security.CloudFoundryContainerTrustManagerFactory$SimpleFactory");
            put("TrustManagerFactory.PKIX", "org.cloudfoundry.security.CloudFoundryContainerTrustManagerFactory$PKIXFactory");
            put("Alg.Alias.TrustManagerFactory.SunPKIX", "PKIX");
            put("Alg.Alias.TrustManagerFactory.X509", "PKIX");
            put("Alg.Alias.TrustManagerFactory.X.509", "PKIX");
        }

        this.logger.fine("Provider loaded");
    }

    private static boolean get(String key) {
        String value = System.getProperty(key);
        return value == null || value.trim().isEmpty() ? true : Boolean.valueOf(value);
    }

}
