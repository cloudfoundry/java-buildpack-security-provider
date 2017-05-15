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

import javax.net.ssl.ManagerFactoryParameters;
import javax.net.ssl.TrustManager;
import javax.net.ssl.TrustManagerFactorySpi;
import java.lang.reflect.Method;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.security.InvalidAlgorithmParameterException;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;
import java.util.List;
import java.util.logging.Logger;

abstract class CloudFoundryContainerTrustManagerFactory extends TrustManagerFactorySpi {

    static final List<Path> OPENSSL_CERTIFICATE_FILES = Arrays.asList(
        Paths.get("/etc/ssl/cert.pem"),
        Paths.get("/etc/ssl/certs/ca-certificates.crt"),
        Paths.get("/usr/local/etc/openssl/cert.pem")
    );

    private final Logger logger = Logger.getLogger(this.getClass().getName());

    private final String algorithm;

    private final TrustManagerFactorySpi delegate;

    private final Method engineGetTrustManagers;

    private final Method engineInitKeyStore;

    private final Method engineInitManagerFactoryParameters;

    private CloudFoundryContainerTrustManagerFactory(String algorithm) throws NoSuchAlgorithmException {
        this.algorithm = algorithm;
        this.delegate = ServiceUtils.getService("TrustManagerFactory", algorithm);

        this.engineGetTrustManagers = ClassUtils.findMethod(this.delegate.getClass(), "engineGetTrustManagers");
        ReflectionUtils.makeAccessible(this.engineGetTrustManagers);

        this.engineInitKeyStore = ClassUtils.findMethod(this.delegate.getClass(), "engineInit", KeyStore.class);
        ReflectionUtils.makeAccessible(this.engineInitKeyStore);

        this.engineInitManagerFactoryParameters = ClassUtils.findMethod(this.delegate.getClass(), "engineInit", ManagerFactoryParameters.class);
        ReflectionUtils.makeAccessible(this.engineInitManagerFactoryParameters);
    }

    @Override
    protected final TrustManager[] engineGetTrustManagers() {
        List<TrustManager> trustManagers = new ArrayList<>();
        Collections.addAll(trustManagers, (TrustManager[]) ReflectionUtils.invokeMethod(this.engineGetTrustManagers, this.delegate));

        for (Path certificateFile : OPENSSL_CERTIFICATE_FILES) {
            if (Files.exists(certificateFile)) {
                trustManagers.add(new FileWatchingX509TrustManager(this.algorithm, certificateFile));
                this.logger.info(String.format("Added TrustManager for %s", certificateFile));
            }
        }

        return trustManagers.toArray(new TrustManager[trustManagers.size()]);
    }

    @Override
    protected final void engineInit(ManagerFactoryParameters managerFactoryParameters) throws InvalidAlgorithmParameterException {
        ReflectionUtils.invokeMethod(this.engineInitManagerFactoryParameters, this.delegate, managerFactoryParameters);
    }

    @Override
    protected final void engineInit(KeyStore keyStore) throws KeyStoreException {
        ReflectionUtils.invokeMethod(this.engineInitKeyStore, this.delegate, keyStore);
    }

    public static final class PKIXFactory extends CloudFoundryContainerTrustManagerFactory {

        public PKIXFactory() throws NoSuchAlgorithmException {
            super("PKIX");
        }
    }

    public static final class SimpleFactory extends CloudFoundryContainerTrustManagerFactory {

        public SimpleFactory() throws NoSuchAlgorithmException {
            super("SunX509");
        }

    }

}
