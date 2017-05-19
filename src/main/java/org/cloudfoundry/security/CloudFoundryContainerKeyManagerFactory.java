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

import javax.net.ssl.KeyManager;
import javax.net.ssl.KeyManagerFactory;
import javax.net.ssl.KeyManagerFactorySpi;
import javax.net.ssl.ManagerFactoryParameters;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.security.InvalidAlgorithmParameterException;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.UnrecoverableKeyException;
import java.util.logging.Logger;

abstract class CloudFoundryContainerKeyManagerFactory extends KeyManagerFactorySpi {

    static final String KEY_STORE_PROPERTY = "javax.net.ssl.keyStore";

    private static final String CERTIFICATES_PROPERTY = "CF_INSTANCE_CERT";

    private static final String PRIVATE_KEY_PROPERTY = "CF_INSTANCE_KEY";

    private final Logger logger = Logger.getLogger(this.getClass().getName());

    private final Path certificates;

    private final KeyManagerFactory keyManagerFactory;

    private final Path privateKey;

    private CloudFoundryContainerKeyManagerFactory(String algorithm, Path certificates, Path privateKey) throws NoSuchAlgorithmException, NoSuchProviderException {
        this.certificates = certificates;
        this.keyManagerFactory = KeyManagerFactory.getInstance(algorithm, "SunJSSE");
        this.privateKey = privateKey;
    }

    @Override
    protected final KeyManager[] engineGetKeyManagers() {
        if (System.getProperty(KEY_STORE_PROPERTY) == null && this.certificates != null && this.privateKey != null) {
            if (Files.exists(this.certificates) && Files.exists(this.privateKey)) {
                this.logger.info(String.format("Added Key Manager for %s and %s", this.privateKey, this.certificates));
                return new KeyManager[]{new FileWatchingX509ExtendedKeyManager(this.certificates, this.privateKey, this.keyManagerFactory)};
            }
        }

        return this.keyManagerFactory.getKeyManagers();
    }

    @Override
    protected final void engineInit(ManagerFactoryParameters managerFactoryParameters) throws InvalidAlgorithmParameterException {
        this.keyManagerFactory.init(managerFactoryParameters);
    }

    @Override
    protected final void engineInit(KeyStore keyStore, char[] chars) throws KeyStoreException, NoSuchAlgorithmException, UnrecoverableKeyException {
        this.keyManagerFactory.init(keyStore, chars);
    }

    private static Path getProperty(String name) {
        String value = System.getenv(name);
        return name != null ? Paths.get(name) : null;
    }

    public static final class SunX509 extends CloudFoundryContainerKeyManagerFactory {

        public SunX509() throws NoSuchAlgorithmException, NoSuchProviderException {
            this(getProperty(CERTIFICATES_PROPERTY), getProperty(PRIVATE_KEY_PROPERTY));
        }

        SunX509(Path certificates, Path privateKey) throws NoSuchAlgorithmException, NoSuchProviderException {
            super("SunX509", certificates, privateKey);
        }

    }

    public static final class X509 extends CloudFoundryContainerKeyManagerFactory {

        public X509() throws NoSuchAlgorithmException, NoSuchProviderException {
            this(getProperty(CERTIFICATES_PROPERTY), getProperty(PRIVATE_KEY_PROPERTY));
        }

        X509(Path certificates, Path privateKey) throws NoSuchAlgorithmException, NoSuchProviderException {
            super("NewSunX509", certificates, privateKey);
        }

    }

}
