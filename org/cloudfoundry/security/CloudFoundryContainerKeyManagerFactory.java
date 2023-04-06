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

import javax.net.ssl.KeyManager;
import javax.net.ssl.KeyManagerFactory;
import javax.net.ssl.KeyManagerFactorySpi;
import javax.net.ssl.ManagerFactoryParameters;
import javax.net.ssl.X509ExtendedKeyManager;
import java.lang.reflect.UndeclaredThrowableException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.security.InvalidAlgorithmParameterException;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.UnrecoverableKeyException;
import java.util.ArrayList;
import java.util.List;
import java.util.logging.Logger;

abstract class CloudFoundryContainerKeyManagerFactory extends KeyManagerFactorySpi {

    private static final String CERTIFICATES_PROPERTY = "CF_INSTANCE_CERT";

    private static final Object MONITOR = new Object();

    private static final String PRIVATE_KEY_PROPERTY = "CF_INSTANCE_KEY";

    private static FileWatchingX509ExtendedKeyManager CACHED_CONTAINER_KEY_MANAGER;

    private final Logger logger = Logger.getLogger(this.getClass().getName());

    private final String algorithm;

    private final Path certificates;

    private final Path privateKey;

    private final KeyManagerFactory systemKeyManagerFactory;

    private X509ExtendedKeyManager cachedSystemKeyManager;

    private CloudFoundryContainerKeyManagerFactory(String algorithm, Path certificates, Path privateKey) {
        this.algorithm = algorithm;
        this.certificates = certificates;
        this.privateKey = privateKey;
        this.systemKeyManagerFactory = getKeyManagerFactory();

        this.logger.fine(String.format("Algorithm: %s", algorithm));
        this.logger.fine(String.format("Certificates: %s", certificates));
        this.logger.fine(String.format("Private Key: %s", privateKey));
    }

    @Override
    protected final KeyManager[] engineGetKeyManagers() {
        List<X509ExtendedKeyManager> delegates = new ArrayList<>();

        X509ExtendedKeyManager systemKeyManager = getSystemKeyManager();
        if (systemKeyManager != null) {
            delegates.add(systemKeyManager);
        }

        FileWatchingX509ExtendedKeyManager containerKeyManager = getContainerKeyManager();
        if (containerKeyManager != null) {
            delegates.add(containerKeyManager);
        }

        return new KeyManager[]{new DelegatingX509ExtendedKeyManager(delegates)};
    }

    @Override
    protected final void engineInit(ManagerFactoryParameters managerFactoryParameters) throws InvalidAlgorithmParameterException {
        this.systemKeyManagerFactory.init(managerFactoryParameters);
        invalidateSystemKeyManager();
    }

    @Override
    protected final void engineInit(KeyStore keyStore, char[] chars) throws KeyStoreException, NoSuchAlgorithmException, UnrecoverableKeyException {
        this.systemKeyManagerFactory.init(keyStore, chars);
        invalidateSystemKeyManager();
    }

    private static Path getProperty(String name) {
        String candidate = System.getenv(name);
        return candidate != null ? Paths.get(candidate) : null;
    }

    private FileWatchingX509ExtendedKeyManager getContainerKeyManager() {
        synchronized (MONITOR) {
            if (CACHED_CONTAINER_KEY_MANAGER == null && this.certificates != null && Files.exists(this.certificates) && this.privateKey != null && Files.exists(this.privateKey)) {
                this.logger.info(String.format("Adding Key Manager for %s and %s", this.privateKey, this.certificates));
                CACHED_CONTAINER_KEY_MANAGER = new FileWatchingX509ExtendedKeyManager(this.certificates, this.privateKey, getKeyManagerFactory());
            }

            return CACHED_CONTAINER_KEY_MANAGER;
        }
    }

    private KeyManagerFactory getKeyManagerFactory() {
        try {
            return KeyManagerFactory.getInstance(this.algorithm, "SunJSSE");
        } catch (NoSuchAlgorithmException | NoSuchProviderException e) {
            throw new UndeclaredThrowableException(e);
        }
    }

    private X509ExtendedKeyManager getSystemKeyManager() {
        synchronized (MONITOR) {
            if (this.cachedSystemKeyManager == null) {
                for (KeyManager candidate : this.systemKeyManagerFactory.getKeyManagers()) {
                    if (candidate instanceof X509ExtendedKeyManager) {
                        this.logger.info("Adding System Key Manager");
                        this.cachedSystemKeyManager = (X509ExtendedKeyManager) candidate;
                        break;
                    }
                }
            }

            return this.cachedSystemKeyManager;
        }
    }

    private void invalidateSystemKeyManager() {
        synchronized (MONITOR) {
            this.cachedSystemKeyManager = null;
        }
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
