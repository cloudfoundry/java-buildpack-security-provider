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
import javax.net.ssl.SSLEngine;
import javax.net.ssl.X509ExtendedKeyManager;
import java.io.IOException;
import java.lang.reflect.UndeclaredThrowableException;
import java.net.Socket;
import java.nio.file.Path;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.Principal;
import java.security.PrivateKey;
import java.security.UnrecoverableKeyException;
import java.security.cert.Certificate;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.util.List;
import java.util.concurrent.atomic.AtomicReference;
import java.util.logging.Logger;

final class FileWatchingX509ExtendedKeyManager extends X509ExtendedKeyManager {

    private final Logger logger = Logger.getLogger(this.getClass().getName());

    private final Path certificates;

    private final AtomicReference<X509ExtendedKeyManager> keyManager = new AtomicReference<>();

    private final KeyManagerFactory keyManagerFactory;

    private final Path privateKey;

    FileWatchingX509ExtendedKeyManager(Path certificates, Path privateKey, KeyManagerFactory keyManagerFactory) {
        this.certificates = certificates;
        this.privateKey = privateKey;
        this.keyManagerFactory = keyManagerFactory;

        new FileWatcher(this.certificates, new FileWatcherCallback()).watch();
        new FileWatcher(this.privateKey, new FileWatcherCallback()).watch();

        if (this.keyManager.compareAndSet(null, getKeyManager(getKeyStore()))) {
            this.logger.info(String.format("Initialized KeyManager for %s and %s", this.privateKey, this.certificates));
        }
    }

    @Override
    public String chooseClientAlias(String[] strings, Principal[] principals, Socket socket) {
        return this.keyManager.get().chooseClientAlias(strings, principals, socket);
    }

    @Override
    public String chooseEngineClientAlias(String[] strings, Principal[] principals, SSLEngine sslEngine) {
        return this.keyManager.get().chooseEngineClientAlias(strings, principals, sslEngine);
    }

    @Override
    public String chooseEngineServerAlias(String s, Principal[] principals, SSLEngine sslEngine) {
        return this.keyManager.get().chooseEngineServerAlias(s, principals, sslEngine);
    }

    @Override
    public String chooseServerAlias(String s, Principal[] principals, Socket socket) {
        return this.keyManager.get().chooseServerAlias(s, principals, socket);
    }

    @Override
    public X509Certificate[] getCertificateChain(String s) {
        return this.keyManager.get().getCertificateChain(s);
    }

    @Override
    public String[] getClientAliases(String s, Principal[] principals) {
        return this.keyManager.get().getClientAliases(s, principals);
    }

    @Override
    public PrivateKey getPrivateKey(String s) {
        return this.keyManager.get().getPrivateKey(s);
    }

    @Override
    public String[] getServerAliases(String s, Principal[] principals) {
        return this.keyManager.get().getServerAliases(s, principals);
    }

    private X509ExtendedKeyManager getKeyManager(KeyStore keyStore) {
        try {
            this.keyManagerFactory.init(keyStore, new char[0]);

            for (KeyManager keyManager : this.keyManagerFactory.getKeyManagers()) {
                if (keyManager instanceof X509ExtendedKeyManager) {
                    return (X509ExtendedKeyManager) keyManager;
                }
            }

            throw new IllegalStateException("No X509ExtendedKeyManager available");
        } catch (KeyStoreException | NoSuchAlgorithmException | UnrecoverableKeyException e) {
            throw new UndeclaredThrowableException(e);
        }
    }

    private KeyStore getKeyStore() {
        try {
            KeyStore keyStore = KeyStoreEntryCollector.identity();
            PrivateKey privateKey = PrivateKeyFactory.generate(this.privateKey);
            List<X509Certificate> certificates = X509CertificateFactory.generate(this.certificates);

            KeyStoreEntryCollector.accumulate(keyStore, privateKey, new char[0], certificates.toArray(new Certificate[certificates.size()]));

            return keyStore;
        } catch (CertificateException | IOException | KeyStoreException | NoSuchAlgorithmException e) {
            throw new UndeclaredThrowableException(e);
        }
    }

    private final class FileWatcherCallback implements Runnable {

        @Override
        public void run() {
            if (FileWatchingX509ExtendedKeyManager.this.keyManager.getAndSet(getKeyManager(getKeyStore())) == null) {
                FileWatchingX509ExtendedKeyManager.this.logger.info(String.format("Initialized KeyManager for %s and %s", FileWatchingX509ExtendedKeyManager.this.privateKey,
                    FileWatchingX509ExtendedKeyManager.this.certificates));
            } else {
                FileWatchingX509ExtendedKeyManager.this.logger.info(String.format("Updated KeyManager for %s and %s", FileWatchingX509ExtendedKeyManager.this.privateKey,
                    FileWatchingX509ExtendedKeyManager.this.certificates));
            }
        }

    }

}
