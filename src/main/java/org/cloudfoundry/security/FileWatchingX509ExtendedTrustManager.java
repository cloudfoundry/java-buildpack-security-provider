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

import javax.net.ssl.SSLEngine;
import javax.net.ssl.TrustManager;
import javax.net.ssl.TrustManagerFactory;
import javax.net.ssl.X509ExtendedTrustManager;
import java.io.IOException;
import java.lang.reflect.UndeclaredThrowableException;
import java.net.Socket;
import java.nio.file.Path;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.util.concurrent.atomic.AtomicReference;
import java.util.logging.Logger;

final class FileWatchingX509ExtendedTrustManager extends X509ExtendedTrustManager {

    private final Logger logger = Logger.getLogger(this.getClass().getName());

    private final Path certificates;

    private final AtomicReference<X509ExtendedTrustManager> trustManager = new AtomicReference<>();

    private final TrustManagerFactory trustManagerFactory;

    FileWatchingX509ExtendedTrustManager(Path certificates, TrustManagerFactory trustManagerFactory) {
        this.certificates = certificates;
        this.trustManagerFactory = trustManagerFactory;

        new FileWatcher(this.certificates, new FileWatcherCallback()).watch();

        if (this.trustManager.compareAndSet(null, getTrustManager(getKeyStore()))) {
            this.logger.info(String.format("Initialized TrustManager for %s", this.certificates));
        }
    }

    @Override
    public void checkClientTrusted(X509Certificate[] x509Certificates, String s, Socket socket) throws CertificateException {
        this.trustManager.get().checkClientTrusted(x509Certificates, s, socket);
    }

    @Override
    public void checkClientTrusted(X509Certificate[] x509Certificates, String s, SSLEngine sslEngine) throws CertificateException {
        this.trustManager.get().checkClientTrusted(x509Certificates, s, sslEngine);
    }

    @Override
    public void checkClientTrusted(X509Certificate[] x509Certificates, String s) throws CertificateException {
        this.trustManager.get().checkClientTrusted(x509Certificates, s);
    }

    @Override
    public void checkServerTrusted(X509Certificate[] x509Certificates, String s, SSLEngine sslEngine) throws CertificateException {
        this.trustManager.get().checkServerTrusted(x509Certificates, s, sslEngine);
    }

    @Override
    public void checkServerTrusted(X509Certificate[] x509Certificates, String s, Socket socket) throws CertificateException {
        this.trustManager.get().checkServerTrusted(x509Certificates, s, socket);
    }

    @Override
    public void checkServerTrusted(X509Certificate[] x509Certificates, String s) throws CertificateException {
        this.trustManager.get().checkServerTrusted(x509Certificates, s);
    }

    @Override
    public X509Certificate[] getAcceptedIssuers() {
        return this.trustManager.get().getAcceptedIssuers();
    }

    private KeyStore getKeyStore() {
        try {
            KeyStore keyStore = KeyStoreEntryCollector.identity();

            for (X509Certificate certificate : X509CertificateFactory.generate(this.certificates)) {
                KeyStoreEntryCollector.accumulate(keyStore, certificate);
            }

            return keyStore;
        } catch (CertificateException | IOException | KeyStoreException | NoSuchAlgorithmException e) {
            throw new UndeclaredThrowableException(e);
        }
    }

    private X509ExtendedTrustManager getTrustManager(KeyStore keyStore) {
        try {
            this.trustManagerFactory.init(keyStore);

            for (TrustManager trustManager : this.trustManagerFactory.getTrustManagers()) {
                if (trustManager instanceof X509ExtendedTrustManager) {
                    return (X509ExtendedTrustManager) trustManager;
                }
            }

            throw new IllegalStateException("No X509ExtendedTrustManager available");
        } catch (KeyStoreException e) {
            throw new UndeclaredThrowableException(e);
        }
    }

    private class FileWatcherCallback implements Runnable {

        @Override
        public void run() {
            if (FileWatchingX509ExtendedTrustManager.this.trustManager.getAndSet(getTrustManager(getKeyStore())) == null) {
                FileWatchingX509ExtendedTrustManager.this.logger.info(String.format("Initialized TrustManager for %s", FileWatchingX509ExtendedTrustManager.this.certificates));
            } else {
                FileWatchingX509ExtendedTrustManager.this.logger.info(String.format("Updated TrustManager for %s", FileWatchingX509ExtendedTrustManager.this.certificates));
            }
        }

    }
}
