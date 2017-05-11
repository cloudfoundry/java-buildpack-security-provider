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

import javax.net.ssl.TrustManager;
import javax.net.ssl.TrustManagerFactory;
import javax.net.ssl.X509TrustManager;
import java.io.IOException;
import java.lang.reflect.UndeclaredThrowableException;
import java.nio.charset.Charset;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.util.List;
import java.util.concurrent.atomic.AtomicReference;
import java.util.logging.Logger;

final class FileWatchingX509TrustManager implements X509TrustManager {

    private final Logger logger = Logger.getLogger(this.getClass().getName());

    private final String algorithm;

    private final Path source;

    private final AtomicReference<X509TrustManager> trustManager = new AtomicReference<>();

    FileWatchingX509TrustManager(String algorithm, Path source) {
        this.algorithm = algorithm;
        this.source = source;

        new FileWatcher(this.source, new Runnable() {

            @Override
            public void run() {
                if (FileWatchingX509TrustManager.this.trustManager.getAndSet(getTrustManager(getKeyStore())) == null) {
                    FileWatchingX509TrustManager.this.logger.info(String.format("Initialized TrustManager for %s", FileWatchingX509TrustManager.this.source));
                } else {
                    FileWatchingX509TrustManager.this.logger.info(String.format("Updated TrustManager for %s", FileWatchingX509TrustManager.this.source));
                }
            }

        }).watch();

        if (this.trustManager.compareAndSet(null, getTrustManager(getKeyStore()))) {
            this.logger.info(String.format("Initialized TrustManager for %s", this.source));
        }
    }

    @Override
    public void checkClientTrusted(X509Certificate[] x509Certificates, String s) throws CertificateException {
        this.trustManager.get().checkClientTrusted(x509Certificates, s);
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
            List<String> lines = Files.readAllLines(this.source, Charset.defaultCharset());

            PemEncodedCertificateBuilder certificateBuilder = PemEncodedCertificateBuilder.identity();
            for (String line : lines) {
                PemEncodedCertificateBuilder.accumulate(certificateBuilder, line);
            }

            KeyStore keyStore = KeyStoreBuilder.identity();
            for (String certificate : certificateBuilder.pemEncodedCertificates()) {
                KeyStoreBuilder.accumulate(keyStore, X509CertificateBuilder.toCertificate(certificate));
            }

            return keyStore;
        } catch (CertificateException | IOException | KeyStoreException | NoSuchAlgorithmException e) {
            throw new UndeclaredThrowableException(e);
        }
    }

    private X509TrustManager getTrustManager(KeyStore keyStore) {
        try {
            TrustManagerFactory trustManagerFactory = TrustManagerFactory.getInstance(this.algorithm, "SunJSSE");
            trustManagerFactory.init(keyStore);

            for (TrustManager trustManager : trustManagerFactory.getTrustManagers()) {
                if (trustManager instanceof X509TrustManager) {
                    return (X509TrustManager) trustManager;
                }
            }

            throw new IllegalStateException("No X509TrustManager available");
        } catch (KeyStoreException | NoSuchAlgorithmException | NoSuchProviderException e) {
            throw new UndeclaredThrowableException(e);
        }
    }

}
