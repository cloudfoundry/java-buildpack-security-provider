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

import com.google.errorprone.annotations.concurrent.GuardedBy;

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
import java.security.PublicKey;
import java.security.UnrecoverableKeyException;
import java.security.cert.Certificate;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.security.interfaces.RSAKey;
import java.time.Instant;
import java.util.List;
import java.util.concurrent.atomic.AtomicReference;
import java.util.logging.Logger;

final class FileWatchingX509ExtendedKeyManager extends X509ExtendedKeyManager {

    private final Logger logger = Logger.getLogger(this.getClass().getName());

    private final Path certificates;

    private final AtomicReference<X509ExtendedKeyManager> keyManager = new AtomicReference<>();

    @GuardedBy("updateLock")
    private final KeyManagerFactory keyManagerFactory;

    private final Object updateLock = new Object();

    @GuardedBy("updateLock")
    private Instant notAfter;

    private final Path privateKey;

    FileWatchingX509ExtendedKeyManager(Path certificates, Path privateKey, KeyManagerFactory keyManagerFactory) {
        this.certificates = certificates;
        this.privateKey = privateKey;
        this.keyManagerFactory = keyManagerFactory;

        // Only the certificate file is watched: the Diego executor renames the new private key into place
        // before the new certificate, so a certificate change means both files are new.
        // Watching the key file as well caused #8.
        new FileWatcher(this.certificates, this::update).watch();
        update();
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

    private KeyStore getKeyStore(PrivateKey privateKey, List<X509Certificate> certificates) {
        try {
            KeyStore keyStore = KeyStoreEntryCollector.identity();
            KeyStoreEntryCollector.accumulate(keyStore, privateKey, new char[0], certificates.toArray(new Certificate[certificates.size()]));
            return keyStore;
        } catch (CertificateException | IOException | KeyStoreException | NoSuchAlgorithmException e) {
            throw new UndeclaredThrowableException(e);
        }
    }

    // Only RSA keys, the type the Diego executor issues, are compared; other key types are accepted unchecked.
    private boolean matches(PrivateKey privateKey, List<X509Certificate> certificates) {
        if (certificates.isEmpty()) {
            return false;
        }

        PublicKey publicKey = certificates.get(0).getPublicKey();
        if (!(privateKey instanceof RSAKey) || !(publicKey instanceof RSAKey)) {
            this.logger.info(String.format("Private key %s is not an RSA key, not checked against certificate %s. This is unexpected: " +
                "check the key generator, the security provider probably needs an update", this.privateKey, this.certificates));
            return true;
        }

        return ((RSAKey) privateKey).getModulus().equals(((RSAKey) publicKey).getModulus());
    }

    void update() {
        // The whole update is locked: with the files read outside the lock, an update that read the files earlier
        // could finish later and replace a newer pair with the older one. Also, the shared KeyManagerFactory is not
        // thread-safe. No contention cost: updates come from the constructor and the single watcher thread, and
        // handshakes never take the lock.
        synchronized (this.updateLock) {
            PrivateKey privateKey;
            List<X509Certificate> certificates;
            try {
                privateKey = PrivateKeyFactory.generate(this.privateKey);
                certificates = X509CertificateFactory.generate(this.certificates);
            } catch (CertificateException | IOException e) {
                throw new UndeclaredThrowableException(e);
            }

            // No retry: the Diego executor never writes a mismatched pair, and the next certificate change
            // triggers a new update. Until then the current pair, still valid, beats one that cannot authenticate.
            if (this.keyManager.get() != null && !matches(privateKey, certificates)) {
                this.logger.warning(String.format("Private key %s does not match certificate %s, keeping current KeyManager (certificate chain expires at %s)",
                    this.privateKey, this.certificates, this.notAfter));
                return;
            }

            X509ExtendedKeyManager keyManager = getKeyManager(getKeyStore(privateKey, certificates));
            Instant notAfter = notAfter(certificates);
            boolean initialized = this.keyManager.getAndSet(keyManager) == null;
            this.notAfter = notAfter;

            X509Certificate leaf = certificates.get(0);
            this.logger.info(String.format("%s KeyManager for %s and %s: serial %s, subject %s, certificate chain expires at %s",
                initialized ? "Initialized" : "Updated", this.privateKey, this.certificates,
                leaf.getSerialNumber().toString(16), leaf.getSubjectX500Principal().getName(), notAfter));

            if (notAfter.isBefore(Instant.now())) {
                this.logger.warning(String.format("Certificate chain %s expired at %s, TLS handshakes using it will fail", this.certificates, notAfter));
            }
        }
    }

    // Instant prints as ISO-8601 in UTC, independent of the default time zone.
    static Instant notAfter(List<X509Certificate> certificates) {
        Instant notAfter = Instant.MAX;
        for (X509Certificate certificate : certificates) {
            Instant certificateNotAfter = certificate.getNotAfter().toInstant();
            if (certificateNotAfter.isBefore(notAfter)) {
                notAfter = certificateNotAfter;
            }
        }
        return notAfter;
    }

}
