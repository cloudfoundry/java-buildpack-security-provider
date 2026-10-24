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
        // before the new certificate, so a certificate change means both files are new. See
        // https://github.com/cloudfoundry/executor/blob/208a08c51850167d93e1040cfd8538fc1925c882/depot/containerstore/instance_identity_handler.go#L94-L102
        // If that order ever changes, the update reads the old key with the new certificate and the mismatch check
        // below keeps the current pair. Watching the key file as well caused
        // https://github.com/cloudfoundry/java-buildpack-security-provider/issues/8
        new FileWatcher(this.certificates, this::update).watch();
        update();
    }

    @Override
    public String chooseClientAlias(String[] strings, Principal[] principals, Socket socket) {
        X509ExtendedKeyManager keyManager = this.keyManager.get();
        return keyManager != null ? keyManager.chooseClientAlias(strings, principals, socket) : null;
    }

    @Override
    public String chooseEngineClientAlias(String[] strings, Principal[] principals, SSLEngine sslEngine) {
        X509ExtendedKeyManager keyManager = this.keyManager.get();
        return keyManager != null ? keyManager.chooseEngineClientAlias(strings, principals, sslEngine) : null;
    }

    @Override
    public String chooseEngineServerAlias(String s, Principal[] principals, SSLEngine sslEngine) {
        X509ExtendedKeyManager keyManager = this.keyManager.get();
        return keyManager != null ? keyManager.chooseEngineServerAlias(s, principals, sslEngine) : null;
    }

    @Override
    public String chooseServerAlias(String s, Principal[] principals, Socket socket) {
        X509ExtendedKeyManager keyManager = this.keyManager.get();
        return keyManager != null ? keyManager.chooseServerAlias(s, principals, socket) : null;
    }

    @Override
    public X509Certificate[] getCertificateChain(String s) {
        X509ExtendedKeyManager keyManager = this.keyManager.get();
        return keyManager != null ? keyManager.getCertificateChain(s) : null;
    }

    @Override
    public String[] getClientAliases(String s, Principal[] principals) {
        X509ExtendedKeyManager keyManager = this.keyManager.get();
        return keyManager != null ? keyManager.getClientAliases(s, principals) : null;
    }

    @Override
    public PrivateKey getPrivateKey(String s) {
        X509ExtendedKeyManager keyManager = this.keyManager.get();
        return keyManager != null ? keyManager.getPrivateKey(s) : null;
    }

    @Override
    public String[] getServerAliases(String s, Principal[] principals) {
        X509ExtendedKeyManager keyManager = this.keyManager.get();
        return keyManager != null ? keyManager.getServerAliases(s, principals) : null;
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
            this.logger.info(() -> String.format("Private key %s is not an RSA key, not checked against certificate %s. This is unexpected: " +
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
            // A single delayed retry would also cover a certificate renamed before its key, but Diego renames the
            // key first; add one only if real-world cases show the need.
            // On the first load there is no current pair: none is installed, so no client certificate is presented
            // and other TLS connections keep working, until a certificate change brings a matching pair.
            if (!matches(privateKey, certificates)) {
                if (this.keyManager.get() != null) {
                    Instant currentNotAfter = this.notAfter;
                    this.logger.severe(() -> String.format("Private key %s does not match certificate %s, keeping current KeyManager (certificate chain expires at %s). " +
                        "The private key may not have been replaced before the certificate",
                        this.privateKey, this.certificates, currentNotAfter));
                } else {
                    this.logger.severe(() -> String.format("Private key %s does not match certificate %s, no KeyManager installed: " +
                        "no client certificate is presented until a matching pair is loaded", this.privateKey, this.certificates));
                }
                return;
            }

            X509ExtendedKeyManager keyManager = getKeyManager(getKeyStore(privateKey, certificates));
            Instant notAfter = notAfter(certificates);
            boolean initialized = this.keyManager.getAndSet(keyManager) == null;
            this.notAfter = notAfter;

            X509Certificate leaf = certificates.get(0);
            this.logger.info(() -> String.format("%s KeyManager for %s and %s: serial %s, subject %s, certificate chain expires at %s",
                initialized ? "Initialized" : "Updated", this.privateKey, this.certificates,
                leaf.getSerialNumber().toString(16), leaf.getSubjectX500Principal().getName(), notAfter));

            if (notAfter.isBefore(Instant.now())) {
                this.logger.severe(() -> String.format("Certificate chain %s expired at %s, TLS handshakes using it will fail", this.certificates, notAfter));
            }
        }
    }

    // Instant prints as ISO-8601 in UTC, independent of the default time zone. Never called with an empty list:
    // matches() rejects it first.
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
