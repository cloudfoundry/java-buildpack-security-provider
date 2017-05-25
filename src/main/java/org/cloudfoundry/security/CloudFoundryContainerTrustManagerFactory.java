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
import javax.net.ssl.TrustManagerFactory;
import javax.net.ssl.TrustManagerFactorySpi;
import javax.net.ssl.X509ExtendedTrustManager;
import java.lang.reflect.UndeclaredThrowableException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.security.InvalidAlgorithmParameterException;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import java.util.logging.Logger;

abstract class CloudFoundryContainerTrustManagerFactory extends TrustManagerFactorySpi {

    private static final List<Path> OPENSSL_CERTIFICATES_FILES = Arrays.asList(
        Paths.get("src/test/resources/ca-certs.pem")
//        Paths.get("/etc/ssl/certs/ca-certificates.crt"),
//        Paths.get("/usr/local/etc/openssl/cert.pem"),
//        Paths.get("/etc/ssl/cert.pem")
    );

    private final Logger logger = Logger.getLogger(this.getClass().getName());

    private final String algorithm;

    private final Path certificates;

    private final TrustManagerFactory systemTrustManagerFactory;

    private CloudFoundryContainerTrustManagerFactory(String algorithm, Path certificates) {
        this.algorithm = algorithm;
        this.certificates = certificates;
        this.systemTrustManagerFactory = getTrustManagerFactory();

        this.logger.fine(String.format("Algorithm: %s", algorithm));
        this.logger.fine(String.format("Certificates: %s", certificates));
    }

    @Override
    protected final TrustManager[] engineGetTrustManagers() {
        List<X509ExtendedTrustManager> delegates = new ArrayList<>();

        for (TrustManager candidate : this.systemTrustManagerFactory.getTrustManagers()) {
            if (candidate instanceof X509ExtendedTrustManager) {
                this.logger.info("Adding System Trust Manager");
                delegates.add((X509ExtendedTrustManager) candidate);
            }
        }

        if (this.certificates != null && Files.exists(this.certificates)) {
            this.logger.info(String.format("Adding TrustManager for %s", this.certificates));
            delegates.add(new FileWatchingX509ExtendedTrustManager(this.certificates, getTrustManagerFactory()));
        }

        return new TrustManager[]{new DelegatingX509ExtendedTrustManager(delegates)};
    }

    @Override
    protected final void engineInit(ManagerFactoryParameters managerFactoryParameters) throws InvalidAlgorithmParameterException {
        this.systemTrustManagerFactory.init(managerFactoryParameters);
    }

    @Override
    protected final void engineInit(KeyStore keyStore) throws KeyStoreException {
        this.systemTrustManagerFactory.init(keyStore);
    }

    private static Path getCertificatesLocation() {
        for (Path certificatesFile : OPENSSL_CERTIFICATES_FILES) {
            if (Files.exists(certificatesFile)) {
                return certificatesFile;
            }
        }

        return null;
    }

    private TrustManagerFactory getTrustManagerFactory() {
        try {
            return TrustManagerFactory.getInstance(this.algorithm, "SunJSSE");
        } catch (NoSuchAlgorithmException | NoSuchProviderException e) {
            throw new UndeclaredThrowableException(e);
        }
    }

    public static final class PKIXFactory extends CloudFoundryContainerTrustManagerFactory {

        public PKIXFactory() throws NoSuchProviderException, NoSuchAlgorithmException {
            this(getCertificatesLocation());
        }

        PKIXFactory(Path certificates) throws NoSuchAlgorithmException, NoSuchProviderException {
            super("PKIX", certificates);
        }
    }

    public static final class SimpleFactory extends CloudFoundryContainerTrustManagerFactory {

        public SimpleFactory() throws NoSuchProviderException, NoSuchAlgorithmException {
            this(getCertificatesLocation());
        }

        SimpleFactory(Path certificates) throws NoSuchAlgorithmException, NoSuchProviderException {
            super("SunX509", certificates);
        }

    }

}
