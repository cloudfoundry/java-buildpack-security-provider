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

import javax.net.ssl.SSLEngine;
import javax.net.ssl.X509ExtendedTrustManager;
import java.net.Socket;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.Collections;
import java.util.List;

final class DelegatingX509ExtendedTrustManager extends X509ExtendedTrustManager {

    private final List<X509ExtendedTrustManager> delegates;

    DelegatingX509ExtendedTrustManager(List<X509ExtendedTrustManager> delegates) {
        this.delegates = delegates;
    }

    @Override
    public void checkClientTrusted(final X509Certificate[] x509Certificates, final String s, final Socket socket) throws CertificateException {
        with(new Consumer() {

            @Override
            public void accept(X509ExtendedTrustManager delegate) throws CertificateException {
                delegate.checkClientTrusted(x509Certificates, s, socket);
            }

        });
    }

    @Override
    public void checkClientTrusted(final X509Certificate[] x509Certificates, final String s) throws CertificateException {
        with(new Consumer() {

            @Override
            public void accept(X509ExtendedTrustManager delegate) throws CertificateException {
                delegate.checkClientTrusted(x509Certificates, s);
            }

        });
    }

    @Override
    public void checkClientTrusted(final X509Certificate[] x509Certificates, final String s, final SSLEngine sslEngine) throws CertificateException {
        with(new Consumer() {

            @Override
            public void accept(X509ExtendedTrustManager delegate) throws CertificateException {
                delegate.checkClientTrusted(x509Certificates, s, sslEngine);
            }

        });
    }

    @Override
    public void checkServerTrusted(final X509Certificate[] x509Certificates, final String s, final Socket socket) throws CertificateException {
        with(new Consumer() {

            @Override
            public void accept(X509ExtendedTrustManager delegate) throws CertificateException {
                delegate.checkServerTrusted(x509Certificates, s, socket);
            }

        });
    }

    @Override
    public void checkServerTrusted(final X509Certificate[] x509Certificates, final String s) throws CertificateException {
        with(new Consumer() {

            @Override
            public void accept(X509ExtendedTrustManager delegate) throws CertificateException {
                delegate.checkServerTrusted(x509Certificates, s);
            }

        });
    }

    @Override
    public void checkServerTrusted(final X509Certificate[] x509Certificates, final String s, final SSLEngine sslEngine) throws CertificateException {
        with(new Consumer() {

            @Override
            public void accept(X509ExtendedTrustManager delegate) throws CertificateException {
                delegate.checkServerTrusted(x509Certificates, s, sslEngine);
            }

        });
    }

    @Override
    public X509Certificate[] getAcceptedIssuers() {
        return collect(new Function() {

            @Override
            public X509Certificate[] apply(X509ExtendedTrustManager delegate) {
                return delegate.getAcceptedIssuers();
            }

        });
    }

    int size() {
        return this.delegates.size();
    }

    private X509Certificate[] collect(Function function) {
        List<X509Certificate> collected = new ArrayList<>();

        for (X509ExtendedTrustManager delegate : this.delegates) {
            X509Certificate[] candidate = function.apply(delegate);
            if (candidate != null) {
                Collections.addAll(collected, candidate);
            }
        }

        return collected.toArray(new X509Certificate[collected.size()]);

    }

    private void with(Consumer consumer) throws CertificateException {
        CertificateException exception = null;

        for (X509ExtendedTrustManager delegate : this.delegates) {
            try {
                consumer.accept(delegate);
                return;
            } catch (CertificateException e) {
                exception = e;
            }
        }

        if (exception != null) {
            throw exception;
        }
    }

    private interface Consumer {

        void accept(X509ExtendedTrustManager delegate) throws CertificateException;
    }

    private interface Function {

        X509Certificate[] apply(X509ExtendedTrustManager delegate);
    }

}
