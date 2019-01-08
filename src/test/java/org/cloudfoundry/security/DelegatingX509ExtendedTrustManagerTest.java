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

import org.junit.Test;

import javax.net.ssl.SSLEngine;
import javax.net.ssl.X509ExtendedTrustManager;
import java.net.Socket;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.util.Arrays;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.Mockito.doThrow;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.verifyZeroInteractions;
import static org.mockito.Mockito.when;

public final class DelegatingX509ExtendedTrustManagerTest {

    private final X509ExtendedTrustManager trustManager1 = mock(X509ExtendedTrustManager.class);

    private final X509ExtendedTrustManager trustManager2 = mock(X509ExtendedTrustManager.class);

    private final X509ExtendedTrustManager delegatingTrustManager = new DelegatingX509ExtendedTrustManager(Arrays.asList(this.trustManager1, this.trustManager2));

    @Test
    public void checkClientTrustedFirstPass() throws CertificateException {
        X509Certificate[] x509Certificates = new X509Certificate[0];
        String s = "";

        this.delegatingTrustManager.checkClientTrusted(x509Certificates, s);

        verify(this.trustManager1).checkClientTrusted(x509Certificates, s);
        verifyZeroInteractions(this.trustManager1);
    }

    @Test
    public void checkClientTrustedLastPass() throws CertificateException {
        X509Certificate[] x509Certificates = new X509Certificate[0];
        String s = "";

        doThrow(new CertificateException("1")).when(this.trustManager1).checkClientTrusted(x509Certificates, s);

        this.delegatingTrustManager.checkClientTrusted(x509Certificates, s);

        verify(this.trustManager2).checkClientTrusted(x509Certificates, s);
    }

    @Test
    public void checkClientTrustedNonePass() throws CertificateException {
        X509Certificate[] x509Certificates = new X509Certificate[0];
        String s = "";

        doThrow(new CertificateException("1")).when(this.trustManager1).checkClientTrusted(x509Certificates, s);
        doThrow(new CertificateException("2")).when(this.trustManager2).checkClientTrusted(x509Certificates, s);

        try {
            this.delegatingTrustManager.checkClientTrusted(x509Certificates, s);
        } catch (CertificateException e) {
            assertThat(e).hasMessage("2");
        }
    }

    @Test
    public void checkClientTrustedSocketFirstPass() throws CertificateException {
        X509Certificate[] x509Certificates = new X509Certificate[0];
        String s = "";
        Socket socket = mock(Socket.class);

        this.delegatingTrustManager.checkClientTrusted(x509Certificates, s, socket);

        verify(this.trustManager1).checkClientTrusted(x509Certificates, s, socket);
        verifyZeroInteractions(this.trustManager2);
    }

    @Test
    public void checkClientTrustedSocketLastPass() throws CertificateException {
        X509Certificate[] x509Certificates = new X509Certificate[0];
        String s = "";
        Socket socket = mock(Socket.class);

        doThrow(new CertificateException("1")).when(this.trustManager1).checkClientTrusted(x509Certificates, s, socket);

        this.delegatingTrustManager.checkClientTrusted(x509Certificates, s, socket);

        verify(this.trustManager2).checkClientTrusted(x509Certificates, s, socket);
    }

    @Test
    public void checkClientTrustedSocketNonePass() throws CertificateException {
        X509Certificate[] x509Certificates = new X509Certificate[0];
        String s = "";
        Socket socket = mock(Socket.class);

        doThrow(new CertificateException("1")).when(this.trustManager1).checkClientTrusted(x509Certificates, s, socket);
        doThrow(new CertificateException("2")).when(this.trustManager2).checkClientTrusted(x509Certificates, s, socket);

        try {
            this.delegatingTrustManager.checkClientTrusted(x509Certificates, s, socket);
        } catch (CertificateException e) {
            assertThat(e).hasMessage("2");
        }
    }

    @Test
    public void checkClientTrustedSslEngineFirstPass() throws CertificateException {
        X509Certificate[] x509Certificates = new X509Certificate[0];
        String s = "";
        SSLEngine sslEngine = mock(SSLEngine.class);

        this.delegatingTrustManager.checkClientTrusted(x509Certificates, s, sslEngine);

        verify(this.trustManager1).checkClientTrusted(x509Certificates, s, sslEngine);
        verifyZeroInteractions(this.trustManager2);
    }

    @Test
    public void checkClientTrustedSslEngineLastPass() throws CertificateException {
        X509Certificate[] x509Certificates = new X509Certificate[0];
        String s = "";
        SSLEngine sslEngine = mock(SSLEngine.class);

        doThrow(new CertificateException("1")).when(this.trustManager1).checkClientTrusted(x509Certificates, s, sslEngine);

        this.delegatingTrustManager.checkClientTrusted(x509Certificates, s, sslEngine);

        verify(this.trustManager2).checkClientTrusted(x509Certificates, s, sslEngine);
    }

    @Test
    public void checkClientTrustedSslEngineNonePass() throws CertificateException {
        X509Certificate[] x509Certificates = new X509Certificate[0];
        String s = "";
        SSLEngine sslEngine = mock(SSLEngine.class);

        doThrow(new CertificateException("1")).when(this.trustManager1).checkClientTrusted(x509Certificates, s, sslEngine);
        doThrow(new CertificateException("2")).when(this.trustManager2).checkClientTrusted(x509Certificates, s, sslEngine);

        try {
            this.delegatingTrustManager.checkClientTrusted(x509Certificates, s, sslEngine);
        } catch (CertificateException e) {
            assertThat(e).hasMessage("2");
        }
    }

    @Test
    public void checkServerTrustedFirstPass() throws CertificateException {
        X509Certificate[] x509Certificates = new X509Certificate[0];
        String s = "";

        this.delegatingTrustManager.checkServerTrusted(x509Certificates, s);

        verify(this.trustManager1).checkServerTrusted(x509Certificates, s);
        verifyZeroInteractions(this.trustManager2);
    }

    @Test
    public void checkServerTrustedLastPass() throws CertificateException {
        X509Certificate[] x509Certificates = new X509Certificate[0];
        String s = "";

        doThrow(new CertificateException("1")).when(this.trustManager1).checkServerTrusted(x509Certificates, s);

        this.delegatingTrustManager.checkServerTrusted(x509Certificates, s);

        verify(this.trustManager2).checkServerTrusted(x509Certificates, s);
    }

    @Test
    public void checkServerTrustedNonePass() throws CertificateException {
        X509Certificate[] x509Certificates = new X509Certificate[0];
        String s = "";

        doThrow(new CertificateException("1")).when(this.trustManager1).checkServerTrusted(x509Certificates, s);
        doThrow(new CertificateException("2")).when(this.trustManager2).checkServerTrusted(x509Certificates, s);

        try {
            this.delegatingTrustManager.checkServerTrusted(x509Certificates, s);
        } catch (CertificateException e) {
            assertThat(e).hasMessage("2");
        }
    }

    @Test
    public void checkServerTrustedSocketFirstPass() throws CertificateException {
        X509Certificate[] x509Certificates = new X509Certificate[0];
        String s = "";
        Socket socket = mock(Socket.class);

        this.delegatingTrustManager.checkServerTrusted(x509Certificates, s, socket);

        verify(this.trustManager1).checkServerTrusted(x509Certificates, s, socket);
        verifyZeroInteractions(this.trustManager2);
    }

    @Test
    public void checkServerTrustedSocketLastPass() throws CertificateException {
        X509Certificate[] x509Certificates = new X509Certificate[0];
        String s = "";
        Socket socket = mock(Socket.class);

        doThrow(new CertificateException("1")).when(this.trustManager1).checkServerTrusted(x509Certificates, s, socket);

        this.delegatingTrustManager.checkServerTrusted(x509Certificates, s, socket);

        verify(this.trustManager2).checkServerTrusted(x509Certificates, s, socket);
    }

    @Test
    public void checkServerTrustedSocketNonePass() throws CertificateException {
        X509Certificate[] x509Certificates = new X509Certificate[0];
        String s = "";
        Socket socket = mock(Socket.class);

        doThrow(new CertificateException("1")).when(this.trustManager1).checkServerTrusted(x509Certificates, s, socket);
        doThrow(new CertificateException("2")).when(this.trustManager2).checkServerTrusted(x509Certificates, s, socket);

        try {
            this.delegatingTrustManager.checkServerTrusted(x509Certificates, s, socket);
        } catch (CertificateException e) {
            assertThat(e).hasMessage("2");
        }
    }

    @Test
    public void checkServerTrustedSslEngineFirstPass() throws CertificateException {
        X509Certificate[] x509Certificates = new X509Certificate[0];
        String s = "";
        SSLEngine sslEngine = mock(SSLEngine.class);

        this.delegatingTrustManager.checkServerTrusted(x509Certificates, s, sslEngine);

        verify(this.trustManager1).checkServerTrusted(x509Certificates, s, sslEngine);
        verifyZeroInteractions(this.trustManager2);
    }

    @Test
    public void checkServerTrustedSslEngineLastPass() throws CertificateException {
        X509Certificate[] x509Certificates = new X509Certificate[0];
        String s = "";
        SSLEngine sslEngine = mock(SSLEngine.class);

        doThrow(new CertificateException("1")).when(this.trustManager1).checkServerTrusted(x509Certificates, s, sslEngine);

        this.delegatingTrustManager.checkServerTrusted(x509Certificates, s, sslEngine);

        verify(this.trustManager2).checkServerTrusted(x509Certificates, s, sslEngine);
    }

    @Test
    public void checkServerTrustedSslEngineNonePass() throws CertificateException {
        X509Certificate[] x509Certificates = new X509Certificate[0];
        String s = "";
        SSLEngine sslEngine = mock(SSLEngine.class);

        doThrow(new CertificateException("1")).when(this.trustManager1).checkServerTrusted(x509Certificates, s, sslEngine);
        doThrow(new CertificateException("2")).when(this.trustManager2).checkServerTrusted(x509Certificates, s, sslEngine);

        try {
            this.delegatingTrustManager.checkServerTrusted(x509Certificates, s, sslEngine);
        } catch (CertificateException e) {
            assertThat(e).hasMessage("2");
        }
    }

    @Test
    public void getAcceptedIssuers() {
        X509Certificate certificate1 = mock(X509Certificate.class);
        when(this.trustManager1.getAcceptedIssuers()).thenReturn(new X509Certificate[]{certificate1});

        X509Certificate certificate2 = mock(X509Certificate.class);
        when(this.trustManager2.getAcceptedIssuers()).thenReturn(new X509Certificate[]{certificate2});

        assertThat(this.delegatingTrustManager.getAcceptedIssuers()).contains(certificate1, certificate2);
    }

    @Test
    public void getAcceptedIssuersNull() {
        assertThat(this.delegatingTrustManager.getAcceptedIssuers()).isEmpty();
    }

}