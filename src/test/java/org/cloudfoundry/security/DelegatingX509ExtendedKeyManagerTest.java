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

import org.junit.Test;

import javax.net.ssl.SSLEngine;
import javax.net.ssl.X509ExtendedKeyManager;
import java.net.Socket;
import java.security.Principal;
import java.security.PrivateKey;
import java.security.cert.X509Certificate;
import java.util.Arrays;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

public final class DelegatingX509ExtendedKeyManagerTest {

    private final X509ExtendedKeyManager keyManager1 = mock(X509ExtendedKeyManager.class);

    private final X509ExtendedKeyManager keyManager2 = mock(X509ExtendedKeyManager.class);

    private final X509ExtendedKeyManager delegatingKeyManager = new DelegatingX509ExtendedKeyManager(Arrays.asList(this.keyManager1, this.keyManager2));

    @Test
    public void chooseClientAliasFirst() {
        String[] strings = new String[0];
        Principal[] principals = new Principal[0];
        Socket socket = mock(Socket.class);

        String alias = "alias";
        when(this.keyManager1.chooseClientAlias(strings, principals, socket)).thenReturn(alias);

        assertThat(this.delegatingKeyManager.chooseClientAlias(strings, principals, socket)).isEqualTo(alias);
    }

    @Test
    public void chooseClientAliasLast() {
        String[] strings = new String[0];
        Principal[] principals = new Principal[0];
        Socket socket = mock(Socket.class);

        String alias = "alias";
        when(this.keyManager2.chooseClientAlias(strings, principals, socket)).thenReturn(alias);

        assertThat(this.delegatingKeyManager.chooseClientAlias(strings, principals, socket)).isEqualTo(alias);
    }

    @Test
    public void chooseClientAliasNone() {
        String[] strings = new String[0];
        Principal[] principals = new Principal[0];
        Socket socket = mock(Socket.class);

        assertThat(this.delegatingKeyManager.chooseClientAlias(strings, principals, socket)).isNull();
    }

    @Test
    public void chooseEngineClientAliasFirst() {
        String[] strings = new String[0];
        Principal[] principals = new Principal[0];
        SSLEngine sslEngine = mock(SSLEngine.class);

        String alias = "alias";
        when(this.keyManager1.chooseEngineClientAlias(strings, principals, sslEngine)).thenReturn(alias);

        assertThat(this.delegatingKeyManager.chooseEngineClientAlias(strings, principals, sslEngine)).isEqualTo(alias);
    }

    @Test
    public void chooseEngineClientAliasLast() {
        String[] strings = new String[0];
        Principal[] principals = new Principal[0];
        SSLEngine sslEngine = mock(SSLEngine.class);

        String alias = "alias";
        when(this.keyManager2.chooseEngineClientAlias(strings, principals, sslEngine)).thenReturn(alias);

        assertThat(this.delegatingKeyManager.chooseEngineClientAlias(strings, principals, sslEngine)).isEqualTo(alias);
    }

    @Test
    public void chooseEngineClientAliasNone() {
        String[] strings = new String[0];
        Principal[] principals = new Principal[0];
        SSLEngine sslEngine = mock(SSLEngine.class);

        assertThat(this.delegatingKeyManager.chooseEngineClientAlias(strings, principals, sslEngine)).isNull();
    }

    @Test
    public void chooseEngineServerAliasFirst() {
        String s = "";
        Principal[] principals = new Principal[0];
        SSLEngine sslEngine = mock(SSLEngine.class);

        String alias = "alias";
        when(this.keyManager1.chooseEngineServerAlias(s, principals, sslEngine)).thenReturn(alias);

        assertThat(this.delegatingKeyManager.chooseEngineServerAlias(s, principals, sslEngine)).isEqualTo(alias);
    }

    @Test
    public void chooseEngineServerAliasLast() {
        String s = "";
        Principal[] principals = new Principal[0];
        SSLEngine sslEngine = mock(SSLEngine.class);

        String alias = "alias";
        when(this.keyManager2.chooseEngineServerAlias(s, principals, sslEngine)).thenReturn(alias);

        assertThat(this.delegatingKeyManager.chooseEngineServerAlias(s, principals, sslEngine)).isEqualTo(alias);
    }

    @Test
    public void chooseEngineServerAliasNone() {
        String s = "";
        Principal[] principals = new Principal[0];
        SSLEngine sslEngine = mock(SSLEngine.class);

        assertThat(this.delegatingKeyManager.chooseEngineServerAlias(s, principals, sslEngine)).isNull();
    }

    @Test
    public void chooseServerAliasFirst() {
        String s = "";
        Principal[] principals = new Principal[0];
        Socket socket = mock(Socket.class);

        String alias = "alias";
        when(this.keyManager1.chooseServerAlias(s, principals, socket)).thenReturn(alias);

        assertThat(this.delegatingKeyManager.chooseServerAlias(s, principals, socket)).isEqualTo(alias);
    }

    @Test
    public void chooseServerAliasLast() {
        String s = "";
        Principal[] principals = new Principal[0];
        Socket socket = mock(Socket.class);

        String alias = "alias";
        when(this.keyManager2.chooseServerAlias(s, principals, socket)).thenReturn(alias);

        assertThat(this.delegatingKeyManager.chooseServerAlias(s, principals, socket)).isEqualTo(alias);
    }

    @Test
    public void chooseServerAliasNone() {
        String s = "";
        Principal[] principals = new Principal[0];
        Socket socket = mock(Socket.class);

        assertThat(this.delegatingKeyManager.chooseServerAlias(s, principals, socket)).isNull();
    }

    @Test
    public void getCertificateChainFirst() {
        String s = "";

        X509Certificate[] certificateChain = new X509Certificate[0];
        when(this.keyManager1.getCertificateChain(s)).thenReturn(certificateChain);

        assertThat(this.delegatingKeyManager.getCertificateChain(s)).isEqualTo(certificateChain);
    }

    @Test
    public void getCertificateChainLast() {
        String s = "";

        X509Certificate[] certificateChain = new X509Certificate[0];
        when(this.keyManager2.getCertificateChain(s)).thenReturn(certificateChain);

        assertThat(this.delegatingKeyManager.getCertificateChain(s)).isEqualTo(certificateChain);
    }

    @Test
    public void getCertificateChainNone() {
        String s = "";
        assertThat(this.delegatingKeyManager.getCertificateChain(s)).isNull();
    }

    @Test
    public void getClientAliases() {
        String s = "";
        Principal[] principals = new Principal[0];

        String alias1 = "alias1";
        when(this.keyManager1.getClientAliases(s, principals)).thenReturn(new String[]{alias1});

        String alias2 = "alias2";
        when(this.keyManager2.getClientAliases(s, principals)).thenReturn(new String[]{alias2});

        assertThat(this.delegatingKeyManager.getClientAliases(s, principals)).contains(alias1, alias2);
    }

    @Test
    public void getClientAliasesNull() {
        String s = "";
        Principal[] principals = new Principal[0];

        assertThat(this.delegatingKeyManager.getClientAliases(s, principals)).isEmpty();
    }

    @Test
    public void getPrivateKeyFirst() {
        String s = "";

        PrivateKey privateKey = mock(PrivateKey.class);
        when(this.keyManager1.getPrivateKey(s)).thenReturn(privateKey);

        assertThat(this.delegatingKeyManager.getPrivateKey(s)).isEqualTo(privateKey);
    }

    @Test
    public void getPrivateKeyLast() {
        String s = "";

        PrivateKey privateKey = mock(PrivateKey.class);
        when(this.keyManager2.getPrivateKey(s)).thenReturn(privateKey);

        assertThat(this.delegatingKeyManager.getPrivateKey(s)).isEqualTo(privateKey);
    }

    @Test
    public void getPrivateKeyNone() {
        String s = "";

        assertThat(this.delegatingKeyManager.getPrivateKey(s)).isNull();
    }

    @Test
    public void getServerAliases() {
        String s = "";
        Principal[] principals = new Principal[0];

        String alias1 = "alias1";
        when(this.keyManager1.getServerAliases(s, principals)).thenReturn(new String[]{alias1});

        String alias2 = "alias2";
        when(this.keyManager2.getServerAliases(s, principals)).thenReturn(new String[]{alias2});

        assertThat(this.delegatingKeyManager.getServerAliases(s, principals)).contains(alias1, alias2);
    }

    @Test
    public void getServerAliasesNull() {
        String s = "";
        Principal[] principals = new Principal[0];

        assertThat(this.delegatingKeyManager.getServerAliases(s, principals)).isEmpty();
    }

}