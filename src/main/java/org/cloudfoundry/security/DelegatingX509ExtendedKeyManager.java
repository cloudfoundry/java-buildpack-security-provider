/*
 * Copyright 2017-2018 the original author or authors.
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
import javax.net.ssl.X509ExtendedKeyManager;
import java.net.Socket;
import java.security.Principal;
import java.security.PrivateKey;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.Collections;
import java.util.List;

final class DelegatingX509ExtendedKeyManager extends X509ExtendedKeyManager {

    private final List<X509ExtendedKeyManager> delegates;

    DelegatingX509ExtendedKeyManager(List<X509ExtendedKeyManager> delegates) {
        this.delegates = delegates;
    }

    @Override
    public String chooseClientAlias(final String[] strings, final Principal[] principals, final Socket socket) {
        return with(new Function<String>() {

            @Override
            public String apply(X509ExtendedKeyManager delegate) {
                return delegate.chooseClientAlias(strings, principals, socket);
            }

        });
    }

    @Override
    public String chooseEngineClientAlias(final String[] strings, final Principal[] principals, final SSLEngine sslEngine) {
        return with(new Function<String>() {

            @Override
            public String apply(X509ExtendedKeyManager delegate) {
                return delegate.chooseEngineClientAlias(strings, principals, sslEngine);
            }

        });
    }

    @Override
    public String chooseEngineServerAlias(final String s, final Principal[] principals, final SSLEngine sslEngine) {
        return with(new Function<String>() {

            @Override
            public String apply(X509ExtendedKeyManager delegate) {
                return delegate.chooseEngineServerAlias(s, principals, sslEngine);
            }

        });
    }

    @Override
    public String chooseServerAlias(final String s, final Principal[] principals, final Socket socket) {
        return with(new Function<String>() {

            @Override
            public String apply(X509ExtendedKeyManager delegate) {
                return delegate.chooseServerAlias(s, principals, socket);
            }

        });
    }

    @Override
    public X509Certificate[] getCertificateChain(final String s) {
        return with(new Function<X509Certificate[]>() {

            @Override
            public X509Certificate[] apply(X509ExtendedKeyManager delegate) {
                return delegate.getCertificateChain(s);
            }

        });
    }

    @Override
    public String[] getClientAliases(final String s, final Principal[] principals) {
        return collect(new Function<String[]>() {

            @Override
            public String[] apply(X509ExtendedKeyManager delegate) {
                return delegate.getClientAliases(s, principals);
            }

        });
    }

    @Override
    public PrivateKey getPrivateKey(final String s) {
        return with(new Function<PrivateKey>() {

            @Override
            public PrivateKey apply(X509ExtendedKeyManager delegate) {
                return delegate.getPrivateKey(s);
            }

        });
    }

    @Override
    public String[] getServerAliases(final String s, final Principal[] principals) {
        return collect(new Function<String[]>() {

            @Override
            public String[] apply(X509ExtendedKeyManager delegate) {
                return delegate.getServerAliases(s, principals);
            }

        });
    }

    int size() {
        return this.delegates.size();
    }

    private String[] collect(Function<String[]> function) {
        List<String> collected = new ArrayList<>();

        for (X509ExtendedKeyManager delegate : this.delegates) {
            String[] candidate = function.apply(delegate);
            if (candidate != null) {
                Collections.addAll(collected, candidate);
            }
        }

        return collected.toArray(new String[collected.size()]);

    }

    private <T> T with(Function<T> function) {
        for (X509ExtendedKeyManager delegate : this.delegates) {
            T candidate = function.apply(delegate);
            if (candidate != null) {
                return candidate;
            }
        }

        return null;
    }

    private interface Function<T> {

        T apply(X509ExtendedKeyManager delegate);
    }

}
