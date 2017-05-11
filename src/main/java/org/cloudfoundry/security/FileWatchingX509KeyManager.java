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

import javax.net.ssl.X509KeyManager;
import java.net.Socket;
import java.nio.file.Path;
import java.security.Principal;
import java.security.PrivateKey;
import java.security.cert.X509Certificate;
import java.util.concurrent.atomic.AtomicReference;

final class FileWatchingX509KeyManager implements X509KeyManager {

    private final AtomicReference<X509KeyManager> delegate = new AtomicReference<>();

    private final Path source;

    FileWatchingX509KeyManager(Path source) {
        this.source = source;
    }

    @Override
    public String chooseClientAlias(String[] strings, Principal[] principals, Socket socket) {
        return this.delegate.get().chooseClientAlias(strings, principals, socket);
    }

    @Override
    public String chooseServerAlias(String s, Principal[] principals, Socket socket) {
        return this.delegate.get().chooseServerAlias(s, principals, socket);
    }

    @Override
    public X509Certificate[] getCertificateChain(String s) {
        return this.delegate.get().getCertificateChain(s);
    }

    @Override
    public String[] getClientAliases(String s, Principal[] principals) {
        return this.delegate.get().getClientAliases(s, principals);
    }

    @Override
    public PrivateKey getPrivateKey(String s) {
        return this.delegate.get().getPrivateKey(s);
    }

    @Override
    public String[] getServerAliases(String s, Principal[] principals) {
        return this.delegate.get().getServerAliases(s, principals);
    }

}
