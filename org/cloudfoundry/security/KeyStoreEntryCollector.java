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

import java.io.IOException;
import java.security.Key;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.cert.Certificate;
import java.security.cert.CertificateException;
import java.util.concurrent.atomic.AtomicInteger;

final class KeyStoreEntryCollector {

    private static final AtomicInteger COUNTER = new AtomicInteger();

    static KeyStore accumulate(KeyStore keyStore, Certificate certificate) throws KeyStoreException {
        keyStore.setCertificateEntry(getAlias(), certificate);
        return keyStore;
    }

    static KeyStore accumulate(KeyStore keyStore, Key key, char[] password, Certificate[] chain) throws KeyStoreException {
        keyStore.setKeyEntry(getAlias(), key, password, chain);
        return keyStore;
    }

    static KeyStore identity() throws KeyStoreException, CertificateException, NoSuchAlgorithmException, IOException {
        KeyStore keyStore = KeyStore.getInstance(KeyStore.getDefaultType());
        keyStore.load(null);
        return keyStore;
    }

    private static String getAlias() {
        return String.format("cloud-foundry-container-%03d", COUNTER.getAndIncrement());
    }

}