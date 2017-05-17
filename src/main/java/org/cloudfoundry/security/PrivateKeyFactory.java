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

import org.bouncycastle.asn1.pkcs.PrivateKeyInfo;
import org.bouncycastle.openssl.PEMKeyPair;
import org.bouncycastle.openssl.PEMParser;
import org.bouncycastle.openssl.jcajce.JcaPEMKeyConverter;

import java.io.IOException;
import java.io.Reader;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.PrivateKey;

final class PrivateKeyFactory {

    private static final JcaPEMKeyConverter CONVERTER = new JcaPEMKeyConverter();

    static PrivateKey generate(Path path) throws IOException {
        try (Reader in = Files.newBufferedReader(path, StandardCharsets.UTF_8)) {
            PEMParser parser = new PEMParser(in);

            Object keyPair = parser.readObject();
            if (!(keyPair instanceof PEMKeyPair)) {
                throw new IllegalStateException(String.format("%s contains an artifact that is not a key pair: %s", path, keyPair));
            }

            PrivateKeyInfo privateKeyInfo = ((PEMKeyPair) keyPair).getPrivateKeyInfo();
            if (privateKeyInfo == null) {
                throw new IllegalStateException(String.format("%s does not contain a private key", path));
            }

            return CONVERTER.getPrivateKey(privateKeyInfo);
        }
    }

}
