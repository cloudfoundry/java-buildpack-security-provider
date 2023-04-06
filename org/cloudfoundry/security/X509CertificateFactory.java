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

import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.cert.jcajce.JcaX509CertificateConverter;
import org.bouncycastle.openssl.PEMParser;

import java.io.IOException;
import java.io.Reader;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.List;

final class X509CertificateFactory {

    private static final JcaX509CertificateConverter CONVERTER = new JcaX509CertificateConverter();

    static List<X509Certificate> generate(Path path) throws IOException, CertificateException {
        List<X509Certificate> certificates = new ArrayList<>();

        try (Reader in = Files.newBufferedReader(path, StandardCharsets.UTF_8)) {
            PEMParser parser = new PEMParser(in);

            Object certificate;
            while ((certificate = parser.readObject()) != null) {
                if (!(certificate instanceof X509CertificateHolder)) {
                    throw new IllegalStateException(String.format("%s contains an artifact that is not a certificate: %s", path, certificate));
                }

                certificates.add(CONVERTER.getCertificate((X509CertificateHolder) certificate));
            }
        }

        return certificates;
    }

}