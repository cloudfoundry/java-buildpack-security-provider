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

import java.util.ArrayList;
import java.util.List;

final class PemEncodedCertificateBuilder {

    private static final String BEGIN_CERTIFICATE = "-----BEGIN CERTIFICATE-----";

    private static final String END_CERTIFICATE = "-----END CERTIFICATE-----";

    private final List<String> certificates = new ArrayList<>();

    private List<String> current;

    private PemEncodedCertificateBuilder() {
    }

    static PemEncodedCertificateBuilder accumulate(PemEncodedCertificateBuilder builder, String s) {
        if (BEGIN_CERTIFICATE.equals(s)) {
            builder.start();
        }

        builder.add(s);

        if (END_CERTIFICATE.equals(s)) {
            builder.end();
        }

        return builder;

    }

    static PemEncodedCertificateBuilder combine(PemEncodedCertificateBuilder left, PemEncodedCertificateBuilder right) {
        left.pemEncodedCertificates().addAll(right.certificates);
        return left;
    }

    static PemEncodedCertificateBuilder identity() {
        return new PemEncodedCertificateBuilder();
    }

    List<String> pemEncodedCertificates() {
        return this.certificates;
    }

    private void add(String s) {
        if (this.current == null) {
            return;
        }

        this.current.add(s);
    }

    private void end() {
        if (this.current == null) {
            return;
        }

        this.certificates.add(join(this.current, "\n"));
        this.current = null;
    }

    private String join(List<String> source, String delimiter) {
        StringBuilder sb = new StringBuilder();

        int i = 0;
        for (String s : source) {
            if (i > 0) {
                sb.append(delimiter);
            }
            sb.append(s);
            i++;

        }
        return sb.toString();
    }

    private void start() {
        this.current = new ArrayList<>();
    }

}