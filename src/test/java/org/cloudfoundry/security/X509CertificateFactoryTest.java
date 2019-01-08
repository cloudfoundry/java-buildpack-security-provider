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

import java.io.IOException;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.security.cert.CertificateException;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.failBecauseExceptionWasNotThrown;

public final class X509CertificateFactoryTest {

    @Test
    public void generateOpenSsl() throws IOException, CertificateException {
        assertThat(X509CertificateFactory.generate(Paths.get("src/test/resources/client-certificates-1.pem"))).hasSize(2);
        assertThat(X509CertificateFactory.generate(Paths.get("src/test/resources/server-certificates-48.pem"))).hasSize(48);
        assertThat(X509CertificateFactory.generate(Paths.get("src/test/resources/server-certificates-173.pem"))).hasSize(173);
    }

    @Test
    public void generateOpenSslNonCertificate() throws IOException, CertificateException {
        Path path = Paths.get("src/test/resources/client-private-key-1.pem");

        try {
            X509CertificateFactory.generate(path);
            failBecauseExceptionWasNotThrown(IllegalStateException.class);
        } catch (IllegalStateException e) {
            assertThat(e).hasMessageStartingWith(String.format("%s contains an artifact that is not a certificate: ", path));
        }
    }

}