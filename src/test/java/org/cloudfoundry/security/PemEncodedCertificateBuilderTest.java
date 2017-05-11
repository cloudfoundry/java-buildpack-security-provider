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

import java.io.IOException;
import java.nio.charset.Charset;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.util.List;

import static org.assertj.core.api.Assertions.assertThat;

public final class PemEncodedCertificateBuilderTest {

    @Test
    public void darwin() throws IOException {
        assertThat(getPemEncodedCertificates(Paths.get("src/test/resources/darwin-48.pem"))).hasSize(48);
    }

    @Test
    public void unix() throws IOException {
        assertThat(getPemEncodedCertificates(Paths.get("src/test/resources/unix-173.pem"))).hasSize(173);
    }

    private List<String> getPemEncodedCertificates(Path source) throws IOException {
        List<String> lines = Files.readAllLines(source, Charset.defaultCharset());

        PemEncodedCertificateBuilder pemEncodedCertificateBuilder = PemEncodedCertificateBuilder.identity();
        for (String line : lines) {
            PemEncodedCertificateBuilder.accumulate(pemEncodedCertificateBuilder, line);
        }

        return pemEncodedCertificateBuilder.pemEncodedCertificates();
    }

}