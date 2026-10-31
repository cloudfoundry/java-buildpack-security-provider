/*
 * Copyright 2026 the original author or authors.
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

import org.junit.Rule;
import org.junit.Test;
import org.junit.rules.TemporaryFolder;

import java.io.File;
import java.io.IOException;
import java.nio.file.Files;
import java.util.Arrays;

import static org.assertj.core.api.Assertions.assertThat;

public class TrustStoreDiagnosticsTest {

    private static final String FINGERPRINT_1 = "03DB9E5E79FE6117177F81C11595AF598CB176AF766290DBCEB2C318B32E39A2";

    private static final String FINGERPRINT_2 = "08C396C006A21055D00826A5781A5CCFCE2C8D053AB3C197637A4A7A5BB9A650";

    private static final String FINGERPRINT_3 = "14E6D2764A4B06701C6CBC376A253775F79C782FBCB6C0EE6F99DE4BA102B9C0";

    @Rule
    public final TemporaryFolder securityDirectory = new TemporaryFolder();

    @Test
    public void blockedCountsFingerprintsAndIgnoresCommentsAndBlankLines() throws IOException {
        writeBlocklist("blocked.certs", "# comment", "", FINGERPRINT_1, "  " + FINGERPRINT_2 + "  ", FINGERPRINT_3 + "=");

        assertThat(TrustStoreDiagnostics.blocked(this.securityDirectory.getRoot().toPath()))
                .startsWith("3 blocked certificates, caDistrustPolicies=");
    }

    @Test
    public void blockedFallsBackToLegacyJava8FileName() throws IOException {
        writeBlocklist("blacklisted.certs", "# comment", FINGERPRINT_1);

        assertThat(TrustStoreDiagnostics.blocked(this.securityDirectory.getRoot().toPath()))
                .startsWith("1 blocked certificates, caDistrustPolicies=");
    }

    @Test
    public void blockedIsUnknownWhenNoBlocklistIsReadable() {
        assertThat(TrustStoreDiagnostics.blocked(this.securityDirectory.getRoot().toPath()))
                .startsWith("unknown (no readable blocked.certs or blacklisted.certs), caDistrustPolicies=");
    }

    @Test
    public void bestEffortReturnsDiagnostic() {
        assertThat(TrustStoreDiagnostics.bestEffort(() -> "diagnostic")).isEqualTo("diagnostic");
    }

    @Test
    public void bestEffortReportsUnavailableWhenAccessIsDenied() {
        assertThat(TrustStoreDiagnostics.bestEffort(() -> {
            throw new SecurityException("denied");
        })).isEqualTo("unavailable (access denied)");
    }

    private void writeBlocklist(String name, String... lines) throws IOException {
        File blocklist = new File(this.securityDirectory.getRoot(), name);
        Files.write(blocklist.toPath(), Arrays.asList(lines));
    }

}
