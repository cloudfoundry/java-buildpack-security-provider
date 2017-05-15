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

import java.security.NoSuchAlgorithmException;
import java.security.Provider;
import java.security.Security;

final class ServiceUtils {

    private ServiceUtils() {
    }

    @SuppressWarnings("unchecked")
    static <T> T getService(String type, String algorithm) throws NoSuchAlgorithmException {
        for (Provider provider : Security.getProviders(String.format("%s.%s", type, algorithm))) {
            if (!(provider instanceof CloudFoundryContainerProvider)) {
                return (T) provider.getService(type, algorithm).newInstance(null);
            }
        }

        throw new IllegalStateException(String.format("Unable to find a %s", type));
    }

}
