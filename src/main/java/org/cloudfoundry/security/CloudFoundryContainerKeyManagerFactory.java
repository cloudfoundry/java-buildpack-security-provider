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

import javax.net.ssl.KeyManager;
import javax.net.ssl.KeyManagerFactorySpi;
import javax.net.ssl.ManagerFactoryParameters;
import java.lang.reflect.Method;
import java.security.InvalidAlgorithmParameterException;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.UnrecoverableKeyException;
import java.util.ArrayList;
import java.util.Collections;
import java.util.List;
import java.util.logging.Logger;

abstract class CloudFoundryContainerKeyManagerFactory extends KeyManagerFactorySpi {

    private final Logger logger = Logger.getLogger(this.getClass().getName());

    private final Method engineGetKeyManagers;

    private final Method engineInitKeyStoreCharArray;

    private final Method engineInitManagerFactoryParameters;

    private KeyManagerFactorySpi delegate;

    private CloudFoundryContainerKeyManagerFactory(String algorithm) throws NoSuchAlgorithmException {
        this.delegate = ServiceUtils.getService("KeyManagerFactory", algorithm);

        this.engineGetKeyManagers = ClassUtils.findMethod(this.delegate.getClass(), "engineGetKeyManagers");
        ReflectionUtils.makeAccessible(this.engineGetKeyManagers);

        this.engineInitKeyStoreCharArray = ClassUtils.findMethod(this.delegate.getClass(), "engineInit", KeyStore.class, char[].class);
        ReflectionUtils.makeAccessible(this.engineInitKeyStoreCharArray);

        this.engineInitManagerFactoryParameters = ClassUtils.findMethod(this.delegate.getClass(), "engineInit", ManagerFactoryParameters.class);
        ReflectionUtils.makeAccessible(this.engineInitManagerFactoryParameters);
    }

    @Override
    protected final KeyManager[] engineGetKeyManagers() {
        List<KeyManager> keyManagers = new ArrayList<>();
        Collections.addAll(keyManagers, (KeyManager[]) ReflectionUtils.invokeMethod(this.engineGetKeyManagers, this.delegate));

        // TODO: Add KeyManagers for Diego keys

        return keyManagers.toArray(new KeyManager[keyManagers.size()]);
    }

    @Override
    protected final void engineInit(ManagerFactoryParameters managerFactoryParameters) throws InvalidAlgorithmParameterException {
        ReflectionUtils.invokeMethod(this.engineInitManagerFactoryParameters, this.delegate, managerFactoryParameters);
    }

    @Override
    protected final void engineInit(KeyStore keyStore, char[] chars) throws KeyStoreException, NoSuchAlgorithmException, UnrecoverableKeyException {
        ReflectionUtils.invokeMethod(this.engineInitKeyStoreCharArray, this.delegate, keyStore, chars);
    }

    public static final class SunX509 extends CloudFoundryContainerKeyManagerFactory {

        public SunX509() throws NoSuchAlgorithmException {
            super("SunX509");
        }

    }

    public static final class X509 extends CloudFoundryContainerKeyManagerFactory {

        public X509() throws NoSuchAlgorithmException {
            super("NewSunX509");
        }

    }

}
