/*
 * Copyright 2023-present the original author or authors.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *    http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package org.shenjia.mavenplugins.cryptor;

import static org.springframework.security.crypto.encrypt.AesBytesEncryptor.CipherAlgorithm.GCM;
import static org.springframework.security.crypto.keygen.KeyGenerators.secureRandom;

import java.nio.charset.Charset;
import java.nio.charset.StandardCharsets;
import java.util.Base64;

import javax.crypto.SecretKey;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.PBEKeySpec;

import org.springframework.security.crypto.codec.Hex;
import org.springframework.security.crypto.encrypt.AesBytesEncryptor;
import org.springframework.security.crypto.encrypt.BytesEncryptor;
import org.springframework.security.crypto.encrypt.TextEncryptor;

class AesEncryptor implements TextEncryptor {
    
    public static final Charset CHAREST = StandardCharsets.UTF_8; 
    private BytesEncryptor encryptor;
    
    public AesEncryptor(BytesEncryptor encryptor) {
        this.encryptor = encryptor;
    }
    
    public AesEncryptor(String algorithm, String password, String salt) {
        PBEKeySpec spec = new PBEKeySpec(password.toCharArray(), Hex.decode(salt), 2048, 256);
        try {
            SecretKey key = SecretKeyFactory.getInstance(algorithm).generateSecret(spec);
            this.encryptor = new AesBytesEncryptor(key, secureRandom(16), GCM);
        } catch (Exception e) {
            throw new RuntimeException("Build TextEncryptor failed", e);
        }
    }

    @Override
    public String encrypt(String text) {
        byte[] bytes = encryptor.encrypt(text.getBytes(CHAREST));
        return Base64.getEncoder().encodeToString(bytes);
    }

    @Override
    public String decrypt(String encrypted) {
        byte[] bytes = Base64.getDecoder().decode(encrypted);
        return new String(encryptor.decrypt(bytes), CHAREST);
    }

}
