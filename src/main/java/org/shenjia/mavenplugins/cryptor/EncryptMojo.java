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

import java.io.BufferedReader;
import java.io.BufferedWriter;
import java.io.File;
import java.io.FileReader;
import java.io.FileWriter;
import java.io.IOException;

import org.apache.maven.plugin.AbstractMojo;
import org.apache.maven.plugin.MojoExecutionException;
import org.apache.maven.plugin.MojoFailureException;
import org.apache.maven.plugins.annotations.Mojo;
import org.apache.maven.plugins.annotations.Parameter;
import org.springframework.security.crypto.encrypt.TextEncryptor;

@Mojo(name = "encrypt")
public class EncryptMojo extends AbstractMojo {

    @Parameter(defaultValue = "${project.basedir}/src/main/resources", readonly = true, required = true)
    private File source;

    @Parameter(defaultValue = "application.properties", readonly = true, required = true)
    private String[] includes;

    @Parameter(defaultValue = "PBKDF2WithHmacSHA256", readonly = true, required = true)
    private String algorithm;

    @Parameter(defaultValue = "${encrypt(\"", readonly = true, required = true)
    private String startToken;

    @Parameter(defaultValue = "\")}", readonly = true, required = true)
    private String endToken;

    @Parameter(readonly = true, required = true)
    private String aesSecretKey;

    @Parameter(readonly = true, required = true)
    private String aesSecretSalt;

    public void setSource(File source) {
		this.source = source;
	}

	public void setIncludes(String[] includes) {
		this.includes = includes;
	}

	public void setAlgorithm(String algorithm) {
		this.algorithm = algorithm;
	}

	public void setStartToken(String startToken) {
		this.startToken = startToken;
	}

	public void setEndToken(String endToken) {
		this.endToken = endToken;
	}

	public void setAesSecretKey(String aesSecretKey) {
		this.aesSecretKey = aesSecretKey;
	}

	public void setAesSecretSalt(String aesSecretSalt) {
		this.aesSecretSalt = aesSecretSalt;
	}

	public void execute() throws MojoExecutionException, MojoFailureException {
        TextEncryptor encryptor = new AesEncryptor(algorithm, aesSecretKey, aesSecretSalt);
        encrypt(source, encryptor);
    }

    private void encrypt(File source, TextEncryptor encryptor) throws MojoExecutionException {
        if (source.isDirectory()) {
            for (File file : source.listFiles()) {
                encrypt(file, encryptor);
            }
        }
        if (!source.isFile() || !isInclude(source)) {
            return;
        }
        getLog().info("Start processing file -> " + source.getPath());

        String[] lines;
        try (BufferedReader br = new BufferedReader(new FileReader(source))) {
            lines = br.lines().map(line -> {
                int pos = line.indexOf("=");
                if (pos > 0) {
                    String val = line.substring(pos + 1).trim();
                    if (val.startsWith(startToken) && val.endsWith(endToken)) {
                        val = val.substring(startToken.length(), val.length() - endToken.length());
                        val = encryptor.encrypt(val);
                        String key = line.substring(0, pos);
                        line = key + "=$decrypt(\"" + val + "\")";
                        getLog().info(line);
                    }
                }
                return line;
            }).toArray(size -> new String[size]);
        } catch (IOException e) {
            throw new MojoExecutionException("Failed to encrypt file content", e);
        }
        
        try (BufferedWriter bw = new BufferedWriter(new FileWriter(source))) {
            for (String line : lines) {
                bw.write(line);
                bw.newLine();
            }
        } catch (IOException e) {
            throw new MojoExecutionException("Failed to write encrypted file", e);
        }
    }

    private boolean isInclude(File file) {
        if (file.length() == 0) {
            return false;
        }
        for (String suffix : includes) {
            if (file.getName().endsWith(suffix)) {
                return true;
            }
        }
        return false;
    }
}
