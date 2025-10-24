package com.maclebtec.security.saml;

import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;

/**
 * Spring Boot アプリケーションのエントリーポイント
 */
@SpringBootApplication
public class SamlServiceProviderApplication {

    public static void main(String[] args) {
        SpringApplication.run(SamlServiceProviderApplication.class, args);
    }
}
