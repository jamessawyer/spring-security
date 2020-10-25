package com.amigo.securities;

import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.boot.context.properties.ConfigurationPropertiesScan;

@SpringBootApplication
@ConfigurationPropertiesScan
public class SecuritiesApplication {

    public static void main(String[] args) {
        SpringApplication.run(SecuritiesApplication.class, args);
    }

}
