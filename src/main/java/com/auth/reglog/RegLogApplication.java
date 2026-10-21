package com.auth.reglog;

import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.boot.context.properties.ConfigurationPropertiesScan;

@SpringBootApplication
@ConfigurationPropertiesScan
public class RegLogApplication {

    public static void main(String[] args) {
        SpringApplication.run(RegLogApplication.class, args);
    }
}
