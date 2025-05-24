package com.VirusTotal.VirusTotalScanner.config;

import lombok.Data;
import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.stereotype.Component;

@Component
@ConfigurationProperties(prefix = "my.config")
@Data
public class UserPreferencesConfig {
    private String apiKey = "d59f374d1176f2a3884cbfd44b883c1b411437b733aa3d86fc16ef04e74c0856";
    private boolean wantBigFiles = false;
    private int maximumMBForBigFile = 0;
}