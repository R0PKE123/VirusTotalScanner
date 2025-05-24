package com.VirusTotal.VirusTotalScanner.services;

import com.VirusTotal.VirusTotalScanner.config.UserPreferencesConfig;
import lombok.RequiredArgsConstructor;
import org.springframework.stereotype.Service;

import java.util.List;

@Service
@RequiredArgsConstructor
public class ConfigService {
    private final UserPreferencesConfig userPreferencesConfig;

    public List<String> getCurrentConfig() {
        return List.of(userPreferencesConfig.getApiKey(), String.valueOf(userPreferencesConfig.isWantBigFiles()), String.valueOf(userPreferencesConfig.getMaximumMBForBigFile()));
    }

    public List<String> saveConfig(List<String> config) {
        userPreferencesConfig.setApiKey(config.get(0));
        userPreferencesConfig.setWantBigFiles(Boolean.parseBoolean(config.get(1)));
        userPreferencesConfig.setMaximumMBForBigFile(Integer.parseInt(config.get(2)));
        return config;
    }
}