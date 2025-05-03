package com.VirusTotal.VirusTotalScanner.util;

import com.VirusTotal.VirusTotalScanner.scanner.Scanner;
import jakarta.annotation.PostConstruct;
import lombok.RequiredArgsConstructor;
import org.springframework.stereotype.Service;

@Service
@RequiredArgsConstructor
public class StartupService {
    private final Scanner scanner;

    @PostConstruct
    public void startup() {
        scanner.start();
    }
}