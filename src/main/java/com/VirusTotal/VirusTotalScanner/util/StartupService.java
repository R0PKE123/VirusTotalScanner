package com.VirusTotal.VirusTotalScanner.util;

import com.VirusTotal.VirusTotalScanner.services.Scanner;
import lombok.RequiredArgsConstructor;
import org.springframework.boot.context.event.ApplicationReadyEvent;
import org.springframework.context.event.EventListener;
import org.springframework.stereotype.Service;

@Service
@RequiredArgsConstructor
public class StartupService {
    private final Scanner scanner;

    @EventListener(ApplicationReadyEvent.class)
    public void startup() {
        scanner.start();
    }
}