package com.VirusTotal.VirusTotalScanner.controller;

import com.VirusTotal.VirusTotalScanner.services.ConfigService;
import com.VirusTotal.VirusTotalScanner.services.FileToScanRepositoryService;
import com.VirusTotal.VirusTotalScanner.services.Scanner;
import lombok.RequiredArgsConstructor;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

import java.util.ArrayList;
import java.util.List;

@RestController
@RequiredArgsConstructor
@RequestMapping("/api")
public class ScannerController {
    private final Scanner scanner;
    private final FileToScanRepositoryService fileToScanRepositoryService;
    private final ConfigService configService;

    @GetMapping("/stop")
    public void stopScanner() {
        scanner.stop();
    }

    @GetMapping("/allFileStatuses")
    public ResponseEntity<List<Integer>> listAllFileStatuses() {
        List<Integer> fileStatuses = new ArrayList<>();
        fileStatuses.add((int) fileToScanRepositoryService.listAllFilesToScan().stream().filter(fileToScan -> !fileToScan.isWasChecked()).count());
        fileStatuses.add((int) fileToScanRepositoryService.listAllFilesToScan().stream().filter(fileToScan -> fileToScan.isWasChecked() && !fileToScan.isVirus()).count());
        fileStatuses.add((int) fileToScanRepositoryService.listAllFilesToScan().stream().filter(fileToScan -> fileToScan.isWasChecked() && fileToScan.isVirus()).count());
        return ResponseEntity.ok(fileStatuses);
    }

    @GetMapping("/config")
    public ResponseEntity<List<String>> getCurrentConfig() {
        return ResponseEntity.ok(configService.getCurrentConfig());
    }

    @PostMapping("/config")
    public ResponseEntity<List<String>> updateCurrentConfig(@RequestBody List<String> config) {
        return ResponseEntity.ok(configService.saveConfig(config));
    }
}