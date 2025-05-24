package com.VirusTotal.VirusTotalScanner.services;

import com.VirusTotal.VirusTotalScanner.entity.FileToScan;
import com.VirusTotal.VirusTotalScanner.repository.FileToScanRepository;
import lombok.RequiredArgsConstructor;
import org.springframework.stereotype.Service;

import java.util.List;

@Service
@RequiredArgsConstructor
public class FileToScanRepositoryService {
    private final FileToScanRepository fileToScanRepository;

    public List<FileToScan> listAllFilesToScan() {
        return fileToScanRepository.findAll();
    }
}