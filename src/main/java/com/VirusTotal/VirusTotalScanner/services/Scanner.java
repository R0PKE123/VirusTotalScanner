package com.VirusTotal.VirusTotalScanner.services;

import com.VirusTotal.VirusTotalScanner.entity.FileToScan;
import com.VirusTotal.VirusTotalScanner.event.MalwareEvent;
import com.VirusTotal.VirusTotalScanner.repository.FileToScanRepository;
import com.sun.jna.Library;
import com.sun.jna.Native;
import com.sun.jna.WString;
import lombok.RequiredArgsConstructor;
import lombok.SneakyThrows;
import lombok.extern.slf4j.Slf4j;
import org.json.JSONObject;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.cache.Cache;
import org.springframework.cache.CacheManager;
import org.springframework.context.ApplicationEventPublisher;
import org.springframework.core.io.FileSystemResource;
import org.springframework.http.*;
import org.springframework.stereotype.Service;
import org.springframework.util.LinkedMultiValueMap;
import org.springframework.util.MultiValueMap;
import org.springframework.web.client.RestTemplate;

import java.io.File;
import java.util.*;

import static com.sun.jna.platform.win32.WinBase.INVALID_FILE_ATTRIBUTES;


@Service
@RequiredArgsConstructor
@Slf4j
public class Scanner {
    private final FileToScanRepository fileToScanRepository;
    private final ApplicationEventPublisher publisher;
    File downloadsDir = new File(System.getenv("USERPROFILE") + "\\Downloads");
    private final CacheManager cacheManager;
    @Value("${virustotal.api.key}")
    private String apiKey;
    @Value("${maximum.mb.forBigFile}")
    private int maximumMbForBigFile;
    @Value("${want.big.files}")
    private boolean wantToBeUploadingBigFiles;
    boolean wasDbModified = false;
    private boolean shouldBeRunning = true;

    public static boolean hasMarkOfTheWeb(String filePath) {
        if (filePath == null || filePath.isEmpty()) {
            return false;
        }
        try {
            String adsPath = filePath + ":Zone.Identifier";
            int fileAttributes = Kernel32.INSTANCE.GetFileAttributesW(new WString(adsPath));
            return fileAttributes != INVALID_FILE_ATTRIBUTES;
        } catch (Exception e) {
            return false;
        }
    }

    public void start() {
        log.info("Starting");
        while (shouldBeRunning) {
            var newFiles = detectNewFiles();
            if (!newFiles.isEmpty()) {
                log.info("Found new file/files");
                List<FileToScan> newFilesWithMoTW = findMoTWFiles(newFiles);
                if (!newFilesWithMoTW.isEmpty()) {
                    log.info("Found new file/files with MoTW");
                    checkForViruses(newFilesWithMoTW);
                }
            }
        }
    }

    public void stop() {
        log.info("Stopping");
        shouldBeRunning = false;
    }

    @SneakyThrows
    private void checkForViruses(List<FileToScan> filesToScan) {
        final RestTemplate restTemplate = new RestTemplate();
        List<String> analysesId = new ArrayList<>();
        List<FileToScan> scannedFiles = new ArrayList<>();
        for (FileToScan fileToScan : filesToScan) {
            File file = new File(fileToScan.getDirectory());
            long fileSizeInBytes = file.length();
            if (fileSizeInBytes <= 32L * 1024 * 1024) {
                scannedFiles.add(uploadFilesLessThan33MB(fileToScan, restTemplate, analysesId));
            } else if (wantToBeUploadingBigFiles && fileSizeInBytes <= maximumMbForBigFile * 1024L * 1024) {
                scannedFiles.add(uploadBiggerFiles(fileToScan, restTemplate, analysesId));
            }
        }
        Set<String> pending = new HashSet<>(analysesId);
        while (!pending.isEmpty()) {
            Thread.sleep(30000);
            pending.removeIf(id -> checkScanStatus(id, restTemplate));
        }
        for (FileToScan scannedFile : scannedFiles) {
            Optional<FileToScan> file = fileToScanRepository.findByName(scannedFile.getName());
            if (file.isPresent()) {
                fileToScanRepository.save(scannedFile);
            }
        }
    }

    private boolean checkScanStatus(String id, RestTemplate restTemplate) {
        String url = "https://www.virustotal.com/api/v3/analyses/" + id;
        HttpHeaders headers = new HttpHeaders();
        headers.add("x-apikey", apiKey);
        HttpEntity<Void> requestEntity = new HttpEntity<>(headers);
        ResponseEntity<String> response = restTemplate.exchange(url, HttpMethod.GET, requestEntity, String.class);
        if (!response.getStatusCode().is2xxSuccessful()) {
            throw new RuntimeException("Failed to get analysis: " + response.getStatusCode());
        }
        JSONObject json = new JSONObject(response.getBody());
        JSONObject attributes = json.getJSONObject("data").getJSONObject("attributes");
        String status = attributes.getString("status");
        if ("completed".equals(status)) {
            int malicious = attributes.getJSONObject("stats").getInt("malicious");
            if (malicious >= 5) {
                log.info("Malicious file detected: ID=" + id + ", detections=" + malicious);
                FileToScan file = fileToScanRepository.findByScanId(id).orElse(null);
                if (file != null) {
                    publisher.publishEvent(new MalwareEvent(this, malicious, file.getDirectory()));
                    log.info("File was malicious");
                    return true;
                }
            }
            log.info("File was not malicious");
            return true;
        }
        return false;
    }

    private FileToScan uploadBiggerFiles(FileToScan fileToScan, RestTemplate restTemplate, List<String> analysesId) {
        log.info("Uploading file up to " + maximumMbForBigFile + " MB");
        String url = "https://www.virustotal.com/api/v3/files/upload_url";
        HttpHeaders headers = new HttpHeaders();
        headers.add("x-apikey", apiKey);
        HttpEntity<Void> requestEntity = new HttpEntity<>(headers);
        ResponseEntity<String> response = restTemplate.exchange(url, HttpMethod.GET, requestEntity, String.class);
        String url2 = new JSONObject(response.getBody()).getString("data");
        HttpHeaders headers2 = new HttpHeaders();
        headers2.add("x-apikey", apiKey);
        headers2.setContentType(MediaType.MULTIPART_FORM_DATA);
        MultiValueMap<String, Object> body = new LinkedMultiValueMap<>();
        body.add("file", new FileSystemResource(fileToScan.getDirectory()));
        HttpEntity<MultiValueMap<String, Object>> requestEntity2 = new HttpEntity<>(body, headers2);
        ResponseEntity<String> response2 = restTemplate.postForEntity(url2, requestEntity2, String.class);
        if (response2.getStatusCode().is2xxSuccessful()) {
            JSONObject json = new JSONObject(response2.getBody());
            analysesId.add(json.getJSONObject("data").getString("id"));
            fileToScan.setScanId(json.getJSONObject("data").getString("id"));
            fileToScan.setWasChecked(true);
            return fileToScan;
        } else {
            throw new RuntimeException("Failed to upload file: " + response2.getStatusCode());
        }
    }

    private FileToScan uploadFilesLessThan33MB(FileToScan fileToScan, RestTemplate restTemplate, List<String> analysesId) {
        log.info("Uploading file up to 32 MB");
        String url = "https://www.virustotal.com/api/v3/files";
        HttpHeaders headers = new HttpHeaders();
        headers.add("x-apikey", apiKey);
        headers.setContentType(MediaType.MULTIPART_FORM_DATA);
        MultiValueMap<String, Object> body = new LinkedMultiValueMap<>();
        body.add("file", new FileSystemResource(fileToScan.getDirectory()));
        HttpEntity<MultiValueMap<String, Object>> requestEntity = new HttpEntity<>(body, headers);
        ResponseEntity<String> response = restTemplate.postForEntity(url, requestEntity, String.class);
        if (response.getStatusCode().is2xxSuccessful()) {
            log.info("Uploaded successfully");
            JSONObject json = new JSONObject(response.getBody());
            analysesId.add(json.getJSONObject("data").getString("id"));
            fileToScan.setScanId(json.getJSONObject("data").getString("id"));
            fileToScan.setWasChecked(true);
            return fileToScan;
        } else {
            throw new RuntimeException("Failed to upload file: " + response.getStatusCode());
        }
    }

    private List<FileToScan> findMoTWFiles(List<FileToScan> filesToScan) {
        List<FileToScan> filesWithMoTW = filesToScan.stream().filter(fileToCheck -> hasMarkOfTheWeb(fileToCheck.getDirectory())).toList();
        List<FileToScan> filesToSave = filesToScan.stream().filter(fileToScan -> !filesWithMoTW.contains(fileToScan)).toList();
        filesToSave.forEach(file -> file.setWasChecked(true));
        if (!filesToSave.isEmpty()) {
            for (FileToScan file : filesToSave) {
                fileToScanRepository.save(file);
            }
            wasDbModified = true;
        }
        return filesWithMoTW;
    }

    private List<FileToScan> detectNewFiles() {
        List<FileToScan> allFilesToScan = Arrays.stream(downloadsDir.listFiles()).map(file -> FileToScan.builder().name(file.getName()).directory(file.getPath()).build()).toList();
        List<FileToScan> toReturn = new ArrayList<>();
        List<FileToScan> toSave = new ArrayList<>();
        for (FileToScan fileToScan : allFilesToScan) {
            String statusOfFileToScan = getStatusOfFileToScanByName(fileToScan.getName());
            switch (statusOfFileToScan) {
                case "Was checked" -> {
                }
                case "Was not checked" -> toReturn.add(fileToScan);
                case "Not present" -> {
                    toSave.add(fileToScan);
                    toReturn.add(fileToScan);
                }
            }
        }
        if (!toSave.isEmpty()) {
            fileToScanRepository.saveAll(toSave);
            wasDbModified = true;
        }
        return toReturn;
    }

    public String getStatusOfFileToScanByName(final String name) {
        Cache fileToScanCache = cacheManager.getCache("filesToScan");

        if (fileToScanCache != null) {
            String cachedResult = fileToScanCache.get(name, String.class);
            if (cachedResult != null) {
                if (wasDbModified) {
                    fileToScanCache.clear();
                    wasDbModified = false;
                } else {
                    return cachedResult;
                }
            }
        }
        Optional<FileToScan> fileOpt = fileToScanRepository.findByName(name);
        boolean exists = fileOpt.isPresent();
        boolean wasChecked = false;
        if (exists) {
            wasChecked = fileOpt.get().isWasChecked();
        }
        if (exists && wasChecked) {
            if (fileToScanCache != null) {
                fileToScanCache.put(name, "Was checked");
            }
            return "Was checked";
        } else if (exists) {
            if (fileToScanCache != null) {
                fileToScanCache.put(name, "Was not checked");
            }
            return "Was not checked";
        } else {
            if (fileToScanCache != null) {
                fileToScanCache.put(name, "Not present");
            }
            return "Not present";
        }
    }


    // Windows API interface for accessing alternate data streams
    public interface Kernel32 extends Library {
        Kernel32 INSTANCE = Native.load("kernel32", Kernel32.class);

        int GetFileAttributesW(WString lpFileName);
    }

}