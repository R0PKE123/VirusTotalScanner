package com.VirusTotal.VirusTotalScanner.scanner;

import com.VirusTotal.VirusTotalScanner.entity.FileToScan;
import com.VirusTotal.VirusTotalScanner.event.MalwareEvent;
import com.VirusTotal.VirusTotalScanner.repository.FileToScanRepository;
import lombok.RequiredArgsConstructor;
import lombok.SneakyThrows;
import lombok.extern.slf4j.Slf4j;
import org.json.JSONObject;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.ApplicationEventPublisher;
import org.springframework.core.io.FileSystemResource;
import org.springframework.http.*;
import org.springframework.stereotype.Service;
import org.springframework.util.LinkedMultiValueMap;
import org.springframework.util.MultiValueMap;
import org.springframework.web.client.RestTemplate;

import java.io.File;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;


@Service
@RequiredArgsConstructor
@Slf4j
public class Scanner {
    private final FileToScanRepository fileToScanRepository;
    private final ApplicationEventPublisher publisher;
    File downloadsDir = new File(System.getenv("USERPROFILE") + "\\Downloads");
    private final boolean shouldBeRunning = true;
    @Value("${virustotal.api.key}")
    private String apiKey;
    @Value("${maximum.mb.forBigFile}")
    private int maximumMbForBigFile;
    @Value("${want.big.files}")
    private boolean wantToBeUploadingBigFiles;

    public void start() {
        log.info("Starting");
        while (shouldBeRunning) {
            if (!detectNewFiles().isEmpty()) {
                log.info("Found new file/files");
                List<FileToScan> newFilesWithMoTW = findMoTWFiles(detectNewFiles());
                if (!newFilesWithMoTW.isEmpty()) {
                    log.info("Found new file/files with MoTW");
                    checkForViruses(newFilesWithMoTW);
                }
            }
        }
    }

    @SneakyThrows
    private void checkForViruses(List<FileToScan> filesToScan) {
        final RestTemplate restTemplate = new RestTemplate();
        List<String> analysesId = new ArrayList<>();
        for (FileToScan fileToScan : filesToScan) {
            File file = new File(fileToScan.getDirectory());
            if ((file.length() / 1048576) <= 32) {
                log.info("Uploading file up to 32 MB");
                String url = "https://www.virustotal.com/api/v3/files";
                HttpHeaders headers = new HttpHeaders();
                headers.setBearerAuth(apiKey);
                headers.setContentType(MediaType.MULTIPART_FORM_DATA);
                MultiValueMap<String, Object> body = new LinkedMultiValueMap<>();
                body.add("file", new FileSystemResource(fileToScan.getDirectory()));
                HttpEntity<MultiValueMap<String, Object>> requestEntity = new HttpEntity<>(body, headers);
                ResponseEntity<String> response = restTemplate.postForEntity(url, requestEntity, String.class);
                if (response.getStatusCode().is2xxSuccessful()) {
                    JSONObject json = new JSONObject(response.getBody());
                    analysesId.add(json.getJSONObject("data").getString("id"));
                    fileToScan.setScanId(json.getJSONObject("data").getString("id"));
                } else {
                    throw new RuntimeException("Failed to upload file: " + response.getStatusCode());
                }
            } else if (wantToBeUploadingBigFiles && (file.length() / 1048576) <= maximumMbForBigFile) {
                log.info("Uploading file up to " + maximumMbForBigFile + " MB");
                String url = "https://www.virustotal.com/api/v3/files/upload_url";
                HttpHeaders headers = new HttpHeaders();
                headers.setBearerAuth(apiKey);
                HttpEntity<Void> requestEntity = new HttpEntity<>(headers);
                ResponseEntity<String> response = restTemplate.exchange(url, HttpMethod.GET, requestEntity, String.class);
                String url2 = new JSONObject(response.getBody()).getString("data");
                HttpHeaders headers2 = new HttpHeaders();
                headers2.setBearerAuth(apiKey);
                headers2.setContentType(MediaType.MULTIPART_FORM_DATA);
                MultiValueMap<String, Object> body = new LinkedMultiValueMap<>();
                body.add("file", new FileSystemResource(fileToScan.getDirectory()));
                HttpEntity<MultiValueMap<String, Object>> requestEntity2 = new HttpEntity<>(body, headers2);
                ResponseEntity<String> response2 = restTemplate.postForEntity(url2, requestEntity2, String.class);
                if (response2.getStatusCode().is2xxSuccessful()) {
                    JSONObject json = new JSONObject(response2.getBody());
                    analysesId.add(json.getJSONObject("data").getString("id"));
                    fileToScan.setScanId(json.getJSONObject("data").getString("id"));
                } else {
                    throw new RuntimeException("Failed to upload file: " + response2.getStatusCode());
                }
            }
        }
        JSONObject responseJson = new JSONObject();
        while (!responseJson.getJSONObject("data").getJSONObject("attributes").getString("status").equals("completed")) {
            wait(30000);
            for (String id : analysesId) {
                String url = "https://www.virustotal.com/api/v3/analyses/" + id;
                HttpHeaders headers = new HttpHeaders();
                headers.setBearerAuth(apiKey);
                HttpEntity<Void> requestEntity = new HttpEntity<>(headers);
                ResponseEntity<String> response = restTemplate.exchange(url, HttpMethod.GET, requestEntity, String.class);
                if (response.getStatusCode().is2xxSuccessful()) {
                    responseJson = new JSONObject(response.getBody());
                } else {
                    throw new RuntimeException("Failed to get analysis: " + response.getStatusCode());
                }
                int malicious = responseJson.getJSONObject("data").getJSONObject("attributes").getJSONObject("stats").getInt("malicious");
                if (malicious >= 5) {
                    log.info("Malicious file found");
                    publisher.publishEvent(new MalwareEvent(this, malicious, fileToScanRepository.findByScanId(id).orElse(null).getName()));
                }
            }
        }
    }

    private List<FileToScan> findMoTWFiles(List<FileToScan> filesToScan) {
        List<FileToScan> filesWithMoTW = filesToScan.stream().filter(fileToCheck -> Arrays.stream(downloadsDir.listFiles()).anyMatch(file -> file.getName().equals(fileToCheck.getName() + "Zone.Identifier:$DATA"))).toList();
        return filesWithMoTW;
    }

    private List<FileToScan> detectNewFiles() {
        List<FileToScan> allFilesToScan = Arrays.stream(downloadsDir.listFiles()).map(file -> FileToScan.builder().name(file.getName()).directory(file.getPath()).build()).toList();
        List<FileToScan> allFilesToScanThatAreNotInDB = allFilesToScan.stream().filter(fileToScan -> !fileToScanRepository.existsByName(fileToScan.getName())).toList();
        fileToScanRepository.saveAll(allFilesToScanThatAreNotInDB);
        return allFilesToScanThatAreNotInDB;
    }
}