package com.VirusTotal.VirusTotalScanner.services;

import com.VirusTotal.VirusTotalScanner.entity.FileToScan;
import com.VirusTotal.VirusTotalScanner.event.MalwareEvent;
import com.VirusTotal.VirusTotalScanner.repository.FileToScanRepository;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.context.ApplicationListener;
import org.springframework.stereotype.Service;

import java.io.File;
import java.io.IOException;
import java.util.ArrayList;
import java.util.List;
import java.util.concurrent.TimeUnit;

@Service
@Slf4j
@RequiredArgsConstructor
public class VirusDetectedService implements ApplicationListener<MalwareEvent> {
    private final FileToScanRepository fileToScanRepository;

    @Override
    public void onApplicationEvent(MalwareEvent event) {
        FileToScan file = event.getFile();
        assert file != null;
        file.setVirus(true);
        fileToScanRepository.save(file);
        Scanner.wasDbModified = true;
        try {
            ProcessBuilder processBuilder = new ProcessBuilder();
            List<String> command = new ArrayList<>();

            command.add("C:\\Users\\R0pke\\IdeaProjects\\VirusTotalScanner\\src\\main\\resources\\messagebox.exe");
            command.add("-m");
            command.add("A virus was detected with " + event.getAmmount() + " antivirus vendors flagging it as malicious");
            command.add("-b");
            command.add("Delete");
            command.add("Ignore");

            processBuilder.command(command);
            Process process = processBuilder.start();

            // Wait for the process to complete and get the exit code
            boolean completed = process.waitFor(30, TimeUnit.SECONDS);
            if (completed) {
                if (process.exitValue() == 0) {
                    log.info("User chose to proceed");
                    if (new File(event.getFile().getDirectory()).delete()) {
                        log.info("File successfully deleted");
                    } else {
                        log.error("File was not deleted");
                    }
                }
            } else {
                process.destroyForcibly();
                log.info("User closed the dialog, an exception happened or the dismiss button was clicked");
            }
        } catch (IOException | InterruptedException e) {
            e.printStackTrace();
        }
    }
}