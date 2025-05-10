package com.VirusTotal.VirusTotalScanner.services;

import com.VirusTotal.VirusTotalScanner.event.MalwareEvent;
import lombok.RequiredArgsConstructor;
import lombok.SneakyThrows;
import lombok.extern.slf4j.Slf4j;
import org.springframework.context.ApplicationListener;
import org.springframework.stereotype.Service;

import javax.swing.*;
import java.nio.file.Path;

@Service
@Slf4j
@RequiredArgsConstructor
public class VirusDetectedService implements ApplicationListener<MalwareEvent> {
    @SneakyThrows
    @Override
    public void onApplicationEvent(MalwareEvent event) {
        String message = "Virus detected in " + event.getDirectory() + " with " + event.getAmmount() + " antiviruses marking it as malicious";
        String title = "Virus detected";
        Object[] options = {"Delete", "Ignore"};
        int result = JOptionPane.showOptionDialog(
                null,
                message,
                title,
                JOptionPane.YES_NO_OPTION,
                JOptionPane.WARNING_MESSAGE,
                null,
                options,
                options[0]
        );
        if (result == JOptionPane.YES_OPTION) {
            log.info("User chose to delete the virus with path of " + event.getDirectory());
            java.nio.file.Files.deleteIfExists(Path.of(event.getDirectory()));
        } else {
            log.info("User chose to ignore file with filepath " + event.getDirectory() + " or closed the dialog");
        }
    }
}