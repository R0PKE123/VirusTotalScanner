package com.VirusTotal.VirusTotalScanner.repository;

import com.VirusTotal.VirusTotalScanner.entity.FileToScan;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;

import java.util.List;
import java.util.Optional;

@Repository
public interface FileToScanRepository extends JpaRepository<FileToScan, Long> {
    Optional<FileToScan> findByName(String name);

    List<Optional<FileToScan>> findAllByWasChecked(boolean wasChecked);
}