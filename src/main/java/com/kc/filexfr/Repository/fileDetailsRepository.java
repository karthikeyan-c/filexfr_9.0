package com.kc.filexfr.Repository;

import com.kc.filexfr.Entity.fileDetails;
import com.kc.filexfr.Entity.fileDetailsKey;
import org.springframework.data.jpa.repository.JpaRepository;

import java.util.List;
import java.util.UUID;

public interface fileDetailsRepository extends JpaRepository<fileDetails, fileDetailsKey> {
    List<fileDetails> findAllByFileId(String fileId);
}
