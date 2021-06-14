package com.kc.filexfr.Repository;

import com.kc.filexfr.Entity.reqDetails;
import org.springframework.data.jpa.repository.JpaRepository;

import java.util.UUID;

public interface reqDetailsRepository extends JpaRepository<reqDetails, String> {
}
