package com.kc.filexfr.Entity;

import lombok.*;

import javax.persistence.Entity;
import javax.persistence.Id;
import javax.persistence.Lob;
import javax.persistence.Table;
import java.util.List;
import java.util.UUID;

@Entity
@Data
@Table
@AllArgsConstructor
@NoArgsConstructor
public class reqDetails {
    @Id
    private String reqId;

    private Character reqType;
    private String fileId;
    private String Link1;
    private String Link2;
    private String Link3;
    @Lob
    private String cryptoKey;
    private Integer failureAttempts;
}
