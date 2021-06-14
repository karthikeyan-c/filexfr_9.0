package com.kc.filexfr.Entity;

import lombok.*;

import javax.persistence.Entity;
import javax.persistence.Id;
import javax.persistence.IdClass;
import javax.persistence.Table;
import java.util.Date;
import java.util.UUID;

@Entity
@Data
@Table
@AllArgsConstructor
@NoArgsConstructor
@IdClass(fileDetailsKey.class)
public class fileDetails {
    @Id
    private String fileId;
    @Id
    private String fileName;

    private String filePath;
    private Date expiryTime;
}
