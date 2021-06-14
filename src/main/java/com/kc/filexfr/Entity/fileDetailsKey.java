package com.kc.filexfr.Entity;

import lombok.*;

import java.io.Serializable;
@Getter
@Setter
@AllArgsConstructor
@NoArgsConstructor
@EqualsAndHashCode
public class fileDetailsKey implements Serializable {
    private String fileId;
    private String fileName;
}
