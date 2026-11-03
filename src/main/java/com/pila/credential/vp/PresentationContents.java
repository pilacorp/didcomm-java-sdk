package com.pila.credential.vp;

import com.pila.credential.vc.Credential;
import lombok.Getter;
import lombok.Setter;

import java.time.Instant;
import java.util.ArrayList;
import java.util.List;

@Getter
@Setter
public class PresentationContents {
    private List<Object> context = new ArrayList<>();
    private String id;
    private List<String> types = new ArrayList<>();
    private String holder;
    private Instant validFrom;
    private Instant validUntil;
    private List<Credential> verifiableCredentials = new ArrayList<>();
}
