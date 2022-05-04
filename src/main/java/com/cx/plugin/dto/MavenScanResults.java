package com.cx.plugin.dto;

import com.cx.restclient.dto.ScanResults;
import java.util.HashMap;

public class MavenScanResults extends ScanResults{

    public MavenScanResults() {
        super();
    }

    private HashMap<String, String> summary = new HashMap<String, String>();

    public HashMap<String, String> getSummary() 
    {
        return summary;
    }

    public void setSummary(HashMap<String, String> summary) {
        this.summary = summary;
    }
}
