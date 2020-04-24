package com.oktaliem;

import org.testng.annotations.Test;
import org.zaproxy.clientapi.core.ClientApiException;
import java.io.IOException;

public class SecurityTest extends SecurityScanner {

    String TARGET = "http://localhost:3000/login.php";

    @Test
    public void SpiderWithZAP() throws IOException, ClientApiException {
        spider(TARGET);
    }

    @Test
    public void SpiderAjaxWithZAP() throws IOException, ClientApiException {
        spiderWithAjax(TARGET);
    }

    @Test
    public void PassiveScanWithZAP() throws IOException, ClientApiException {
        passiveScan();
    }

    @Test
    public void ActiveScanWithZAP() {
        activeScan(TARGET);
    }

    @Test
    public void AlertWithZAP() throws IOException, ClientApiException {
        alert(TARGET);
    }


}
