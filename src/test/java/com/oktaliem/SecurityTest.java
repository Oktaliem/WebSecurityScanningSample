package com.oktaliem;

import org.testng.annotations.Test;
import org.zaproxy.clientapi.core.ClientApiException;
import java.io.IOException;

public class SecurityTest extends SecurityScanner {

    String TARGET = "http://localhost:3000/";

    @Test
    public void spiderWithZAP() throws IOException, ClientApiException {
        spider(TARGET);
    }

    @Test
    public void ajaxSpiderWithZAP() throws IOException, ClientApiException {
        spiderWithAjax(TARGET);
    }

    @Test
    public void passiveScanWithZAP() throws IOException, ClientApiException {
        passiveScan();
    }

    @Test
    public void activeScanWithZAP() {
        activeScan(TARGET);
    }

    @Test
    public void alertWithZAP() throws IOException, ClientApiException {
        alert(TARGET);
    }

    @Test
    public void passiveScanWithAuthentication() throws IOException, ClientApiException {
        loginAuthenticationSetUp(TARGET);
        spider(TARGET);
        spiderWithAjax(TARGET);
        passiveScan();
        alert(TARGET);
    }

    @Test
    public void activeScanWithAuthentication() throws IOException, ClientApiException {
        loginAuthenticationSetUp(TARGET);
        spider(TARGET);
        spiderWithAjax(TARGET);
        activeScan(TARGET);
        alert(TARGET);
    }

    @Test
    public void passiveScanWithoutAuthentication() throws IOException, ClientApiException {
        spider(TARGET);
        spiderWithAjax(TARGET);
        passiveScan();
        alert(TARGET);
    }

    @Test
    public void activeScanWithoutAuthentication() throws IOException, ClientApiException {
        spider(TARGET);
        spiderWithAjax(TARGET);
        activeScan(TARGET);
        alert(TARGET);
    }

}
