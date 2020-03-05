package com.oktaliem;

import org.zaproxy.clientapi.core.*;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.util.Arrays;
import java.util.List;
import java.util.Map;
import java.util.concurrent.TimeUnit;


public class SecurityScanner {
    private static final String ZAP_ADDRESS = "localhost";
    private static final int ZAP_PORT = 8089;
    private static final String ZAP_API_KEY = null;
    private static List<String> blackListPlugins = Arrays.asList("1000", "1025");
    private static final String contextId = "1";
    private static final String contextName = "Default Context";

    public void spider(String target) throws IOException, ClientApiException {
        ClientApi api = new ClientApi(ZAP_ADDRESS, ZAP_PORT, ZAP_API_KEY);

        try {
            // Start spidering the target
            System.out.println("Spidering target : " + target);
            ApiResponse resp = api.spider.scan(target, null, null, null, null);
            String scanID;
            int progress;

            // The scan returns a scan id to support concurrent scanning
            scanID = ((ApiResponseElement) resp).getValue();
            // Poll the status until it completes
            while (true) {
//                Thread.sleep(1000);
                TimeUnit.MILLISECONDS.sleep(1000);
                progress = Integer.parseInt(((ApiResponseElement) api.spider.status(scanID)).getValue());
                System.out.println("Spider progress : " + progress + "%");
                if (progress >= 100) {
                    break;
                }
            }
            System.out.println("Spider completed");
            // If required post process the spider results
            List<ApiResponse> spiderResults = ((ApiResponseList) api.spider.results(scanID)).getItems();

            // TODO: Explore the Application more with Ajax Spider or Start scanning the application for vulnerabilities

        } catch (Exception e) {
            System.out.println("Exception : " + e.getMessage());
            e.printStackTrace();
        }
        generateHTMLReport("Spider", api);
    }


    public void spiderWithAjax(String target) throws IOException, ClientApiException {
        ClientApi api = new ClientApi(ZAP_ADDRESS, ZAP_PORT, ZAP_API_KEY);

        try {
            // Start spidering the target
            System.out.println("Ajax Spider target : " + target);
            ApiResponse resp = api.ajaxSpider.scan(target, null, null, null);
            String status;

            long startTime = System.currentTimeMillis();
            long timeout = TimeUnit.MINUTES.toMillis(2); // Two minutes in milli seconds
            // Loop until the ajax spider has finished or the timeout has exceeded
            while (true) {
//                Thread.sleep(2000);
                TimeUnit.MILLISECONDS.sleep(2000);
                status = (((ApiResponseElement) api.ajaxSpider.status()).getValue());
                System.out.println("Spider status : " + status);
//                if (!("stopped".equals(status)) || (System.currentTimeMillis() - startTime) < timeout) {
//                    break;
//                }

                if (status.equals("stopped")) {
                    break;
                }
            }
            System.out.println("Ajax Spider completed");
            // Perform additional operations with the Ajax Spider results
            List<ApiResponse> ajaxSpiderResponse = ((ApiResponseList) api.ajaxSpider.results("0", "10")).getItems();

            // TODO: Start scanning(passive/active scan) the application to find vulnerabilities

        } catch (Exception e) {
            System.out.println("Exception : " + e.getMessage());
            e.printStackTrace();
        }
        generateHTMLReport("SpiderWithAjax", api);
    }

    public void passiveScan() throws IOException, ClientApiException {
        ClientApi api = new ClientApi(ZAP_ADDRESS, ZAP_PORT, ZAP_API_KEY);
        int numberOfRecords;

        try {
            // TODO : explore the app (Spider, etc) before using the Passive Scan API, Refer the explore section for details
            // Loop until the ajax spider has finished or the timeout has exceeded
            while (true) {
//                Thread.sleep(2000);
                TimeUnit.MILLISECONDS.sleep(2000);
                api.pscan.recordsToScan();
                numberOfRecords = Integer.parseInt(((ApiResponseElement) api.pscan.recordsToScan()).getValue());
                System.out.println("Number of records left for scanning : " + numberOfRecords);
                if (numberOfRecords == 0) {
                    break;
                }
            }
            System.out.println("Passive Scan completed");

            // Print Passive scan results/alerts
            System.out.println("Alerts:");
            System.out.println(new String(api.core.xmlreport(), StandardCharsets.UTF_8));

        } catch (Exception e) {
            System.out.println("Exception : " + e.getMessage());
            e.printStackTrace();
        }
        generateHTMLReport("PassiveScan", api);
    }

    public void activeScan(String target) {
        ClientApi api = new ClientApi(ZAP_ADDRESS, ZAP_PORT, ZAP_API_KEY);

        try {
            // TODO : explore the app (Spider, etc) before using the Active Scan API, Refer the explore section
            System.out.println("Active Scanning target : " + target);
            ApiResponse resp = api.ascan.scan(target, "True", "False", null, null, null);
            String scanid;
            int progress;

            // The scan now returns a scan id to support concurrent scanning
            scanid = ((ApiResponseElement) resp).getValue();
            // Poll the status until it completes
            while (true) {
//                Thread.sleep(5000);
                TimeUnit.MILLISECONDS.sleep(5000);
                progress =
                        Integer.parseInt(
                                ((ApiResponseElement) api.ascan.status(scanid)).getValue());
                System.out.println("Active Scan progress : " + progress + "%");
                if (progress >= 100) {
                    break;
                }
            }

            System.out.println("Active Scan complete");
            // Print vulnerabilities found by the scanning
            System.out.println("Alerts:");
            System.out.println(new String(api.core.xmlreport(), StandardCharsets.UTF_8));
            generateHTMLReport("ActiveScan", api);

        } catch (Exception e) {
            System.out.println("Exception : " + e.getMessage());
            e.printStackTrace();
        }

    }

    public void alert(String target) throws IOException, ClientApiException {
        ClientApi api = new ClientApi(ZAP_ADDRESS, ZAP_PORT, ZAP_API_KEY);

        try {
            // TODO: Check if the scanning has completed

            // Retrieve the alerts using paging in case there are lots of them
            int start = 0;
            int count = 5000;
            int alertCount = 0;
            ApiResponse resp = api.alert.alerts(target, String.valueOf(start), String.valueOf(count), null);

            while (((ApiResponseList) resp).getItems().size() != 0) {
                System.out.println("Reading " + count + " alerts from " + start);
                alertCount += ((ApiResponseList) resp).getItems().size();

                for (ApiResponse l : (((ApiResponseList) resp).getItems())) {

                    Map<String, ApiResponse> element = ((ApiResponseSet) l).getValuesMap();
                    if (blackListPlugins.contains(element.get("pluginId").toString())) {
                        // TODO: Trigger any relevant postprocessing
                    } else if ("High".equals(element.get("risk").toString())) {
                        // TODO: Trigger any relevant postprocessing
                    } else if ("Informational".equals(element.get("risk").toString())) {
                        // TODO: Ignore all info alerts - some of them may have been downgraded by security annotations
                    }
                }
                start += count;
                resp = api.alert.alerts(target, String.valueOf(start), String.valueOf(count), null);
            }
            System.out.println("Total number of Alerts: " + alertCount);

        } catch (Exception e) {
            System.out.println("Exception : " + e.getMessage());
            e.printStackTrace();
        }
        generateHTMLReport("Alert", api);
    }

    private void generateHTMLReport(String reportName, ClientApi api) throws IOException, ClientApiException {
        byte[] html = api.core.htmlreport();
        Path pathToFile = Paths.get(System.getProperty("user.dir"));
        Files.createDirectories(Paths.get(pathToFile + "/target/html"));
        Files.write(Paths.get(pathToFile + "/target/html/" + reportName + ".html"), html);
    }

}
