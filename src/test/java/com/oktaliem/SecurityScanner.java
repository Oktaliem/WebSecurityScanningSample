package com.oktaliem;

import org.zaproxy.clientapi.core.*;

import java.io.IOException;
import java.io.UnsupportedEncodingException;
import java.net.URLEncoder;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.text.SimpleDateFormat;
import java.util.*;
import java.util.concurrent.TimeUnit;


public class SecurityScanner {
    private static final String ZAP_ADDRESS = "localhost";
    private static final int ZAP_PORT = 8089;
    private static final String ZAP_API_KEY = null;
    private static final List<String> blackListPlugins = Arrays.asList("1000", "1025");
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

//            long startTime = System.currentTimeMillis();
//            long timeout = TimeUnit.MINUTES.toMillis(2); // Two minutes in milli seconds
            // Loop until the ajax spider has finished or the timeout has exceeded
            while (true) {
                TimeUnit.MILLISECONDS.sleep(2000);

                String pattern = "dd MMM yyyy hh:mm:ss aa";
                SimpleDateFormat simpleDateFormat =
                        new SimpleDateFormat(pattern, new Locale("en", "SG"));
                String date = simpleDateFormat.format(new Date());

                status = (((ApiResponseElement) api.ajaxSpider.status()).getValue());
                System.out.println("Spider status : " + status+" at "+ date);
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

    private static void setIncludeAndExcludeInContext(ClientApi clientApi) throws UnsupportedEncodingException, ClientApiException {
        String includeInContext = "http://localhost:3000.*";
        clientApi.context.includeInContext(contextName, includeInContext);
        clientApi.context.excludeFromContext(contextName, "\\Qhttp://localhost:3000/login.php\\E");
        clientApi.context.excludeFromContext(contextName, "\\Qhttp://localhost:3000/logout.php\\E");
        clientApi.context.excludeFromContext(contextName, "\\Qhttp://localhost:3000/setup.php\\E");
        clientApi.context.excludeFromContext(contextName, "\\Qhttp://localhost:3000/security.php\\E");
    }
    private static void setLoggedInIndicator(ClientApi clientApi) throws UnsupportedEncodingException, ClientApiException {
        // Prepare values to set, with the logged in indicator as a regex matching the logout link
        String loggedInIndicator = "\\Q<a href=\"logout.php\">Logout</a>\\E";
        String loggedOutIndicator = "(?:Location: [./]*login\\.php)|(?:\\Q<form action=\"login.php\" method=\"post\">\\E)";
        // Actually set the logged in indicator
        clientApi.authentication.setLoggedInIndicator( contextId, loggedInIndicator);
        clientApi.authentication.setLoggedOutIndicator( contextId, loggedOutIndicator);
        // Check out the logged in indicator that is set
        System.out.println("Configured logged in indicator regex: "
                + ((ApiResponseElement) clientApi.authentication.getLoggedInIndicator(contextId)).getValue());
    }
    private static void setScriptBasedAuthenticationForDVWA(ClientApi clientApi) throws ClientApiException,
            UnsupportedEncodingException {
        String postData = "username={%username%}&password={%password%}" + "&Login=Login&user_token={%user_token%}";
        String postDataEncode = URLEncoder.encode(postData, "UTF-8");
        String sb = ("scriptName=auth-dvwa.js&Login_URL=http://localhost:3000/login.php&CSRF_Field=user_token&")
                .concat("POST_Data=").concat(postDataEncode);

        clientApi.authentication.setAuthenticationMethod(contextId, "scriptBasedAuthentication", sb.toString());
        System.out.println("Authentication config: " + clientApi.authentication.getAuthenticationMethod(contextId).toString(0));
    }
    private static String setUserAuthConfigForDVWA(ClientApi clientApi) throws ClientApiException, UnsupportedEncodingException {
        // Prepare info
        String user = "Admin";
        String username = "admin";
        String password = "password";

        // Make sure we have at least one user
        String userId = extractUserId(clientApi.users.newUser(contextId, user));

        // Prepare the configuration in a format similar to how URL parameters are formed. This
        // means that any value we add for the configuration values has to be URL encoded.
        StringBuilder userAuthConfig = new StringBuilder();
        userAuthConfig.append("Username=").append(URLEncoder.encode(username, "UTF-8"));
        userAuthConfig.append("&Password=").append(URLEncoder.encode(password, "UTF-8"));

        System.out.println("Setting user authentication configuration as: " + userAuthConfig.toString());
        clientApi.users.setAuthenticationCredentials(contextId, userId, userAuthConfig.toString());
        clientApi.users.setUserEnabled(contextId, userId, "true");
        clientApi.forcedUser.setForcedUser(contextId, userId);
        clientApi.forcedUser.setForcedUserModeEnabled(true);

        // Check if everything is set up ok
        System.out.println("Authentication config: " + clientApi.users.getUserById(contextId, userId).toString(0));
        return userId;
    }
    private static void uploadScript(ClientApi clientApi) throws ClientApiException {
        String script_name = "auth-dvwa.js";
        String script_type = "authentication";
        String script_engine = "Oracle Nashorn";
        String file_name = System.getProperty("user.dir")+"/src/main/resources/auth-dvwa.js";
        clientApi.script.load(script_name, script_type, script_engine, file_name, null);
    }
    private static String extractUserId(ApiResponse response) {
        return ((ApiResponseElement) response).getValue();
    }
    private static void scanAsUser(ClientApi clientApi, String userId, String target) throws ClientApiException {
        clientApi.spider.scanAsUser(contextId, userId, target, null, "true", null);
    }

    public void loginAuthenticationSetUp(String target) throws ClientApiException, UnsupportedEncodingException {
        ClientApi clientApi = new ClientApi(ZAP_ADDRESS, ZAP_PORT, ZAP_API_KEY);
        uploadScript(clientApi);
        setIncludeAndExcludeInContext(clientApi);
        setScriptBasedAuthenticationForDVWA(clientApi);
        setLoggedInIndicator(clientApi);
        String userId = setUserAuthConfigForDVWA(clientApi);
        scanAsUser(clientApi, userId, target);
    }

}
