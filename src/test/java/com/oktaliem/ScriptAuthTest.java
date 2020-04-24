package com.oktaliem;

import org.testng.annotations.Test;
import org.zaproxy.clientapi.core.ApiResponse;
import org.zaproxy.clientapi.core.ApiResponseElement;
import org.zaproxy.clientapi.core.ClientApi;
import org.zaproxy.clientapi.core.ClientApiException;

import java.io.UnsupportedEncodingException;
import java.net.URLEncoder;

public class ScriptAuthTest {
    private static final String ZAP_ADDRESS = "localhost";
    private static final int ZAP_PORT = 8089;
    private static final String ZAP_API_KEY = null;
    private static final String contextId = "1";
    private static final String contextName = "Default Context";
    private static final String target = "http://localhost:3000";
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
    private static void scanAsUser(ClientApi clientApi, String userId) throws ClientApiException {
        clientApi.spider.scanAsUser(contextId, userId, target, null, "true", null);
    }

    @Test
    public void Scanning() throws ClientApiException, UnsupportedEncodingException {
        ClientApi clientApi = new ClientApi(ZAP_ADDRESS, ZAP_PORT, ZAP_API_KEY);
        uploadScript(clientApi);
        setIncludeAndExcludeInContext(clientApi);
        setScriptBasedAuthenticationForDVWA(clientApi);
        setLoggedInIndicator(clientApi);
        String userId = setUserAuthConfigForDVWA(clientApi);
        scanAsUser(clientApi, userId);
    }

}
