package com.oktaliem.dvwa;

import com.oktaliem.SecurityScanner;
import io.github.bonigarcia.wdm.WebDriverManager;
import org.openqa.selenium.By;
import org.openqa.selenium.Proxy;
import org.openqa.selenium.WebDriver;
import org.openqa.selenium.chrome.ChromeDriver;
import org.openqa.selenium.chrome.ChromeOptions;
import org.openqa.selenium.remote.CapabilityType;
import org.openqa.selenium.remote.DesiredCapabilities;
import org.testng.annotations.AfterMethod;
import org.testng.annotations.BeforeMethod;
import org.testng.annotations.Test;
import org.zaproxy.clientapi.core.ClientApiException;

import java.io.IOException;
import java.util.concurrent.TimeUnit;

public class BaseTest extends SecurityScanner{
    public WebDriver driver;
    private static final String ZAP_ADDRESS = "localhost";
    private static final int ZAP_PORT = 8089;


    @BeforeMethod
    public void beforeTestCase() {
        /** cara 1 https://owasp.org/www-chapter-london/assets/slides/OWASPLondon-OWASP-ZAP-Selenium-20180830-PDF.pdf */
        WebDriverManager.chromedriver().setup();
        // Set Chrome Options
        ChromeOptions chromeOptions = new ChromeOptions();
        chromeOptions.addArguments("--ignore-certificate-errors");
        // Set proxy
        String proxyAddress = ZAP_ADDRESS + ":" + ZAP_PORT;
        Proxy proxy = new Proxy();
        proxy.setHttpProxy(proxyAddress)
                .setSslProxy(proxyAddress);
        // Set Desired Capabilities
        DesiredCapabilities capabilities = DesiredCapabilities.chrome();
        capabilities.setCapability(CapabilityType.PROXY, proxy);
        capabilities.setCapability(CapabilityType.ACCEPT_SSL_CERTS, true);
        capabilities.setCapability(CapabilityType.ACCEPT_INSECURE_CERTS,
                true);
        capabilities.setCapability(ChromeOptions.CAPABILITY, chromeOptions);
        driver = new ChromeDriver(capabilities);
        driver.manage().window().fullscreen();
        driver.get("http://localhost/login.php");


        /** cara 2 https://techyworks.blogspot.com/2019/05/automate-security-tests-using-OWASP-ZAP-Selenium-Jenkins.html */
//        WebDriverManager.chromedriver().setup();
//        Proxy proxy = new Proxy();
//        proxy.setHttpProxy("localhost:8089");
//        proxy.setFtpProxy("localhost:8089");
//        proxy.setSslProxy("localhost:8089");
//        DesiredCapabilities capabilities = DesiredCapabilities.chrome();
//        capabilities.setCapability(CapabilityType.PROXY, proxy);
//        driver = new ChromeDriver(capabilities);
//        driver.manage().window().maximize();
//        driver.get("http://localhost/login.php");
    }


    @AfterMethod
    public void afterTestCase() {
        driver.quit();
    }


    @Test
    public void trialTest() throws InterruptedException, IOException, ClientApiException {
        driver.findElement(By.name("username")).sendKeys("admin");
        driver.findElement(By.name("password")).sendKeys("password");
        driver.findElement(By.name("Login")).click();
        driver.findElement(By.linkText("About")).click();
        TimeUnit.MILLISECONDS.sleep(6000);
        alert("http://localhost/login.php");
    }

}
