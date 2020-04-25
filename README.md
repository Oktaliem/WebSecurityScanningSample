<h1 align="center"><img src="https://user-images.githubusercontent.com/26521948/72658109-63a1d400-39e7-11ea-9667-c652586b4508.png" alt="Apache JMeter logo" /></h1>
<h4 align="center">SOFTWARE TESTING ENTHUSIAST</h4>
<br>


# WebSecurityScanningSample


## ZAP Security Scanning Life cycle
Workflow-1
```
Spider --> Spider with AJAX --> Active Scan ---> Alerts --> HTML Report
```

Workflow-2
```
Spider --> Spider with AJAX --> Passive Scan ---> Alerts --> HTML Report
```

## Precondition (prepare test environment)
1. Application Under Test : Damn Vulnerable Web Application (DVWA) in Docker
```
$ docker run --rm -it -p 3000:80 vulnerables/web-dvwa
```
2. Open OWASP ZAP Proxy Desktop (Ubuntu)
```
$ zap.sh
```

## Run Automated Security Scanning
Workflow-1 (Active Scan with or without Authentication)
```
$ mvn clean test -Dtest=SecurityTest#activeScanWithoutAuthentication
$ mvn clean test -Dtest=SecurityTest#activeScanWithAuthentication
```
Workflow-2
```
$ mvn clean test -Dtest=SecurityTest#passiveScanWithoutAuthentication
$ mvn clean test -Dtest=SecurityTest#passiveScanWithAuthentication
```

## References
- https://www.zaproxy.org/getting-started/
- https://www.zaproxy.org/docs/api/?java#documentation-structure
- https://www.zaproxy.org/docs/desktop/start/pentest/

