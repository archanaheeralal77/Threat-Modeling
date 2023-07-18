# Threat-Modeling-Checklist

1. What type of application are you building?
    •	Web application
    •	Web Service
    •	Mobile Client
      etc
**Note:** Architecture questions are information used to conclude holistic view of your application
2. Who will be end users of this application?
3. Provide  critical data/asset of the application.
   Critical data/Asset:
     • Customer's Personally Identifiable Information (PII) like: Name; ID; Password; Address; Contact Numbers; Email ID; etc.
     • Customer's SSN Number (XXX-XXX-XXXX)
     • ustomer's Money transaction information
     • Customer's Banking information
       etc.
4. Provide the list of Programming Languages, / Platforms / Frameworks along with their versions used to develop this application
   • List down Server side technologies
   • List down client side technologies
   • Structured Data- JSON/XML is used to interchange data
    For example:
    Programming Language / Platforms- Version Number
  -----------------------------------------------------------
    JAVA   -  JDK x.x[version]
    Microsoft Visual Studio .NET  - Version
    Microsoft SQL Server  - Version
5. Provide the list of process that performs critical security functions?
  For example: List of process that perform critical security functions are: 
    • Authentication performed using SSO
    • Force Re-authentication when executing critical functionality
    • Passwords are managed using Active Directory
    • Cryptographic operations (key generation, encryption, and signing) are handled internally by the application

6. Data stores that contain sensitive information, such as encryption keys or authentication credentials
7. Provide details about data stores that contain sensitive information like encryption keys, Password e.t.c
    Explain how the application handles abnormal requests or processing high volume of data for any requests received by the application?
    For example: The application should be capable of detecting large number of commands or requests that may lead to Denial of Service (DOS) attack or
                 Distributed Denial of Service (DDOS) attack and eventually shutting down the system.
8. Do you have transaction signing for critical functionality?
  Transaction signing requires a user to interact with some out of bound device, such as a two factor token calculator or SMS message(OTP) to complete a
  high value transaction
 **Example Scenario-1:**
    User 'A' wants to transfer funds. Does the application request User 'A' to provide a One Time Password (OTP) before moving funds?

  **Example Scenario-2:**
    If a bank wishes to establish an online credit card registration process, they could get the user to verify that this transaction is valid by completing
    a transaction verification. In the case of mobile phones, this could simply include sending a random value (OTP) to the user's phone and set of digits
    to be entered by user.
9. Ensure that What gatekeepers are used at the entry points of the application, If yes -  please provide the details about Load balancer, Reverse Proxy,   
   Firewall etc
    Eg- Web Application Firewall, other application controls 
10. What are the various security services (network perimeter protection / firewall, host based protection, security monitoring, etc) that are enabled?
11. What all are the ports need to be opened at Network  firewall? 
12. Is IPS/IDS in place to detect or prevent the malicious traffic?
13. Authentication mechanism used by the application?
    Eg : 
    •	Username and Password (Form based Authentication)
    •	2FA
    •	OAuth
14. Are all authentication controls have been enforced on a trusted system (e.g., the server)?
15. A Centralized authentication component has been identified to perform authentication check: Java Authentication and Authorization Service, SSO,  LDAP  
    etc.
    For example : SSO, SAML, LDAP etc
16. 2FA  implementation mechanism.
    •	Client Side certificate?
    •	Hardware Token
    •	Software Token?
17. Is communication happening over secure channel.
    Eg :  TLS 1.2 and Above
          HTTPS communication over the network

18. Is Application adhering to desired Password policy.
19. Account is disabled after a certain number of failed consecutive login attempts Or Maximum login attempts should be control as per Certain Standards.
    Account lockout after 3 unsuccessful login attempts. If the number of invalid login attempts are more than three, such accounts must be locked out to
    prevent brute force attacks
20. If authentication takes place using Digital Certificates ,then design has identified the Certificate attributes, such as its validity period,
    distinguish name, signature to approve authentication
    Digital Certificate configurations
21. Ensure backdoors are not present in production code
22. Password resets should require the same level of stringent security controls as account creation and authentication. 
    •	For email based resets,  send email only to a pre-registered address with a temporary link/password.
    •	Temporary passwords and links should have a short expiration time (typically < 24 hours)
    •	First time users with temporary passwords must change their passwords on the first use
    •	The system should notify users when a password reset occurs
23. Test IDs, issued for the purpose of executing application testing such as performance and product tests, should be set to expire for a certain periods ,
    it must be reactivated after expiration to continue use.
24. Ensure the role design offers sufficient separation of privileges.
    System must implement the principle of Least Privilege. Assigned privileges must be documented as part of the design along with any identified risks and
    mitigations.
    For example: Admin Role and Normal User has different level of access restriction
25. How many of users will be going to use this application ?
26. Processes that run with different privilege levels
    For example:
    Describe different processes existed in the application and the privilege required to run those processes.

    An example of the processes will be a batch job. Person with Admin role has execute privilege to run the batch job. A regular user can add a project
    through GUI. An admin can run a batch job which can add multiple projects during one batch run. Admin is the only role who has execute privilege to run
    the batch job.
27. Share an access-control matrix depicting the Role-to-Function mapping 
    For example:

    Role                      Functions
    -------------------------------------------------
    1. Admin             User Management; Portal and Server Management
    2. Level 1            Read only access to Customer support module
    3. Level 2            Create new tickets in Customer support module and assign the same to Level 1 group
    4. Customers     Module access: Register New User; Update their respective profile; etc.
28. What is the process for Access model? Like access provision, access revoke, user roles etc..
29. The application must support disabling of accounts and terminating sessions immediately when authorization ceases. (e.g., Changes to role, employment
    status, and business process.) 
30. Assure authorization fail securely and only allow access upon successful confirmation of credentials.
31. Is database in production environment is protected from unauthorized access? Are all default database administrative logins/passwords has been removed
    or changed?
32. Is Passwords for database access following strong password policy?
33. All database accounts are created with Least Privileges
34. How does vendor securely / permanently delete data when no longer required within its backup & restore services?
35. Applications must not connect as the schema/database owner. The application's login should not have permissions to access tables directly.
36. Design should identify that direct database connectivity from an Internet accessible web server or other publicly accessed device must not be used.
37. What all are the security controls are in place for data backup? 
    •	Who will be having access to back up?
    •	What level of access they will be having?
    •	Can they delete the data backups?
38. Data must be validated at all points where it crosses a trust boundary.
    Input validation is applied whenever input is received from outside the current trust  boundary
39. All external input, no matter what it is, is examined and validated? Input validation must happen on the trusted system. 
40. Data validation should use a positive or “white listing” approach with canonicalization.
    •	Regular Expressions should be used to validate user input.
    •	If regular expressions cannot be used or are insufficient, technology-specific custom validators should be used instead.
41. All untrusted input must be validated at least on type, length, range and format.
42. All input validation failures must result in input rejection?
43. Examine How is session generated?  Unauthenticated and authenticated.
44. TLS must protect both credentials and session id at all times during and after login.
    For Example : Configure TLS latest version for ensuring encrypting information over the channel
45. Clarify how multithreaded/concurrent user session management is performed in the application.
    E.g. Two concurrent logins of same user account at same time
46. What Session Management Mechanism is used?Examine How is persistent session state secured as it crosses the network?
    •	Cookie
    •	Session Class in Java/ View State parameter in .Net
    •	URL re Writing
    •	Hidden value
    •	Others
47. Upon expiration or logout, the session and corresponding data shall be removed and fully terminate the application sessions.
48. Design clarifies all session management checks and controls are adhere?
    For example: If the application needs to pass the session ID it must pass it in cookie instead of in a URL parameter.
49. Do you restrict session lifetime and Session length ?Session inactivity timeout must not exceed 20 minutes. 
    a. Licensed applications should use 20 minutes as a default session inactivity timeout. 
      Define the time limit the session should expire after inactivity, after which the user is required to re-login again. This should be as minimal as
      possible. For example: Session inactivity timeout must not exceed 20 minute

50. Assure that if cookies contain some private information, then entire cookies are encrypted
51. Determine how the application handle error conditions
52. Design ensures that all unforeseen or unexpected error conditions are caught to protect applications from disclosing sensitive information
53. Ensure resources are released if an error occurs. And no system errors can be returned to the user.
54. Using the default framework implementation (ex: garbage collection) or custom implementation, it should be ensured to deallocate the unused allocated
    memory when an error condition occur
55. Examine What sensitive data is handled by the application?
    Provide details of Sensitive data in the Application.
    The product holistically should ensure sensitive data is properly protected through the use of encryption or compensating controls, such as  hash and
    /or password protected, data masking, or other means.
56. Highly sensitive stored information, like authentication verification data, must be stored on the trusted system. 
57. Is Data in Motion both within the organisation infrastructure and between any other Parties  encrypted?
58. Network data encrypted when in transit? (using encrypted network services such as SSH, Secure FTP, HTTPS instead of insecure network services such as         Telnet, FTP, HTTP, etc),  TLS 1.2 or higher version of SSL encryption must be used for the transmission of all sensitive information outside the trust       boundary.
59. All cryptographic functions used to protect secrets from the application user must be implemented on a trusted system (e.g., The server)
60. Is Data at Rest encrypted as per certain cryptography standard? 
61. What type of encryption is used ?
62. Where data encryption key is stored
63. Who will be having access to data encryption keys?
64. Does data encryption keys used for encrypting the data at rest is been updated/rotated regularly? If yes, how often it changed/updated/rotated?
65. Has segregation of duties implemented where people who is managing the keys does not have access to protected data?
66. What are the security controls are in place for data backup? 
    •	Who will be having access to back up?
    •	What level of access they will be having?
    •	Can they delete the data backups?
67. How long data will be retained? The Data retention policy….
68. Does application have capability to store data locally? 
69. Is Data backup encrypted? If yes Which algorithm is used?
70. Does log captures the activities of data encryption keys, key encryption keys, master key (like access, modification etc...)? 
71. Authentication credentials for accessing services external to the application such as database, email server, file server, third party APIs, etc. should     be encrypted and stored in a protected location on a trusted system.
72. Examine How are log files secured?
73. Is design identifies the level of auditing and logging necessary for the application and identifies the key parameters to be logged and audited
74. Determine your application audit activity across all tiers on all servers?
75. Design identifies the storage, security and analysis of the application log files.
    Log files should be archived regularly to ensure that they do not fill up or start to cycle, and they should be regularly analysed to detect signs of
    intrusion.
76. Make sure no sensitive information is logged in the event of errors. Sensitive Information including unnecessary system details, session identifiers
    ,passwords CC data must not be logged in the logs.
    Recommended log capture for the following:
    •	Input validation failures
    •	Authentication attempts, especially failures
    •	Access control failures
    •	Log attempts to connect with invalid or expired session tokens
    •	System exceptions
    •	Administrative functions, including changes to the security configuration settings
    •	Backend TLS connection failures
    •	Log cryptographic module failures
77. Implement a centralized routine/mechanism for all logging operations.
78. Applications must require users to be authenticated before allowing file movement across trust boundaries or between application layers. This includes
    file uploads. 
79. Limit the type of files that can be uploaded to only those types that are needed for business purposes, do not accept file types such as .EXE, .PHP,
    .JSP, etc. Checking for file type by extension alone is not sufficient, we have to check the content of the file as well. For example: it is possible to
    upload .bat or .exe files while editing their extension type as .docx or .xls at intermediate proxy.
80. Do not save files in the same web context as the application. For example: Files should either go to the content server or in the database or on File
    server.
81. The execution privileges on file upload directories must be turned off
82. Do not pass directory or file paths, use index values mapped to pre-defined list of paths
83. The absolute file path should not be exposed to the client. (Example: Do not display "C:\Users\ABC\Desktop\EmployeeDetails.xlsx", instead display just       "EmployeeDetails.xlsx")
84. Uploaded files should always be scanned for viruses and malware. Alternative is that the file location storing these files should be scanned regularly (real time scanning)
85. Validate incoming content-types 
     When POSTing or PUTting new data, the client will specify the Content-Type (e.g. application/xml or application/json) of the incoming data. The server       should never assume the Content-Type; it should always check that the Content-Type header and the content are the same type. A lack of Content-Type
    header or an unexpected Content-Type header should result in the server rejecting the content with a 406 Not Acceptable response
85. Validate response types
    It is common for REST services to allow multiple response types (e.g. application/xml or application/json, and the client specifies the preferred order      of response types by the Accept header in the request. Prohibit copying the Accept header to the Content-type header of the response. Reject the
    request (ideally with a 406 Not Acceptable response) if the Accept header does not specifically contain one of the allowable types
86. XML input validation 
     XML-based services must ensure that they are protected against common XML based attacks by using secure XML-parsing. This typically means protecting
    against XML External Entity attacks, XML-signature wrapping etc. (example of XML attacks -  http://ws-attacks.org)
87. Send security headers 
     To make sure the content of a given resources is interpreted correctly by the browser, the server should always send the Content-Type header with the
     correct Content-Type, and preferably the Content-Type header should include a charset. The server should also send an X-Content-Type-Options: nosniff
     to make sure the browser does not try to detect a different Content-Type than what is actually sent (can lead to XSS). Additionally the client should
     send an X-Frame-Options: deny to protect against drag'n drop clickjacking attacks in older browsers.
88. XML encoding 
    XML should not be constructed using string concatenation, instead an XML serializer. This ensures that the XML content sent to the browser is parseable
    and does not contain XML injection
89. REST services should be secured with a token based approach (OAuth2 recommended) or approved existing mechanism currently in place. In case of the
    server to server communication two way TLS with certificate inspection should be used.
90. API keys as well as tokens should be stored in cryptographically secure format.
91. It is recommended to use following authentication mechanisms: 
    • Client certificate authentication inspection
    • Token based authentication 
    • Wherever applicable in RESTful context, tokens should be used instead of username and password. 
92. Use the newer version of the protocol, OAuthx.x,
93. The authorization grant type depends on the method used by the application to request authorization, and the grant types supported by the API. OAuth2
    defines four grant types, each of which is useful in different cases: Please mention which  grant type is used?
    •	Authorization Code: used with server-side Applications.
    •	Implicit: used with Mobile Apps or Web Applications (applications that run on the user's device)
    •	Resource Owner Password Credentials: used with trusted Applications, such as those owned by the service itself
    •	Client Credentials: used with Applications API access
94. Is  Access token secure during transit and at rest which includes Authorization code, Access token etc.
    Always log the User out after handling the third-party OAuth authorization flow in situations where the User was not already logged into the Server
    before the OAuth initiation request 
95. When using OAuth2.0, the "Refresh Token" value must be refreshed after a specified time span. For example: Refresh tokens can be refreshed after
    30minutes
96. JWT Token
    JSON Web Token (JWT) is an open standard that defines a compact and self-contained way for securely transmitting information between parties as a JSON
    object. This information can be verified and trusted because it is digitally signed. JWTs can be signed using a secret (with the HMAC algorithm) or a
    public/private key pair using RSA. OAuth allows the definition of additional authentication mechanisms to be used by the clients when interacting with
    the authorization server.
97. Best Practices
    1. Signatures should be verified before trusting any JWT related information The authorization server should reject JWTs with an invalid signature or Message Authentication Code.
    2. The JWT should be digitally signed or have a Message Authentication Code applied by the issuer.
    3. The Secret Signing Key used for calculating and verifying the signature should be secured and only be accessible by the Issuer and the Consumer
    4. If user is passing a secret signing key to the method that verifies the signature and the signature algorithm is set to ‘none’, it should fail verification.
    5. Privacy Consideration - A JWT may contain privacy-sensitive information. When this is the case, measures should be taken to prevent disclosure of this information to unintended parties. One way to achieve this is to use an encrypted JWT ( i.e.JWE) and authenticate the recipient.
    6. if both signing and encryption are necessary, normally issuer should sign the message and then encrypt the result (thus encrypting the signature). 
    7. To protect against replay attacks, include a nonce ( jti claim), expiration time (exp claim), and creation time (iat claim) in the claims.
    If JWT is used as a bearer token.Do you verify the signature before you trust any information in the JWT.
    Ensure JWT should not be created without signature.
     JWTs may also be created without a signature or encryption. An UnsecuredJWT is a JWS using the "alg" Header Parameter value "none" and with the empty string for its JWS Signature value. 
