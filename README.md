# @Andrewiski/LetsEncrypt
 Node.js LetsEncrypt (ACME) Helper Library

 Tool to assist with requesting lets Encrypt (ACME) certificates

 ```

letsEncrypt.createRenewServerCertificate(
    {
        keyFile: "www.example.com.pem.key",
        certFile: "www.example.com.pem.crt",
        dnsNames: ["www.example.com"]
    }
).then(
    function(result){
        console.log('Success Create/Renew Server Certificate', result);
        
    },
    function(err){
        console.error('Error Create/Renew Server Certificate', err);
    }
)


 ```
