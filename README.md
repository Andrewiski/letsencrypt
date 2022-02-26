# @Andrewiski/LetsEncrypt
 Node.js LetsEncrypt (ACME) Helper Library

 Tool to assist with requesting lets Encrypt (ACME) certificates

 See /examples/

 ```

letsEncrypt.createRenewServerCertificate(
    {
        keyFile: "www.example.com.pem.key",  //Will Create if Missing
        certFile: "www.example.com.pem.crt",
        dnsNames: ["www.example.com"],
        autoRenew:true
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
