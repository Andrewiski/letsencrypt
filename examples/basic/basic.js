'use strict';

const http = require('http');
const https = require('https');
const path = require('path');
//const extend = require('extend');
const fs = require('fs');
//const Deferred = require('deferred');
//const moment = require('moment');
//const ACMECert = require('./acmeCertificateManager');
//const ACMEHttp01 = require('./acme-http-01-memory.js');


var httpport = 80;
var httpsport = 443;

var certificatesFolder = "./certs";
//var httpsServerKey = "www.example.com.pem.key"
//var httpsServerCert = "www.example.com.pem.crt"



if (certificatesFolder && certificatesFolder.startsWith("./") === true) {
    certificatesFolder = path.join(__dirname, certificatesFolder)
}

if (fs.existsSync(certificatesFolder) === false) {
    fs.mkdirSync(certificatesFolder,{ recursive: true, mode: "744" });
}


var httpsServerKey = path.join(certificatesFolder,"dev.voice.wilcowireless.com.pem.key");
var httpsServerCert = path.join(certificatesFolder,"dev.voice.wilcowireless.com.pem.crt");
var dnsNames = ["dev.voice.wilcowireless.com"]


//const openssl = require('openssl');
var LetsEncrypt = null;
if (process.env.USELOCALLIB === "true"){
    LetsEncrypt = require("../../letsencrypt.js");
}else{
    LetsEncrypt = require("@andrewiski/letsencrypt");
}


var letsEncryptOptions = {
    certificatesFolder:  certificatesFolder,
    useLetsEncryptStagingUrl: true
}

var letsEncrypt = new LetsEncrypt(letsEncryptOptions);






//routes.get('/.well-known/acme-challenge/*', function (req, res) {

var httpRequestListener = function(req, res){
    try{
        if (req.url.startsWith('/.well-known/acme-challenge/'))
        {    
            let token = req.url.substring('/.well-known/acme-challenge/'.length);
            letsEncrypt.getToken({ token:token }).then(
                function (challenge) {
                    if (challenge && challenge.keyAuthorization) {  //Add Expiration Check
                        res.setHeader('content-type', 'application/octet-stream');
                        //res.send(challenge.keyAuthorization);
                        
                        res.end(challenge.keyAuthorization, 'utf8');
                        //letsEncrypt.removeToken({ token: token })
                        //finalizeOrder();
                        console.log("Challenge Was Returned " + req.url + " " + challenge.keyAuthorization )
                    } else {
                        console.log("Challenge Not Found");
                        //res.status(404).send('Challenge Not Found');
                        res.statusCode = 404;
                        res.end('Challenge Not Found', 'utf8');
                    }
                },
                function (ex) {
                    
                    //res.status(404).send(ex);
                    res.statusCode = 500;
                    res.end('Challenge Not Found ' + ex.message, 'utf8');
                }
            );
            
        }else if (req.url === "/") {
            //res.status(200).send('<html><head><title>LetsEncrypt Example</title></head><body>Lets Encrypt Example</body></html>');
            
            res.end('<html><head><title>LetsEncrypt Example</title></head><body>Lets Encrypt Example</body></html>', 'utf8');
        
        }else{
            //res.status(404).send('Challenge Not Found');
            console.error('File Not Found', req.path);
            res.statusCode = 404;
            res.end('File Not Found', 'utf8');
        }
    }catch(ex){
        console.error('httpRequestListener', ex);
        //res.status(500).send(ex);
        res.statusCode = 500;
        res.end(ex.message, 'utf8');
    }

}

var httpsRequestListener = function(req, res){
    try{
        console.log("httpsRequestListener");
        if(req.url === "/"){
            //res.status(200).send('<html><head><title>LetsEncrypt Example</title></head><body>Lets Encrypt Example</body></html>');
            res.end('<html><head><title>LetsEncrypt Example</title></head><body>Lets Encrypt Example HTTPS</body></html>', 'utf8');
        }else{
            //res.status(404).send('File Not Found');
            res.statusCode = 404;
            res.end('File Not Found', 'utf8');
        }
    }catch(ex){
        console.error('httpsRequestListener', ex);
        //res.status(500).send(ex);
        res.statusCode = 500;
        res.end(ex.message, 'utf8');
    }
    
}


var https_srv = null;
var http_srv = null;


var getHttpsServerOptions = function () {
    
    var httpsOptions = {
        
    };
    if(fs.existsSync(httpsServerKey) && fs.existsSync(httpsServerCert) ){
        httpsOptions.key = fs.readFileSync( httpsServerKey);
        httpsOptions.cert = fs.readFileSync( httpsServerCert);
    }
    return httpsOptions;
};


var startHttpServer = function(){
    http_srv = http.createServer(httpRequestListener).listen(httpport, function () {
        //console.log('Express server listening on port ' + port);
        console.log('http server listening on http port ' + httpport);
    });
}

var startHttpsServer = function(){
    let httpsOptions = getHttpsServerOptions();
    try{
        if(httpsOptions.key && httpsOptions.cert){
            https_srv = https.createServer(httpsOptions, httpsRequestListener).listen(httpsport, function () {
                //console.log('Express server listening on port ' + port);
                console.log('https server listening on https port ' + httpsport);
            });
        }else{
            console.log('https missing key and certs server not started');
        }
    }catch(ex){
        console.error('https failed to start server on https port ' + httpsport, ex);
    }
}


var checkCertificateStatus = function(){

    var needToCreateCertificates = false;
    if(fs.existsSync( httpsServerKey) == false || fs.existsSync(httpsServerCert) == false ){
        needToCreateCertificates = true;
    }
    if(needToCreateCertificates === false ){
        try{
           var x509Cert = letsEncrypt.loadX509CertSync({certFile:httpsServerCert , keyFile:httpsServerKey });
           if(x509Cert.isExpired === true){
            needToCreateCertificates = true;
           }
           if(x509Cert.privateKeyValid === false){
            needToCreateCertificates = true;
           }
        }catch(ex){
            needToCreateCertificates = true;
        }
    }

    if(needToCreateCertificates === true || fs.existsSync(httpsServerKey) === false || fs.existsSync(httpsServerCert) === false ){
        letsEncrypt.createRenewServerCertificate(
            {
                keyFile:  httpsServerKey,
                certFile: httpsServerCert,
                dnsNames: dnsNames,
                certificateSubscriberEmail:"adevries@digitalexample.com",  //used to create Lets Encrypt Account
                https_srv: https_srv,  //setSecureContext will be called on this object if we get a cert to update the current cert beign used
                useLetsEncryptStagingUrl : true,
                skipDryRun: true,
                skipChallengeTest: false,
                debug: true
                
                //acmeServerUrlOverride: null,
                //retryInterval: 15000,
                //retryPending: 10,
                //retryPoll: 10,
                //deauthWait: 30000

            }
        ).then(
            function(result){
                console.log('Success Create/Renew Server Certificate', result);
                updateHttpsServer()
            },
            function(err){
                console.error('Error Create/Renew Server Certificate', err);
            }
        )    
    }
}



//This function is called on an https certificate change
var updateHttpsServer = function () {
    if(https_srv === null){
        startHttpsServer() 
    }
    if(https_srv !== null){
        https_srv.setSecureContext(getHttpsServerOptions());
    }
};

startHttpServer();
startHttpsServer();
checkCertificateStatus();






