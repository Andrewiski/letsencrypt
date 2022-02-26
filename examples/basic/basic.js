'use strict';

const http = require('http');
const https = require('https');
const path = require('path');
const fs = require('fs');
//const LetsEncrypt = require('@andrewiski/letsencrypt');
var LetsEncrypt = null;
if (process.env.USELOCALLIB === "true"){
    LetsEncrypt = require("../../letsencrypt.js");
}else{
    LetsEncrypt = require("@andrewiski/letsencrypt");
}

var httpport = 80;
var httpsport = 443;

var certificatesFolder = "./certs";

if (certificatesFolder && certificatesFolder.startsWith("./") === true) {
    certificatesFolder = path.join(__dirname, certificatesFolder)
}

if (fs.existsSync(certificatesFolder) === false) {
    fs.mkdirSync(certificatesFolder,{ recursive: true, mode: "744" });
}


var httpsServerKey = path.join(certificatesFolder,"www.example.com.pem.key");
var httpsServerCert = path.join(certificatesFolder,"www.example.com.pem.crt");
var dnsNames = ["www.example.com"]
var certificateSubscriberEmail = "jdoe@example.com"

var letsEncryptOptions = {
    certificatesFolder:  certificatesFolder,
    useLetsEncryptStagingUrl: true
}

var letsEncrypt = new LetsEncrypt(letsEncryptOptions);

var httpRequestListener = function(req, res){
    try{
        letsEncrypt.httpRequestHandler(req,res, httpRequestLisnerNext);
    }catch(ex){
        console.error('httpRequestListener', ex);
        //res.status(500).send(ex);
        res.statusCode = 500;
        res.end(ex.message, 'utf8');
    }
}

var httpRequestListenerNext = function(req, res){
    //This get called as the Next if its not a well known 
    try{
        if (req.url === "/") {
            res.end('<html><head><title>LetsEncrypt Example</title></head><body>Lets Encrypt Example</body></html>', 'utf8');
        }else{
            console.error('File Not Found', req.path);
            res.statusCode = 404;
            res.end('File Not Found', 'utf8');
        }
    }catch(ex){
        console.error('httpRequestListenerNext', ex);
        res.statusCode = 500;
        res.end(ex.message, 'utf8');
    }

}

var httpsRequestListener = function(req, res){
    try{
        console.log("httpsRequestListener");
        if(req.url === "/"){
            res.end('<html><head><title>LetsEncrypt Example</title></head><body>Lets Encrypt Example HTTPS</body></html>', 'utf8');
        }else{
            res.statusCode = 404;
            res.end('File Not Found', 'utf8');
        }
    }catch(ex){
        console.error('httpsRequestListener', ex);
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
        
        console.log('http server listening on http port ' + httpport);
    });
}

var startHttpsServer = function(){
    let httpsOptions = getHttpsServerOptions();
    try{
        if(httpsOptions.key && httpsOptions.cert){
            https_srv = https.createServer(httpsOptions, httpsRequestListener).listen(httpsport, function () {
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

    letsEncrypt.checkCreateRenewScheduleCertificate(
        {
            keyFile:  httpsServerKey,
            certFile: httpsServerCert,
            dnsNames: dnsNames,
            certificateSubscriberEmail:certificateSubscriberEmail,  //used to create Lets Encrypt Account
            autoRenew: true,
            https_srv: https_srv,  //setSecureContext will be called on this object if we get a cert to update the current cert beign used
            useLetsEncryptStagingUrl : true,
            skipDryRun: true,
            skipChallengeTest: true,  //When set to false Started getting a self signed certificate in Windows on ChallengeTest but could not find what in the challenge was using TLS and exceptions had not stack other then Node TLS Calls.
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



//This function is called on an https certificate change to start https_srv incase we didn't have any cert fiels when we started so delayed start until they were created.
var updateHttpsServer = function () {
    if(https_srv === null){
        startHttpsServer();
        //need to update letsEncrypt.options so it will autoupdate https.setSecureContext as https_srv = null
        letsEncrypt.option.http_srv = https_srv;
    }
};

startHttpServer();
startHttpsServer();
checkCertificateStatus();






