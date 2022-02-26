"use strict";

const { spawn } = require('child_process');
const debug = require('debug')('letsencrypt');
const path = require('path');
const extend = require('extend');
const Deferred = require('deferred');
const fs = require('fs');
const moment = require('moment');
const { Certificate, PrivateKey } = require('@fidm/x509');
const ACMECert = require('./acmeCertificateManager');
const ACMEHttp01 = require('./acme-http-01-memory.js');

var LetsEncrypt = function (options) {
    var self = this;
    var defaultOptions = {
        certificatesFolder: './certs',
        accountFolder: './certs/accounts',
        backupFolder: './certs/backups',
        eventHandler: null,
        canRenewInDays: 30
    };
    


    if(options.certificatesFolder){
        defaultOptions.accountFolder = path.join(options.certificatesFolder, 'accounts');
        defaultOptions.backupFolder = path.join(options.certificatesFolder, 'backups');
    }

    self.options = extend({}, defaultOptions, options);

   
    if (self.options.certificatesFolder.startsWith('./') === true) {
        self.options.certificatesFolder = path.join(__dirname, self.options.certificatesFolder.substring(1));
    }

    if (self.options.accountFolder.startsWith('./') === true) {
        self.options.accountFolder = path.join(__dirname, self.options.accountFolder.substring(1));
    }

    if (self.options.backupFolder.startsWith('./') === true) {
        self.options.backupFolder = path.join(__dirname, self.options.backupFolder.substring(1));
    }

    if (!fs.existsSync(self.options.certificatesFolder)){
        fs.mkdirSync(self.options.certificatesFolder, { recursive: true, mode: "744" });
    }

    if (!fs.existsSync(self.options.accountFolder)){
        fs.mkdirSync(self.options.accountFolder, { recursive: true, mode: "744" });
    }

    if (!fs.existsSync(self.options.backupFolder)){
        fs.mkdirSync(self.options.backupFolder, { recursive: true, mode: "744" });
    }

    var isObject = function(value){
        if(value instanceof Object){
            return true;
        }else{
            return false;
        }
    }
    var acmeNotify = function (ev, msg) {
        let data = null;
        let message = '';
        if (isObject(msg)) {
            data = msg;
            message = ev;
        } else {
            message = msg;
        }
        if (ev === 'error' || ev === 'warning') {
            debug(ev, 'Acme', msg || '');
             
            //emit('createLetsEncrypt', { status: 'progress', success: false, error: ev, msg: message || '', data: data });
            
        } else {
            debug( 'info', 'Acme', ev || '', msg || '');
            
            //emit('createLetsEncrypt', { status: 'progress', success: false, error: null, msg: message || '', data: data });
            
        }

    };

    var acmehttp01 = ACMEHttp01.create(); 


    


    var getToken = function(token){
        return acmehttp01.get(token);
    }
    var removeToken = function(token){
        return acmehttp01.remove(token);
    }

   
    

    var loadX509CertSync = function (options) {
            
        try {

            let certBuffer = null;

            if (Buffer.isBuffer(options.certFile) === true) {
                vertBuffer = options.certFile;
            } else {
                //debug('info', 'Reading public Server Cert File');
                if (fs.existsSync(options.certFile)) {
                    certBuffer = fs.readFileSync(options.certFile, { encoding: 'ascii' });
                }
            }

            let key = null;
            if (options.keyFile) {
                try {
                    let keyBuffer = null;
                    if (Buffer.isBuffer(options.keyFile) === true) {
                        keyBuffer = options.keyFile;
                    } else {
                        if (options.keyFile && fs.existsSync(options.keyFile)) {
                            keyBuffer = fs.readFileSync(options.keyFile, { encoding: 'ascii' });
                        }
                    }
                    key = PrivateKey.fromPEM(keyBuffer);
                } catch (ex) {
                    debug('warning', 'Error Loading Private Pem Cert');
                }

            }

            var retval = null;
            var certs = [];
            certs = Certificate.fromPEMs(certBuffer);
            let now = new Date();
            for (let i = 0; i < certs.length; i++) {
                let x509cert = certs[i];
                //default are checks to false
                x509cert.isIssuerThisPem = false;
                x509cert.foundIssuerThisPem = false;
                x509cert.signatureIsValidIssuerThisPem = false;
                x509cert.privateKeyValid = false;
                x509cert.isExpired = false;
                if(x509cert.validFrom > now && x509cert.validTo < now){
                    x509cert.isExpired = true;
                }
                let canRenewDate = new Date();
                canRenewDate.setTime(now.getTime()-(self.options.canRenewInDays*86400000));
                if(x509cert.validTo <= canRenewDate){
                    x509cert.canBeRenewed = true;
                }
                retval = x509cert;
                if (key) {
                    try {
                        const data = Buffer.allocUnsafe(100);
                        const signature = key.sign(data, 'sha256');
                        x509cert.privateKeyValid = x509cert.publicKey.verify(data, signature, 'sha256');
                        
                        break;
                        debug('info', 'Found valid private Key');
                    } catch (ex) {
                        debug('warning', 'Error Loading Private Pem to Test x509 Cert');
                    }
                }

            }

            //Check if any of the certs are signed by other certs is so check that they are valid
            for (let i = 0; i < certs.length; i++) {
                let x509cert = certs[i];
                //See if Pem contains the Authority Cert
                for (var k = 0; k < certs.length; k++) {
                    let testCert = certs[k];
                    if (k !== i && x509cert.isIssuer(testCert)) {
                        try {
                            testCert.isIssuerThisPem = true;
                            x509cert.foundIssuerThisPem = true;
                            if (testCert.checkSignature(x509cert) === null) {
                                x509cert.signatureIsValidIssuerThisPem = true;
                                x509cert.issuerCert = testCert;
                            }
                            
                        } catch (ex) {
                            debug('warning', 'Error Validating Issuer In Same Pem x509 Cert');
                        }
                    }

                }
            }
            
            return retval;

        } catch (ex) {
            debug('error', 'Error loading Public Cert', ex);
            throw ex;
        }

    }
    var loadX509Cert = function (options) {
        let deferred = Deferred();

        try {
            var certs = [];
            certs = this.loadX509PublicCertSync(options);
            deferred.resolve(certs);

        } catch (ex) {
            debug('error', 'Error loading Public Cert', ex);
            deferred.reject('error', ex);
        }
        return deferred.promise;

    } 

    
    var checkCertificate = function(options){
        var needToCreateCertificates = false;
            if(fs.existsSync( options.keyFile) == false || fs.existsSync(options.certFile) == false ){
                needToCreateCertificates = true;
            }
            if(needToCreateCertificates === false ){
                try{
                    var x509Cert = loadX509CertSync({certFile:options.certFile , keyFile:options.keyFile });
                    if(x509Cert.isExpired === true){
                        needToCreateCertificates = true;
                    }
                    if(x509Cert.privateKeyValid === false){
                        needToCreateCertificates = true;
                    }
                    //Are we within the Renew Windows
                    if(x509Cert.canBeRenewed){
                        needToCreateCertificates = true;
                    }
                    //IS the current certificate an exact match for the dns names as if the changed the DNS Names we should request a new Certificate
                    if(x509Cert.dnsNames.length === options.dnsNames.length){
                        for (let i = 0; i < options.dnsNames.length; i++) {
                            let foundDnsName = false;
                            for (let k = 0; k < x509Cert.dnsNames.length; i++) {
                                if(options.dnsNames[i] === x509Cert.dnsNames[k]){
                                    foundDnsName = true;
                                    break;
                                }
                            }
                            if(foundDnsName === false){
                                needToCreateCertificates = true;
                                break;
                            }
                        }
                    }else{
                        needToCreateCertificates = true;
                    }

                    
                }catch(ex){
                    needToCreateCertificates = true;
                }
            }
            return needToCreateCertificates;
    }


    var httpRequestHandler = function(req, res, next){
        try{
            if (req.url.startsWith('/.well-known/acme-challenge/'))
            {    
                let token = req.url.substring('/.well-known/acme-challenge/'.length);
                getToken({ token:token }).then(
                    function (challenge) {
                        if (challenge && challenge.keyAuthorization) {  //Add Expiration Check
                            res.setHeader('content-type', 'application/octet-stream');
                            //res.send(challenge.keyAuthorization);
                            
                            res.end(challenge.keyAuthorization, 'utf8');
                            //letsEncrypt.removeToken({ token: token })
                            //finalizeOrder();
                            debug("info","Challenge Was Returned " + req.url + " " + challenge.keyAuthorization )
                        } else {
                            debug("warning","Challenge Not Found");
                            //res.status(404).send('Challenge Not Found');
                            res.statusCode = 404;
                            res.end('Challenge Not Found');
                        }
                    },
                    function (ex) {
                        debug("error",'Challenge Not Found', ex);
                        //res.status(404).send(ex);
                        res.statusCode = 500;
                        res.end('Challenge Not Found ' + ex.message, 'utf8');
                    }
                );
                
            }else {
                if(next){
                    next();
                }

            }
            
        }catch(ex){
            debug("error",'httpRequestListener', ex);
            //res.status(500).send(ex);
            throw(ex);
        }
    
    }

    var autoRenewList = {};
    var processAutoRenewList = function(){
        try{
            for (const [key, value] of Object.entries(autoRenewList)) {
                debug("info", `processing autorenew for ${key}`);
                value.lastRunStart = new Date();
                checkCreateRenewScheduleCertificate(value.options).then(
                    function(result){
                        debug("info", `success processing autorenew for ${key}`);
                        value.lastResult = result;
                        value.lastRunEnd = new Date();
                    },
                    function(err){
                        debug("error", `success processing autorenew for ${key}`);
                        value.lastResult = err;
                        value.lastRunEnd = new Date();
                    }
                )
            }
        }catch(ex){
            debug( 'error', 'processAutoRenewList', ex);
        }   
    }
    var autoRenewTimer = null;
    var startAutoRenewScheduler = function()
    {
        if(autoRenewTimer !== null){
            clearTimeout(autoRenewTimer)
        }

        autoRenewTimer = setTimeout(processAutoRenewList, 1000 * 60 * 60 * 24);
    }
    startAutoRenewScheduler();

    var checkCreateRenewScheduleCertificate = function(options){
        let deferred = Deferred();
        try {
            var needToCreateCertificates = checkCertificate(options);
            

            if(needToCreateCertificates){
                createRenewServerCertificate(options).then(
                    function(result){
                        deferred.resolve(result);    
                    },
                    function(err){
                        deferred.reject( err);
                    }
                )
            }else{
                deferred.resolve({ success: true, error: null, msg: "Certificated are Valid", keyFile: options.keyFile, certFile: options.certFile });    
            }
            if(options.autoRenew){
                let myKey = options.dnsNames[0].replace(/\./g, "-");
                autoRenewList[myKey] = {options: options};
                
            }
        }catch (ex) {
            debug( 'error', 'Error Renewing Certificate', ex);
            
            deferred.reject( {  status: 'complete', success: false, error: ex, msg: "Error Renewing Certificate" });
            
        }
            return deferred.promise;
    }

    var createRenewServerCertificate = function (options) {
        let deferred = Deferred();
        try {

            var defaultOptions = {
                keyFile: null,
                certFile: null,
                dnsNames: null,
                certificateSubscriberEmail:null,
                https_srv: null,
                useLetsEncryptStagingUrl : false,
                skipDryRun: true,
                skipChallengeTest: false,
                debug: true,
                acmeServerUrlOverride: null,
                retryInterval: 15000,
                retryPending: 10,
                retryPoll: 10,
                deauthWait: 30000
                
            };
            
            let myOptions = extend({}, defaultOptions, options);

            if(!!myOptions.certificateSubscriberEmail === false){
                throw new Error("certificateSubscriberEmail must be provided")
            }

            if(!!myOptions.keyFile === false){
                throw new Error("keyFile must be provided")
            }

            if(!!myOptions.certFile === false){
                throw new Error("certFile must be provided")
            }
        

            let acmeUrl = "";
    
            if(myOptions.acmeServerUrlOverride){
                acmeUrl = self.options.acmeServerUrlOverride;
            }else{
                if(myOptions.useLetsEncryptStagingUrl){
                    acmeUrl = 'https://acme-staging-v02.api.letsencrypt.org/directory';
                }else{
                    acmeUrl = 'https://acme-v02.api.letsencrypt.org/directory';
                }
            }
            

            var acmeCertificateManagerOptions = {
                maintainerEmail: "adevries@digitalexample.com",
                subscriberEmail: myOptions.certificateSubscriberEmail,
                acmeAccountFile: path.join(self.options.accountFolder, myOptions.certificateSubscriberEmail.replace(/[/\\?%*:|"<>]/g, '-') + "-" + new URL(acmeUrl).hostname + "-acmeAccount.json"),
                retryInterval: myOptions.retryInterval,
                retryPending: myOptions.retryPending,
                retryPoll: myOptions.retryPoll,
                deauthWait: myOptions.deauthWait,
                skipDryRun: myOptions.skipDryRun,
                skipChallengeTest: myOptions.skipChallengeTest,
                debug: myOptions.debug,
                directoryUrl: acmeUrl,
                http01: acmehttp01,
                notify: acmeNotify
            }

                
            var acmeCert = ACMECert.create(acmeCertificateManagerOptions);
           
            acmeCert.getKeyPair({ privateKeyFile: myOptions.keyFile}).then(
                function (keyPair) {
                    try {
                        if (keyPair.fileMissing === true) {
                            if (fs.existsSync( myOptions.keyFile)) {
                                if (fs.existsSync(path.join(myOptions.certificatesFolder, 'backups')) === false) {
                                    fs.mkdirSync(path.join( myOptions.certificatesFolder, 'backups'));
                                }
                                fs.copyFileSync( myOptions.keyFile, path.join(myOptions.certificatesFolder, 'backups', moment().format("YYYYMMDDhhmmss") + '_' + path.basename(options.keyFile)));
                            }
                            fs.writeFileSync( myOptions.keyFile, keyPair.privateKeyPem);
                        }
        
                        var createCertOptions = {
                            domains: myOptions.dnsNames,
                            privateKey: keyPair.privateKey
                            
                        };
                        acmeCert.createLetsEncryptSignedCert(createCertOptions).then(
                            function (pem) {
                                var publicCertPem = "";
                                try {
                                    if (fs.existsSync(myOptions.certFile)) {
                                        publicCertPem = fs.readFileSync(myOptions.certFile, 'ascii');
                                    }
                                } catch (ex) {
                                    debug( 'error', 'Error loading server cert file',  myOptions.certFile);
                                }
                                if (pem !== publicCertPem) {
                                    debug( 'info', 'We Got a New Cert', pem);
                                    try {
                                        if (fs.existsSync( myOptions.certFile)) {
                                            if (fs.existsSync(path.join(myOptions.certificatesFolder, 'backups')) === false) {
                                                fs.mkdirSync(path.join(myOptions.certificatesFolder, 'backups'));
                                            }
                                            fs.copyFileSync( myOptions.certFile, path.join(myOptions.certificatesFolder, 'backups', moment().format("YYYYMMDDhhmmss") + '_' + path.basename(myOptions.certFile)));
                                        }
                                        fs.writeFileSync( myOptions.certFile, pem);

                                        if(myOptions.https_srv){
                                            //This function is called on an https certificate change
                                            debug( 'info', 'updating https_srv with new Certificates');
                                            var httpsOptions = {   
                                                key: keyPair.privateKeyPem,
                                                cert: pem
                                            }
                                            myOptions.https_srv.setSecureContext(getHttpsServerOptions());
                                        }

                                        deferred.resolve({ success: true, error: null, msg: "New Certificate Saved", keyFile: myOptions.keyFile, certFile: myOptions.certFile });    

                                    } catch (ex) {
                                        debug( 'error', 'Error Saving New LetsEncrypt Signed Cert ', ev, msg);
                                        deferred.reject( {  success: false, error: ex, msg: "Error Creating LetsEncrypt Signed Cert " + ex });
                                        
                                    }
                                } else {
                                    deferred.resolve({ success: true, error: null, msg: "Letsencrypt returned the same cert so keep using it" }); 
                                }
                            },
                            function (ev, msg) {
                                var message = "";
                                if(msg){
                                    message += msg
                                }
                                if(ev.message){
                                    message += ev.message
                                }
                                if(ev.auth && ev.auth.url){
                                    message += " more details may be found by visiting " + ev.auth.url
                                }
                                debug( 'error', 'Error Creating LetsEncrypt Signed Cert ', ev, msg);
                                deferred.reject( { success: false, error: ev, msg: "Error Creating LetsEncrypt Signed Cert " + message });
                                
                            }
                        );
                    } catch (ex) {
                        debug( 'error', 'getKeyPair', ex);
                    }
                },
                function (ev, msg) {
                    debug( 'error', 'Error loading or creating server keypair from file ', ev, msg);
                    
                    deferred.reject( { success: false, error: ev + ' ' + (msg || ''), msg: "Error loading or creating server keypair from file" });
                    
                }
            );
        }
        catch (ex) {
            debug( 'error', 'createRenewServerCertificate()', 'Error Renewing Certificate', ex);
            
            deferred.reject( {  status: 'complete', success: false, error: ex, msg: "Error Renewing Certificate" });
            
        }
        return deferred.promise;
    };

    

    // assign the functions we want to export
    self.createRenewServerCertificate = createRenewServerCertificate;
    self.checkCreateRenewScheduleCertificate =checkCreateRenewScheduleCertificate;
    self.checkCertificate =checkCertificate
    self.getToken = getToken;
    self.loadX509Cert = loadX509Cert;
    self.loadX509CertSync = loadX509CertSync;
    self.httpRequestHandler = httpRequestHandler;
    self.processAutoRenewList = processAutoRenewList;  //only exposed for Testing
};

module.exports = LetsEncrypt;


