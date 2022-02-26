
'use strict';

const ACME = require('@root/acme');
//const ACME = require('acme');

const fs = require('fs');
const debug = require('debug')('letsencrypt:acmeCertificateManager');
const Keypairs = require('@root/keypairs');
const CSR = require('@root/csr');
const PEM = require('@root/pem');
const path = require('path');
const Deferred = require('deferred');
const moment = require('moment');
const punycode = require('punycode/');

const { Certificate, PrivateKey } = require('@fidm/x509');




module.exports.create = function (defaults) {
    var handlers = {
        getOptions: function () {
            return handlers._private.options;
        }
        , _private: {
            inited: false,
            account: null,
            packageAgent: 'github-andrewiski-letsencrypt-acmeCertificateManager/1.1',
            directoryUrl: defaults.directoryUrl || 'https://acme-v02.api.letsencrypt.org/directory', // 'https://acme-v02.api.letsencrypt.org/directory' 'https://acme-staging-v02.api.letsencrypt.org/directory' 
            acme: null,
            options: defaults,
            accountPrivateKey: null,
            accountPublicKey: null
        }
        , getAccount: function () {

            let deferred = Deferred();
            handlers.loadAccount().then(
                function () {
                    deferred.resolve();
                },
                function (ev, msg) {
                    handlers.generateAccount().then(
                        function () {
                            deferred.resolve();
                        },
                        function (ev, msg) {
                            deferred.reject(ev, msg);
                        }
                    );
                }
            );
            return deferred.promise;
        }

        , loadAccount: function () {

            let deferred = Deferred();
            let privateKey = null;
            let publicKey = null;
            let needToCreateAccount = false;
            try {
                debug('Loading saved ACME account ..');
                if (fs.existsSync(handlers._private.options.acmeAccountFile)) {
                    let accountJson = fs.readFileSync( handlers._private.options.acmeAccountFile);
                    let accountData = JSON.parse(accountJson);
                    handlers._private.account = accountData.account;
                    privateKey = accountData.privateKey;
                    publicKey = accountData.publicKey;
                } else {
                    needToCreateAccount = true;
                }
                
                if (needToCreateAccount === false) {
                        Keypairs.import({ pem: privateKey }).then(
                            function (loadedPrivateKey) {
                                debug('info', 'Loaded saved ACME account private key');
                                handlers._private.accountPrivateKey = loadedPrivateKey;
                            
                                Keypairs.import({ pem: publicKey }).then(
                                    function (loadedPublicKey) {
                                        debug('info', 'Loaded saved ACME account public key');
                                        handlers._private.accountPublicKey = loadedPublicKey;
                                        deferred.resolve();
                                    },
                                    function (ev, msg) {
                                        debug('error', 'Error Loading ACME account public key', ev, msg);
                                        deferred.reject(ev, msg);
                                    }
                                );
                            },
                            function (ev, msg) {
                                debug('error', 'Error Loading ACME account private key', ev, msg);
                                deferred.reject(ev, msg);
                            }
                        );
                } else {
                    deferred.reject('info', 'unable to load Acme account file');
                }
            } catch (ex) {
                debug('error', 'Error loading ACME account keyFiles', ex);
                deferred.reject('error', ex);
            }
            return deferred.promise;
        }

        , generateAccount: function () {

            let deferred = Deferred();
            try {
                debug('Creating new ACME account keypair..');
                Keypairs.generate({ kty: 'EC', format: 'jwk' }).then(
                    function (newKeyPairs) {
                        debug('info', 'Created new ACME account keypair');
                        handlers._private.accountPrivateKey = newKeyPairs.private;
                        handlers._private.accountPublicKey = newKeyPairs.public;
                        
                        let agreeToTerms = true;
                        debug('info','registering new ACME account...');
                        handlers._private.acme.accounts.create({
                            subscriberEmail: handlers._private.options.subscriberEmail,
                            agreeToTerms: agreeToTerms,
                            accountKey: handlers._private.accountPrivateKey
                        }).then(
                            function (account) {
                                debug('info', 'created new Lets Encrypt account with id', account.key.kid);
                                let accountData = {
                                    account: account,
                                    //pem: null
                                    privateKey: null,
                                    publicKey: null
                                };
                                Keypairs.export({ jwk: newKeyPairs.private, encoding: 'pem',  public: false }).then(
                                    function (pem) {
                                        accountData.privateKey = pem;
                                        Keypairs.export({ jwk: newKeyPairs.public, encoding: 'pem', public: true }).then(
                                            function (pem) {
                                                accountData.publicKey = pem;
                                                let accountJson = JSON.stringify(accountData);
                                                if (fs.existsSync( handlers._private.options.acmeAccountFile)) {
                                                    fs.copyFileSync( handlers._private.options.acmeAccountFile, path.dirname(handlers._private.options.acmeAccountFile), moment().format("YYYYMMDDhhmmss") + '_' + path.posix.basename(handlers._private.options.acmeAccountFile));
                                                }
                                                fs.writeFileSync(handlers._private.options.acmeAccountFile, accountJson);
                                                deferred.resolve();

                                            },
                                            function (ev, msg) {
                                                debug('error', 'Error Exporting Pem ', ev, msg);
                                                deferred.reject(ev, msg);
                                            }
                                        );       

                                    },
                                    function (ev, msg) {
                                        debug('error', 'Error Exporting Private Key to Pem ', ev, msg);
                                        deferred.reject(ev, msg);
                                    }
                                );


                                
                                
                            },
                            function (ev, msg) {
                                debug('error', 'Error creating new Lets Encrypt account ', ev, msg);
                                deferred.reject(ev, msg);
                            }
                        );
                    },
                    function (ev, msg) {
                        debug('error', 'Error creating new keypairs ', ev, msg);
                        deferred.reject(ev, msg);
                    }
                );
            } catch (ex) {
                debug('error', 'Error creating ACME account', ex);
                deferred.reject('error', ex);
            }
            return deferred.promise;
        }
        , getKeyPair: function (options) {
            let deferred = Deferred();
            try {
                handlers.loadRsaKeyPair(options).then(
                    function (loadedKeyPair) {
                        loadedKeyPair.fileMissing = false;
                        deferred.resolve(loadedKeyPair);
                    },
                    function (ev, msg) {
                        
                        
                        debug('warning', 'loading keypair from rsa key file failed! Generate New Key ', ev, msg || '');
                        
                        handlers.generateKeyPair(options).then(
                            function (generatedKeyPair) {
                                generatedKeyPair.fileMissing = true;
                                deferred.resolve(generatedKeyPair);
                            },
                            function (ev, msg) {
                                deferred.reject(ev, msg);
                            }
                        );
                        
                    }
                );
            }
            catch (ex) {
                debug('error', 'Error get Server Key Pair', ex);
                deferred.reject('error', ex);
            }
            return deferred.promise;
        }
        , generateKeyPair: function (options) {
            let deferred = Deferred();

            try {
                let serverKeys = {
                    privateKeyPem: null,
                    privateKey: null,
                    publicKey: null
                };

                Keypairs.generate({ kty: 'RSA', format: 'jwk' }).then(
                    function (newKeyPairs) {
                        serverKeys.privateKey = newKeyPairs.private;
                        serverKeys.publicKey = newKeyPairs.public;
                        Keypairs.export({ jwk: newKeyPairs.private, encoding: 'pem', public: false }).then(
                            function (pem) {
                                serverKeys.privateKeyPem = pem;                               
                                deferred.resolve(serverKeys);
                            },
                            function (ev, msg) {
                                debug('error', 'Error Exporting Private Key to Pem ', ev, msg);
                                deferred.reject(ev, msg);
                            }
                        );
                    },
                    function (ev, msg) {
                        debug('error', 'Error Generating Key Pair ', ev, msg);
                        deferred.reject(ev, msg);
                    }
                );
            } catch (ex) {
                debug('error', 'Error loading Public Server Key pair', ex);
                deferred.reject('error', ex);
            }
            return deferred.promise;
        }

        

        

        
        , loadRsaKeyPair: function (options) {
            let deferred = Deferred();
            let RsaKeys = {
                privateKeyPem: null,
                privateKey: null,
                publicKey: null
            };
            try {

                debug('Loading saved private Rsa Key File ..');
                if (fs.existsSync( options.privateKeyFile)) {
                    RsaKeys.privateKeyPem = fs.readFileSync(options.privateKeyFile, 'ascii');
                    Keypairs.parse({ key: RsaKeys.privateKeyPem }).then(
                        function (loadedKeys) {
                            //debug('info', 'Loaded rsa key  file');

                            RsaKeys.privateKey = loadedKeys.private;
                            RsaKeys.publicKey = loadedKeys.public;

                            deferred.resolve(RsaKeys);

                        },
                        function (ev, msg) {
                            debug('error', 'Error Parsing RSA Key file', ev, msg || '');
                            deferred.reject(ev, msg);
                        }
                    );
                } else {
                    deferred.reject('error', 'unable to load RSA Key file.', 'File is Missing ');
                }
                
            } catch (ex) {
                debug('error', 'Error loading RSA Key file', ex, options.privateKeyFile);
                deferred.reject('error', ex);
            }
            return deferred.promise;
        }

       

        , createLetsEncryptSignedCert: function (options) {
            let deferred = Deferred();
            try {
                handlers.init().then(
                    function () {
                        //var domains = ['mananger.audio.digitalexample.com'];
                        var domains = options.domains.map(
                            function (name) {
                                return punycode.toASCII(name);
                            }
                        );

                        CSR.csr({ jwk: options.privateKey, domains: domains, encoding:'der' }).then(
                            function (csrDer) {
                                var csr = PEM.packBlock({ type: 'CERTIFICATE REQUEST', bytes: csrDer });

                                var challenges = {
                                    'http-01': handlers._private.options.http01
                                };

                                debug('info','validating domain authorization for ' + domains.join(' '));
                        
                                 handlers._private.acme.certificates.create({

                                    account: handlers._private.account,
                                    accountKey: handlers._private.accountPrivateKey,
                                    csr: csr,
                                    domains: domains,
                                     challenges: challenges,
                                     skipDryRun: handlers._private.options.skipDryRun
                                     
                                }).then(
                                    function (pems) {
                                        debug('info', 'domain validated certificate created ' + domains.join(' '));
                                        var fullchain = pems.cert + '\n' + pems.chain + '\n';
                                        deferred.resolve(fullchain);
                                    },
                                    function (ev, msg) {
                                        debug('error', 'Error Validating Certificate ' + domains.join(' '), ev, msg);
                                        deferred.reject(ev, msg);
                                    }

                                );
                        

                        
                        
                            },
                            function (ev, msg) {
                                debug('error', 'Error Generating CSR ', ev, msg);
                                deferred.reject(ev, msg);
                            }
                        );
                    }, function (ev, msg) {
                        debug('error', 'Error Init ACME', ev, msg);
                        deferred.reject(ev, msg);
                    }
                );

            } catch (ex) {
                debug('error', 'Error Creating Cert', ex);
                deferred.reject('error', ex);
            }
            return deferred.promise;
        }

        

        , init: function () {
            let deferred = Deferred();
            try {
                if (handlers._private.inited === false) {
                    handlers._private.acme = ACME.create(
                        {
                            maintainerEmail: handlers._private.options.maintainerEmail,
                            packageAgent: handlers._private.packageAgent,
                            notify: handlers._notifyHandler,
                            retryInterval: handlers._private.options.retryInterval,
                            deauthWait: handlers._private.options.deauthWait || 30 * 1000,
                            retryPoll: handlers._private.options.retryPoll || 16,
                            retryPending: handlers._private.options.retryPending || 30,
                            debug: handlers._private.options.debug || false,
                            skipChallengeTest: handlers._private.options.skipChallengeTest || false,
                            skipDryRun: handlers._private.options.skipDryRun || false
                        }
                    );
                    handlers._private.acme.init(handlers._private.directoryUrl).then(
                        function () {
                            handlers.getAccount().then(
                                function () {
                                    handlers._private.inited = true;
                                    deferred.resolve();
                                },
                                function (ev, msg) {
                                    debug('error', 'Error getting Account ', ex);
                                    deferred.reject(ev, msg);
                                }

                            );
                        },
                        function (ev, msg) {
                            debug('error', 'Error on Acme Init ', ex);
                            deferred.reject(ev, msg);

                        }
                    );
                } else {
                    deferred.resolve();
                }
            } catch (ex) {
                debug('error', 'Error on Init', ex);
                deferred.reject('error', ex);
            }
            return deferred.promise;
        }
        , get: function (args, domain, token, cb) {
            // TODO keep in mind that, generally get args are just args.domains
            // and it is disconnected from the flow of setChallenge and removeChallenge
            cb(null, handlers._challenges[token]);
        }
        , remove: function (args, domain, token, cb) {
            delete handlers._challenges[token];
            cb(null);
        }
        , _notifyHandler: function (ev, msg) {
            if ('error' === ev || 'warning' === ev) {
                debug(ev, msg);

            } else {
                debug(ev, msg.altname || '', msg.status || '', msg.message || '');
            }
            if (handlers._private.options.notify) {
                handlers._private.options.notify(ev, msg);
            }
        }
        

    };


    return handlers;
};










