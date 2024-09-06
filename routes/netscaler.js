const express = require('express');
const router = express.Router();
const url = require("url");
const https = require('../lib/http');
const netscalerCertTargets = require('../lib/netscalerCertTargets');
const crypto = require('crypto');
const tls = require('tls');
var credentialcache = {}

router.get('/', function(req, res, next) {
    if (!req.headers.authorization || req.headers.authorization.indexOf('Basic ') === -1) {
        res.setHeader("WWW-Authenticate", "Basic realm=\"prometheus-netscaler-sd\"");
        //res.setHeader("HTTP/1.0 401 Unauthorized");
        res.status(401).json({
            error: {
                code: 401,
                message: 'Missing Authorization Header'
            }
        });
        return;
    }
    let parsecreds = Buffer.from(req.headers.authorization.substring(6), 'base64').toString().split(':')
    let creds = {
        username: parsecreds[0],
        password: parsecreds[1]
    }
    //let bufferObj = Buffer.from(req.headers.authorization.substring(6), "utf8");
    //console.log(creds);
    let labels = [];
    if(req.query.hasOwnProperty('labels')) {
        labels = req.query.labels.split(',');
    }
    let maintanancemode = 'any';
    if(req.query.hasOwnProperty('maintanancemode')) {
        maintanancemode = req.query.maintanancemode;
    }
    let targeturls;
    if(req.query.hasOwnProperty('target') === false) {
        res.status(400).json({
            error: {
                code: 400,
                message: 'One or more targets must be specified'
            }
        });
        return;
    }
    let application = false;
    if(req.query.hasOwnProperty('application')) {
        application = req.query.application;
    }
    let groupId = false;
    if(req.query.hasOwnProperty('groupId')) {
        groupId = req.query.groupId;
    }
    let parsedtargets = []
    targeturls = req.query.target.split(',');
    for(let i = 0; i < targeturls.length; i++) {
        let targeturl = new URL(targeturls[i]);
        //console.log(targeturl);
        if(targeturl.protocol!='https:') {
            res.status(400).json({
                error: {
                    code: 400,
                    message: 'All target URLs must be https'
                }
            });
            return;
        }
        let port = 443;
        if(targeturl.port) {
            port = targeturl.port
        }
        parsedtargets.push({
            port: port,
            host: targeturl.host,
            protocol: targeturl.protocol
        });
    }

    let urltargets = {
        targets: parsedtargets,
        creds: creds,
        netscalers: [],
        index: 0
    }
    //console.log(urltargets);
    getNetscalers(urltargets, function(err, resp) {
        if(err) {
            res.status(400).json({
                error: err
            })
        } else {
            let nsct = new netscalerCertTargets();
            nsct.query({netscalers: resp, creds: creds}, function(err, result) {
                if(err) {
                    console.log(err);
                    res.status(400).json({
                        error: err
                    })
                } else {
                    res.json(resp);
                }
            });
        }
    });
    
    //res.json(parsedtargets);
    //return;
    //console.log(cred);
});

var getNetscalers = function(urltargets, callback) {

    let securecontext = tls.createSecureContext({
        secureOptions: crypto.constants.SSL_OP_LEGACY_SERVER_CONNECT
    });

    let options = {
        host: urltargets.targets[urltargets.index].host,
        port: urltargets.targets[urltargets.index].port,
        rejectUnauthorized: false,
        path: '/nitro/v1/config/ns',
        method: 'GET',
        secureContext: securecontext,
        headers: {
            'Content-Type': 'application/json',
            'Authorization': 'Basic ' + Buffer.from(urltargets.creds.username + ':' + urltargets.creds.password).toString('base64'),
            'Accept': 'application/json'
        }
    }
    https.request({ options: options }, function(err, resp) {
        if(err) {
            callback(err, false);
            return;
        } else {
            //prompt for credentials if authentication failure
            if(resp.headers.hasOwnProperty('www-authenticate')) {
                callback('Incorrect username or password on ' + urltargets.targets[urltargets.index].host);
            } else {
                //console.log(resp);
                let data = JSON.parse(resp.body);
                //res.json(data);
                if(data.hasOwnProperty('ns')) {
                    for(let i = 0; i < data.ns.length; i++) {
                        //console.log(data.ns[i].host_type);
                        if(data.ns[i].host_type=='sdx' || data.ns[i].host_type=='xen') {
                            urltargets.netscalers.push({
                                host: data.ns[i].ipv4_address,
                                name: data.ns[i].hostname,
                                port: 443
                                //sdx: urltargets.targets[urltargets.index].host
                            });
                        }
                    }
                } else {
                    urltargets.netscalers.push({
                        host: urltargets.targets[urltargets.index].host,
                        name: urltargets.targets[urltargets.index].host,
                        port: 443
                    });
                }
                urltargets.index++;
                //console.log()
                if(urltargets.index < urltargets.targets.length) {
                    getNetscalers(urltargets, callback);
                } else {
                    callback(false, urltargets.netscalers);
                }
            }
        }
    })
}

// var credentialHandler = function(params, force, callback) {
//     if(credentialcache.hasOwnProperty(params.query.target) && force == false) {
//         // let time = new Date().getTime();
//         // //console.log(time);
//         // if(credentialcache[params.query.target].expiration - 300000 > time) {
//         //     console.log('credentials are cached and valid');
//                 callback(false, credentialcache[params.query.target]);
//         // } else {
//         //     console.log('credentials are cached and expired');
//             //credentialHandler(params, true, callback);
//         //}
//     } else {
//         //console.log(params);
//         console.log('failed to find credentials in cache');
//         //callback('test2', false);
//         //return;
//         let body = {
//             login: {
//                 username: params.creds.username,
//                 password: params.creds.password
//             }
//         }
//         let options = {
//             host: params.url.host,
//             port: params.url.port,
//             rejectUnauthorized: false,
//             path: '/nitro/v1/config/login',
//             method: 'POST',
//             headers: {
//                 'Content-Type': 'application/json',
//                 'Accept': 'application/json'
//             }
//         }
//         https.request({ options: options, body: body }, function(err, resp) {
//             if(err) {
//                 console.log(err);
//                 callback(err, false);
//             } else {
//                 console.log(resp.headers);
//                 console.log(resp.body);
//                 let body = JSON.parse(resp.body);
//                 //let time = new Date().getTime();
//                 let token = {
//                     token: body.sessionid,
//                     //expiration: time + parseInt(body.expires_in)
//                 }
//                 credentialcache[params.query.target] = token;
//                 callback(false, token);
//             }
//         });
//     }
// }

module.exports = router;