const https = require('./http');
const crypto = require('crypto');
const tls = require('tls');

module.exports = function() {

    index = 0;
    lbvserver = {};
    lbvserver_servicegroup_binding = {};
    sslcertkey = {};
    sslvserver_sslcertkey_binding = {};

    this.query = function(params, callback) {
        netscalers = params.netscalers;
        handler(params, function(err, result) {
            callback(err, result)
        });
    }

    var handler = function(params, callback) {
        queryAPI({netscaler: params.netscalers[index], creds: params.creds}, function(err, result) {
            index++;
            if(err) {
                //callback(err, false);
                console.log(err);
                handler(params, callback);
            } else {
                if(index < params.netscalers.length) {
                    handler(params, callback);
                } else {
                    callback(false, false);
                    console.log(lbvserver);
                    console.log(lbvserver_servicegroup_binding);
                    console.log(sslcertkey);
                    //console.log(sslvserver_sslcertkey_binding);
                    console.log(JSON.stringify(sslvserver_sslcertkey_binding, null, 2));
                    let tgts = [];
                    let netscalers = Object.keys(lbvserver);
                    for(let i = 0; i < netscalers.length; i++) {
                        let lbvserverkeys = Object.keys(lbvserver[netscalers[i]]);
                        for(let j = 0; j < lbvserverkeys.length; j++) {
                            if(lbvserver[netscalers[i]][lbvserverkeys[j]].port != 0) {
                                if(lbvserver[netscalers[i]][lbvserverkeys[j]].servicetype=='SSL') {
                                    let port = '';
                                    if(lbvserver[netscalers[i]][lbvserverkeys[j]].port != 443) {
                                        port = ':' + lbvserver[netscalers[i]][lbvserverkeys[j]].port.toString();
                                    }
                                    let names = [];
                                    if(sslvserver_sslcertkey_binding[netscalers[i]].hasOwnProperty(lbvserverkeys[j])) {
                                        for(let k = 0; k < sslvserver_sslcertkey_binding[netscalers[i]][lbvserverkeys[j]].length; k++) {
                                            //console.log(sslvserver_sslcertkey_binding[netscalers[i]][lbvserverkeys[j]][k].certkeyname);
                                            if(sslcertkey[netscalers[i]].hasOwnProperty(sslvserver_sslcertkey_binding[netscalers[i]][lbvserverkeys[j]][k].certkeyname)) {
                                                //console.log(sslcertkey[netscalers[i]][sslvserver_sslcertkey_binding[netscalers[i]][lbvserverkeys[j]][k].certkeyname]);
                                                let name = '';
                                                if(sslcertkey[netscalers[i]][sslvserver_sslcertkey_binding[netscalers[i]][lbvserverkeys[j]][k].certkeyname].hasOwnProperty('subject')) {
                                                    name = sslcertkey[netscalers[i]][sslvserver_sslcertkey_binding[netscalers[i]][lbvserverkeys[j]][k].certkeyname].subject;
                                                } else if(sslcertkey[netscalers[i]][sslvserver_sslcertkey_binding[netscalers[i]][lbvserverkeys[j]][k].certkeyname].hasOwnProperty('sandns')) {
                                                    name = sslcertkey[netscalers[i]][sslvserver_sslcertkey_binding[netscalers[i]][lbvserverkeys[j]][k].certkeyname].sandns[0]
                                                } else {
                                                    console.log('Failed to get certificate domain name for ' + lbvserverkeys[j]);
                                                }
                                                names.push('https://' + name.replace('*.', '') + port);
                                            } else {
                                                console.log('Failed to find certificate for ' + lbvserverkeys[j]);
                                            }
                                        }
                                    } else {
                                        console.log('Failed to find certificate binding for ' + lbvserverkeys[j]);
                                    }
                                    console.log(lbvserver[netscalers[i]][lbvserverkeys[j]]);
                                    //for(let k = 0; k < names.length; k++) {
                                        tgts.push({
                                            targets: names,
                                            labels: {
                                                app: lbvserverkeys[j]
                                            }
                                        });
                                    //}
                                } else {
                                    console.log(lbvserver[netscalers[i]][lbvserverkeys[j]]);
                                }
                            }
                        }
                    }
                    console.log(tgts);
                }
            }
        });
    }

    var parseSubject = function(subjstr) {
        parsedsubject = {};
        subjsplit = subjstr.split(',');
        for(let i = 0; i < subjsplit.length; i++) {
            let attrkv = subjsplit[i].split('=');
            if(parsedsubject.hasOwnProperty(attrkv[0])) {
                parsedsubject[attrkv[0]].push(attrkv[1]);
            } else {
                parsedsubject[attrkv[0]] = [attrkv[1]];
            }
        }
        return parsedsubject;
    }

    var queryAPI = function(params, callback) {
        //console.log(params);

        let securecontext = tls.createSecureContext({
            secureOptions: crypto.constants.SSL_OP_LEGACY_SERVER_CONNECT
        });

        let options = {
            host: params.netscaler.host,
            port: params.netscaler.port,
            rejectUnauthorized: false,
            secureContext: securecontext,
            path: '/nitro/v1/config/lbvserver',
            method: 'GET',
            headers: {
                'Content-Type': 'application/json',
                'Authorization': 'Basic ' + Buffer.from(params.creds.username + ':' + params.creds.password).toString('base64'),
                'Accept': 'application/json'
            }
        }
        https.request({ options: options }, function(err, resp) {
            if(err) {
                callback("Error connecting to " +  params.netscaler.host + ': ' + err, false);
            } else {
                //prompt for credentials if authentication failure
                if(resp.headers.hasOwnProperty('www-authenticate')) {
                    callback('Incorrect username or password on ' + params.netscaler.host);
                    //console.log('Incorrect username or password on ' + params.netscaler.host);
                    //queryAPI(params, callback);
                } else {
                    body = JSON.parse(resp.body);
                    if(resp.error) {
                        callback("Error connecting to " +  params.netscaler.host + ': ' + resp.error, false);
                    } else {
                        //console.log(body);
                        lbvserver[params.netscaler.name] = {};
                        for(let i = 0; i < body.lbvserver.length; i++) {
                            if(body.lbvserver[i].servicetype == 'SSL' || body.lbvserver[i].servicetype == 'SSL_BRIDGE' || (body.lbvserver[i].servicetype=='TCP' && body.lbvserver[i].port != 0)) {
                                lbvserver[params.netscaler.name][body.lbvserver[i].name] = {
                                    ip: body.lbvserver[i].vsvrbindsvcip,
                                    port: body.lbvserver[i].port,
                                    servicetype: body.lbvserver[i].servicetype
                                }
                            }
                        }
                        let options = {
                            host: params.netscaler.host,
                            port: params.netscaler.port,
                            rejectUnauthorized: false,
                            secureContext: securecontext,
                            path: '/nitro/v1/config/lbvserver_servicegroup_binding?bulkbindings=yes',
                            method: 'GET',
                            headers: {
                                'Content-Type': 'application/json',
                                'Authorization': 'Basic ' + Buffer.from(params.creds.username + ':' + params.creds.password).toString('base64'),
                                'Accept': 'application/json'
                            }
                        }
                        https.request({ options: options }, function(err, resp) {
                            if(err) {
                                callback("Error connecting to " +  params.netscaler.host + ': ' + err, false);
                            } else {
                                //prompt for credentials if authentication failure
                                if(resp.headers.hasOwnProperty('www-authenticate')) {
                                    callback('Incorrect username or password on ' + params.netscaler.host);
                                    //console.log('Incorrect username or password on ' + params.netscaler.host);
                                    //queryAPI(params, callback);
                                } else {
                                    body = JSON.parse(resp.body);
                                    if(resp.error) {
                                        callback("Error connecting to " +  params.netscaler.host + ': ' + resp.error, false);
                                    } else {
                                        //console.log(body);
                                        lbvserver_servicegroup_binding[params.netscaler.name] = {};
                                        for(let i = 0; i < body.lbvserver_servicegroup_binding.length; i++) {
                                            lbvserver_servicegroup_binding[params.netscaler.name][body.lbvserver_servicegroup_binding[i].name] = {
                                                servicegroupname: body.lbvserver_servicegroup_binding[i].servicegroupname
                                            }
                                        }
                                        let options = {
                                            host: params.netscaler.host,
                                            port: params.netscaler.port,
                                            rejectUnauthorized: false,
                                            secureContext: securecontext,
                                            path: '/nitro/v1/config/sslcertkey',
                                            method: 'GET',
                                            headers: {
                                                'Content-Type': 'application/json',
                                                'Authorization': 'Basic ' + Buffer.from(params.creds.username + ':' + params.creds.password).toString('base64'),
                                                'Accept': 'application/json'
                                            }
                                        }
                                        https.request({ options: options }, function(err, resp) {
                                            if(err) {
                                                callback("Error connecting to " +  params.netscaler.host + ': ' + err, false);
                                            } else {
                                                //prompt for credentials if authentication failure
                                                if(resp.headers.hasOwnProperty('www-authenticate')) {
                                                    callback('Incorrect username or password on ' + params.netscaler.host);
                                                    //console.log('Incorrect username or password on ' + params.netscaler.host);
                                                    //queryAPI(params, callback);
                                                } else {
                                                    body = JSON.parse(resp.body);
                                                    if(resp.error) {
                                                        callback("Error connecting to " +  params.netscaler.host + ': ' + resp.error, false);
                                                    } else {
                                                        sslcertkey[params.netscaler.name] = {};
                                                        for(let i = 0; i < body.sslcertkey.length; i++) {
                                                            sslcertkey[params.netscaler.name][body.sslcertkey[i].certkey] = {}
                                                            if(body.sslcertkey[i].hasOwnProperty('subject')) {
                                                                //console.log(body.sslcertkey[i].subject);
                                                                parsedsubject = parseSubject(body.sslcertkey[i].subject.trim());
                                                                if(parsedsubject.hasOwnProperty('CN')) {
                                                                    sslcertkey[params.netscaler.name][body.sslcertkey[i].certkey].subject = parsedsubject.CN[0];
                                                                }
                                                            }
                                                            if(body.sslcertkey[i].hasOwnProperty('sandns')) {
                                                                sslcertkey[params.netscaler.name][body.sslcertkey[i].certkey].sandns = body.sslcertkey[i].sandns.split(',');
                                                            }
                                                        }
                                                        let options = {
                                                            host: params.netscaler.host,
                                                            port: params.netscaler.port,
                                                            rejectUnauthorized: false,
                                                            secureContext: securecontext,
                                                            path: '/nitro/v1/config/sslvserver_sslcertkey_binding?bulkbindings=yes',
                                                            method: 'GET',
                                                            headers: {
                                                                'Content-Type': 'application/json',
                                                                'Authorization': 'Basic ' + Buffer.from(params.creds.username + ':' + params.creds.password).toString('base64'),
                                                                'Accept': 'application/json'
                                                            }
                                                        }
                                                        https.request({ options: options }, function(err, resp) {
                                                            if(err) {
                                                                callback("Error connecting to " +  params.netscaler.host + ': ' + err, false);
                                                            } else {
                                                                //prompt for credentials if authentication failure
                                                                if(resp.headers.hasOwnProperty('www-authenticate')) {
                                                                    callback('Incorrect username or password on ' + params.netscaler.host);
                                                                    //console.log('Incorrect username or password on ' + params.netscaler.host);
                                                                    //queryAPI(params, callback);
                                                                } else {
                                                                    body = JSON.parse(resp.body);
                                                                    if(resp.error) {
                                                                        callback("Error connecting to " +  params.netscaler.host + ': ' + resp.error, false);
                                                                    } else {
                                                                        //sslvserver_sslcertkey_binding[params.netscaler.name] = body;
                                                                        sslvserver_sslcertkey_binding[params.netscaler.name] = {};
                                                                        for(let i = 0; i < body.sslvserver_sslcertkey_binding.length; i++) {
                                                                            if(sslvserver_sslcertkey_binding[params.netscaler.name].hasOwnProperty(body.sslvserver_sslcertkey_binding[i].vservername)) {
                                                                                sslvserver_sslcertkey_binding[params.netscaler.name][body.sslvserver_sslcertkey_binding[i].vservername].push(body.sslvserver_sslcertkey_binding[i]);
                                                                            } else {
                                                                                sslvserver_sslcertkey_binding[params.netscaler.name][body.sslvserver_sslcertkey_binding[i].vservername] = [body.sslvserver_sslcertkey_binding[i]];
                                                                            }
                                                                        }
                                                                        callback(false);
                                                                    }
                                                                }
                                                            }
                                                        });
                                                    }
                                                }
                                            }
                                        });
                                    }
                                }
                            }
                        });
                    }
                }
            }
        });
    }
}