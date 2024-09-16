const https = require('./http');
const crypto = require('crypto');
const tls = require('tls');

module.exports = function() {

    index = 0;
    lbvserver = {};
    lbvserver_servicegroup_binding = {};
    sslcertkey = {};
    sslvserver_sslcertkey_binding = {};
    servicegroup_servicegroupmember_binding = {};

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
                    //callback(false, false);
                    //console.log(lbvserver);
                    //console.log(lbvserver_servicegroup_binding);
                    //console.log(sslcertkey);
                    //console.log(sslvserver_sslcertkey_binding);
                    //console.log(servicegroup_servicegroupmember_binding);
                    //console.log(JSON.stringify(sslvserver_sslcertkey_binding, null, 2));
                    //console.log(JSON.stringify(servicegroup_servicegroupmember_binding, null, 2));
                    let backendservers = {};
                    let tgts = {};
                    let netscalers = Object.keys(lbvserver);
                    for(let i = 0; i < netscalers.length; i++) {
                        let lbvserverkeys = Object.keys(lbvserver[netscalers[i]]);
                        for(let j = 0; j < lbvserverkeys.length; j++) {
                            if(lbvserver[netscalers[i]][lbvserverkeys[j]].port != 0) {
                                //if(lbvserver[netscalers[i]][lbvserverkeys[j]].servicetype=='SSL') {
                                    let port = '';
                                    if(lbvserver[netscalers[i]][lbvserverkeys[j]].port != 443) {
                                        port = ':' + lbvserver[netscalers[i]][lbvserverkeys[j]].port.toString();
                                    }
                                    //find listeners with cert bindings
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
                                                let tgt = {
                                                    targets: ['https://' + lbvserver[netscalers[i]][lbvserverkeys[j]].ip + port],
                                                    labels: {
                                                        app: 'Netscaler - ' + lbvserverkeys[j],
                                                        hostname: name.replace('*.', 'wildcard.'),
                                                        type: 'Virtual Server',
                                                        netscaler: netscalers[i]
                                                    }
                                                }
                                                /*if(name.indexOf('*.') >= 0) {
                                                    tgt.labels.hostname = name
                                                }*/
                                                //tgts.push(tgt);
                                                let labelindex = JSON.stringify(tgt.labels);
                                                if(tgts.hasOwnProperty(labelindex)) {
                                                    tgts[labelindex].targets.push(tgt.targets[0]);
                                                } else {
                                                    tgts[labelindex] = {
                                                        targets: [tgt.targets[0]],
                                                        labels: tgt.labels
                                                    };
                                                }
                                            } else {
                                                console.log('Failed to find certificate for ' + lbvserverkeys[j]);
                                            }
                                        }
                                    } else {
                                        //console.log('Failed to find certificate binding for ' + lbvserverkeys[j]);
                                    }
                                    //find vservers with backend servers
                                    if(lbvserver_servicegroup_binding[netscalers[i]].hasOwnProperty(lbvserverkeys[j])) {
                                        let servicegroupname = lbvserver_servicegroup_binding[netscalers[i]][lbvserverkeys[j]].servicegroupname
                                        if(servicegroup_servicegroupmember_binding[netscalers[i]].hasOwnProperty(servicegroupname)) {
                                            for(let k = 0; k < servicegroup_servicegroupmember_binding[netscalers[i]][servicegroupname].length; k++) {
                                                if(servicegroup_servicegroupmember_binding[netscalers[i]][servicegroupname][k].state == 'ENABLED' && servicegroup_servicegroupmember_binding[netscalers[i]][servicegroupname][k].port.toString().indexOf('443') >= 0) {
                                                    //console.log(servicegroup_servicegroupmember_binding[netscalers[i]][servicegroupname][k]);
                                                    let bkendport = '';
                                                    if(servicegroup_servicegroupmember_binding[netscalers[i]][servicegroupname][k].port != 443) {
                                                        bkendport = ':' + servicegroup_servicegroupmember_binding[netscalers[i]][servicegroupname][k].port.toString();
                                                    }
                                                    let instance = 'https://' + servicegroup_servicegroupmember_binding[netscalers[i]][servicegroupname][k].ip + bkendport;
                                                    if(backendservers.hasOwnProperty(instance)) {
                                                        //prevent duplicate monitors of backend servers
                                                        //console.log('https://' + servicegroup_servicegroupmember_binding[netscalers[i]][servicegroupname][k].ip + bkendport + ' already exists');
                                                    } else {
                                                        backendservers[instance] = true;
                                                        let tgt = {
                                                            targets: [instance],
                                                            labels: {
                                                                app: 'Netscaler - ' + lbvserverkeys[j],
                                                                type: 'Backend Server',
                                                                netscaler: netscalers[i]
                                                            }
                                                        }
                                                        let labelindex = JSON.stringify(tgt.labels);
                                                        if(tgts.hasOwnProperty(labelindex)) {
                                                            tgts[labelindex].targets.push(tgt.targets[0]);
                                                        } else {
                                                            tgts[labelindex] = {
                                                                targets: [tgt.targets[0]],
                                                                labels: tgt.labels
                                                            };
                                                        }
                                                    }
                                                }
                                            }
                                        }
                                    }
                                    //ADD HOSTNAME!!!
                                    //console.log(lbvserver[netscalers[i]][lbvserverkeys[j]]);
                                    //for(let k = 0; k < names.length; k++) {
                                    //}
                                //} else {
                                //    console.log(lbvserver[netscalers[i]][lbvserverkeys[j]]);
                                //}
                            }
                        }
                    }
                    let tgtkeys = Object.keys(tgts);
                    let promtgts = [];
                    let totaltargets = 0;
                    for(let i = 0; i < tgtkeys.length; i++) {
                        for(let j = 0; j < tgts[tgtkeys[i]].targets.length; j++) {
                            totaltargets++;
                        }
                        promtgts.push({
                            targets: tgts[tgtkeys[i]].targets,
                            labels: tgts[tgtkeys[i]].labels
                        });
                    }
                    console.log(new Date() + ' Returned ' + totaltargets + ' targets');
                    callback(false, promtgts);
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
                                                                        let options = {
                                                                            host: params.netscaler.host,
                                                                            port: params.netscaler.port,
                                                                            rejectUnauthorized: false,
                                                                            secureContext: securecontext,
                                                                            path: '/nitro/v1/config/servicegroup_servicegroupmember_binding?bulkbindings=yes',
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
                                                                                        //servicegroup_servicegroupmember_binding[params.netscaler.name] = body;
                                                                                        servicegroup_servicegroupmember_binding[params.netscaler.name] = {};
                                                                                        for(let i = 0; i < body.servicegroup_servicegroupmember_binding.length; i++) {
                                                                                            if(servicegroup_servicegroupmember_binding[params.netscaler.name].hasOwnProperty(body.servicegroup_servicegroupmember_binding[i].servicegroupname)) {
                                                                                                servicegroup_servicegroupmember_binding[params.netscaler.name][body.servicegroup_servicegroupmember_binding[i].servicegroupname].push(body.servicegroup_servicegroupmember_binding[i]);
                                                                                            } else {
                                                                                                servicegroup_servicegroupmember_binding[params.netscaler.name][body.servicegroup_servicegroupmember_binding[i].servicegroupname] = [body.servicegroup_servicegroupmember_binding[i]];
                                                                                            }
                                                                                        }
                                                                                        //console.log(body);
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
            }
        });
    }
}