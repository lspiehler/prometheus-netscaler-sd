const { http, https} = require('follow-redirects');

var httpRequest = function(params, callback) {
    let body = '';
    if(params.hasOwnProperty('body')) {
        if(typeof params.body == 'string') {
            body = params.body;
        } else {
            body = JSON.stringify(params.body);
        }
    }
    
    if(params.options.method=='POST') {
        params.options.headers['Content-Length'] = Buffer.byteLength(body)
    }

    const req = https.request(params.options, res => {
        var resp = [];
        res.on('data', function(data) {
            resp.push(data);
        });

        res.on('end', function() {
            callback(false, {statusCode: res.statusCode, options: params.options, headers: res.headers, body: Buffer.concat(resp).toString()});
        });
    })

    req.on('error', function(err) {
        //console.log(err.toString());
        callback(err.toString(), {statusCode: false, options: params.options, headers: false, body: JSON.stringify({ error: err.toString()})});
    })

    if(params.options.method=='POST') {
        req.write(body);
    }

    req.end()
}

module.exports = {
    request: function(params, callback) {
        //console.log(params);
        httpRequest(params, function(err, resp) {
            if(err) {
                callback(err, resp);
            } else {
                callback(false, resp);
            }
        });
    }
}