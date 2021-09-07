var crypto = require('crypto'),
    ALGO = "sha256", //Same algo used to compute HMAC
    EXPIRY = "600",
    SECRET = "eiifcckjcnjkjfrufefdrein"; //Same secret used to compute HMAC

var sendresponse = function(msg) {
    var response = {
        statusCode: 401,
        statusDescription: msg,
        headers: {
            'cloudfront-functions': {
                value: msg
            }
        },
    };
    return response;
}

var getEpochUTCTime = function() {
    var currentTime = new Date(),
        currentTimeInMilliseconds = currentTime.getTime();
    var utcMilllisecondsSinceEpoch = currentTimeInMilliseconds + (currentTime.getTimezoneOffset() * 60 * 1000);
    var utcSecondsSinceEpoch = Math.round(utcMilllisecondsSinceEpoch / 1000);
    return utcSecondsSinceEpoch;
}

function handler(event) {

    var request = event.request,
        headers = event.headers;
    var uri = request.uri;
    console.log(uri);
    var uriArray = uri.split("/");
    var token = uriArray.splice(1, 1)[0];
    var issued_at = uriArray.splice(1, 1)[0];

    if (!token)
        return sendresponse("Missing Security Token");

    var headers_to_validate = []; //["user-agent"]; //Ensure headers are same as the headers used to compute HMAC

    var currentEpochTime = getEpochUTCTime();

    if (!issued_at) {
        return sendresponse("Invalid Security Token");
    }

    if (currentEpochTime < issued_at)
        return sendresponse("Invalid Issue Time in Security Token.");

    var data_to_hash = {
        st: parseInt(issued_at)
    };
    for (var i = 0; i < headers_to_validate.length; i++) {
        var header = headers_to_validate[i],
            header_obj = headers[header] ? headers[header][0][0] : null;
        if (header_obj && header_obj != null)
            data_to_hash[header_obj.key] = header_obj.value;
    }

    console.log(data_to_hash);
    var hmac = crypto.createHmac(ALGO, SECRET);
    hmac.update(JSON.stringify(data_to_hash));
    var hmac_token = hmac.digest('hex');
    console.log("--------TOKEN-------");
    console.log(hmac_token);
    console.log(token);

    if (hmac_token != token)
        return sendresponse("Invalid HMAC Token.");

    if (currentEpochTime - issued_at > EXPIRY)
        return sendresponse("Security Token Expired.");

    request.uri = uriArray.join("/")
    return request;
}
