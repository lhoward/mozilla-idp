/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/. */

const jwcrypto = require("jwcrypto"),
      cert = jwcrypto.cert,
      sjcl = require("sjcl"),
      config = require('./configuration'),
      store = require('./keypair_store');

// load desired algorithms
require("jwcrypto/lib/algs/rs");
require("jwcrypto/lib/algs/ds");

var _privKey = null;

// ENV Variables
try {
  exports.pubKey = JSON.parse(process.env['PUBLIC_KEY']);
  _privKey = jwcrypto.loadSecretKey(process.env['PRIVATE_KEY']);
} catch(e) { }

// or var file system cache
if (!exports.pubKey) {
  try {
    store.read_files_sync(function (err, publicKey, secretKey) {
      if (! err) {
        exports.pubKey = publicKey;
        _privKey = jwcrypto.loadSecretKey(JSON.stringify(secretKey));
      }
    });
  } catch (e) { }
}

// or ephemeral
if (!exports.pubKey) {
  if (exports.pubKey != _privKey) {
    throw "inconsistent configuration!  if privKey is defined, so must be pubKey";
  }
  // if no keys are provided emit a nasty message and generate some
  console.warn("WARNING: you're using ephemeral keys.  They will be purged at restart.");

  jwcrypto.generateKeypair({algorithm: 'RS', keysize: 256}, function(err, keypair) {
    exports.pubKey = JSON.parse(keypair.publicKey.serialize());
    _privKey = keypair.secretKey;
  });
}

exports.cert_key = function(pubkey, email, duration_s, cb) {
  var pubKey = jwcrypto.loadPublicKey(pubkey);

  var expiration = new Date();
  var iat = new Date();

  expiration.setTime(new Date().valueOf() + (duration_s * 1000));

  // Set issuedAt to 10 seconds ago. Pads for verifier clock skew
  iat.setTime(iat.valueOf() - (10 * 1000));

  cert.sign(
    {publicKey: pubKey, principal: {email: email}},
    {issuer: config.get('issuer'), issuedAt: iat, expiresAt: expiration},
    null,
    _privKey,
    cb);
};

function base64urlencode(s) {
  return sjcl.codec.base64url.fromBits(sjcl.codec.utf8String.toBits(s));
}

function hex2b64urlencode(h) {
  return sjcl.codec.base64url.fromBits(sjcl.codec.hex.toBits(h));
}

function rng() {
}

rng.prototype = {
  nextBytes: function(byteArray) {
    var randomBytes = crypto.randomBytes(byteArray.length);
    for (var i=0; i<byteArray.length; i++)
      byteArray[i] = randomBytes[i];
  }
};

function signWithHeader(header, payload, secretKey, cb) {
  header.alg = secretKey.getAlgorithm();
  var algBytes = base64urlencode(JSON.stringify(header));
  var jsonBytes = base64urlencode(JSON.stringify(payload));

  secretKey.sign(algBytes + "." + jsonBytes, rng, function() {}, function(rawSignature) {
    var signatureValue = hex2b64urlencode(rawSignature);

    cb(null, algBytes + "." + jsonBytes + "." + signatureValue);
  });
};

exports.cert_attr = function(id, attrs, certHash, callback) {
  var payload = attrs || {};
  var header = {
    cb: certHash,
    id: id,
    dn: config.get('attr_cert_displayname_mapping')[id] || "Attribute " + id
  };

  signWithHeader(header, payload, _privKey, callback);
};
