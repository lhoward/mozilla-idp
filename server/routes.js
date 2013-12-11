/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/. */

const config = require('./lib/configuration'),
      crypto = require('./lib/crypto'),
        util = require('util'),
        sjcl = require('sjcl'),
           _ = require('underscore'),
emailRewrite = require('./lib/email_rewrite.js');

var auth = require('./lib/auth').auth(config);

exports.routes = function () {
  var well_known_last_mod = new Date().getTime();
  return {
    public_key: null,
    private_key: null,
    ttl: null,
    well_known_browserid: function (req, resp) {
      // 2 minutes in seconds
      var timeout = 120 ; //2 * 60; // in seconds
      if (req.headers['if-modified-since'] !== undefined) {
        var since = new Date(req.headers['if-modified-since']);
        if (isNaN(since.getTime())) {
          console.error('Bad date in If-Modified-Since header [' +
                        req.headers['if-modified-since'] + ']');
        } else {
          // Does the client already have the latest copy?
          if (since >= well_known_last_mod) {
            resp.setHeader('Cache-Control', 'max-age=' + timeout);
            return resp.send(304);
          }
        }
      }
      // On startup, keys need to be pulled from memcache or some such
      var pk = JSON.stringify(crypto.pubKey);
      resp.setHeader('Content-Type', 'application/json');
      resp.setHeader('Cache-Control', 'max-age=' + timeout);
      resp.setHeader('Last-Modified', new Date(well_known_last_mod).toUTCString());
      resp.render('well_known_browserid', {
        public_key: pk,
        layout: false
      });
    },
    provision: function (req, resp) {
      resp.render('provision', {
        user: req.session.email,
        browserid_server: config.get('browserid_server'),
        layout: false});
    },
    provision_key: function (req, resp) {
      if (!req.session || !req.session.email) {
        resp.writeHead(401);
        return resp.end();
      }
      if (!req.body.pubkey || !req.body.duration) {
        resp.writeHead(400);
        return resp.end();
      }

      var idpCertAttrs = {};
      _.map(config.get('idp_cert_attrs'), function(attrName) {
        idpCertAttrs[attrName] = req.session.attrs && req.session.attrs[attrName];
      });

      crypto.cert_key(
        req.body.pubkey,
        req.session.email,
        req.body.duration,
        idpCertAttrs,
        function(err, cert) {
          if (err) {
            resp.writeHead(500);
            resp.end();
          } else {
            var reply = { cert: cert, attrCerts: [] };
            var certDigestInfo = {
                alg: 'S256',
                dig: sjcl.codec.base64url.fromBits(sjcl.hash.sha256.hash(cert))
            };
            var count = 0;
            var attrCertAttrs = config.get('attr_cert_attrs');

            _.map(attrCertAttrs, function(attrName) {
              var attrDict = { iss: config.get('issuer') };
              attrDict[attrName] = req.session.attrs && req.session.attrs[attrName];
              crypto.cert_attr(attrName, attrDict, certDigestInfo, function(err, attrCert) {
                if (attrCert) {
                  reply.attrCerts.push(attrCert);
                }
                if (++count === _.size(attrCertAttrs)) {
                  resp.json(reply);
                }
              });
            });
            if (!_.size(attrCertAttrs)) {
              resp.json(reply);
            }
          }
        });
    },

    /* signin_from_form and check_signin_from_form are used for
       processing form based authentication, used when
       signin_method is 'form' */
    signin_from_form: function (req, resp) {
      var email = (req.query ? req.query.email : null);
      if (email) email = emailRewrite(email);

      resp.render('signin', {
        title: req.gettext("Sign In"),
        email: email
      });
    },
    check_signin_from_form: function (req, resp) {
      var mozillaUser = "";

      if (req.body.user) {
        mozillaUser = emailRewrite(req.body.user).toLowerCase();
      }

      if (!req.body.user || !req.body.pass) {
        resp.writeHead(400);
        return resp.end();
      } else {
        auth.login(mozillaUser, req.body.pass, function (err, passed, attrs) {
          if (err || ! passed) {
            resp.write('Email or Password incorrect');
            resp.writeHead(401);
          } else {
            req.session.email = req.body.user;
            req.session.attrs = attrs;
            resp.writeHead(200);
          }
          resp.end();
        });
      }
    },

    // QA Only URLs
    signout: function (req, resp) { req.session.reset(); resp.redirect(config.get('static_mount_path')); },

    handle404: function (req, resp) {
      resp.render('404', {
        title: '',
        status: 404,

        layout: null
      });
    }
  };
};
