/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/. */

const ldap = require('ldapjs'),
         _ = require('underscore');

exports.auth = function (config) {
  if (! config.get('ldap_server_url')) throw "Configuration error, you must specifiy an ldap_server_url";

  return {

    /**
     * Authenticate with the Mozilla LDAP server.
     *
     * @method bind
     * @param {string} email - mozilla.com email address
     * @param {string} password - password to use.
     * @param {function} [callback] - callback to call when complete.  Will be
     * called with one parameter - err.  err will be null if successful, an object
     * otw.
     */
    login: function(email, password, callback) {
      if (email.indexOf('@de.padl.com') === -1) {
        throw "Invalid ASSERTION, authenticating non de.padl.com email address:" + email;
      }
      var client = ldap.createClient({
        url: config.get('ldap_server_url')
      });

      // always disconnect
      var _callback = callback;
      callback = function() {
        try {
          client.unbind();
        } catch(e) {
          console.error(e);
        }
        if (_callback) {
          _callback.apply(null, arguments);
          _callback = null;
        }
      };

      client.on('close', function(err) {
        if (err) {
          if (_callback) {
            _callback(err);
            _callback = null;
          } else {
            console.error(err);
          }
        }
      });

      var bindDN = email; // AD style
      var userEntry = null;
      var results = 0;
      client.bind(
        bindDN,
        password,
        function(err) {
          if (err) {
            console.error('Unable to bind to LDAP to search for DNs: ' + err.toString());
            return callback(err, false, null);
          } else {
            var attrs = ['mail', 'userPrincipalName'];

            attrs.push.apply(attrs, config.get('idp_cert_attrs') || []);
            _.each(config.get('attr_certs'), function(attrCertConfig) {
              attrs.push.apply(attrs, attrCertConfig['ldap_attrs'].keys());
            });

            client.search('dc=de,dc=padl,dc=com', {
              scope: 'sub',
              filter: '(|(mail=' + email + ')(userPrincipalName=' + email + '))',
              attributes: _.uniq(attrs)
            }, function (err, res) {
              if (err) {
                console.error('error on search ' + err.toString());
                return callback(err, false, null);
              }
              res.on('searchEntry', function(entry) {
                bindDN = entry.dn;
                userEntry = entry.object;
                results++;
              });
              res.on('end', function () {
                if (results == 1) {
                  client.bind(bindDN, password, function (err) {
                    if (err) {
                      console.warn('Wrong username or password ' + err.toString());
                      callback(err, false, null);
                    } else {
                      // Successful LDAP authentication
                      callback(null, true, userEntry);
                    }
                  });
                } else {
                  callback(null, false, null);
                }
              });
            });
          }
        });
    },
    basic_auth_decode: function (cred, cb) {
      var pieces = cred.split(' ');
      if (pieces[0] === 'Basic' && pieces.length === 2) {
        var decoded = new Buffer(pieces[1], 'base64').toString('utf8');
        if (decoded.indexOf(':') === -1) {
          cb("Malformed Basic Authorization [" + decoded + "]", null, null);
        } else {
          var parts = decoded.split(':');
          cb(null, parts[0], parts[1]);
        }
      } else {
        cb("Unknown type of Authentication [" + pieces[0] + "]", null, null);
      }
    }
  };
};

