/*

 ----------------------------------------------------------------------------
 | oidc-provider: OIDC Provider QEWD-Up MicroService                        |
 |                                                                          |
 | Copyright (c) 2019 M/Gateway Developments Ltd,                           |
 | Redhill, Surrey UK.                                                      |
 | All rights reserved.                                                     |
 |                                                                          |
 | http://www.mgateway.com                                                  |
 | Email: rtweed@mgateway.com                                               |
 |                                                                          |
 |                                                                          |
 | Licensed under the Apache License, Version 2.0 (the "License");          |
 | you may not use this file except in compliance with the License.         |
 | You may obtain a copy of the License at                                  |
 |                                                                          |
 |     http://www.apache.org/licenses/LICENSE-2.0                           |
 |                                                                          |
 | Unless required by applicable law or agreed to in writing, software      |
 | distributed under the License is distributed on an "AS IS" BASIS,        |
 | WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. |
 | See the License for the specific language governing permissions and      |
 |  limitations under the License.                                          |
 ----------------------------------------------------------------------------

  9 April 2019

*/

const { createKeyStore } = require('oidc-provider');
const fs = require('fs');
//var oidc_config = require('/opt/qewd/mapped/configuration/oidc.json');

const logger = require('../../../logger').logger;

async function generate_keys() {
  const keystore = createKeyStore();
  return await keystore.generate('RSA', 2048, {
    alg: 'RS256',
    use: 'sig',
  }).then(function () {
    console.log('this is the full private JWKS:\n', keystore.toJSON(true));
    return keystore.toJSON(true);
  });
}

function getAClaim(claimsDoc, name) {
  var id = claimsDoc.$(['by_name', name]).value;
  return claimsDoc.$(['by_id', id, 'fields']).getDocument(true);
}

function getClaims(claimsDoc) {
  var claims = {};
  claimsDoc.$('by_name').forEachChild(function(name) {
    var claim = getAClaim(claimsDoc, name);
    claims[name] = claim;
  });
  return claims;
}

module.exports = function(messageObj, session, send, finished) {
  try {  
    var _this = this;

    var oidcDoc = this.db.use(this.oidc.documentName);
    oidcDoc.$('grants').delete(); // clear down any previously logged grants

    var orchestrator = this.oidc.orchestrator;
    var orchestratorHost = orchestrator.host;
    if (typeof orchestrator.port !== 'undefined' && orchestrator.port !== '') {
      orchestratorHost = orchestratorHost + ':' + orchestrator.port;
    }

    var params = {
      issuer: this.oidc.oidc_provider.issuer,
      Claims: getClaims(oidcDoc.$('Claims')),
      Users: oidcDoc.$('Users').getDocument(true),
      path_prefix: this.oidc.oidc_provider.path_prefix || '',
      postLogoutRedirectUri: orchestratorHost
    };

    if (oidcDoc.$('keystore').exists) {
      params.keystore = oidcDoc.$('keystore').getDocument(true);
      finished(params);
    }
    else {
      generate_keys()
      .then (function(keystore) {
        oidcDoc.$('keystore').setDocument(keystore);
        params.keystore = keystore;
        finished(params);
      });
    }
  } catch (error) {
    logger.error('', error);
  }
};
