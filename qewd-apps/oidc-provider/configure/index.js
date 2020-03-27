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

  14 March 2019

*/

var bcrypt = require('bcrypt');

const logger = require('../../../logger').logger;

module.exports = function(messageObj, session, send, finished) {
  try {
    // Configure with initial data if present

    var oidcDoc = this.db.use(this.oidc.documentName);
    var data;

    try {
      var data = require('/opt/qewd/mapped/configuration/data.json');
    }
    catch(err) {
    }

    var id;
    var now = new Date().toISOString();
    var salt = bcrypt.genSaltSync(10);
    var password;

    if (!oidcDoc.$('Access').exists && data) {
      if (data.Access) {
        var accessDoc = oidcDoc.$('Access');
        data.Access.forEach(function(record) {
          id = accessDoc.$('next_id').increment();
          record.id = id;
          password = record.password || 'password';
          record.password = bcrypt.hashSync(password, salt);
          record.verified = true;
          record.createdBy = 1;
          record.createdAt = now;
          record.modifiedBy = 1;
          record.modifiedAt = now;
          accessDoc.$(['by_id', id]).setDocument(record);
        });
      }
      if (data.Claims) {
        var claimsDoc = oidcDoc.$('Claims');
        data.Claims.forEach(function(record) {
          id = claimsDoc.$('next_id').increment();
          claimsDoc.$(['by_id', id]).setDocument(record);
        });
      }
      if (data.Clients) {
        var clientsDoc = oidcDoc.$('Clients');
        data.Clients.forEach(function(record) {
          id = clientsDoc.$('next_id').increment();
          clientsDoc.$(['by_id', id]).setDocument(record);
        });
      }
      if (data.Users) {
        var usersDoc = oidcDoc.$('Users');
        data.Users.forEach(function(record) {
          id = usersDoc.$('next_id').increment();
          password = record.password || 'password';
          record.password = bcrypt.hashSync(password, salt);
          record.verified = true;
          record.hcp_id = 1;
          record.createdBy = 1;
          record.createdAt = now;
          record.updatedBy = 1;
          record.updatedAt = now;
          usersDoc.$(['by_id', id]).setDocument(record);
        });
      }
    }

    finished({ok: true});
  } catch (error) {
    logger.error('', error);
  }
};
