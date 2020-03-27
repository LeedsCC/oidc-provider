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

  15 March 2019

*/

const logger = require('../../../logger').logger;

module.exports = function(messageObj, session, send, finished) {
  try {
    var email;
    if (messageObj.params) email = messageObj.params.id;
    if (!email || email === '') {
      return finished({error: 'Missing or empty id'});
    }

    var usersDoc = this.db.use(this.oidc.documentName, 'Users');
    var emailIndex = usersDoc.$(['by_email', email]);
    if (!emailIndex.exists) {
      return finished({error: 'No such user'});
    }
    var id = emailIndex.value;
    var userDoc = usersDoc.$(['by_id', id]);

    if (userDoc.exists) {
      var data = {
        sub: id
      }; 
      var scope = messageObj.params.scope;
      var claimsDoc = this.db.use(this.oidc.documentName, 'Claims');
      var claimId = claimsDoc.$(['by_name', scope]).value;
      if (claimId !== '') {
        var _this = this;
        var fields = claimsDoc.$(['by_id', claimId, 'fields']).getDocument(true);
        fields.forEach(function(fieldName) {
          if (fieldName !== 'vouchedBy') {
            data[fieldName] = userDoc.$(fieldName).value;
          }
          else {
            var hcp_id = userDoc.$('hcp_id').value;
            var accessDoc = _this.db.use(_this.oidc.documentName, 'Access', 'by_id', hcp_id);
            var owner = accessDoc.$('name').value;
            if (owner === '') owner = 'Not Known';
            data[fieldName] = owner;              
          }
        });
      }
      finished(data);
    }
    else {
      finished({error: 'No such User'});
    }
  } catch (error) {
    logger.error('', error);
  }
};
