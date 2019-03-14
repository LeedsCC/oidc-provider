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

  13 March 2019

*/

module.exports = function(messageObj, session, send, finished) {

  var claimsDoc = this.db.use(this.oidc.documentName, 'Claims');
  var claims = [];
  claimsDoc.$('by_id').forEachChild(function(id, node) {
    var claim = node.getDocument(true);
    var fieldsList = '';
    var fieldsEdit = '';
    var comma = '';
    var delim = '';
    claim.fields.forEach(function (field) {
      fieldsList = fieldsList + comma + field;
      fieldsEdit = fieldsEdit + delim + field;
      comma = ', ';
      delim = '\n';
    });

    claims.push({
      id: id,
      name: claim.name,
      fieldsList: fieldsList,
      fieldsEdit: fieldsEdit
    });
  });
  finished({
    claims: claims
  });
};
