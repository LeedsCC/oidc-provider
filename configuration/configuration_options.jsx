/*
  Example OIDC Provider Configuration Option function-based settings/overrides
*/


var ttl = {
  IdToken() {
    return 600;
  }
};

module.exports = {
  ttl: ttl
};
