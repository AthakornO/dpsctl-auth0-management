exports.onExecutePostLogin = async (event, api) => {
  const namespace = 'https://github.org/ThoughtWorks-DPS/';
  api.idToken.setCustomClaim(namespace + "teams", event.user.app_metadata.roles);
};
