const request = require('request');

exports.onExecutePostLogin = async (event, api) => {
  /**
   * Get access token from management api
   */

  var body = {
    client_id: event.secrets.client_id,
    client_secret: event.secrets.client_secret,
    audience: `https://${event.tenant.id}.us.auth0.com/api/v2/`,
    grant_type: "client_credentials"
  };

  var options = { 
    method: 'POST',
    url: 'https://' + event.tenant.id + '.us.auth0.com/oauth/token',
    headers: { 'content-type': 'application/json' },
    body: JSON.stringify(body)
  };

  request(options, function (error, response, data) {
    if (error) {
      throw new Error(error);
    }

    let obj = JSON.parse(data);
    var mgnt_access_token = obj.access_token

    let options = {
      method: 'get',
      maxBodyLength: Infinity,
      url: 'https://dev-team12-1.us.auth0.com/api/v2/users/' + event.user.user_id,
      headers: { 
        'Accept': 'application/json', 
        'Authorization': 'Bearer ' + mgnt_access_token
      }
    };

    request(options, (error, response, data) => {
      if (error) {
        throw new Error(error);
      }

      let obj = JSON.parse(data);

      var idp_access_token = obj.identities[0].access_token
      
      request.get({
        url: "https://api.github.com/user/teams",
        headers: {
          // use token authorization to talk to github API
          "Authorization": "token " + idp_access_token,
          // Remember the Application name registered in github?
          // use it to set User-Agent or request will fail
          "User-Agent": "dev-dpsctl",
        }
      }, function(err, res, data) {
        event.user.err = err;
        if (data) {
          // extract github team names to array
          var github_teams = JSON.parse(data).map(function(team) {
            return team.organization.login + "/" + team.slug;
          });

          // deny access if not a member of any org teams
          if (github_teams.length === 0) return api.access.deny("Access denined")

          let roles_set = new Set(event.user.app_metadata.roles)

          github_teams.forEach((element) => roles_set.add(element));

          // add teams to the application metadata
          api.user.setAppMetadata("roles", roles_set);
        }
      });
    });
  });
};
