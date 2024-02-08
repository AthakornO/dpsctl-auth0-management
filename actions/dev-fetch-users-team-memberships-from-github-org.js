const axios = require("axios");

exports.onExecutePostLogin = async (event, api) => {
  /**
   * Get access token from management api
   */

  var body = {
    clientId: event.secrets.clientId,
    clientSecret: event.secrets.clientSecret,
    audience: `https://${event.tenant.id}.us.auth0.com/api/v2/`,
    grantType: "client_credentials",
  };

  let options = {
    method: "POST",
    url: "https://" + event.tenant.id + ".us.auth0.com/oauth/token",
    headers: { "content-type": "application/json" },
    body: JSON.stringify(body),
  };

  axios(options)
    .then((response) => {
      let obj = JSON.parse(response);
      var mgntAccessToken = obj.access_token;

      let options = {
        method: "GET",
        maxBodyLength: Infinity,
        url:
          "https://dev-team12-1.us.auth0.com/api/v2/users/" +
          event.user.user_id,
        headers: {
          Accept: "application/json",
          Authorization: "Bearer " + mgntAccessToken,
        },
      };

      axios(options)
        .then((response) => {
          let obj = JSON.parse(response.data);
          var idpAccessToken = obj.identities[0].access_token;

          let options = {
            method: "GET",
            url: "https://api.github.com/user/teams",
            headers: {
              // use token authorization to talk to github API
              Authorization: "token " + idpAccessToken,
              // Remember the Application name registered in github?
              // use it to set User-Agent or request will fail
              "User-Agent": "dev-dpsctl",
            },
          };
          axios(options)
            .then((response) => {
              const data = response.data;
              if (data) {
                // extract github team names to array
                var githubTeams = JSON.parse(data).map(function (team) {
                  return team.organization.login + "/" + team.slug;
                });

                // deny access if not a member of any org teams
                if (githubTeams.length === 0)
                  return api.access.deny("Access denined");

                let rolesSet = new Set(event.user.app_metadata.roles);

                githubTeams.forEach((element) => rolesSet.add(element));

                // add teams to the application metadata
                api.user.setAppMetadata("roles", rolesSet);
              }
            })
            .catch((error) => {
              console.log("3");
              throw new Error(error);
            });
        })
        .catch((error) => {
          console.log("2");
          throw new Error(error);
        });
    })
    .catch((error) => {
      console.log("1");
      throw new Error(error);
    });
};
