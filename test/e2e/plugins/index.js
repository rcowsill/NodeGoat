// ***********************************************************
// This example plugins/index.js can be used to load plugins
//
// You can change the location of this file or turn off loading
// the plugins file with the 'pluginsFile' configuration option.
//
// You can read more here:
// https://on.cypress.io/plugins-guide
// ***********************************************************

const { port, hostName } = require("../../../config/env/all");

// This function is called when a project is opened or re-opened (e.g. due to
// the project's config changing)
// `on` is used to hook into various events Cypress emits
// `config` is the resolved Cypress config
module.exports = (on, config) => {
  "use strict";

  config.baseUrl = `http://${hostName}:${port}`;

  const tags = config.env.TEST_TAGS;
  if (!Array.isArray(tags)) {
    config.env.TEST_TAGS = [];

    if (tags !== undefined) {
      config.env.TEST_TAGS = tags.split(",");
    }
  }
  console.log(`TEST_TAGS: [${config.env.TEST_TAGS.join(", ")}]`);

  return config;
};
