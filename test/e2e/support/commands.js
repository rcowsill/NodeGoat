(function() {
  "use strict";

  Cypress.Commands.add("signIn", (usr, pw) => {
    cy.visitPage("/login");
    cy.enterFormText("#userName", usr);
    cy.enterFormText("#password", pw);
    cy.get("[type='submit']")
      .click();
  });

  Cypress.Commands.add("adminSignIn", () => {
    cy.fixture("users/admin.json").as("admin");
    cy.get("@admin").then(admin => {
      cy.signIn(admin.user, admin.pass);
    });
  });

  Cypress.Commands.add("userSignIn", () => {
    cy.fixture("users/user.json").as("user");
    cy.get("@user").then(user => {
      cy.signIn(user.user, user.pass);
    });
  });

  Cypress.Commands.add("visitPage", (path = "/", config = {}) => {
    cy.visit(path, config);
  });

  Cypress.Commands.add("enterFormText", (selector, text) => {
    cy.get(selector)
      .each(($input) => {
        cy.wrap($input, { log: false })
          .clear()
          .type(text, { delay: 0 });
      });
  });

  Cypress.Commands.add("formPostRequest", (path = "/", body = {}, extraOptions = {}) => {
    const requestOptions = {
      method: "POST",
      url: path,
      body: body,
      form: true,
      ...extraOptions
    };

    return cy.request(requestOptions);
  });

  Cypress.Commands.add("noRetry", { prevSubject: true }, (subject) => {
    Cypress.log({
      message: "--retry barrier--",
      consoleProps: () => ({ Yielded: subject })
    });

    return subject;
  });

  Cypress.Commands.add("dbReset", () => {
    cy.exec("npm run db:seed", {
      timeout: 6000,
      failOnNonZeroExit: false
    });
  });

}());
