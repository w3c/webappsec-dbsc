const { get } = require("http");
const { from_json, to_json } = require("./cookify");
const { createDecoder, createVerifier } = require("fast-jwt");
const jwkToPem = require('jwk-to-pem');

const path = require("path");
const url = require("url");
const handlebars = require("handlebars");

let g_challenges = [
  "DBSC-challenge0",
  "DBSC-challenge1",
  "DBSC-challenge2",
  "DBSC-challenge3",
  "DBSC-challenge4",
  "DBSC-challenge5",
  "DBSC-challenge6",
  "DBSC-challenge7",
  "DBSC-challenge8",
  "DBSC-challenge9",
];

// Require the fastify framework and instantiate it
const fastify = require("fastify")({
  // Set this to true for detailed logging:
  logger: false,
});

require('dotenv').config();
// Please set up server port and host, for example "127.0.0.1" for local testing.
let g_listening_host = process.env.DBSC_HOST ? process.env.DBSC_HOST : "0.0.0.0";
let g_listening_port = process.env.DBSC_PORT ? process.env.DBSC_PORT : 3000;

let g_sessions = {};
let g_default_cookie_age_sec = 10*60;

// A session registration request and its challenge will be expired after 60 seconds.
let g_session_registration_timeout_sec = 60;

// We will verify the "start-session" request by checking Authorization code
// if "authorization" field exists in registration JWT. 401 error will be
// returned if the Authorization code is existed but not matched.
// As Authorization code is optional, we will not do auth checking for
// auth-code missing or is duplicated case.
let g_pending_sessions = {};
let g_session_id = 1;

handlebars.registerHelper('hasCookieEverRefreshed', function (expires, expiresAtStartSession) {
  return expires > expiresAtStartSession;
})

setInterval(() => {
  Object.values(g_pending_sessions).forEach(pendingSession => {
    if (pendingSession.isExpired) {
      delete g_pending_sessions[pendingSession.sessionId];
    }
  })}, 60*1000);

function getSessionId() {
  return g_session_id++;
}

function getChallengeKey() {
  return Math.floor(Math.random() * g_challenges.length);
}

class SessionInfo {
  constructor(scopeSpecification, cookies, authCode) {
    this.sessionId = getSessionId();
    this.scopeSpecification = scopeSpecification;
    this.challengeKey = getChallengeKey();
    this.authCode = authCode ? authCode : undefined;
    this.cookies = cookies;
    this.expires = undefined;
    this.refreshUrl = "";
  }

  setRefreshUrl(url) {
    this.refreshUrl = url;
  }

  setExpires(time) {
    this.expires = time;
  }

  get isExpired() {
    return this.expires < Date.now();
  }

  getStartSessionResponseObj() {
    let _obj = this;
    let responseObj = {
      "session_identifier": _obj.sessionId.toString(),
      "refresh_url": _obj.refreshUrl,
      "scope": {
        "origin": g_listening_host,
        "include_site": true,
        "defer_requests": true,
        "scope_specification" : this.scopeSpecification
      },
      "credentials": [],
    };
    _obj.cookies.forEach(cookie => {
      responseObj.credentials.push({
        "type": "cookie",
        "name": cookie.name,
        "value": cookie.value,
        "attributes": cookie.attributes,
      });
    });
    return responseObj;
  }

  getStartSessionResponseStr() {
    return to_json(this.getStartSessionResponseObj());
  }
}

class CookieInfo {
  constructor(name, value, maxAgeInSec) {
    this.name = name;
    this.value = value;
    this.maxAgeInSec = maxAgeInSec ? maxAgeInSec : g_default_cookie_age_sec;
    this.domain = g_listening_host;
    this.path = "/";
    this.secure = true;
    this.sameSite = "Strict";
    // expires and expiresAtStartSession are unset until StartSession.
  }

  get attributes() {
    let attributeStr = `Domain=${this.domain}; Path=${this.path}; Max-Age=${this.maxAgeInSec}; SameSite=${this.sameSite};`;
    attributeStr += "Expires=" + this.expires.toUTCString() + ";";
    if (this.secure) {
      attributeStr += " Secure;";
    }
    return attributeStr;
  }

  get isExpired() {
    return this.expires < Date.now();
  }
}

// Setup our static files
fastify.register(require("@fastify/static"), {
  root: path.join(__dirname, "public"),
  prefix: "/", // optional: default '/'
});

// Formbody lets us parse incoming forms
fastify.register(require("@fastify/formbody"));

// View is a templating manager for fastify
fastify.register(require("@fastify/view"), {
  engine: {
    handlebars: handlebars,
  },
});

fastify.register(require("@fastify/cookie"), {
  secret: "my-secret", // for cookies signature
  hook: "onRequest", // set to false to disable cookie autoparsing or set autoparsing on any of the following hooks: 'onRequest', 'preParsing', 'preHandler', 'preValidation'. default: 'onRequest'
  parseOptions: {}, // options for parsing cookies
});

fastify.addHook("preParsing", (request, reply, payload, done) => {
  // We are running on Glitch, so we need to set the right hostname.
  if (g_listening_host === "0.0.0.0") {
    g_listening_host = request.hostname;
    console.log(`Setting hostname to ${g_listening_host}`);
  }
  done(null, payload);
});

fastify.get("/", function (request, reply) {
  console.log("/");
  let params = {};
  params.sessions = Object.values(g_sessions);

  return reply.view("/src/pages/index.hbs", params);
});

fastify.post("/internal/StartSessionForm", function (request, reply) {
  console.log("/internal/StartSessionForm");
  let scopeSpecification = [];
  scopeSpecification.push({ "type": "include", "domain": g_listening_host, "path": request.body.cinclude });
  scopeSpecification.push({ "type": "exclude", "domain": g_listening_host, "path": request.body.cexl });
  // If /internal is in-scope, we can try to apply DBSC to refresh requests
  scopeSpecification.push({ "type": "exclude", "domain": g_listening_host, "path": "/internal" });
  let cookies = [];
  cookies.push(new CookieInfo(request.body.cname, request.body.cvalue, request.body.cexpire));
  let newSession = new SessionInfo(scopeSpecification, cookies, request.body.authCode);
  reply.setCookie("dbsc-registration-sessions-id", to_json(newSession.sessionId), {
    domain: g_listening_host,
    path: "/",
    signed: false,
  });
  newSession.setExpires(Date.now() + g_session_registration_timeout_sec * 1000);
  g_pending_sessions[newSession.sessionId] = newSession;

  let challengeStr = g_challenges[newSession.challengeKey];
  let headerStr = '(ES256 RS256); path="' + encodeURIComponent("StartSession") + '"; challenge="' + challengeStr + '"';
  if (request.body.authCode) {
      headerStr += '; authorization="' + request.body.authCode + '"';
  }

  return (
    reply
      .code(303)
      .header("Location", "/")
      .header(
        "Sec-Session-Registration",
        headerStr
      )
      .send()
  );
});

fastify.post("/internal/StartSession", function (request, reply) {
  console.log("/internal/StartSession");
  let sessionId = undefined;
  // TODO: need to check the session id is in request.body or header.
  const sessionIdCookie = request.cookies["dbsc-registration-sessions-id"];
  if (sessionIdCookie) {
    sessionId = from_json(sessionIdCookie);
  }
  if (!sessionId) {
    // Bad Request error.
    console.log("No session id");
    return reply.code(400).send();
  }
  if (!g_pending_sessions[sessionId]) {
    // Unauthorized error.
    console.log("Unregistered session");
    return reply.code(401).send();
  }
  let sessionInfo = g_pending_sessions[sessionId];
  let reg_response = request.headers["sec-session-response"];
  if (!reg_response) {
    // Bad Request error.
    console.log("No sec-session-response");
    return reply.code(400).send();
  }

  let decoded;
  try {
    const decoder = createDecoder();
    const payload = decoder(reg_response);
    if (!payload.key) {
      return reply.code(401).send();
    }

    sessionInfo.pemKey = jwkToPem(payload.key);
    let verifier = createVerifier({key: sessionInfo.pemKey});
    decoded = verifier(reg_response);
  } catch (e) {
    console.log("Failed to validate JWT");
    console.log(e);
    return reply.code(401).send();
  }

  // Check the AuthCode and challenge
  if (sessionInfo.authCode !== decoded.authorization || g_challenges[sessionInfo.challengeKey] !== decoded.jti) {
    // Unauthorized error.
    console.log("Incorrect authorization or challenge");
    return reply.code(401).send();
  }

  // TODO: check challenge expiration

  g_sessions[sessionId] = sessionInfo;
  delete g_pending_sessions[sessionId];

  // Set all cookies for the session.
  sessionInfo.cookies.forEach(cookie => {
    cookie.expires = new Date(Date.now() + cookie.maxAgeInSec * 1000);
    cookie.expiresAtStartSession = cookie.expires;
    reply.setCookie(cookie.name, to_json(cookie.value), {
      domain: cookie.domain,
      path: cookie.path,
      maxAge: cookie.maxAgeInSec,
      expires: cookie.expires,
      secure: cookie.secure,
      sameSite: true,
    });
  });
  sessionInfo.setRefreshUrl(url.format({
    protocol: 'https',
    host: request.hostname,
    pathname: "/internal/RefreshSession",
  }));
  let responseStr = sessionInfo.getStartSessionResponseStr();
  return (
    reply
      .code(200)
      .send(responseStr)
  );
});

fastify.post("/internal/RefreshSession", function (request, reply) {
  console.log("/internal/RefreshSession");
  let params = {};
  params.cookies = request.cookies;

  const session_id = request.headers['sec-session-id'];
  if (!session_id || !g_sessions[session_id]) {
    console.log("Invalid session");
    return reply.code(401).send();
  }

  let sessionInfo = g_sessions[session_id];
  let jwt = request.headers['sec-session-response'];
  if (!jwt) {
    sessionInfo.challengeKey = getChallengeKey();
    console.log("Provided challenge");
    return reply.code(401).header('Sec-Session-Challenge', `"${g_challenges[sessionInfo.challengeKey]}"`).send();
  }

  let decoded;
  try {
    let verifier = createVerifier({key: sessionInfo.pemKey});
    decoded = verifier(jwt);
  } catch (e) {
    console.log("Failed to validate JWT");
    console.log(e);
    return reply.code(401).send();
  }

  if (g_challenges[sessionInfo.challengeKey] !== decoded.jti) {
    console.log("Invalid challenge response");
    return reply.code(401).send();
  }

  // Refresh all cookies for the session.
  g_sessions[session_id].cookies.forEach(cookie => {
    cookie.expires = new Date(Date.now() + cookie.maxAgeInSec * 1000);
    reply.setCookie(cookie.name, to_json(cookie.value), {
      domain: cookie.domain,
      path: cookie.path,
      maxAge: cookie.maxAgeInSec,
      expires: cookie.expires,
      secure: cookie.secure,
      sameSite: true,
    });
  });

  let responseStr = sessionInfo.getStartSessionResponseStr();

  // TODO: Check this is the correct response, and maybe an example where it is changing
  return (
    reply
      .code(200)
      .send(responseStr)
  );
});

fastify.post("/trusted", function (request, reply) {
  console.log("/trusted");
  let params = {};
  params.cookies = request.cookies;
  console.log(params.cookies);

  // The Handlebars template will use the parameter values to update the page with the chosen color
  return reply.view("/src/pages/index.hbs", params);
});

fastify.post("/untrusted", function (request, reply) {
  console.log("/untrusted");
  let params = {};

  // The Handlebars template will use the parameter values to update the page with the chosen color
  return reply.view("/src/pages/index.hbs", params);
});

fastify.post("/internal/DeleteSession", function (request, reply) {
  console.log("/internal/DeleteSession");
  if (request.body.id && g_sessions[request.body.id]) {
    // Delete all cookies for the session.
    g_sessions[request.body.id].cookies.forEach(cookie => {
      reply.setCookie(cookie.name, "", {
        domain: cookie.domain,
        path: cookie.path,
        expires: Date.now(),
      });
    });

    delete g_sessions[request.body.id];
  }

  // The Handlebars template will use the parameter values to update the page with the chosen color
  return reply.code(303).header("Location", "/").send();
});

// Run the server and report out to the logs
fastify.listen(
  { host: g_listening_host, port: g_listening_port },
  function (err, address) {
    if (err) {
      console.error(err);
      process.exit(1);
    }
    console.log(`Your app is listening on ${address} with ${g_listening_port} and ${g_listening_host}`);
  }
);
