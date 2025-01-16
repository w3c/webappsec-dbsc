# DBSC prototype server

This project is a pretotype implementation of the [DBSC](https://github.com/WICG/dbsc/) server protocol.

_Last updated: 16 Januar 2024_

## Overview

A minimal prototype application for server side DBSC.

## Local testing

An `.env` file could be added to the root folder with following settings for local testing:

```
DBSC_HOST="127.0.0.1"
DBSC_PORT=58529
```

## Routes

The following routes are configured for this application

### /

Renders all current session, a form to create a new session and explaination on how to use the site.

### /internal/StartSession

Dedicated endpoint to handle browser internal start session request.

### /internal/InvalidateSession

Will set the session cookie with Max-Age=0 and redirect back to "/".

### /internal/RefreshSession

Dedicated endpoint to handle browser internal refresh session request. Can optionally request a challenge if specified in the post parameter. If the session is not found for this user, it will end the session.

### /internal/RegisterSession

Handles creating a new session. Sends the DBSC Sec-Session-Registration header and redirects with 302 to "/".

### /internal/DeleteSession

Handles deleting a session. Will end the session on next refresh from browser.

### /internal/DeleteAllSessions

Handles deleting all session. Will send the Clear-Site-Data header with cookie and storage option and redirect with 302 to "/". Will clear server side storage for all sessions for this user.

### /\*

This will do nothing except redirect back to "/". This can be used to test DBSC for specific paths.

## Server state

To maintain the same sesssions as the browser the server maintains two tables, Users and Session as described below.

### Users

Each user is maintained through a cookie (I know right!). This cookie contains an ID which is the ID in the user table. This table also keeps track of when a user last accessed the site, and deletes data after 90 days of inactivity.

### Session

Each session contains which paths it is valid for, the cookie name, attributes and how long the refresh time should be.
