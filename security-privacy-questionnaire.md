# Device Bound Session Credentials Security & Privacy Questionnaire

> 01.  What information does this feature expose,
>      and for what purposes?

The only new information is an identifier for a session, collected at refresh
time. This is necessary to identify the session in certain circumstances
(e.g. when terminating sessions). This is provided by the server at registration
time.

> 02.  Do features in your specification expose the minimum amount of information
>      necessary to implement the intended functionality?

Yes.

> 03.  Do the features in your specification expose personal information,
>      personally-identifiable information (PII), or information derived from
>      either?

No such information is handled by this feature.

> 04.  How do the features in your specification deal with sensitive information?

No such information is handled by this feature.

> 05.  Does data exposed by your specification carry related but distinct
>      information that may not be obvious to users?

No.

> 06.  Do the features in your specification introduce state
>      that persists across browsing sessions?

Yes. Device Bound Session configurations are persisted across browsing sessions.

> 07.  Do the features in your specification expose information about the
>      underlying platform to origins?

Some information is indirectly exposed (e.g. presence of a TPM). We do not
expose detailed information like TPM identifier or model number.

> 08.  Does this specification allow an origin to send data to the underlying
>      platform?

Yes. Challenges are signed by the TPM.

> 09.  Do features in this specification enable access to device sensors?

No.

> 10.  Do features in this specification enable new script execution/loading
>      mechanisms?

No.

> 11.  Do features in this specification allow an origin to access other devices?

No.

> 12.  Do features in this specification allow an origin some measure of control over
>      a user agent's native UI?

No.

> 13.  What temporary identifiers do the features in this specification create or
>      expose to the web?

A session id is created at registration time and exposed at refresh time.

> 14.  How does this specification distinguish between behavior in first-party and
>      third-party contexts?

A bound credential can only trigger a refresh if it would have been included in the
request. If the cookies are not sent in third-party contexts (e.g. SameSite or
users with third-party cookies disabled), a refresh will not occur.

> 15.  How do the features in this specification work in the context of a browser’s
>      Private Browsing or Incognito mode?

In Private Browser or Incognito, the specification works the same, but does not
persist session configuration across browsing sessions.

> 16.  Does this specification have both "Security Considerations" and "Privacy
>      Considerations" sections?

The specification is not yet complete, but the explainer has a
[section](./README.md#privacy-considerations) on that.

> 17.  Do features in your specification enable origins to downgrade default
>      security protections?

No.

> 18.  What happens when a document that uses your feature is kept alive in BFCache
>      (instead of getting destroyed) after navigation, and potentially gets reused
>      on future navigations back to the document?

As long as the session is still active, new requests issued by the
restored document will start being checked by DBSC. This is analogous to
restoring a document that still has a login cookie.

To be cautious, since session termination can indicate a change in
authorization, we do evict documents from the bfcache when sessions are
terminated.

> 19.  What happens when a document that uses your feature gets disconnected?

Nothing. DBSC only applies to documents when they can make network requests. 

> 20.  Does your spec define when and how new kinds of errors should be raised?

No new kinds of errors are included.

> 21.  Does your feature allow sites to learn about the user's use of assistive technology?

No.

> 22.  What should this questionnaire have asked?

Nothing additional.
