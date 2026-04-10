using System;
using System.IO;
using System.IO.Compression;
using System.Text;
using System.Threading;
using Microsoft.AspNetCore.Http;
using dk.nita.saml20.config;
using dk.nita.saml20.Utils;

namespace dk.nita.saml20.Session
{
    internal static class SessionStore
    {
        static SessionStore()
        {
            var type = FederationConfig.GetConfig().SessionType;
            if (!string.IsNullOrEmpty(type))
            {
                try
                {
                    var t = Type.GetType(type);
                    if (t != null)
                    {
                        SessionStoreProvider = (ISessionStoreProvider)Activator.CreateInstance(t);
                    }
                    else
                    {
                        throw new Exception($"The type {type} is not available as session provider. Please check the type name and assembly");
                    }
                }
                catch (Exception e)
                {
                    Trace.TraceData(System.Diagnostics.TraceEventType.Critical, "Could not instantiate the configured session provider. Message: " + e.Message);
                    throw;
                }
            }
            else
            {
                SessionStoreProvider = new InProcSessionStoreProvider();
            }

            var sessionTimeoutMinutes = FederationConfig.GetConfig().SessionTimeout;
            SessionStoreProvider.Initialize(TimeSpan.FromMinutes(sessionTimeoutMinutes), new SessionValueFactory());
        }

        private static readonly ISessionStoreProvider SessionStoreProvider;

        // Key used to cache a newly-written session ID in HttpContext.Items so it is available
        // within the same request. Response.Cookies are not readable via Request.Cookies until
        // the browser sends them on a subsequent request.
        internal const string PendingSessionIdItemKey = "dk.nita.saml20.PendingSessionId";

        // Prefix used to embed the session ID in the SAML RelayState so the session can be
        // recovered on the POST-back even if the browser does not send the Secure session cookie
        // (e.g. when browser SameSite policy blocks the cookie in a cross-site POST).
        internal const string RelayStateSessionPrefix = "oiosaml-sid-";

        // AsyncLocal fallback: carries the recovered session ID through the current async
        // execution context when TryRecoverSessionFromRelayState runs. This works even when
        // SamlHttpContextAccessor.Current is null or points to a different HttpContext object.
        private static readonly AsyncLocal<Guid?> _relayStateRecoveredSessionId = new AsyncLocal<Guid?>();

        /// <summary>
        /// The current user session. User session is read from cookie, HttpContext.Items, or the
        /// AsyncLocal set by TryRecoverSessionFromRelayState. Returns null if none is found.
        /// </summary>
        internal static UserSession CurrentSession
        {
            get
            {
                var sessionId = GetSessionIdFromCookie();
                if (sessionId.HasValue)
                    return new UserSession(SessionStoreProvider, sessionId.Value);
                return null;
            }
        }

        internal static void CreateSessionIfNotExists()
        {
            if (SamlHttpContextAccessor.Current == null)
            {
                throw new InvalidOperationException("A session cannot be created when running outside the context of an ASP.NET Core request");
            }

            var sessionId = GetSessionIdFromCookie();

            if (!sessionId.HasValue)
            {
                WriteSessionCookie();
            }
        }

        /// <summary>
        /// Associates the given userId with the current session id
        /// </summary>
        internal static void AssociateUserIdWithCurrentSession(string userId)
        {
            if (userId == null) throw new ArgumentNullException(nameof(userId));
            SessionStoreProvider.AssociateUserIdWithSessionId(userId.ToLowerInvariant(), CurrentSession.SessionId);
        }

        /// <summary>
        /// Abandons all sessions associated with the given userId
        /// </summary>
        internal static void AbandonAllSessions(string userId)
        {
            if (userId == null) throw new ArgumentNullException(nameof(userId));
            SessionStoreProvider.AbandonSessionsAssociatedWithUserId(userId.ToLowerInvariant());
        }

        private static Guid? GetSessionIdFromCookie()
        {
            // 1. AsyncLocal override — set by TryRecoverSessionFromRelayState when the browser's
            //    SameSite policy blocks the session cookie in a cross-site POST-back from the IdP.
            //    This works even when SamlHttpContextAccessor.Current is null or mismatched.
            var asyncLocal = _relayStateRecoveredSessionId.Value;
            if (asyncLocal.HasValue)
            {
                System.Console.Error.WriteLine($"[OIOSAML] GetSessionIdFromCookie: AsyncLocal={asyncLocal.Value:D}");
                return asyncLocal;
            }

            var context = SamlHttpContextAccessor.Current;
            if (context == null)
            {
                System.Console.Error.WriteLine("[OIOSAML] GetSessionIdFromCookie: context=null");
                return null;
            }

            // 2. HttpContext.Items — set by WriteSessionCookie() within the same request so the
            //    newly-written cookie is visible before the browser sends it back.
            if (context.Items.TryGetValue(PendingSessionIdItemKey, out var pending) && pending is Guid pendingId)
            {
                System.Console.Error.WriteLine($"[OIOSAML] GetSessionIdFromCookie: Items={pendingId:D}");
                return pendingId;
            }

            // 3. Cookie sent by the browser on subsequent requests.
            string cookieValue = context.Request.Cookies[GetSessionCookieName()];
            System.Console.Error.WriteLine($"[OIOSAML] GetSessionIdFromCookie: path={context.Request.Path} cookie={cookieValue ?? "<absent>"}");
            if (cookieValue != null)
                return new Guid(cookieValue);

            return null;
        }

        private static void WriteSessionCookie()
        {
            if (!SamlHttpContextAccessor.Current.Request.IsHttps)
            {
                throw new Saml20Exception("The service provider must use https since session cookie is not allowed on a unsecure transport");
            }

            var sessionId = Guid.NewGuid();
            var cookieName = GetSessionCookieName();

            var cookieOptions = new CookieOptions
            {
                Secure = true,
                HttpOnly = true,
            };

            var shouldSendSameSiteNoneCookie = BrowserSupportUtil.ShouldSendSameSiteNone(SamlHttpContextAccessor.Current.Request.Headers.UserAgent.ToString());
            if (shouldSendSameSiteNoneCookie)
            {
                cookieOptions.SameSite = SameSiteMode.None;
            }

            SamlHttpContextAccessor.Current.Response.Cookies.Append(cookieName, sessionId.ToString(), cookieOptions);
            System.Console.Error.WriteLine($"[OIOSAML] WriteSessionCookie: name={cookieName} sessionId={sessionId:D} sameSite={cookieOptions.SameSite} path={SamlHttpContextAccessor.Current.Request.Path} isHttps={SamlHttpContextAccessor.Current.Request.IsHttps} responseHasStarted={SamlHttpContextAccessor.Current.Response.HasStarted}");

            // Also store the session ID in HttpContext.Items so CurrentSession can find it
            // within the same request before the browser echoes the cookie back.
            SamlHttpContextAccessor.Current.Items[PendingSessionIdItemKey] = sessionId;
        }

        /// <summary>
        /// Builds a RelayState value that embeds the current session ID so the session can be
        /// recovered on the POST-back even when the browser does not send the session cookie.
        /// Returns null when there is no active session.
        /// </summary>
        internal static string BuildRelayState()
        {
            var session = CurrentSession;
            return session != null ? RelayStateSessionPrefix + session.SessionId.ToString("D") : null;
        }

        /// <summary>
        /// If <paramref name="relayState"/> contains our embedded session prefix (either as plain
        /// text or DEFLATE+base64-encoded as produced by HttpRedirectBindingBuilder for requests),
        /// injects the recovered session ID into the AsyncLocal and HttpContext.Items so
        /// <see cref="CurrentSession"/> can find it even if the browser session cookie was blocked.
        /// </summary>
        internal static void TryRecoverSessionFromRelayState(string relayState)
        {
            if (string.IsNullOrEmpty(relayState)) return;

            // HttpRedirectBindingBuilder DEFLATE-compresses and base64-encodes the RelayState
            // value before embedding it in the AuthnRequest URL.  The IdP echoes the encoded
            // blob back unchanged in the POST form field, so we must decode it first.
            var decoded = TryDecodeRelayState(relayState);
            if (!decoded.StartsWith(RelayStateSessionPrefix, StringComparison.Ordinal)) return;

            var sessionIdStr = decoded.Substring(RelayStateSessionPrefix.Length);
            if (Guid.TryParse(sessionIdStr, out var sessionId))
            {
                // Primary: AsyncLocal — works even if SamlHttpContextAccessor.Current is null.
                _relayStateRecoveredSessionId.Value = sessionId;

                // Belt-and-suspenders: also set via IHttpContextAccessor if available.
                if (SamlHttpContextAccessor.Current != null)
                    SamlHttpContextAccessor.Current.Items[PendingSessionIdItemKey] = sessionId;
            }
        }

        /// <summary>
        /// Returns the plain-text relay state value.  HttpRedirectBindingBuilder encodes relay
        /// state with DEFLATE + base64 for requests; this reverses that encoding when present.
        /// </summary>
        private static string TryDecodeRelayState(string relayState)
        {
            // Already plain text — nothing to decode.
            if (relayState.StartsWith(RelayStateSessionPrefix, StringComparison.Ordinal))
                return relayState;

            try
            {
                var compressed = Convert.FromBase64String(relayState);
                using var input = new MemoryStream(compressed);
                using var deflate = new DeflateStream(input, CompressionMode.Decompress);
                using var reader = new StreamReader(deflate, Encoding.UTF8);
                return reader.ReadToEnd();
            }
            catch
            {
                // Not base64+deflate encoded — return original.
                return relayState;
            }
        }

        private static string GetSessionCookieName()
        {
            var name = FederationConfig.GetConfig().SessionCookieName;

            if (string.IsNullOrWhiteSpace(name))
            {
                throw new Saml20Exception($"The session cookie name ''{name}'' is not valid. Ensure a valid cookie name is set in the configuration element ''SessionCookieName''");
            }

            return name;
        }

        /// <summary>
        /// Asserts that the user has a session.
        /// </summary>
        internal static void AssertSessionExists()
        {
            if (!DoesSessionExists())
            {
                if (CurrentSession == null)
                {
                    throw new Saml20Exception(
                        "The user doesn''t have a session in context of a cookie ... which is required at this point in the pipeline. Plausible reason is that OIOSAML.Net is not running under https. The session cookie is marked with ''secure only''.");
                }
                else if (!SessionStoreProvider.DoesSessionExists(CurrentSession.SessionId))
                {
                    throw new Saml20Exception(
                        "The user doesn''t have a session in session store which is required at this point in the pipeline. Plausible reason is that the user''s session has expired. \nIf the application is running in a web farm ensure distributed sessions is supported by the session store provider.");
                }
                else
                {
                    throw new Saml20Exception("The user doesn''t have a session for unknown reasons.");
                }
            }
        }

        /// <summary>
        /// Checks whether or not the user has a session.
        /// SamlAssertionLite is the only item in the session store after a successful login flow.
        /// </summary>
        internal static bool DoesSessionExists()
        {
            var session = CurrentSession;
            if (session == null)
            {
                System.Console.Error.WriteLine("[OIOSAML] DoesSessionExists: CurrentSession=null");
                return false;
            }
            var exists = SessionStoreProvider.DoesSessionExists(session.SessionId);
            System.Console.Error.WriteLine($"[OIOSAML] DoesSessionExists: sessionId={session.SessionId:D} exists={exists}");
            return exists;
        }
    }
}
