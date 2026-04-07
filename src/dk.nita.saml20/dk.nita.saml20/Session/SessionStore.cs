using System;
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

        /// <summary>
        /// The current user session. User session is read from cookie. If it doesn''t exist, null is returned.
        /// </summary>
        internal static UserSession CurrentSession
        {
            get
            {
                if (SamlHttpContextAccessor.Current != null)
                {
                    var sessionId = GetSessionIdFromCookie();

                    if (sessionId.HasValue)
                    {
                        return new UserSession(SessionStoreProvider, sessionId.Value);
                    }
                }

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
            string cookieValue = SamlHttpContextAccessor.Current.Request.Cookies[GetSessionCookieName()];
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
            return CurrentSession != null && SessionStoreProvider.DoesSessionExists(CurrentSession.SessionId);
        }
    }
}
