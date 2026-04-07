using Microsoft.AspNetCore.Http;
using dk.nita.saml20.session;
using dk.nita.saml20.identity;
using dk.nita.saml20.protocol;
using System.Security.Principal;
using dk.nita.saml20.Identity;
using dk.nita.saml20.Utils;

namespace dk.nita.saml20.Actions
{
    /// <summary>
    /// Sets the SamlPrincipal on the current http context
    /// </summary>
    public class SamlPrincipalAction : IAction
    {
        /// <summary>
        /// The default action name
        /// </summary>
        public const string ACTION_NAME = "SetSamlPrincipal";

        /// <summary>
        /// Action performed during login.
        /// </summary>
        public void LoginAction(AbstractEndpointHandler handler, HttpContext context, Saml20Assertion assertion)
        {
            // FormsAuthentication is not available in .NET Core. Auth cookie management is handled by the hosting application.
        }

        /// <summary>
        /// Action performed during logout.
        /// </summary>
        public void LogoutAction(AbstractEndpointHandler handler, HttpContext context, bool IdPInitiated)
        {
            // Set anonymous principal to make User.Identity.IsAuthenticated false in the current request.
            if (SamlHttpContextAccessor.Current != null)
            {
                SamlHttpContextAccessor.Current.User = new GenericPrincipal(new GenericIdentity(string.Empty), null);
            }
        }

        /// <summary>
        /// <see cref="IAction.SoapLogoutAction"/>
        /// </summary>
        public void SoapLogoutAction(AbstractEndpointHandler handler, HttpContext context, string userId)
        {
            // Do nothing
        }

        private string _name;

        /// <summary>
        /// Gets or sets the name of the action.
        /// </summary>
        public string Name
        {
            get
            {
                return string.IsNullOrEmpty(_name) ? ACTION_NAME : _name;
            }
            set { _name = value; }
        }
    }
}
