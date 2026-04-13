using System.Text;
using dk.nita.saml20.config;
using Microsoft.AspNetCore.Http;
using Saml2.Properties;

namespace dk.nita.saml20.protocol.pages
{
    /// <summary>
    /// Page that handles selecting an IdP when more than one is configured
    /// </summary>
    public class SelectSaml20IDP : BasePage
    {
        public override void ProcessRequest(HttpContext context)
        {
            TitleText = Resources.ChooseIDP;
            HeaderText = Resources.ChooseIDP;

            var sb = new StringBuilder();
            sb.Append(Resources.ChooseDesc);
            sb.Append("<br/><br/>");

            SAML20FederationConfig config = SAML20FederationConfig.GetConfig();
            string forceAuthnAsString = context.Request.Query[Saml20SignonHandler.IDPForceAuthn].ToString();
            bool.TryParse(forceAuthnAsString, out bool forceAuthn);

            string isPassiveAsString = context.Request.Query[Saml20SignonHandler.IDPIsPassive].ToString();
            bool.TryParse(isPassiveAsString, out bool isPassive);

            string desiredNsisLoa = context.Request.Query[Saml20SignonHandler.NsisLoa].ToString();
            string desiredProfile = context.Request.Query[Saml20SignonHandler.Profile].ToString();

            foreach (IDPEndPoint endPoint in config.IDPEndPoints)
            {
                if (endPoint.metadata != null)
                {
                    string linkText = System.Net.WebUtility.HtmlEncode(string.IsNullOrEmpty(endPoint.Name) ? endPoint.metadata.EntityId : endPoint.Name);
                    sb.Append($"<a href=\"{System.Net.WebUtility.HtmlEncode(endPoint.GetIDPLoginUrl(forceAuthn, isPassive, desiredNsisLoa, desiredProfile))}\">{linkText}</a>");
                    sb.Append($" <a href=\"{System.Net.WebUtility.HtmlEncode(endPoint.GetIDPLoginUrl(forceAuthn, isPassive, desiredNsisLoa, desiredProfile, "Android"))}\" style=\"margin-left:10px\">({Resources.PlatformAndroid})</a>");
                    sb.Append($" <a href=\"{System.Net.WebUtility.HtmlEncode(endPoint.GetIDPLoginUrl(forceAuthn, isPassive, desiredNsisLoa, desiredProfile, "iOS"))}\" style=\"margin-left:10px\">({Resources.PlatformIOS})</a>");
                    sb.Append("<br/>");
                }
                else
                {
                    sb.Append($"<span style=\"text-decoration:line-through\">{System.Net.WebUtility.HtmlEncode(endPoint.Name)}</span> <span style=\"font-size:x-small\">(Metadata not found)</span><br/>");
                }
            }
            sb.Append("<br/><br/>");
            BodyContent = sb.ToString();

            context.Response.ContentType = "text/html";
            context.Response.WriteAsync(RenderHtml()).GetAwaiter().GetResult();
        }
    }
}
