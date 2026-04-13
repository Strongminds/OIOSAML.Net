using System;
using System.Text;
using Microsoft.AspNetCore.Http;
using dk.nita.saml20.config;

namespace dk.nita.saml20.Bindings
{
    /// <summary>
    /// Implementation of the HTTP POST binding.
    /// </summary>
    public class HttpPostBindingBuilder
    {
        private IDPEndPointElement _destinationEndpoint;

        /// <summary>
        /// Initializes a new instance of the <see cref="HttpPostBindingBuilder"/> class.
        /// </summary>
        public HttpPostBindingBuilder(IDPEndPointElement endpoint)
        {
            _destinationEndpoint = endpoint;
            _action = SAMLAction.SAMLRequest;
            _relayState = string.Empty;
        }

        private SAMLAction _action;

        /// <summary>
        /// Gets or sets the action.
        /// </summary>
        public SAMLAction Action
        {
            get { return _action; }
            set { _action = value; }
        }

        private string _relayState;

        /// <summary>
        /// Gets or sets the relaystate
        /// </summary>
        public string RelayState
        {
            get { return _relayState; }
            set { _relayState = value; }
        }

        private string _request;

        /// <summary>
        /// Gets or sets the request.
        /// </summary>
        public string Request
        {
            get { return _request; }
            set
            {
                if (!string.IsNullOrEmpty(_response))
                    throw new ArgumentException("Response property is already specified. Unable to set Request property.");
                _request = value;
            }
        }

        private string _response;

        /// <summary>
        /// Gets or sets the response.
        /// </summary>
        public string Response
        {
            get { return _response; }
            set
            {
                if (!string.IsNullOrEmpty(_request))
                    throw new ArgumentException("Request property is already specified. Unable to set Response property.");
                _response = value;
            }
        }

        /// <summary>
        /// Writes the POST binding HTML page directly to the HTTP response.
        /// </summary>
        public void ProcessRequest(HttpContext context)
        {
            if (_request == null && _response == null)
                throw new InvalidOperationException("A response or request message MUST be specified before generating the page.");

            string msg = _request ?? _response;
            string actionName = Enum.GetName(typeof(SAMLAction), Action);
            string encodedMsg = Convert.ToBase64String(Encoding.UTF8.GetBytes(msg));

            var sb = new StringBuilder();
            sb.AppendLine("<?xml version=\"1.0\" encoding=\"utf-8\"?>");
            sb.AppendLine("<!DOCTYPE html PUBLIC \"-//W3C//DTD XHTML 1.1//EN\" \"http://www.w3.org/TR/xhtml11/DTD/xhtml11.dtd\">");
            sb.AppendLine("<html xmlns=\"http://www.w3.org/1999/xhtml\" xml:lang=\"en\">");
            sb.AppendLine("<head><title>SAML2.0 POST binding</title></head>");
            sb.AppendLine("<body onload=\"document.forms[0].submit()\">");
            sb.AppendLine("<noscript><p><strong>Note:</strong> Since your browser does not support JavaScript, you must press the Continue button once to proceed.</p></noscript>");
            sb.AppendLine($"<form action=\"{System.Net.WebUtility.HtmlEncode(_destinationEndpoint.Url)}\" method=\"post\"><div>");

            if (!string.IsNullOrEmpty(RelayState))
            {
                sb.AppendLine($"<input type=\"hidden\" id=\"RelayState\" name=\"RelayState\" value=\"{System.Net.WebUtility.HtmlEncode(RelayState)}\" />");
            }

            sb.AppendLine($"<input type=\"hidden\" id=\"{actionName}\" name=\"{actionName}\" value=\"{encodedMsg}\" />");
            sb.AppendLine("<noscript><div><input type=\"submit\" value=\"Continue\"/></div></noscript>");
            sb.AppendLine("</div></form>");
            sb.AppendLine("</body>");
            sb.AppendLine("</html>");

            context.Response.ContentType = "text/html; charset=utf-8";
            context.Response.WriteAsync(sb.ToString()).GetAwaiter().GetResult();
        }
    }
}
