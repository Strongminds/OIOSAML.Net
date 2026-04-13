using System;
using System.IO;
using System.Net;
using System.Net.Mime;
using System.Net.Security;
using System.Security.Cryptography.X509Certificates;
using System.ServiceModel;
using System.ServiceModel.Channels;
using System.Text;
using Microsoft.AspNetCore.Http;
using System.Xml;
using dk.nita.saml20.config;
using dk.nita.saml20.Utils;

namespace dk.nita.saml20.Bindings
{
    /// <summary>
    /// Implements the HTTP SOAP binding
    /// </summary>
    public class HttpSOAPBindingBuilder
    {
        /// <summary>
        /// The current http context
        /// </summary>
        protected HttpContext _context;

        /// <summary>
        /// Initializes a new instance of the <see cref="HttpSOAPBindingBuilder"/> class.
        /// </summary>
        public HttpSOAPBindingBuilder(HttpContext context)
        {
            _context = context;
        }

        /// <summary>
        /// Sends a response message.
        /// </summary>
        public void SendResponseMessage(string samlMessage)
        {
            _context.Response.ContentType = "text/xml";
            StreamWriter writer = new StreamWriter(_context.Response.Body);
            writer.Write(WrapInSoapEnvelope(samlMessage));
            writer.Flush();
            writer.Close();
        }

        /// <summary>
        /// Wraps a message in a SOAP envelope.
        /// </summary>
        public string WrapInSoapEnvelope(string s)
        {
            StringBuilder builder = new StringBuilder();
            builder.AppendLine(SOAPConstants.EnvelopeBegin);
            builder.AppendLine(SOAPConstants.BodyBegin);
            builder.AppendLine(s);
            builder.AppendLine(SOAPConstants.BodyEnd);
            builder.AppendLine(SOAPConstants.EnvelopeEnd);

            return builder.ToString();
        }

        /// <summary>
        /// Validates the server certificate.
        /// </summary>
        public static bool ValidateServerCertificate(object sender, X509Certificate certificate, X509Chain chain, SslPolicyErrors sslPolicyErrors)
        {
            if (sslPolicyErrors == SslPolicyErrors.None)
                return true;
            return false;
        }

        private static Binding CreateSslBinding()
        {
            BasicHttpBinding binding = new BasicHttpBinding(BasicHttpSecurityMode.Transport);
            binding.TextEncoding = Encoding.UTF8;
            return binding;
        }

        /// <summary>
        /// Gets a response from the IdP based on a message.
        /// </summary>
        public Stream GetResponse(string endpoint, string message, HttpBasicAuthElement basicAuth)
        {
            Binding binding = CreateSslBinding();
            Message request = Message.CreateMessage(binding.MessageVersion, HttpArtifactBindingConstants.SOAPAction, new SimpleBodyWriter(message));

            request.Headers.To = new Uri(endpoint);

            HttpRequestMessageProperty property = new HttpRequestMessageProperty();
            property.Method = "POST";
            property.Headers.Add(HttpRequestHeader.ContentType, "text/xml; charset=utf-8");

            if (basicAuth != null && basicAuth.Enabled)
            {
                string basicAuthzHeader = "Basic " +
                                          Convert.ToBase64String(Encoding.UTF8.GetBytes(basicAuth.Username + ":" + basicAuth.Password));
                property.Headers.Add(HttpRequestHeader.Authorization, basicAuthzHeader);
            }

            request.Properties.Add(HttpRequestMessageProperty.Name, property);
            string relayState = _context.GetRequestParam("relayState");
            if (relayState != null)
                request.Properties.Add("relayState", relayState);

            EndpointAddress epa = new EndpointAddress(endpoint);

            ChannelFactory<IRequestChannel> factory = new ChannelFactory<IRequestChannel>(binding, epa);
            IRequestChannel reqChannel = factory.CreateChannel();

            reqChannel.Open();
            Message response = reqChannel.Request(request);
            Console.WriteLine(response);
            reqChannel.Close();
            XmlDocument xDoc = new XmlDocument();
            xDoc.XmlResolver = null;
            xDoc.PreserveWhitespace = true;
            xDoc.Load(response.GetReaderAtBodyContents());
            string outerXml = xDoc.DocumentElement.OuterXml;
            MemoryStream memStream = new MemoryStream(Encoding.UTF8.GetBytes(outerXml));
            return memStream;
        }
    }

    /// <summary>
    /// A simple body writer
    /// </summary>
    internal class SimpleBodyWriter : BodyWriter
    {
        private string _message;

        public SimpleBodyWriter(string message) : base(false)
        {
            _message = message;
        }

        protected override void OnWriteBodyContents(XmlDictionaryWriter writer)
        {
            writer.WriteRaw(_message);
        }
    }
}
