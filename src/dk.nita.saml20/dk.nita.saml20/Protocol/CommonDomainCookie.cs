using System;
using System.Collections.Generic;
using System.Text;
using System.Net;

namespace dk.nita.saml20.protocol
{
    /// <summary>
    /// Implements access to the common domain cookie specified in the SAML20 identity provider discovery profile
    /// </summary>
    public class CommonDomainCookie
    {
        /// <summary>
        /// The name of the CDC cookie
        /// </summary>
        public const string COMMON_DOMAIN_COOKIE_NAME = "_saml_idp";

        private readonly string _saml_idp;
        private bool _isLoaded = false;
        private bool _isSet = false;
        private readonly List<string> _knownIDPs;

        /// <summary>
        /// Initializes a new instance of the <see cref="CommonDomainCookie"/> class.
        /// </summary>
        /// <param name="saml_idp">The cookie value.</param>
        public CommonDomainCookie(string saml_idp)
        {
            _saml_idp = saml_idp;
            _knownIDPs = new List<string>();
        }

        /// <summary>
        /// Gets a value indicating whether the Common Domain Cookie was set (had valid values).
        /// </summary>
        public bool IsSet
        {
            get
            {
                Load();
                return _isSet;
            }
        }

        /// <summary>
        /// Gets the list of known IDPs.
        /// </summary>
        public List<string> KnownIDPs
        {
            get
            {
                EnsureSet();
                return _knownIDPs;
            }
        }

        /// <summary>
        /// Gets the preferred IDP.
        /// </summary>
        public string PreferredIDP
        {
            get
            {
                EnsureSet();

                if (_knownIDPs.Count > 0)
                    return _knownIDPs[_knownIDPs.Count - 1];

                return string.Empty;
            }
        }

        private void EnsureSet()
        {
            Load();
            if (!_isSet)
                throw new Saml20Exception("The common domain cookie is not set. Please make sure to check the IsSet property before accessing the class'' properties.");
        }

        private void Load()
        {
            if (!string.IsNullOrEmpty(_saml_idp))
                LoadFromString();
        }

        private void LoadFromString()
        {
            if (!_isLoaded)
            {
                ParseCookie(_saml_idp);
                _isSet = true;
                _isLoaded = true;
            }
        }

        private void ParseCookie(string rawValue)
        {
            string value = WebUtility.UrlDecode(rawValue);
            string[] idps = value.Split(new char[] { ' ' }, StringSplitOptions.RemoveEmptyEntries);
            foreach (string base64idp in idps)
            {
                byte[] bytes = Convert.FromBase64String(base64idp);
                string idp = Encoding.ASCII.GetString(bytes);
                _knownIDPs.Add(idp);
            }
        }
    }
}
