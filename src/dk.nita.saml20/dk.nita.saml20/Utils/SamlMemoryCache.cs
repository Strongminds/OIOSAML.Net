using System;
using Microsoft.Extensions.Caching.Memory;

namespace dk.nita.saml20.Utils
{
    internal static class SamlMemoryCache
    {
        private static readonly IMemoryCache Cache = new MemoryCache(new MemoryCacheOptions());

        internal static object Get(string key) => Cache.TryGetValue(key, out var val) ? val : null;

        internal static void Insert(string key, object value, DateTime absoluteExpiration)
        {
            Cache.Set(key, value, absoluteExpiration);
        }
    }
}
