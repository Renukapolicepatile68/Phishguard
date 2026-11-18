(() => {
  const configuredUrl = window.PHISHGUARD_API_URL;
  if (configuredUrl) {
    window.PHISHGUARD_API_URL = configuredUrl.replace(/\/+$/, "");
    return;
  }

  const hostname = window.location.hostname.replace(/^\[|\]$/g, "");
  const privateIpv4 = /^(10\.|192\.168\.|172\.(1[6-9]|2\d|3[01])\.)/.test(hostname);
  const localHost = hostname === "localhost" || hostname === "127.0.0.1" ||
    hostname === "::1" || hostname.endsWith(".localhost") || privateIpv4;
  const apiOrigin = localHost
    ? `${window.location.protocol}//${window.location.hostname}:5000`
    : window.location.origin;
  window.PHISHGUARD_API_URL = `${apiOrigin}/api`;
})();
