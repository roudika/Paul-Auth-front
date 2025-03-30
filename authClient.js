// authClient.js with dynamic redirect_uri support
function base64URLEncode(str) {
  return btoa(String.fromCharCode(...new Uint8Array(str)))
    .replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
}

async function generatePKCE() {
  const code_verifier = [...crypto.getRandomValues(new Uint8Array(64))]
    .map(x => ('0' + x.toString(16)).slice(-2)).join('');

  const digest = await crypto.subtle.digest('SHA-256', new TextEncoder().encode(code_verifier));
  const code_challenge = base64URLEncode(digest);

  return { code_verifier, code_challenge };
}

const authClient = {
  baseUrl: 'https://auth.finanzam.com',

  async loginRedirect() {
    const { code_verifier, code_challenge } = await generatePKCE();
    localStorage.setItem('pkce_verifier', code_verifier);

    const redirect_uri = window.location.origin + window.location.pathname;

    window.location.href = `${this.baseUrl}/login?code_challenge=${code_challenge}&redirect_uri=${encodeURIComponent(redirect_uri)}`;
  },

  async handleCallback() {
    const code = new URLSearchParams(window.location.search).get('code');
    const code_verifier = localStorage.getItem('pkce_verifier');
    const redirect_uri = window.location.origin + window.location.pathname;

    if (!code || !code_verifier) throw new Error('Missing code or verifier');

    const res = await fetch(`${this.baseUrl}/callback`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ code, code_verifier, redirect_uri })
    });

    const data = await res.json();
    localStorage.setItem('msauth', JSON.stringify(data));
    return data;
  },

  getToken() {
    const session = JSON.parse(localStorage.getItem('msauth'));
    return session?.appToken || null;
  },

  getUser() {
    const session = JSON.parse(localStorage.getItem('msauth'));
    return session?.user || null;
  },

  logout() {
    localStorage.removeItem('msauth');
    location.reload();
  },

  isAuthenticated() {
    return !!this.getToken();
  }
};

export default authClient;
