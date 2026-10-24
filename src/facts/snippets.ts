/*
 * Fix snippets per framework and topic. Each one was checked against the
 * framework's own documentation (linked) on FACTS_VERIFIED_ON, for the
 * current major version. A topic a framework does not need (TRACE in
 * Express, which only answers routed methods) has no snippet; the finding's
 * generic fix text still applies.
 */
import type { FixTopic, FrameworkId, Snippet, Source } from '../types.js';

const src = (title: string, url: string): Source => ({ title, url });
const CSP = "default-src 'self'; object-src 'none'; base-uri 'self'; frame-ancestors 'self'";

type Table = Partial<Record<FixTopic, Omit<Snippet, 'framework'>>>;

const express: Table = {
  headers: {
    lang: 'js',
    code: `import helmet from "helmet"; // helmet 8 sets CSP, HSTS, nosniff, frame and COOP headers
app.use(helmet({
  referrerPolicy: { policy: "strict-origin-when-cross-origin" },
  strictTransportSecurity: { maxAge: 31536000, includeSubDomains: true },
}));
app.use((req, res, next) => { // helmet does not set Permissions-Policy
  res.setHeader("Permissions-Policy", "camera=(), microphone=(), geolocation=()"); next();
});`,
    source: src('Helmet', 'https://helmetjs.github.io/'),
  },
  cookies: {
    lang: 'js',
    code: `app.set("trust proxy", 1); // only behind a TLS-terminating proxy
app.use(session({ secret: process.env.SESSION_SECRET, resave: false, saveUninitialized: false,
  cookie: { secure: true, httpOnly: true, sameSite: "lax" } }));`,
    source: src('express-session: cookie options', 'https://github.com/expressjs/session#cookie'),
  },
  cors: {
    lang: 'js',
    code: `import cors from "cors";
app.use(cors({ origin: ["https://app.example.com"], credentials: true }));
// never origin: true (reflects any Origin) together with credentials`,
    source: src('cors: configuration options', 'https://github.com/expressjs/cors#configuration-options'),
  },
  version: {
    lang: 'js',
    code: `app.disable("x-powered-by"); // helmet() also removes it`,
    source: src('Express: security best practices', 'https://expressjs.com/en/advanced/best-practice-security.html'),
  },
};

const nextjs: Table = {
  headers: {
    lang: 'ts',
    code: `// next.config.ts — for a nonce-based CSP on App Router pages, see the CSP guide
const securityHeaders = [
  { key: "Strict-Transport-Security", value: "max-age=63072000; includeSubDomains" },
  { key: "Content-Security-Policy", value: "${CSP}" },
  { key: "X-Content-Type-Options", value: "nosniff" },
  { key: "Referrer-Policy", value: "strict-origin-when-cross-origin" },
  { key: "Permissions-Policy", value: "camera=(), microphone=(), geolocation=()" },
];
export default { poweredByHeader: false, async headers() { return [{ source: "/(.*)", headers: securityHeaders }]; } };`,
    source: src('Next.js: headers in next.config', 'https://nextjs.org/docs/app/api-reference/config/next-config-js/headers'),
  },
  cookies: {
    lang: 'ts',
    code: `import { cookies } from "next/headers";
(await cookies()).set("session", token, { secure: true, httpOnly: true, sameSite: "lax", path: "/" });`,
    source: src('Next.js: cookies()', 'https://nextjs.org/docs/app/api-reference/functions/cookies'),
  },
  cors: {
    lang: 'ts',
    code: `// proxy.ts (middleware.ts before Next.js 16)
const allowed = ["https://app.example.com"];
export function proxy(req: NextRequest) {
  const origin = req.headers.get("origin") ?? "";
  const res = NextResponse.next();
  if (allowed.includes(origin)) res.headers.set("Access-Control-Allow-Origin", origin);
  return res;
}`,
    source: src('Next.js: proxy, CORS', 'https://nextjs.org/docs/app/api-reference/file-conventions/proxy#cors'),
  },
  version: {
    lang: 'ts',
    code: `// next.config.ts
export default { poweredByHeader: false };`,
    source: src('Next.js: poweredByHeader', 'https://nextjs.org/docs/app/api-reference/config/next-config-js/poweredByHeader'),
  },
};

const nestjs: Table = {
  headers: {
    lang: 'ts',
    code: `const app = await NestFactory.create(AppModule);
app.useSecurityHeaders({ // NestJS 12.1+ (Helmet 8 defaults); before 12.1: app.use(helmet({...}))
  referrerPolicy: { policy: "strict-origin-when-cross-origin" },
  strictTransportSecurity: { maxAge: 31536000 },
});`,
    source: src('NestJS: Helmet / security headers', 'https://docs.nestjs.com/security/helmet'),
  },
  cookies: {
    lang: 'ts',
    code: `app.use(session({ secret: process.env.SESSION_SECRET, resave: false, saveUninitialized: false,
  cookie: { secure: true, httpOnly: true, sameSite: "lax" } }));`,
    source: src('NestJS: Session', 'https://docs.nestjs.com/techniques/session'),
  },
  cors: {
    lang: 'ts',
    code: `app.enableCors({ origin: ["https://app.example.com"], credentials: true });`,
    source: src('NestJS: CORS', 'https://docs.nestjs.com/security/cors'),
  },
  version: {
    lang: 'ts',
    code: `app.useSecurityHeaders(); // or helmet(): both remove X-Powered-By`,
    source: src('NestJS: Helmet / security headers', 'https://docs.nestjs.com/security/helmet'),
  },
};

const django: Table = {
  headers: {
    lang: 'python',
    code: `MIDDLEWARE = ["django.middleware.security.SecurityMiddleware",
              "django.middleware.csp.ContentSecurityPolicyMiddleware",  # Django 6.0+
              "django.middleware.clickjacking.XFrameOptionsMiddleware", ...]
SECURE_HSTS_SECONDS = 31536000          # sent on HTTPS responses only
SECURE_HSTS_INCLUDE_SUBDOMAINS = True
SECURE_REFERRER_POLICY = "strict-origin-when-cross-origin"
from django.utils.csp import CSP
SECURE_CSP = {"default-src": [CSP.SELF], "object-src": [CSP.NONE],
              "base-uri": [CSP.SELF], "frame-ancestors": [CSP.SELF]}`,
    source: src('Django: Content Security Policy', 'https://docs.djangoproject.com/en/6.1/ref/csp/'),
  },
  cookies: {
    lang: 'python',
    code: `SESSION_COOKIE_SECURE = True
SESSION_COOKIE_HTTPONLY = True   # default
SESSION_COOKIE_SAMESITE = "Lax"  # default
CSRF_COOKIE_SECURE = True`,
    source: src('Django settings: SESSION_COOKIE_SECURE', 'https://docs.djangoproject.com/en/6.1/ref/settings/#session-cookie-secure'),
  },
  version: {
    lang: 'sh',
    code: `# Django adds no Server header; "WSGIServer" comes from runserver, which is for development only.
gunicorn mysite.wsgi   # or another production server`,
    source: src('django-admin: runserver', 'https://docs.djangoproject.com/en/6.1/ref/django-admin/#runserver'),
  },
  methods: {
    lang: 'python',
    code: `from django.views.decorators.http import require_http_methods
@require_http_methods(["GET", "POST"])
def my_view(request): ...`,
    source: src('Django: view decorators', 'https://docs.djangoproject.com/en/6.1/topics/http/decorators/'),
  },
};

const flask: Table = {
  headers: {
    lang: 'python',
    code: `@app.after_request
def security_headers(response):
    response.headers["Strict-Transport-Security"] = "max-age=31536000; includeSubDomains"
    response.headers["Content-Security-Policy"] = "${CSP}"
    response.headers["X-Content-Type-Options"] = "nosniff"
    response.headers["Referrer-Policy"] = "strict-origin-when-cross-origin"
    response.headers["Permissions-Policy"] = "camera=(), microphone=(), geolocation=()"
    return response`,
    source: src('Flask: Security headers', 'https://flask.palletsprojects.com/en/stable/web-security/#security-headers'),
  },
  cookies: {
    lang: 'python',
    code: `app.config.update(SESSION_COOKIE_SECURE=True, SESSION_COOKIE_HTTPONLY=True, SESSION_COOKIE_SAMESITE="Lax")`,
    source: src('Flask: Set-Cookie options', 'https://flask.palletsprojects.com/en/stable/web-security/#set-cookie-options'),
  },
  version: {
    lang: 'sh',
    code: `# "Server: Werkzeug/..." comes from the development server; deploy behind a production server.
gunicorn "app:app"`,
    source: src('Flask: Deploying to production', 'https://flask.palletsprojects.com/en/stable/deploying/'),
  },
};

const fastapi: Table = {
  headers: {
    lang: 'python',
    code: `@app.middleware("http")
async def security_headers(request: Request, call_next):
    response = await call_next(request)
    response.headers["Strict-Transport-Security"] = "max-age=31536000; includeSubDomains"
    response.headers["Content-Security-Policy"] = "${CSP}"  # breaks /docs, which loads from a CDN
    response.headers["X-Content-Type-Options"] = "nosniff"
    response.headers["Referrer-Policy"] = "strict-origin-when-cross-origin"
    return response`,
    source: src('FastAPI: Middleware', 'https://fastapi.tiangolo.com/tutorial/middleware/'),
  },
  cookies: {
    lang: 'python',
    code: `from starlette.middleware.sessions import SessionMiddleware
app.add_middleware(SessionMiddleware, secret_key=SECRET, https_only=True, same_site="lax")
# your own cookies: response.set_cookie("k", v, secure=True, httponly=True, samesite="lax")`,
    source: src('Starlette: SessionMiddleware', 'https://www.starlette.io/middleware/#sessionmiddleware'),
  },
  cors: {
    lang: 'python',
    code: `from fastapi.middleware.cors import CORSMiddleware
app.add_middleware(CORSMiddleware, allow_origins=["https://app.example.com"],
                   allow_credentials=True, allow_methods=["GET", "POST"], allow_headers=["Content-Type"])`,
    source: src('FastAPI: CORS', 'https://fastapi.tiangolo.com/tutorial/cors/'),
  },
  version: {
    lang: 'sh',
    code: `uvicorn main:app --no-server-header`,
    source: src('Uvicorn: settings', 'https://www.uvicorn.org/settings/'),
  },
};

const rails: Table = {
  headers: {
    lang: 'ruby',
    code: `# config/environments/production.rb
config.force_ssl = true  # HTTPS redirect, HSTS and Secure cookies
# config/initializers/content_security_policy.rb
Rails.application.configure do
  config.content_security_policy do |policy|
    policy.default_src :self; policy.object_src :none
    policy.base_uri :self;    policy.frame_ancestors :self
  end
end`,
    source: src('Rails Security Guide: Content-Security-Policy', 'https://guides.rubyonrails.org/security.html#content-security-policy-header'),
  },
  cookies: {
    lang: 'ruby',
    code: `# config/environments/production.rb
config.force_ssl = true  # marks cookies Secure; session cookies are HttpOnly and SameSite=Lax by default`,
    source: src('Rails: config.force_ssl', 'https://guides.rubyonrails.org/configuring.html#config-force-ssl'),
  },
};

const laravel: Table = {
  headers: {
    lang: 'php',
    code: `// app/Http/Middleware/SecurityHeaders.php, appended in bootstrap/app.php
public function handle(Request $request, Closure $next): Response {
    $response = $next($request);
    if ($request->secure()) $response->headers->set('Strict-Transport-Security', 'max-age=31536000; includeSubDomains');
    $response->headers->set('Content-Security-Policy', "${CSP}");
    $response->headers->set('X-Content-Type-Options', 'nosniff');
    $response->headers->set('Referrer-Policy', 'strict-origin-when-cross-origin');
    return $response;
}`,
    source: src('Laravel: Middleware', 'https://laravel.com/docs/13.x/middleware'),
  },
  cookies: {
    lang: 'ini',
    code: `# .env (read by config/session.php)
SESSION_SECURE_COOKIE=true
SESSION_HTTP_ONLY=true
SESSION_SAME_SITE=lax`,
    source: src('Laravel: config/session.php', 'https://github.com/laravel/framework/blob/13.x/config/session.php'),
  },
  cors: {
    lang: 'php',
    code: `// config/cors.php (php artisan config:publish cors) — the default allowed_origins is ['*']
'allowed_origins' => ['https://app.example.com'],
'supports_credentials' => true,`,
    source: src('Laravel: CORS', 'https://laravel.com/docs/13.x/routing#cors'),
  },
  version: {
    lang: 'ini',
    code: `; php.ini
expose_php = Off`,
    source: src('PHP: expose_php', 'https://www.php.net/manual/en/ini.core.php#ini.expose-php'),
  },
};

const spring: Table = {
  headers: {
    lang: 'java',
    code: `http.headers(headers -> headers
    .httpStrictTransportSecurity(hsts -> hsts.includeSubDomains(true).maxAgeInSeconds(31536000))
    .contentSecurityPolicy(csp -> csp.policyDirectives("${CSP}"))
    .referrerPolicy(ref -> ref.policy(ReferrerPolicy.STRICT_ORIGIN_WHEN_CROSS_ORIGIN))
    .permissionsPolicyHeader(pp -> pp.policy("camera=(), microphone=(), geolocation=()")));  // 6.4+`,
    source: src('Spring Security: Security HTTP response headers', 'https://docs.spring.io/spring-security/reference/servlet/exploits/headers.html'),
  },
  cookies: {
    lang: 'properties',
    code: `server.servlet.session.cookie.secure=true
server.servlet.session.cookie.http-only=true
server.servlet.session.cookie.same-site=lax`,
    source: src('Spring Boot: application properties', 'https://docs.spring.io/spring-boot/appendix/application-properties/index.html'),
  },
  cors: {
    lang: 'java',
    code: `CorsConfiguration config = new CorsConfiguration();
config.setAllowedOrigins(List.of("https://app.example.com"));
config.setAllowCredentials(true);  // never with "*" or a reflected origin
UrlBasedCorsConfigurationSource source = new UrlBasedCorsConfigurationSource();
source.registerCorsConfiguration("/**", config);  // expose as a @Bean; http.cors(withDefaults())`,
    source: src('Spring Security: CORS', 'https://docs.spring.io/spring-security/reference/servlet/integrations/cors.html'),
  },
};

const aspnet: Table = {
  headers: {
    lang: 'csharp',
    code: `builder.Services.AddHsts(o => { o.MaxAge = TimeSpan.FromDays(365); o.IncludeSubDomains = true; }); // default 30 days
if (!app.Environment.IsDevelopment()) app.UseHsts();
app.Use(async (context, next) => {
    var h = context.Response.Headers;
    h.Append("Content-Security-Policy", "${CSP}");
    h.Append("X-Content-Type-Options", "nosniff");
    h.Append("Referrer-Policy", "strict-origin-when-cross-origin");
    await next(context);
});`,
    source: src('ASP.NET Core: Enforce HTTPS and HSTS', 'https://learn.microsoft.com/en-us/aspnet/core/security/enforcing-ssl?view=aspnetcore-10.0'),
  },
  cookies: {
    lang: 'csharp',
    code: `builder.Services.Configure<CookiePolicyOptions>(o => {
    o.MinimumSameSitePolicy = SameSiteMode.Lax;
    o.HttpOnly = HttpOnlyPolicy.Always;
    o.Secure = CookieSecurePolicy.Always; });
app.UseCookiePolicy();  // before UseAuthentication`,
    source: src('ASP.NET Core: CookiePolicyOptions', 'https://learn.microsoft.com/en-us/dotnet/api/microsoft.aspnetcore.builder.cookiepolicyoptions'),
  },
  cors: {
    lang: 'csharp',
    code: `builder.Services.AddCors(o => o.AddPolicy("Frontend", p =>
    p.WithOrigins("https://app.example.com").AllowCredentials()));
app.UseCors("Frontend");  // after UseRouting; never AllowAnyOrigin or SetIsOriginAllowed(_ => true) with credentials`,
    source: src('ASP.NET Core: CORS', 'https://learn.microsoft.com/en-us/aspnet/core/security/cors?view=aspnetcore-10.0'),
  },
  version: {
    lang: 'csharp',
    code: `builder.WebHost.ConfigureKestrel(o => o.AddServerHeader = false);`,
    source: src('Kestrel: AddServerHeader', 'https://learn.microsoft.com/en-us/dotnet/api/microsoft.aspnetcore.server.kestrel.core.kestrelserveroptions.addserverheader'),
  },
};

const nginx: Table = {
  headers: {
    lang: 'nginx',
    code: `# in the "listen 443 ssl" server block; "always" also covers 4xx/5xx responses
add_header Strict-Transport-Security "max-age=31536000; includeSubDomains" always;
add_header Content-Security-Policy "${CSP}" always;
add_header X-Content-Type-Options "nosniff" always;
add_header Referrer-Policy "strict-origin-when-cross-origin" always;
add_header Permissions-Policy "camera=(), microphone=(), geolocation=()" always;
# a location with its own add_header drops these (unless add_header_inherit merge; in 1.29.3+)`,
    source: src('nginx: ngx_http_headers_module', 'https://nginx.org/en/docs/http/ngx_http_headers_module.html'),
  },
  cookies: {
    lang: 'nginx',
    code: `proxy_cookie_flags ~ secure httponly samesite=lax;  # nginx 1.19.3+`,
    source: src('nginx: proxy_cookie_flags', 'https://nginx.org/en/docs/http/ngx_http_proxy_module.html#proxy_cookie_flags'),
  },
  version: {
    lang: 'nginx',
    code: `server_tokens off;
proxy_hide_header X-Powered-By;   # or fastcgi_hide_header X-Powered-By;`,
    source: src('nginx: server_tokens', 'https://nginx.org/en/docs/http/ngx_http_core_module.html#server_tokens'),
  },
  methods: {
    lang: 'nginx',
    code: `location / { limit_except GET POST { deny all; } }  # GET also allows HEAD`,
    source: src('nginx: limit_except', 'https://nginx.org/en/docs/http/ngx_http_core_module.html#limit_except'),
  },
};

const apache: Table = {
  headers: {
    lang: 'apache',
    code: `# in <VirtualHost *:443>, with mod_headers
Header always set Strict-Transport-Security "max-age=31536000; includeSubDomains"
Header always set Content-Security-Policy "${CSP}"
Header always set X-Content-Type-Options "nosniff"
Header always set Referrer-Policy "strict-origin-when-cross-origin"
Header always set Permissions-Policy "camera=(), microphone=(), geolocation=()"`,
    source: src('Apache httpd: mod_headers', 'https://httpd.apache.org/docs/2.4/mod/mod_headers.html#header'),
  },
  cors: {
    lang: 'apache',
    code: `SetEnvIf Origin "^https://app\\.example\\.com$" CORS_ORIGIN=$0
Header always set Access-Control-Allow-Origin "%{CORS_ORIGIN}e" env=CORS_ORIGIN
Header always set Access-Control-Allow-Credentials "true" env=CORS_ORIGIN
Header always merge Vary "Origin"`,
    source: src('Apache httpd: mod_setenvif', 'https://httpd.apache.org/docs/2.4/mod/mod_setenvif.html'),
  },
  version: {
    lang: 'apache',
    code: `ServerTokens Prod      # server config only
ServerSignature Off
Header always unset X-Powered-By`,
    source: src('Apache httpd: ServerTokens', 'https://httpd.apache.org/docs/2.4/mod/core.html#servertokens'),
  },
  methods: {
    lang: 'apache',
    code: `TraceEnable Off   # the default is on`,
    source: src('Apache httpd: TraceEnable', 'https://httpd.apache.org/docs/2.4/mod/core.html#traceenable'),
  },
};

/** Snippets by framework and topic. */
export const SNIPPETS: Record<FrameworkId, Table> = { express, nextjs, nestjs, django, flask, fastapi, rails, laravel, spring, aspnet, nginx, apache };

/** The snippet for one framework and topic, if there is one. */
export function snippetFor(framework: FrameworkId, topic: FixTopic): Snippet | null {
  const s = SNIPPETS[framework][topic];
  return s ? { framework, ...s } : null;
}
