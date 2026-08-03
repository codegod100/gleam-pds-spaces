/// Web pages for the PDS

import gleam_pds/context.{type Context}
import gleam/option.{None, Some}
import gleam/string
import wisp.{type Request, type Response}

fn html_response(html: String) -> Response {
  wisp.response(200)
  |> wisp.set_header("content-type", "text/html; charset=utf-8")
  |> wisp.set_body(wisp.Text(html))
}

const lucide_script = "<script src='https://unpkg.com/lucide@0.468.0/dist/umd/lucide.min.js'></script><script>lucide.createIcons();</script>"

/// Brooke's hand-drawn star, served from priv/static (also the favicon and
/// the face of the OG card).
const star_mascot = "<img class='star-mascot' src='/static/logo.png' alt='' width='24' height='24'>"

/// tangled.org's Dolly mark (their brand page permits recoloring); fill
/// tracks currentColor so it takes the footer link color.
const tangled_logo = "<svg class='tangled-mark' viewBox='0 0 32 32' fill='currentColor' xmlns='http://www.w3.org/2000/svg' aria-hidden='true'><path d='M21.0971 30.866C20.0566 30.8575 19.2628 30.5542 18.4016 30.0269C17.1668 29.3753 16.2237 28.2808 15.5497 27.0739C14.4789 28.4065 13.0476 29.215 11.4453 29.6718C10.763 29.8705 9.56809 30.0721 7.58737 29.3523C4.73277 28.3905 2.65342 25.4114 2.88973 22.3758C2.8465 21.1175 3.30392 19.8825 3.95228 18.8208C2.22264 17.8897 0.81225 16.3266 0.272148 14.4098C-0.0560731 13.3604 -0.042271 12.2299 0.0787626 11.1512C0.512215 8.60429 2.41697 6.38956 4.86912 5.59294C5.8479 3.35574 7.98378 1.68743 10.4037 1.34778C12.0104 1.12338 13.6735 1.46075 15.0792 2.27979C17.1272 0.00158595 20.6952 -0.671697 23.4195 0.727793C25.4978 1.72322 26.9839 3.80003 27.3447 6.06471C29.3222 6.85928 30.9877 8.47971 31.6413 10.5368C32.0784 11.8104 32.0928 13.2132 31.8098 14.5209C31.3041 16.5615 29.8679 18.2987 28.009 19.2482C28.0135 19.6113 29.2037 22.2296 29.0047 24.2056C28.9612 26.676 27.399 29.0172 25.2325 30.1544C23.9683 30.8945 22.4702 30.8805 21.0971 30.866ZM15.1733 23.755C16.9256 23.5593 18.0743 22.0269 18.9665 20.6469C19.3883 20.0182 19.7105 19.3146 20.0306 18.6454C20.4458 19.0271 20.7975 19.7461 21.4541 19.9173C22.1457 20.1333 22.9566 19.9579 23.38 19.3277C24.1902 17.8118 23.7908 15.9827 23.319 14.4119C23.0284 13.5097 22.6472 12.5841 21.9218 11.9446C22.0765 10.85 21.4299 9.73834 20.5106 9.16542C19.7272 9.79198 18.5352 9.78821 17.7794 9.11795C16.3309 10.5997 15.0034 10.5505 13.7212 9.37618C13.4331 9.11226 12.8832 10.9871 10.9535 9.92506C9.84488 10.8567 8.98526 11.753 8.22356 13.0435C7.48342 14.4347 6.70829 15.6703 6.64151 17.1811C6.6094 18.0641 7.29731 18.9892 8.22942 18.9174C9.16105 19.0009 9.7952 18.0813 10.5006 17.6993C10.6058 18.9316 10.7243 20.2556 11.1395 21.4587C11.6161 23.0155 13.2947 24.005 14.8835 23.7784C14.9959 23.7696 15.1733 23.7549 15.1733 23.755ZM16.0828 19.1062C15.2306 18.5823 15.6407 17.4452 15.6066 16.6193C15.6914 15.6227 15.7594 14.575 16.2061 13.667C16.6788 13.0197 17.8318 13.2694 17.8827 14.0999C17.8488 14.9353 17.4664 15.767 17.5121 16.633C17.4129 17.3561 17.5839 18.1684 17.265 18.8293C17.0033 19.195 16.4703 19.3013 16.0828 19.1062ZM12.3606 18.6302C11.5578 18.1933 11.8129 17.0941 11.687 16.3298C11.7914 15.445 11.7045 14.3226 12.4431 13.7021C13.1653 13.1969 14.1485 14.0621 13.8069 14.8564C13.4426 15.8602 13.6814 16.957 13.6891 17.9748C13.5512 18.5752 12.911 18.894 12.3606 18.6302Z'/></svg>"

/// Lexend is the face gleam.run sets its titles in.
const font_links = "<link rel='preconnect' href='https://fonts.googleapis.com'>
  <link rel='preconnect' href='https://fonts.gstatic.com' crossorigin>
  <link rel='stylesheet' href='https://fonts.googleapis.com/css2?family=Lexend:wght@400;500;600;700&display=swap'>
  <link rel='icon' type='image/png' href='/static/logo.png'>"

/// Official Gleam palette, https://gleam.run/branding/, plus semantic tokens
/// derived from it that flip for light/dark via prefers-color-scheme. Every
/// page pulls colors from the tokens (--bg, --text, --accent, ...) rather than
/// the raw swatches, so the whole site re-themes from one place.
const brand_css = "
    :root {
      --font-sans: 'Lexend', -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif;
      --font-mono: ui-monospace, SFMono-Regular, Menlo, monospace;

      /* raw swatches */
      --faff-pink: #ffaff3;
      --faff-pink-hover: #ffc4f6;
      --faff-pink-active: #e895dc;
      --unnamed-blue: #a6f0fc;
      --aged-plastic-yellow: #fffbe8;
      --unexpected-aubergine: #584355;
      --underwater-blue: #292d3e;
      --charcoal: #2f2f2f;
      --black: #1e1e1e;
      --blacker: #151515;
      --white: #fefefc;

      /* semantic tokens: dark theme (default) */
      --bg: var(--blacker);
      --bg-elevated: var(--black);
      --bg-sunken: #101010;
      --border: var(--charcoal);
      --border-strong: #3a3a3a;
      --text: var(--white);
      --text-muted: #8d8a87;
      --text-faint: #6f6c6a;
      --text-placeholder: #55524f;
      --accent: var(--faff-pink);
      --accent-text: var(--faff-pink);
      --accent-hover: var(--faff-pink-hover);
      --accent-active: var(--faff-pink-active);
      --accent-contrast: var(--black);
      --accent-soft-bg: rgba(88,67,85,0.45);
      --accent-soft-bg-hover: rgba(88,67,85,0.7);
      --accent-soft-bg-active: rgba(88,67,85,0.85);
      --link: var(--unnamed-blue);
      --error: #ff6b6b;
      --success: #6bff6b;
      --focus-ring: rgba(166,240,252,0.4);
      --wave-back: var(--unexpected-aubergine);
      --wave-front: rgba(41,45,62,0.65);
    }

    @media (prefers-color-scheme: light) {
      :root {
        --bg: var(--aged-plastic-yellow);
        --bg-elevated: var(--white);
        --bg-sunken: #fffef8;
        --border: #d9c8a4;
        --border-strong: #c4ae7f;
        --text: #241f28;
        --text-muted: #6b6152;
        --text-faint: #8a8069;
        --text-placeholder: #a1946f;
        --accent: var(--faff-pink);
        --accent-text: #b03589;
        --accent-hover: #ff8bea;
        --accent-active: #e262cf;
        --accent-contrast: #241f28;
        --accent-soft-bg: rgba(255,175,243,0.25);
        --accent-soft-bg-hover: rgba(255,175,243,0.38);
        --accent-soft-bg-active: rgba(255,175,243,0.5);
        --link: #157e9c;
        --error: #c8395a;
        --success: #1d8a4d;
        --focus-ring: rgba(21,126,156,0.3);
        --wave-back: rgba(255,175,243,0.7);
        --wave-front: rgba(166,240,252,0.45);
      }
    }
"

/// Button system ported from pckt's Components/Buttons/DashboardButton: 3rem
/// tall, rounded-2xl, bordered, inset ring on the solid variant, 150ms ease-out
/// transitions and a 0.96 press scale. Variants remapped to the Gleam palette.
const button_css = "
    .btn {
      display: inline-flex; align-items: center; justify-content: center;
      gap: 0.5rem; height: 3rem; padding: 0 1.25rem;
      border: 1px solid transparent; border-radius: 1rem;
      font-size: 1rem; font-weight: 500; white-space: nowrap;
      text-decoration: none; cursor: pointer; font-family: inherit;
      transition: background-color 0.15s ease-out, border-color 0.15s ease-out,
                  color 0.15s ease-out, box-shadow 0.15s ease-out,
                  opacity 0.15s ease-out, scale 0.15s ease-out;
    }
    .btn:active:not(:disabled) { scale: 0.96; }
    .btn:focus-visible { outline: none; box-shadow: 0 0 0 2px var(--focus-ring); }
    .btn:disabled { opacity: 0.5; cursor: not-allowed; }
    .btn svg, .btn i { width: 18px; height: 18px; }
    .btn-full { width: 100%; }
    .btn-lg { height: 3.5rem; font-size: 1.0625rem; }

    /* Same family as .btn-soft — flat fill + visible accent border — but a
       solid fill keeps it the highest-priority action. */
    .btn-primary {
      background: var(--accent); color: var(--unexpected-aubergine);
      border-color: color-mix(in srgb, var(--accent-active) 60%, transparent);
    }
    .btn-primary:hover:not(:disabled) { background: var(--accent-hover); border-color: color-mix(in srgb, var(--accent-active) 85%, transparent); }
    .btn-primary:active:not(:disabled) { background: var(--accent-active); box-shadow: inset 0 3px 6px rgba(0,0,0,0.25); }

    .btn-secondary {
      background: transparent; color: var(--link);
      border-color: color-mix(in srgb, var(--link) 35%, transparent);
      box-shadow: inset 0 0 0 1px color-mix(in srgb, var(--link) 10%, transparent);
    }
    .btn-secondary:hover:not(:disabled) { background: color-mix(in srgb, var(--link) 8%, transparent); border-color: color-mix(in srgb, var(--link) 60%, transparent); }
    .btn-secondary:active:not(:disabled) { background: color-mix(in srgb, var(--link) 15%, transparent); box-shadow: inset 0 3px 6px rgba(0,0,0,0.25); }

    .btn-soft {
      background: var(--accent-soft-bg); color: var(--accent-text);
      border-color: color-mix(in srgb, var(--accent-text) 35%, transparent);
    }
    .btn-soft:hover:not(:disabled) {
      background: var(--accent-soft-bg-hover);
      border-color: color-mix(in srgb, var(--accent-text) 60%, transparent);
    }
    .btn-soft:active:not(:disabled) { background: var(--accent-soft-bg-active); box-shadow: inset 0 3px 6px rgba(0,0,0,0.25); }
"

pub fn landing_page(_req: Request, ctx: Context) -> Response {
  let cta = case ctx.config.signups_disabled {
    True ->
      "<a href='/login' class='btn btn-primary'>Sign in</a>
       <p class='cta-note'><i data-lucide='lock'></i> Registration is closed on this server right now.</p>"
    False ->
      "<a href='/register' class='btn btn-primary'>Create your handle</a>"
  }

  html_response(
    "<!DOCTYPE html>
<html lang='en'>
<head>
  <meta charset='utf-8'>
  <meta name='viewport' content='width=device-width, initial-scale=1, viewport-fit=cover'>
  <title>Gleam PDS - AT Protocol Personal Data Server</title>
  <meta name='description' content='An AT Protocol Personal Data Server built in Gleam, the type-safe language on the BEAM.'>
  <meta property='og:title' content='Gleam PDS'>
  <meta property='og:description' content='An AT Protocol Personal Data Server built in Gleam, the type-safe language on the BEAM.'>
  <meta property='og:type' content='website'>
  <meta property='og:url' content='" <> ctx.config.public_url <> "'>
  <meta property='og:image' content='" <> ctx.config.public_url <> "/static/og.png'>
  <meta name='twitter:card' content='summary_large_image'>
  " <> font_links <> "
  <style>
" <> brand_css <> "
    * { margin: 0; padding: 0; box-sizing: border-box; }
    html { background: var(--bg); }
    body {
      font-family: var(--font-sans);
      background: var(--bg);
      color: var(--text);
      min-height: 100vh; min-height: 100lvh;
      position: relative;
      display: flex; flex-direction: column;
      line-height: 1.5;
      -webkit-font-smoothing: antialiased;
      overflow-x: hidden;
    }

    /* Absolute, NOT fixed. iOS Safari crops fixed elements to the small
       viewport (the area above its toolbar) while the body keeps painting down
       to the large viewport, which left a strip of --bg showing behind the
       toolbar. Anchored to the body's bottom edge, the wave covers exactly
       what the body covers. display:block kills the inline-baseline gap. */
    .waves {
      position: absolute; left: 0; width: 100%;
      /* Hangs a tenth of the viewport below the page so the wave runs off the
         bottom of the screen instead of ending on an edge, safe area or not. */
      bottom: -10vh; height: 50vh;
      overflow: hidden; z-index: 0; pointer-events: none;
    }
    /* The shape is stretched over an extra 80px that the box crops away, which
       is what puts the crest at the right height; without it the wave squashes
       and the crest rides up. */
    .waves svg {
      display: block; width: 100%;
      height: calc((clamp(280px, 42vw, 460px) + 80px) * 2);
    }
    .waves .wave-back { fill: var(--wave-back); }
    .waves .wave-front { fill: var(--wave-front); }
    @media (max-width: 640px) {
      .waves svg { height: calc((clamp(320px, 80vw, 400px) + 80px) * 2); }
    }

    .wrap {
      position: relative; z-index: 1;
      flex: 1; width: 100%; max-width: 60rem; margin: 0 auto;
      padding: 0 1.75rem calc(2rem + env(safe-area-inset-bottom, 0px));
      display: flex; flex-direction: column;
    }

    .topbar { display: flex; align-items: center; justify-content: space-between; padding: 1.5rem 0; }
    .brand { display: flex; align-items: center; gap: 0.5rem; color: var(--text); text-decoration: none; font-weight: 600; letter-spacing: -0.01em; }
    .brand svg, .brand i { width: 22px; height: 22px; color: var(--accent); }
    .brand img { width: 24px; height: 24px; }
    .topbar-link { color: var(--text-muted); text-decoration: none; font-size: 0.95rem; }
    .topbar-link:hover { color: var(--text); }

    .hero {
      flex: 1; display: flex; flex-direction: column;
      align-items: center; justify-content: center; text-align: center;
      padding: 2rem 0 4rem; gap: 1.5rem;
    }
    .hero-logo { width: 88px; height: 88px; }
    @media (min-width: 641px) {
      /* Larger mark with more lift on desktop; mobile keeps the 88px version. */
      .hero-logo { width: 120px; height: 120px; margin-bottom: 1rem; }
      .hero { padding-bottom: 8.75rem; }
    }
    .hero h1 {
      font-size: clamp(1.9rem, 4.6vw, 3rem); line-height: 1.08;
      letter-spacing: -0.03em; font-weight: 700; max-width: 24ch;
    }
    .hero .cta { margin-top: 0.5rem; }
    .cta-note { display: flex; align-items: center; justify-content: center; gap: 0.4rem; color: var(--text-faint); font-size: 0.85rem; margin-top: 0.9rem; }
    .cta-note svg, .cta-note i { width: 14px; height: 14px; flex-shrink: 0; }

    .info {
      position: relative; z-index: 1;
      padding-top: 1.75rem; padding-right: 3.5rem;
      display: grid; gap: 0.45rem; font-size: 0.8rem; color: var(--text);
    }
    .info div {
      display: grid; grid-template-columns: 8rem 1fr;
      column-gap: 0.5rem; align-items: baseline;
    }
    .info dt { color: var(--text); opacity: 0.7; }
    .info code {
      font-family: var(--font-mono);
      color: var(--link); word-break: break-all;
    }
    .corner-links {
      position: absolute; right: 1.75rem; z-index: 1;
      bottom: calc(1.4rem + env(safe-area-inset-bottom, 0px));
      display: flex; align-items: center; gap: 1rem;
    }
    .credit-link {
      display: inline-flex; color: var(--text); opacity: 0.7;
      transition: opacity 0.15s ease;
    }
    .credit-link:hover { opacity: 1; }
    .tangled-mark { width: 22px; height: 22px; }
    .lucy-mark { width: 22px; height: 21px; }
    @media (max-width: 640px) {
      .wrap { padding: 0 1.25rem calc(1.5rem + env(safe-area-inset-bottom, 0px)); }
      .hero { padding: 1rem 0 2rem; }
      .corner-links { right: 1.25rem; bottom: calc(1.1rem + env(safe-area-inset-bottom, 0px)); }
      .info { gap: 0.75rem; }
      /* Stack label over value — but as a single-column grid, so BOTH rows
         break identically instead of wrapping independently. */
      .info div { grid-template-columns: 1fr; row-gap: 0.1rem; }
    }
" <> button_css <> "
  </style>
</head>
<body>
  <div class='waves' aria-hidden='true'>
  <svg viewBox='0 0 1440 640' preserveAspectRatio='none' xmlns='http://www.w3.org/2000/svg'>
    <path class='wave-back' d='M0,110 C180,60 300,140 480,100 C660,60 780,25 960,80 C1140,135 1260,155 1440,90 L1440,640 L0,640 Z'/>
    <path class='wave-front' d='M0,150 C220,100 340,170 540,130 C740,95 860,55 1080,115 C1240,155 1340,140 1440,150 L1440,640 L0,640 Z'/>
  </svg>
  </div>
  <div class='wrap'>
    <header class='topbar'>
      <a class='brand' href='/'>" <> star_mascot <> " Gleam PDS</a>
      <a class='topbar-link' href='/login'>Sign in</a>
    </header>

    <section class='hero'>
      <img class='hero-logo' src='/static/logo.png' alt='' width='88' height='88'>
      <h1>It's your PDS. It's Gleam.</h1>
      <div class='cta'>" <> cta <> "</div>
    </section>

    <footer class='footer'>
    <dl class='info'>
      <div><dt>Server DID</dt><code>did:web:" <> ctx.config.hostname <> "</code></div>
      <div><dt>XRPC endpoint</dt><code>" <> ctx.config.public_url <> "/xrpc/</code></div>
    </dl>
    <div class='corner-links'>
      <a class='credit-link' href='https://gleam.run' title='Built with Gleam' aria-label='Built with Gleam'><img class='lucy-mark' src='/static/lucy.svg' alt='' width='22' height='21'></a>
      <a class='credit-link' href='https://tangled.org/brookie.blog/gleam-pds' title='Source on tangled' aria-label='Source on tangled'>" <> tangled_logo <> "</a>
    </div>
    </footer>
  </div>
  " <> lucide_script <> "
</body>
</html>",
  )
}

/// Minimal HTML escaping for untrusted values interpolated into markup.
pub fn html_escape(value: String) -> String {
  value
  |> string.replace("&", "&amp;")
  |> string.replace("<", "&lt;")
  |> string.replace(">", "&gt;")
  |> string.replace("\"", "&quot;")
  |> string.replace("'", "&#39;")
}

/// The OAuth authorize form, on the same theme as /login. `login_hint` is
/// client-supplied (from PAR or the query string) and is escaped here.
pub fn oauth_authorize_page(
  request_id: String,
  login_hint: String,
  ctx: Context,
) -> Response {
  let hint_attr = html_escape(login_hint)
  let rid_attr = html_escape(request_id)
  html_response(
    "<!DOCTYPE html>
<html lang='en'>
<head>
  <meta charset='utf-8'>
  <meta name='viewport' content='width=device-width, initial-scale=1, viewport-fit=cover'>
  <title>Authorize - Gleam PDS</title>
  " <> font_links <> "
  <style>
" <> brand_css <> "
    * { margin: 0; padding: 0; box-sizing: border-box; }
    html { background: var(--bg); }
    body {
      font-family: var(--font-sans); background: var(--bg); color: var(--text);
      display: flex; align-items: center; justify-content: center;
      min-height: 100vh; min-height: 100lvh;
      padding-bottom: env(safe-area-inset-bottom, 0px);
      position: relative; overflow-x: hidden;
    }
    /* Absolute, NOT fixed. iOS Safari crops fixed elements to the small
       viewport (the area above its toolbar) while the body keeps painting down
       to the large viewport, which left a strip of --bg showing behind the
       toolbar. Anchored to the body's bottom edge, the wave covers exactly
       what the body covers. display:block kills the inline-baseline gap. */
    .waves {
      position: absolute; left: 0; width: 100%;
      /* Hangs a tenth of the viewport below the page so the wave runs off the
         bottom of the screen instead of ending on an edge, safe area or not. */
      bottom: -10vh; height: 50vh;
      overflow: hidden; z-index: 0; pointer-events: none;
    }
    .waves svg {
      display: block; width: 100%;
      height: calc((clamp(280px, 42vw, 460px) + 80px) * 2);
    }
    .waves .wave-back { fill: var(--wave-back); }
    .waves .wave-front { fill: var(--wave-front); }
    @media (max-width: 640px) {
      .waves svg { height: calc((clamp(320px, 80vw, 400px) + 80px) * 2); }
    }
    .card {
      position: relative; z-index: 1;
      background: var(--bg-elevated); border: 1px solid var(--border);
      border-radius: 16px; padding: 2rem; max-width: 420px; width: 100%; margin: 1rem;
    }
    h1 { font-size: 1.5rem; margin-bottom: 0.5rem; text-align: center; color: var(--accent-text); display: flex; align-items: center; justify-content: center; gap: 0.5rem; }
    h1 i, h1 svg { width: 24px; height: 24px; flex-shrink: 0; }
    .sub { text-align: center; color: var(--text-muted); margin-bottom: 1.9rem; font-size: 0.875rem; }
    input { width: 100%; padding: 0.75rem; background: var(--bg-sunken); border: 1px solid var(--border); border-radius: 8px; color: var(--text); font-size: 1rem; }
    input:focus { outline: none; border-color: var(--accent-text); }
" <> button_css <> "
    .divider { text-align: center; margin: 1rem 0; color: var(--text-faint); font-size: 0.875rem; }

    /* Form field, ported from pckt's Components/Atproto/IdentityInput: tall
       pill, leading icon that lights up on focus, label chipped over the
       border. Gleam palette instead of the pckt gradient. */
    .field { position: relative; margin-bottom: 1.35rem; }
    .field .field-label {
      position: absolute; left: 2.5rem; top: -0.45rem; z-index: 2; margin: 0;
      padding: 0 0.4rem; font-size: 0.75rem; line-height: 1;
      color: var(--text-muted); background: var(--bg-elevated);
      opacity: 0; transform: translateY(3px);
      transition: color 0.15s ease, opacity 0.15s ease, transform 0.15s ease;
    }
    .field:focus-within .field-label {
      color: var(--accent-text); opacity: 1; transform: none;
    }
    @media (prefers-reduced-motion: reduce) {
      .field .field-label { transition: color 0.15s ease; transform: none; }
    }
    .field .field-icon {
      position: absolute; left: 0.9rem; top: 29px; transform: translateY(-50%);
      display: flex; color: var(--text-faint); pointer-events: none; transition: color 0.15s ease;
    }
    .field .field-icon svg { width: 20px; height: 20px; }
    .field:focus-within .field-icon { color: var(--accent-text); }
    input.field-input {
      min-height: 58px; padding: 0 1rem 0 2.75rem;
      font-size: 1.125rem; border-radius: 16px;
      transition: border-color 0.15s ease, box-shadow 0.15s ease;
    }
    input.field-input::placeholder { color: var(--text-placeholder); }
    .field:hover input.field-input { border-color: var(--unexpected-aubergine); }
    input.field-input:focus { border-color: var(--accent-text); box-shadow: 0 0 0 3px var(--accent-soft-bg); }
  </style>
</head>
<body>
  <div class='waves' aria-hidden='true'>
  <svg viewBox='0 0 1440 640' preserveAspectRatio='none' xmlns='http://www.w3.org/2000/svg'>
    <path class='wave-back' d='M0,110 C180,60 300,140 480,100 C660,60 780,25 960,80 C1140,135 1260,155 1440,90 L1440,640 L0,640 Z'/>
    <path class='wave-front' d='M0,150 C220,100 340,170 540,130 C740,95 860,55 1080,115 C1240,155 1340,140 1440,150 L1440,640 L0,640 Z'/>
  </svg>
  </div>
  <div class='card'>
    <h1><i data-lucide='lock-keyhole'></i> Sign In</h1>
    <p class='sub'>Authorize an app to access your Atmosphere account</p>

    <button class='btn btn-soft btn-full' onclick='loginPasskey()'>
      <i data-lucide='fingerprint'></i> Sign in with Passkey
    </button>

    <div class='divider'>or</div>

    <form method='POST' action='/oauth/authorize'>
      <input type='hidden' name='request_id' value='" <> rid_attr <> "'>
      <div class='field'>
        <label class='field-label' for='identifier'>Handle or email</label>
        <span class='field-icon'><i data-lucide='at-sign'></i></span>
        <input class='field-input' type='text' name='identifier' id='identifier'
               value='" <> hint_attr <> "'
               placeholder='you." <> ctx.config.handle_domain <> "' required
               autocomplete='username' autocapitalize='none' autocorrect='off' spellcheck='false'>
      </div>
      <div class='field'>
        <label class='field-label' for='password'>Password</label>
        <span class='field-icon'><i data-lucide='lock'></i></span>
        <input class='field-input' type='password' name='password' id='password'
               placeholder='&#8226;&#8226;&#8226;&#8226;&#8226;&#8226;&#8226;&#8226;'
               autocomplete='current-password' required>
      </div>
      <button type='submit' class='btn btn-primary btn-full'>Let's gleam <i data-lucide='arrow-right'></i></button>
    </form>
  </div>
  <script>
    async function loginPasskey(){try{
      var r=await fetch('/api/passkey/login/begin',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({request_id:'" <> rid_attr <> "'})});
      var d=await r.json();var ch=b64d(d.challenge);var ac=(d.allowCredentials||[]).map(function(c){return{type:c.type,id:b64d(c.id)}});
      var cred=await navigator.credentials.get({publicKey:{challenge:ch,allowCredentials:ac,rpId:d.rpId,timeout:60000,userVerification:'preferred'}});
      var fr=await fetch('/api/passkey/login/finish',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({request_id:'" <> rid_attr <> "',id:cred.id,rawId:b64e(cred.rawId),response:{authenticatorData:b64e(cred.response.authenticatorData),clientDataJSON:b64e(cred.response.clientDataJSON),signature:b64e(cred.response.signature)},type:cred.type})});
      var fd=await fr.json();if(fd.redirect)window.location.href=fd.redirect;
    }catch(e){alert('Passkey error: '+e.message)}}
    function b64d(b){var p='='.repeat((4-b.length%4)%4);var s=(b+p).split('-').join('+').split('_').join('/');return Uint8Array.from(atob(s),function(c){return c.charCodeAt(0)}).buffer}
    function b64e(buf){var s='';var u=new Uint8Array(buf);for(var i=0;i<u.length;i++)s+=String.fromCharCode(u[i]);return btoa(s).split('+').join('-').split('/').join('_').split('=').join('')}
  </script>
  " <> lucide_script <> "
</body>
</html>",
  )
}

pub fn login_page(_req: Request, ctx: Context) -> Response {
  html_response(
    "<!DOCTYPE html>
<html lang='en'>
<head>
  <meta charset='utf-8'>
  <meta name='viewport' content='width=device-width, initial-scale=1, viewport-fit=cover'>
  <title>Sign In - Gleam PDS</title>
  " <> font_links <> "
  <style>
" <> brand_css <> "
    * { margin: 0; padding: 0; box-sizing: border-box; }
    html { background: var(--bg); }
    body {
      font-family: var(--font-sans); background: var(--bg); color: var(--text);
      display: flex; align-items: center; justify-content: center;
      min-height: 100vh; min-height: 100lvh;
      padding-bottom: env(safe-area-inset-bottom, 0px);
      position: relative; overflow-x: hidden;
    }
    /* Absolute, NOT fixed. iOS Safari crops fixed elements to the small
       viewport (the area above its toolbar) while the body keeps painting down
       to the large viewport, which left a strip of --bg showing behind the
       toolbar. Anchored to the body's bottom edge, the wave covers exactly
       what the body covers. display:block kills the inline-baseline gap. */
    .waves {
      position: absolute; left: 0; width: 100%;
      /* Hangs a tenth of the viewport below the page so the wave runs off the
         bottom of the screen instead of ending on an edge, safe area or not. */
      bottom: -10vh; height: 50vh;
      overflow: hidden; z-index: 0; pointer-events: none;
    }
    .waves svg {
      display: block; width: 100%;
      height: calc((clamp(280px, 42vw, 460px) + 80px) * 2);
    }
    .waves .wave-back { fill: var(--wave-back); }
    .waves .wave-front { fill: var(--wave-front); }
    @media (max-width: 640px) {
      .waves svg { height: calc((clamp(320px, 80vw, 400px) + 80px) * 2); }
    }
    .card {
      position: relative; z-index: 1;
      background: var(--bg-elevated); border: 1px solid var(--border);
      border-radius: 16px; padding: 2rem; max-width: 420px; width: 100%; margin: 1rem;
    }
    h1 { font-size: 1.5rem; margin-bottom: 0.5rem; text-align: center; color: var(--accent-text); display: flex; align-items: center; justify-content: center; gap: 0.5rem; }
    h1 i, h1 svg { width: 24px; height: 24px; flex-shrink: 0; }
    .sub { text-align: center; color: var(--text-muted); margin-bottom: 1.9rem; font-size: 0.875rem; }
    input { width: 100%; padding: 0.75rem; background: var(--bg-sunken); border: 1px solid var(--border); border-radius: 8px; color: var(--text); font-size: 1rem; }
    input:focus { outline: none; border-color: var(--accent-text); }
" <> button_css <> "
    .divider { text-align: center; margin: 1rem 0; color: var(--text-faint); font-size: 0.875rem; }
    .error { color: var(--error); font-size: 0.875rem; margin-top: 0.5rem; display: none; }
    .success { color: var(--success); font-size: 0.875rem; margin-top: 0.5rem; display: none; }
    .links { text-align: center; margin-top: 1.4rem; font-size: 0.85rem; }
    .links a { color: var(--accent-text); }

    /* Form field, ported from pckt's Components/Atproto/IdentityInput: tall
       pill, leading icon that lights up on focus, label chipped over the
       border. Gleam palette instead of the pckt gradient. */
    .field { position: relative; margin-bottom: 1.35rem; }
    .field .field-label {
      position: absolute; left: 2.5rem; top: -0.45rem; z-index: 2; margin: 0;
      padding: 0 0.4rem; font-size: 0.75rem; line-height: 1;
      color: var(--text-muted); background: var(--bg-elevated);
      opacity: 0; transform: translateY(3px);
      transition: color 0.15s ease, opacity 0.15s ease, transform 0.15s ease;
    }
    .field:focus-within .field-label {
      color: var(--accent-text); opacity: 1; transform: none;
    }
    @media (prefers-reduced-motion: reduce) {
      .field .field-label { transition: color 0.15s ease; transform: none; }
    }
    .field .field-icon {
      position: absolute; left: 0.9rem; top: 29px; transform: translateY(-50%);
      display: flex; color: var(--text-faint); pointer-events: none; transition: color 0.15s ease;
    }
    .field .field-icon svg { width: 20px; height: 20px; }
    .field:focus-within .field-icon { color: var(--accent-text); }
    input.field-input {
      min-height: 58px; padding: 0 1rem 0 2.75rem;
      font-size: 1.125rem; border-radius: 16px;
      transition: border-color 0.15s ease, box-shadow 0.15s ease;
    }
    input.field-input::placeholder { color: var(--text-placeholder); }
    .field:hover input.field-input { border-color: var(--unexpected-aubergine); }
    input.field-input:focus { border-color: var(--accent-text); box-shadow: 0 0 0 3px var(--accent-soft-bg); }

  </style>
</head>
<body>
  <div class='waves' aria-hidden='true'>
  <svg viewBox='0 0 1440 640' preserveAspectRatio='none' xmlns='http://www.w3.org/2000/svg'>
    <path class='wave-back' d='M0,110 C180,60 300,140 480,100 C660,60 780,25 960,80 C1140,135 1260,155 1440,90 L1440,640 L0,640 Z'/>
    <path class='wave-front' d='M0,150 C220,100 340,170 540,130 C740,95 860,55 1080,115 C1240,155 1340,140 1440,150 L1440,640 L0,640 Z'/>
  </svg>
  </div>
  <div class='card'>
    <h1><i data-lucide='lock-keyhole'></i> Sign In</h1>
    <p class='sub'>Access your Atmosphere account</p>
    
    <button class='btn btn-soft btn-full' onclick='loginWithPasskey()' id='passkey-btn'>
      <i data-lucide='fingerprint'></i> Sign in with Passkey
    </button>
    
    <div class='divider'>or</div>
    
    <form id='login-form' onsubmit='loginWithPassword(event)'>
      <div class='field'>
        <label class='field-label' for='identifier'>Handle or email</label>
        <span class='field-icon'><i data-lucide='at-sign'></i></span>
        <input class='field-input' type='text' name='identifier' id='identifier'
               placeholder='you." <> ctx.config.handle_domain <> "' required
               autocomplete='username' autocapitalize='none' autocorrect='off' spellcheck='false'>
      </div>
      <div class='field'>
        <label class='field-label' for='password'>Password</label>
        <span class='field-icon'><i data-lucide='lock'></i></span>
        <input class='field-input' type='password' name='password' id='password'
               placeholder='&#8226;&#8226;&#8226;&#8226;&#8226;&#8226;&#8226;&#8226;'
               autocomplete='current-password' required>
      </div>
      <div class='error' id='error-msg'></div>
      <div class='success' id='success-msg'></div>
      <button type='submit' class='btn btn-primary btn-full'>Let's gleam <i data-lucide='arrow-right'></i></button>
    </form>
    
    <div class='links'>
      <a href='/register'>Create an account</a> &middot; <a href='/'>Home</a>
    </div>
  </div>
  <script>
    const BASE = window.location.origin;
    
    async function loginWithPassword(e) {
      e.preventDefault();
      hideMessages();
      try {
        const resp = await fetch(BASE + '/xrpc/com.atproto.server.createSession', {
          method: 'POST',
          headers: {'Content-Type': 'application/json'},
          body: JSON.stringify({
            identifier: document.getElementById('identifier').value,
            password: document.getElementById('password').value
          })
        });
        const data = await resp.json();
        if (data.error) { showError(data.message || data.error); return; }
        localStorage.setItem('pds_session', JSON.stringify(data));
        showSignedIn(data.handle, data.did);
      } catch(e) { showError('Login failed: ' + e.message); }
    }
    
    async function loginWithPasskey() {
      hideMessages();
      try {
        const beginResp = await fetch(BASE + '/api/passkey/login/begin', {
          method: 'POST',
          headers: {'Content-Type': 'application/json'},
          body: JSON.stringify({})
        });
        const beginData = await beginResp.json();
        const challenge = base64urlToBuffer(beginData.challenge);
        const allowCredentials = (beginData.allowCredentials || []).map(c => ({...c, id: base64urlToBuffer(c.id)}));
        
        const credential = await navigator.credentials.get({
          publicKey: { challenge, allowCredentials, rpId: beginData.rpId, timeout: 60000, userVerification: 'preferred' }
        });
        
        const finishResp = await fetch(BASE + '/api/passkey/login/finish', {
          method: 'POST',
          headers: {'Content-Type': 'application/json'},
          body: JSON.stringify({
            id: credential.id,
            rawId: bufferToBase64url(credential.rawId),
            response: {
              authenticatorData: bufferToBase64url(credential.response.authenticatorData),
              clientDataJSON: bufferToBase64url(credential.response.clientDataJSON),
              signature: bufferToBase64url(credential.response.signature)
            },
            type: credential.type
          })
        });
        const finishData = await finishResp.json();
        if (finishData.error) { showError(finishData.message || finishData.error); return; }
        if (finishData.redirect) { window.location.href = finishData.redirect; return; }
        localStorage.setItem('pds_session', JSON.stringify(finishData));
        showSignedIn(finishData.handle, finishData.did);
      } catch(e) { showError('Passkey login failed: ' + e.message); }
    }
    
    function base64urlToBuffer(b64) {
      const padding = '='.repeat((4 - b64.length % 4) % 4);
      const base64 = (b64 + padding).replace(/-/g, '+').replace(/_/g, '/');
      return Uint8Array.from(atob(base64), c => c.charCodeAt(0)).buffer;
    }
    function bufferToBase64url(buffer) {
      return btoa(String.fromCharCode(...new Uint8Array(buffer))).split('+').join('-').split('/').join('_').split('=').join('');
    }
    function showError(msg) { const el = document.getElementById('error-msg'); el.textContent = msg; el.style.display = 'block'; }
    function showSuccess(msg) { const el = document.getElementById('success-msg'); el.textContent = msg; el.style.display = 'block'; }
    function hideMessages() { document.getElementById('error-msg').style.display = 'none'; document.getElementById('success-msg').style.display = 'none'; }
    // The PDS has no account dashboard — after minting a session, send people
    // into an ATProto client. Bluesky is the default; any client that asks for
    // a PDS host can use this hostname.
    function showSignedIn(handle, did) {
      const card = document.querySelector('.card');
      if (!card) { showSuccess('Signed in as ' + handle); return; }
      const profile = 'https://bsky.app/profile/' + encodeURIComponent(handle);
      card.innerHTML =
        '<h1><i data-lucide=\"circle-check\"></i> Signed in</h1>' +
        '<p class=\"sub\">@' + handle + '</p>' +
        '<p style=\"color:var(--text-muted);font-size:0.9rem;line-height:1.55;margin-bottom:1.25rem;text-align:center\">' +
        'This host is your personal data server, not an app. Open Bluesky (or another ATProto client) and sign in with this handle.</p>' +
        '<a class=\"btn btn-primary btn-full\" href=\"' + profile + '\">Open in Bluesky <i data-lucide=\"arrow-right\"></i></a>' +
        '<div class=\"links\" style=\"margin-top:1rem\"><code style=\"font-size:0.75rem;color:var(--text-faint)\">' + did + '</code></div>';
      if (window.lucide) lucide.createIcons();
    }
  </script>
  " <> lucide_script <> "
</body>
</html>",
  )
}

pub fn register_page(_req: Request, ctx: Context) -> Response {
  case ctx.config.signups_disabled {
    True -> signups_closed_page()
    False -> register_form_page(ctx)
  }
}

/// Shown at /register while GLEAM_PDS_SIGNUPS_DISABLED is set, so a bookmark or a
/// stale link explains itself instead of failing on submit.
fn signups_closed_page() -> Response {
  html_response(
    "<!DOCTYPE html>
<html lang='en'>
<head>
  <meta charset='utf-8'>
  <meta name='viewport' content='width=device-width, initial-scale=1, viewport-fit=cover'>
  <title>Registration Closed - Gleam PDS</title>
  " <> font_links <> "
  <style>
" <> brand_css <> "
    * { margin: 0; padding: 0; box-sizing: border-box; }
    html { background: var(--bg); }
    body {
      font-family: var(--font-sans); background: var(--bg); color: var(--text);
      display: flex; align-items: center; justify-content: center;
      min-height: 100vh; min-height: 100lvh;
      padding-bottom: env(safe-area-inset-bottom, 0px);
      position: relative; overflow-x: hidden;
    }
    /* Absolute, NOT fixed. iOS Safari crops fixed elements to the small
       viewport (the area above its toolbar) while the body keeps painting down
       to the large viewport, which left a strip of --bg showing behind the
       toolbar. Anchored to the body's bottom edge, the wave covers exactly
       what the body covers. display:block kills the inline-baseline gap. */
    .waves {
      position: absolute; left: 0; width: 100%;
      /* Hangs a tenth of the viewport below the page so the wave runs off the
         bottom of the screen instead of ending on an edge, safe area or not. */
      bottom: -10vh; height: 50vh;
      overflow: hidden; z-index: 0; pointer-events: none;
    }
    .waves svg {
      display: block; width: 100%;
      height: calc((clamp(280px, 42vw, 460px) + 80px) * 2);
    }
    .waves .wave-back { fill: var(--wave-back); }
    .waves .wave-front { fill: var(--wave-front); }
    @media (max-width: 640px) {
      .waves svg { height: calc((clamp(320px, 80vw, 400px) + 80px) * 2); }
    }
    .card {
      position: relative; z-index: 1;
      background: var(--bg-elevated); border: 1px solid var(--border);
      border-radius: 16px; padding: 2rem; max-width: 420px; width: 100%; margin: 1rem; text-align: center;
    }
    h1 { font-size: 1.5rem; margin-bottom: 0.75rem; color: var(--accent-text); display: flex; align-items: center; justify-content: center; gap: 0.5rem; }
    h1 i { width: 24px; height: 24px; }
    p { color: var(--text-muted); font-size: 0.9rem; line-height: 1.6; }
    .links { margin-top: 1.5rem; font-size: 0.85rem; }
    .links a { color: var(--accent-text); }
  </style>
</head>
<body>
  <div class='waves' aria-hidden='true'>
  <svg viewBox='0 0 1440 640' preserveAspectRatio='none' xmlns='http://www.w3.org/2000/svg'>
    <path class='wave-back' d='M0,110 C180,60 300,140 480,100 C660,60 780,25 960,80 C1140,135 1260,155 1440,90 L1440,640 L0,640 Z'/>
    <path class='wave-front' d='M0,150 C220,100 340,170 540,130 C740,95 860,55 1080,115 C1240,155 1340,140 1440,150 L1440,640 L0,640 Z'/>
  </svg>
  </div>
  <div class='card'>
    <h1><i data-lucide='lock'></i> Registration Closed</h1>
    <p>This server isn't accepting new accounts right now. If you already have
    an account here, you can still sign in.</p>
    <div class='links'>
      <a href='/login'>Sign in</a> &middot; <a href='/'>Home</a>
    </div>
  </div>
  " <> lucide_script <> "
</body>
</html>",
  )
}

fn register_form_page(ctx: Context) -> Response {
  // Turnstile is opt-in: only load the widget script and render the widget
  // when a site key is configured (GLEAM_PDS_TURNSTILE_SITE_KEY). The site key is
  // public by design — it identifies the widget, not a credential.
  let turnstile_script = case ctx.config.turnstile_site_key {
    Some(_) ->
      "<script src='https://challenges.cloudflare.com/turnstile/v0/api.js' async defer></script>"
    None -> ""
  }
  // data-size='flexible' stretches the widget to the card's inner width so it
  // reads as a form row rather than a floating box; data-theme='auto' keeps it
  // in step with the page's light/dark tokens.
  let turnstile_widget = case ctx.config.turnstile_site_key {
    Some(site_key) ->
      "<div class='captcha-row'><div class='cf-turnstile' data-sitekey='"
      <> site_key
      <> "' data-action='turnstile-spin-v1' data-theme='auto' data-size='flexible'></div></div>"
    None -> ""
  }

  html_response(
    "<!DOCTYPE html>
<html lang='en'>
<head>
  <meta charset='utf-8'>
  <meta name='viewport' content='width=device-width, initial-scale=1, viewport-fit=cover'>
  <title>Create Account - Gleam PDS</title>
  " <> font_links <> "
  " <> turnstile_script <> "
  <style>
" <> brand_css <> "
    * { margin: 0; padding: 0; box-sizing: border-box; }
    html { background: var(--bg); }
    body {
      font-family: var(--font-sans); background: var(--bg); color: var(--text);
      display: flex; align-items: center; justify-content: center;
      min-height: 100vh; min-height: 100lvh;
      padding-bottom: env(safe-area-inset-bottom, 0px);
      position: relative; overflow-x: hidden;
    }
    /* Absolute, NOT fixed. iOS Safari crops fixed elements to the small
       viewport (the area above its toolbar) while the body keeps painting down
       to the large viewport, which left a strip of --bg showing behind the
       toolbar. Anchored to the body's bottom edge, the wave covers exactly
       what the body covers. display:block kills the inline-baseline gap. */
    .waves {
      position: absolute; left: 0; width: 100%;
      /* Hangs a tenth of the viewport below the page so the wave runs off the
         bottom of the screen instead of ending on an edge, safe area or not. */
      bottom: -10vh; height: 50vh;
      overflow: hidden; z-index: 0; pointer-events: none;
    }
    .waves svg {
      display: block; width: 100%;
      height: calc((clamp(280px, 42vw, 460px) + 80px) * 2);
    }
    .waves .wave-back { fill: var(--wave-back); }
    .waves .wave-front { fill: var(--wave-front); }
    @media (max-width: 640px) {
      .waves svg { height: calc((clamp(320px, 80vw, 400px) + 80px) * 2); }
    }
    .card {
      position: relative; z-index: 1;
      background: var(--bg-elevated); border: 1px solid var(--border);
      border-radius: 16px; padding: 2rem; max-width: 420px; width: 100%; margin: 1rem;
    }
    h1 { font-size: 1.5rem; margin-bottom: 0.5rem; text-align: center; color: var(--accent-text); display: flex; align-items: center; justify-content: center; gap: 0.5rem; }
    h1 i, h1 svg { width: 24px; height: 24px; flex-shrink: 0; }
    .sub { text-align: center; color: var(--text-muted); margin-bottom: 1.9rem; font-size: 0.875rem; }
    input { width: 100%; padding: 0.75rem; background: var(--bg-sunken); border: 1px solid var(--border); border-radius: 8px; color: var(--text); font-size: 1rem; }
    input:focus { outline: none; border-color: var(--accent-text); }
    /* Handle-domain suffix rendered inside the pill, mirroring the leading
       icon: fixed at the right edge, non-interactive, muted until the field
       has focus. The padding-right below is sized for the current
       handle_domain — widen it if the domain gets longer. */
    .field .field-suffix {
      position: absolute; right: 1.1rem; top: 29px; transform: translateY(-50%);
      color: var(--text-muted); font-size: 1rem; pointer-events: none;
      transition: color 0.15s ease;
    }
    .field:focus-within .field-suffix { color: var(--text); }
    input.field-input.has-suffix { padding-right: 8.25rem; }
    /* Captcha sits on the same vertical rhythm as the .field rows above it.
       The iframe's width is driven by data-size='flexible'; min-height stops
       the form jumping when the widget pops in. */
    .captcha-row { margin-bottom: 1.35rem; min-height: 65px; }
    .captcha-row .cf-turnstile { width: 100%; }
" <> button_css <> "
    .error { color: var(--error); font-size: 0.875rem; margin-top: 0.5rem; display: none; }
    .success { color: var(--success); font-size: 0.875rem; margin-top: 0.5rem; display: none; }
    .passkey-section { margin-top: 1rem; padding-top: 1rem; border-top: 1px solid var(--border); display: none; }
    .links { text-align: center; margin-top: 1.4rem; font-size: 0.85rem; }
    .links a { color: var(--accent-text); }

    /* Form field, ported from pckt's Components/Atproto/IdentityInput: tall
       pill, leading icon that lights up on focus, label chipped over the
       border. Gleam palette instead of the pckt gradient. */
    .field { position: relative; margin-bottom: 1.35rem; }
    .field .field-label {
      position: absolute; left: 2.5rem; top: -0.45rem; z-index: 2; margin: 0;
      padding: 0 0.4rem; font-size: 0.75rem; line-height: 1;
      color: var(--text-muted); background: var(--bg-elevated);
      opacity: 0; transform: translateY(3px);
      transition: color 0.15s ease, opacity 0.15s ease, transform 0.15s ease;
    }
    .field:focus-within .field-label {
      color: var(--accent-text); opacity: 1; transform: none;
    }
    @media (prefers-reduced-motion: reduce) {
      .field .field-label { transition: color 0.15s ease; transform: none; }
    }
    .field .field-icon {
      position: absolute; left: 0.9rem; top: 29px; transform: translateY(-50%);
      display: flex; color: var(--text-faint); pointer-events: none; transition: color 0.15s ease;
    }
    .field .field-icon svg { width: 20px; height: 20px; }
    .field:focus-within .field-icon { color: var(--accent-text); }
    input.field-input {
      min-height: 58px; padding: 0 1rem 0 2.75rem;
      font-size: 1.125rem; border-radius: 16px;
      transition: border-color 0.15s ease, box-shadow 0.15s ease;
    }
    input.field-input::placeholder { color: var(--text-placeholder); }
    .field:hover input.field-input { border-color: var(--unexpected-aubergine); }
    input.field-input:focus { border-color: var(--accent-text); box-shadow: 0 0 0 3px var(--accent-soft-bg); }

  </style>
</head>
<body>
  <div class='waves' aria-hidden='true'>
  <svg viewBox='0 0 1440 640' preserveAspectRatio='none' xmlns='http://www.w3.org/2000/svg'>
    <path class='wave-back' d='M0,110 C180,60 300,140 480,100 C660,60 780,25 960,80 C1140,135 1260,155 1440,90 L1440,640 L0,640 Z'/>
    <path class='wave-front' d='M0,150 C220,100 340,170 540,130 C740,95 860,55 1080,115 C1240,155 1340,140 1440,150 L1440,640 L0,640 Z'/>
  </svg>
  </div>
  <div class='card'>
    <h1><svg xmlns='http://www.w3.org/2000/svg' width='24' height='24' viewBox='0 0 24 24' fill='none' stroke='currentColor' stroke-width='2' stroke-linecap='round' stroke-linejoin='round'><path d='M16.051 12.616a1 1 0 0 1 1.909.024l.737 1.452a1 1 0 0 0 .737.535l1.634.256a1 1 0 0 1 .588 1.806l-1.172 1.168a1 1 0 0 0-.282.866l.259 1.613a1 1 0 0 1-1.541 1.134l-1.465-.75a1 1 0 0 0-.912 0l-1.465.75a1 1 0 0 1-1.539-1.133l.258-1.613a1 1 0 0 0-.282-.866l-1.156-1.153a1 1 0 0 1 .572-1.822l1.633-.256a1 1 0 0 0 .737-.535z'/><path d='M8 15H7a4 4 0 0 0-4 4v2'/><circle cx='10' cy='7' r='4'/></svg> Create Account</h1>
    <p class='sub'>Join the Atmosphere</p>
    
    <form id='register-form' onsubmit='createAccount(event)'>
      <div class='field'>
        <label class='field-label' for='handle'>Your handle</label>
        <span class='field-icon'><i data-lucide='at-sign'></i></span>
        <input class='field-input has-suffix' type='text' name='handle' id='handle'
               placeholder='yourname' required
               autocomplete='username' autocapitalize='none' autocorrect='off' spellcheck='false'>
        <span class='field-suffix'>." <> ctx.config.handle_domain <> "</span>
      </div>
      <div class='field'>
        <label class='field-label' for='email'>Email (optional)</label>
        <span class='field-icon'><i data-lucide='mail'></i></span>
        <input class='field-input' type='email' name='email' id='email'
               placeholder='you@example.com' autocomplete='email'>
      </div>
      <div class='field'>
        <label class='field-label' for='password'>Password</label>
        <span class='field-icon'><i data-lucide='lock'></i></span>
        <input class='field-input' type='password' name='password' id='password'
               placeholder='Choose a strong password' autocomplete='new-password' required>
      </div>
      " <> turnstile_widget <> "
      <div class='error' id='error-msg'></div>
      <div class='success' id='success-msg'></div>
      <button type='submit' class='btn btn-primary btn-full'>Gleam me up <i data-lucide='arrow-right'></i></button>
    </form>
    
    <div class='passkey-section' id='passkey-section'>
      <p style='text-align:center;color:#b6b3b0;font-size:0.85rem;margin-bottom:0.75rem;'>Add a passkey for passwordless login:</p>
      <button class='btn btn-soft btn-full' id='passkey-btn' onclick='registerPasskey()'>
        <i data-lucide='fingerprint'></i> Register Passkey
      </button>
    </div>
    
    <div class='links'>
      <a href='/login'>Already have an account?</a> &middot; <a href='/'>Home</a>
    </div>
  </div>
  <script>
    const BASE = window.location.origin;
    let session = null;
    
    async function createAccount(e) {
      e.preventDefault();
      hideMessages();
      try {
        const handle = document.getElementById('handle').value;
        const email = document.getElementById('email').value;
        const password = document.getElementById('password').value;
        const turnstileToken = document.querySelector('[name=\"cf-turnstile-response\"]')?.value;

        const resp = await fetch(BASE + '/xrpc/com.atproto.server.createAccount', {
          method: 'POST',
          headers: {'Content-Type': 'application/json'},
          body: JSON.stringify({ handle, email: email || undefined, password, turnstileToken })
        });
        const data = await resp.json();
        if (data.error) { showError(data.message || data.error); return; }
        session = data;
        localStorage.setItem('pds_session', JSON.stringify(data));
        showSuccess('Account created! DID: ' + data.did);
        document.getElementById('passkey-section').style.display = 'block';
        document.getElementById('register-form').style.display = 'none';
        lucide.createIcons();
      } catch(e) { showError('Registration failed: ' + e.message); }
    }
    
    async function registerPasskey() {
      if (!session) { showError('Create account first'); return; }
      hideMessages();
      try {
        const beginResp = await fetch(BASE + '/api/passkey/register/begin', {
          method: 'POST',
          headers: {
            'Content-Type': 'application/json',
            'Authorization': 'Bearer ' + session.accessJwt
          }
        });
        const options = await beginResp.json();
        if (options.error) { showError(options.message || options.error); return; }
        
        const credential = await navigator.credentials.create({
          publicKey: {
            challenge: base64urlToBuffer(options.challenge),
            rp: options.rp,
            user: {
              ...options.user,
              id: base64urlToBuffer(options.user.id)
            },
            pubKeyCredParams: options.pubKeyCredParams,
            timeout: options.timeout,
            excludeCredentials: (options.excludeCredentials || []).map(c => ({...c, id: base64urlToBuffer(c.id)})),
            authenticatorSelection: options.authenticatorSelection,
            attestation: options.attestation
          }
        });
        
        const finishResp = await fetch(BASE + '/api/passkey/register/finish', {
          method: 'POST',
          headers: {
            'Content-Type': 'application/json',
            'Authorization': 'Bearer ' + session.accessJwt
          },
          body: JSON.stringify({
            id: credential.id,
            rawId: bufferToBase64url(credential.rawId),
            response: {
              attestationObject: bufferToBase64url(credential.response.attestationObject),
              clientDataJSON: bufferToBase64url(credential.response.clientDataJSON)
            },
            type: credential.type
          })
        });
        const result = await finishResp.json();
        if (result.error) { showError(result.message || result.error); return; }
        showSuccess('Passkey registered! You can now sign in with it.');
        document.getElementById('passkey-btn').innerHTML = '<i data-lucide=\"circle-check\"></i> Passkey Registered';
        document.getElementById('passkey-btn').disabled = true;
        lucide.createIcons();
      } catch(e) { showError('Passkey registration failed: ' + e.message); }
    }
    
    function base64urlToBuffer(b64) {
      const padding = '='.repeat((4 - b64.length % 4) % 4);
      const base64 = (b64 + padding).replace(/-/g, '+').replace(/_/g, '/');
      return Uint8Array.from(atob(base64), c => c.charCodeAt(0)).buffer;
    }
    function bufferToBase64url(buffer) {
      return btoa(String.fromCharCode(...new Uint8Array(buffer))).split('+').join('-').split('/').join('_').split('=').join('');
    }
    function showError(msg) { const el = document.getElementById('error-msg'); el.textContent = msg; el.style.display = 'block'; }
    function showSuccess(msg) { const el = document.getElementById('success-msg'); el.textContent = msg; el.style.display = 'block'; }
    function hideMessages() { document.getElementById('error-msg').style.display = 'none'; document.getElementById('success-msg').style.display = 'none'; }
  </script>
  " <> lucide_script <> "
</body>
</html>",
  )
}
