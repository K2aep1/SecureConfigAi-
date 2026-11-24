# Lovable prompt — SecureConfigAI visual identity

Improve the visual identity of the existing SecureConfigAI frontend. Do not recreate the app from scratch.

Brand direction:
- Product: enterprise Windows endpoint security configuration assessment platform.
- Primary brand color: deep navy `#10243E`.
- Brand accent: aqua/cyan `#45E0CF`.
- Action accent: blue `#3977F6`.
- Surface background: cool light neutral `#F4F7FB`.
- UI font: Inter; technical IDs, JSON keys and evidence values: IBM Plex Mono.
- Brand symbol: a minimal shield containing configuration sliders/nodes, not a lightning bolt and not the Vite logo.
- Wordmark: “SecureConfig” in a strong neutral weight and “AI” in aqua.

Use the supplied `SecureConfigAILogo.tsx`, `brand.css`, `favicon.svg`, and `secureconfigai-wordmark.svg` assets. Replace only the existing branding block in `AppShell.tsx` with the logo component and update `index.html` so the browser favicon uses `/favicon.svg`, removing any `/vite.svg` reference.

Apply typography consistently: use Inter for normal interface content and IBM Plex Mono only for technical data such as control IDs, hashes, JSON, and evidence output. Preserve semantic status colors so security failures, warnings, unknown evidence, and successful assessments remain distinguishable.

Critical constraints:
- Do not modify the backend, API contract, authentication, scan workflow, database or scoring logic.
- Do not hardcode or mock any security metrics or findings.
- Do not overwrite `AppShell.tsx` wholesale; preserve existing navigation, user controls, scan actions, health status, responsiveness and route behavior.
- Do not change Gemini configuration or expose any key to the browser.
- Avoid adding dependencies for icons; use the supplied inline SVG.
- Run the existing TypeScript checks and production build and report actual results.
