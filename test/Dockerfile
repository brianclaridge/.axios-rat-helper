FROM debian:bookworm-slim

RUN apt-get update && apt-get install -y --no-install-recommends \
    python3 procps net-tools iproute2 \
    && rm -rf /var/lib/apt/lists/*

# ── Plant RAT artifact ──────────────────────────────────────────
# Linux RAT payload
RUN echo '#!/usr/bin/env python3\nimport time\nwhile True: time.sleep(60)' > /tmp/ld.py

# Transient dropper artifact
RUN echo 'dropper-payload' > /tmp/6202033

# ── Plant compromised npm project ───────────────────────────────
RUN mkdir -p /projects/infected-app/node_modules/plain-crypto-js \
             /projects/infected-app/node_modules/axios \
             /projects/infected-app/node_modules/@shadanai/openclaw

# Compromised axios@1.14.1 with injected plain-crypto-js dep
RUN echo '{"name":"axios","version":"1.14.1","dependencies":{"plain-crypto-js":"4.2.1","follow-redirects":"^1.15.0"}}' \
    > /projects/infected-app/node_modules/axios/package.json

# Malicious plain-crypto-js with postinstall dropper
RUN echo '{"name":"plain-crypto-js","version":"4.2.1","scripts":{"postinstall":"node setup.js"}}' \
    > /projects/infected-app/node_modules/plain-crypto-js/package.json
RUN echo 'const stq=["malicious","payload"];' \
    > /projects/infected-app/node_modules/plain-crypto-js/setup.js

# Secondary attack vector
RUN echo '{"name":"@shadanai/openclaw","version":"2026.3.31-1"}' \
    > /projects/infected-app/node_modules/@shadanai/openclaw/package.json

# Project package.json referencing compromised axios
RUN echo '{"name":"infected-app","version":"1.0.0","dependencies":{"axios":"1.14.1","plain-crypto-js":"4.2.1","@shadanai/openclaw":"2026.3.31-1"},"scripts":{"postinstall":"node setup.js"}}' \
    > /projects/infected-app/package.json

# Lockfile pinning compromised versions
RUN echo '{"name":"infected-app","lockfileVersion":3,"packages":{"node_modules/axios":{"version":"1.14.1"},"node_modules/plain-crypto-js":{"version":"4.2.1"}}}' \
    > /projects/infected-app/package-lock.json

# ── Plant a clean project (should NOT trigger) ──────────────────
RUN mkdir -p /projects/clean-app/node_modules/axios

RUN echo '{"name":"clean-app","version":"1.0.0","dependencies":{"axios":"1.14.0"}}' \
    > /projects/clean-app/package.json

RUN echo '{"name":"axios","version":"1.14.0","dependencies":{"follow-redirects":"^1.15.0"}}' \
    > /projects/clean-app/node_modules/axios/package.json

RUN echo '{"name":"clean-app","lockfileVersion":3,"packages":{"node_modules/axios":{"version":"1.14.0"}}}' \
    > /projects/clean-app/package-lock.json

# ── Test script ─────────────────────────────────────────────────
COPY test/verify.sh /verify.sh
RUN chmod +x /verify.sh

# Scanner binary will be mounted at /scanner/axios-rat-scan
WORKDIR /projects
ENTRYPOINT ["/verify.sh"]
