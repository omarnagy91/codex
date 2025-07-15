FROM node:24-slim

# ---------- build-time args ----------
ARG TZ
ARG FIREWALL_MODE="off"   # default: full Internet access
ENV TZ="${TZ}"
ENV CODEX_FIREWALL_MODE="${FIREWALL_MODE}"

# ---------- base packages ----------
RUN apt-get update && apt-get install -y --no-install-recommends \
  aggregate ca-certificates curl dnsutils \
  fzf gh git gnupg2 iproute2 ipset iptables jq less man-db \
  procps unzip ripgrep zsh && \
  rm -rf /var/lib/apt/lists/*

# ---------- non-root user setup ----------
RUN mkdir -p /usr/local/share/npm-global && chown -R node:node /usr/local/share
USER node

ENV NPM_CONFIG_PREFIX=/usr/local/share/npm-global
ENV PATH=$PATH:/usr/local/share/npm-global/bin
ENV CODEX_UNSAFE_ALLOW_NO_SANDBOX=1  # container already isolated

# ---------- install codex ----------
COPY dist/codex.tgz codex.tgz
RUN npm install -g codex.tgz && \
    npm cache clean --force && \
    rm -rf /usr/local/share/npm-global/lib/node_modules/codex-cli/{node_modules/.cache,tests,docs}

# ---------- firewall script (kept, but disabled by default) ----------
USER root
COPY scripts/init_firewall.sh /usr/local/bin/
RUN chmod 500 /usr/local/bin/init_firewall.sh
USER node

# ENTRYPOINT / CMD are provided by codex-cli or your compose setup
