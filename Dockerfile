ARG BASE_IMAGE=quay.io/fedora/fedora:43
FROM ${BASE_IMAGE}

RUN dnf install -y \
    caddy \
    php-fpm \
    php-json \
    python3 \
    python3-pip \
    iproute \
    procps-ng \
    curl \
    openssl \
    iptables-nft \
    && dnf clean all

# Tailscale
RUN curl -fsSL https://tailscale.com/install.sh | sh

# PHP-FPM: listen on TCP, run as nobody
RUN mkdir -p /run/php-fpm && \
    sed -i 's|^listen = .*|listen = 127.0.0.1:9000|' /etc/php-fpm.d/www.conf && \
    sed -i 's|^user = .*|user = nobody|' /etc/php-fpm.d/www.conf && \
    sed -i 's|^group = .*|group = nobody|' /etc/php-fpm.d/www.conf

# CITADEL
COPY . /opt/citadel
RUN chmod +x /opt/citadel/scan.sh

# Flask hello_world venv
RUN python3 -m venv /opt/citadel/hello_world/venv && \
    /opt/citadel/hello_world/venv/bin/pip install --no-cache-dir -r /opt/citadel/hello_world/requirements.txt

# Caddyfile
COPY deploy/Caddyfile /etc/caddy/Caddyfile

# Entrypoint
COPY deploy/entrypoint.sh /entrypoint.sh
RUN chmod +x /entrypoint.sh

ENTRYPOINT ["/entrypoint.sh"]
