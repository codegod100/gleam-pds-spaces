# Stage 1: Build
FROM ghcr.io/gleam-lang/gleam:v1.15.2-erlang-alpine AS builder

RUN apk add --no-cache gcc g++ make

WORKDIR /app

# Copy configs first for caching
COPY gleam.toml ./

# Download + compile dependencies (cached as long as gleam.toml doesn't change)
# This is the slow step (SQLite C compilation ~70s) - only reruns when gleam.toml changes
RUN gleam deps download

# Copy source (changing source invalidates only the build step, not dep download)
COPY src/ src/
COPY priv/ priv/

# Build release
RUN gleam export erlang-shipment

# Stage 2: Runtime
FROM ghcr.io/gleam-lang/gleam:v1.15.2-erlang-alpine

RUN apk add --no-cache sqlite-libs

WORKDIR /app

# Copy the built release
COPY --from=builder /app/build/erlang-shipment ./

# Create data directory for SQLite
RUN mkdir -p /data

# Expose port
EXPOSE 8080

ENV GLEAM_PDS_PORT=8080
ENV GLEAM_PDS_DB_PATH=/data/gleam_pds.db
# GLEAM_PDS_HOSTNAME / GLEAM_PDS_PUBLIC_URL are deliberately left unset: they
# identify a specific deployment, so supply them at run time (fly.toml [env],
# `docker run -e`, or the systemd unit).
#
# GLEAM_PDS_SECRET is sensitive and must likewise be injected at run time
# (e.g. `fly secrets set GLEAM_PDS_SECRET=...`), never baked into the image.

# Runtime image includes wget (busybox) for the healthcheck below.
# Hit the app's existing /xrpc/_health route; start-period covers migrations.
HEALTHCHECK --interval=30s --timeout=5s --start-period=20s --retries=3 \
  CMD wget --quiet --tries=1 --spider http://127.0.0.1:8080/xrpc/_health || exit 1

CMD ["./entrypoint.sh", "run"]
