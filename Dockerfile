FROM oven/bun:1-alpine AS runtime
WORKDIR /app

RUN apk add --no-cache git

ENV NODE_ENV=production
ENV ROCKSOUL_SANDBOX_HOST=0.0.0.0
ENV ROCKSOUL_SANDBOX_PORT=4540
ENV ROCKSOUL_SANDBOX_WORKTREES_DIR=/var/lib/rocksoul-sandbox/worktrees
ENV MW_ECHO_OTLP_URL=http://mw-echo:4310/v1/traces

COPY package.json tsconfig.json ./
COPY src ./src

RUN addgroup -S rocksoul && adduser -S rocksoul -G rocksoul \
  && mkdir -p /var/lib/rocksoul-sandbox/worktrees \
  && chown -R rocksoul:rocksoul /app /var/lib/rocksoul-sandbox

USER rocksoul
EXPOSE 4540

HEALTHCHECK --interval=30s --timeout=5s --start-period=5s --retries=3 \
  CMD bun -e "fetch('http://127.0.0.1:' + (process.env.ROCKSOUL_SANDBOX_PORT || '4540') + '/health').then(r => process.exit(r.ok ? 0 : 1)).catch(() => process.exit(1))"

CMD ["bun", "run", "src/server.ts"]
