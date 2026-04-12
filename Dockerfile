# suixploit-hunter: Fast builds on top of the base toolchain image.
# Requires: docker build -f Dockerfile.base -t suixploit-base .  (once)
FROM suixploit-base

WORKDIR /workspace

# Copy package files and install dependencies
COPY package.json pnpm-lock.yaml ./
RUN pnpm install --frozen-lockfile

# Copy project source
COPY tsconfig.json ./
COPY src/ ./src/
COPY contracts/ ./contracts/
COPY entrypoint.sh ./

ENTRYPOINT ["./entrypoint.sh"]
