FROM ubuntu:24.04

# Prevent interactive prompts
ENV DEBIAN_FRONTEND=noninteractive

# Install system dependencies
RUN apt-get update && apt-get install -y \
  curl \
  git \
  python3 \
  build-essential \
  pkg-config \
  libssl-dev \
  && rm -rf /var/lib/apt/lists/*

# Install Sui CLI (devnet binary from GitHub releases, arch-aware)
RUN set -eux; \
  ARCH=$(uname -m); \
  case "$ARCH" in \
    x86_64)  SUI_ARCH="ubuntu-x86_64" ;; \
    aarch64) SUI_ARCH="ubuntu-aarch64" ;; \
    *) echo "Unsupported arch: $ARCH" && exit 1 ;; \
  esac; \
  SUI_VERSION=$(curl -s "https://api.github.com/repos/MystenLabs/sui/releases" \
    | python3 -c "import sys,json; releases=json.load(sys.stdin); print(next(r['tag_name'] for r in releases if r['tag_name'].startswith('devnet-')))"); \
  echo "Installing Sui $SUI_VERSION for $SUI_ARCH"; \
  curl -fsSL "https://github.com/MystenLabs/sui/releases/download/${SUI_VERSION}/sui-${SUI_VERSION}-${SUI_ARCH}.tgz" \
    -o /tmp/sui.tgz; \
  tar -xzf /tmp/sui.tgz -C /usr/local/bin; \
  rm /tmp/sui.tgz; \
  sui --version

# Install Node.js 22
RUN curl -fsSL https://deb.nodesource.com/setup_22.x | bash - \
  && apt-get install -y nodejs \
  && rm -rf /var/lib/apt/lists/*

# Install pnpm
RUN corepack enable && corepack prepare pnpm@latest --activate

# Set up workspace
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
