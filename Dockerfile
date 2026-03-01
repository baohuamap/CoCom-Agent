FROM python:3.11-slim
ENV DEBIAN_FRONTEND=noninteractive

# Install system dependencies (JRE is required for Joern)
RUN apt-get update && apt-get install -y --no-install-recommends \
    openjdk-17-jre-headless \
    curl \
    unzip \
    && rm -rf /var/lib/apt/lists/*

# Install Joern CLI
WORKDIR /opt
RUN curl -L "https://github.com/joernio/joern/releases/latest/download/joern-cli.zip" -o joern-cli.zip \
    && unzip joern-cli.zip \
    && rm joern-cli.zip \
    && mv joern-cli /opt/joern
ENV PATH="/opt/joern:${PATH}"

# Setup Python application
WORKDIR /app
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt
COPY . /app

CMD ["/bin/bash"]
