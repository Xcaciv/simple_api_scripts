FROM python:3.11

# Set working directory
WORKDIR /workspace

# Install system dependencies
RUN apt-get update && apt-get install -y \
    git \
    curl \
    && rm -rf /var/lib/apt/lists/*

# Copy requirements files
COPY requirements.txt /tmp/requirements.txt
COPY src/sitecheck_requiremnts.txt /tmp/sitecheck_requiremnts.txt

# Install Python dependencies from both requirements files
RUN pip install --no-cache-dir -r /tmp/requirements.txt \
    && pip install --no-cache-dir -r /tmp/sitecheck_requiremnts.txt

# Install development tools
RUN pip install --no-cache-dir pytest pytest-cov black isort flake8

# Set the default shell to bash with a better prompt
ENV SHELL /bin/bash
