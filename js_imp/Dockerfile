FROM python:3.11-slim

# Install dependencies
RUN apt-get update && apt-get install -y \
    curl \
    git \
    build-essential \
    libssl-dev \
    && rm -rf /var/lib/apt/lists/*

# Install ZoKrates binary
RUN curl -L https://github.com/Zokrates/ZoKrates/releases/latest/download/zokrates -o /usr/local/bin/zokrates \
    && chmod +x /usr/local/bin/zokrates

# Create app directory
WORKDIR /app
COPY . .

# Install Flask
RUN pip install flask

# Expose Flask port
EXPOSE 5000

# Run server
CMD ["python", "server.py"]
