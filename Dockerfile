FROM python:3.12-slim

# Set working directory
WORKDIR /app

# Install dependencies
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Copy all application files
COPY . .

# Expose the ports (5000 for webhook, 5001 for app, 5002 for poller just in case)
EXPOSE 5000 5001

# Default command (overridden by docker-compose)
CMD ["python", "app.py"]