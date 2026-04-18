# Use Python 3.11 as the base
FROM python:3.11-slim

# Install system dependencies (This is the fix!)
RUN apt-get update && apt-get install -y \
    libzbar0 \
    libgl1-mesa-glx \
    && rm -rf /var/lib/apt/lists/*

# Set the working directory
WORKDIR /app

# Copy requirements and install
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Copy the rest of the backend code
COPY . .

# Start the server using gunicorn
CMD ["gunicorn", "app:app", "--bind", "0.0.0.0:10000"]
