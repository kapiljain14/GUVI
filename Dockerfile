FROM python:3.11-slim

WORKDIR /app

# Install dependencies
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Copy application
COPY main.py .

# Hugging Face Spaces expects port 7860
ENV PORT=7860
ENV HOST=0.0.0.0

# Expose the port
EXPOSE 7860

# Run the application
CMD ["python", "-m", "uvicorn", "main:app", "--host", "0.0.0.0", "--port", "7860"]
