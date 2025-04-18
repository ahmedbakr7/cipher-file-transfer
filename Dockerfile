FROM python:3.10-slim

# Install poetry
RUN pip install poetry==1.6.1

# Set up working directory
WORKDIR /app

# Copy poetry configuration files
COPY pyproject.toml ./

# Configure poetry to not create a virtual environment
RUN poetry config virtualenvs.create false

# Copy application code
COPY . .

# Install dependencies
RUN poetry install --no-interaction --no-ansi

# Port for the application (adjust if needed)
EXPOSE 5000

# Run the application
CMD ["python", "p2p_app.py"]