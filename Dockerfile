# BoundaryForge Streamlit dashboard container
FROM python:3.12-slim

WORKDIR /app

# Install build dependencies and clean up in one layer.
RUN apt-get update && apt-get install -y --no-install-recommends \
    build-essential \
    && rm -rf /var/lib/apt/lists/*

# Copy package metadata and source.
COPY pyproject.toml requirements.txt ./
COPY src ./src

# Install the package with all optional dependencies.
RUN pip install --no-cache-dir -e ".[all]"

# Streamlit listens on 8501 by default.
EXPOSE 8501

# Disable Streamlit usage-gathering prompts and telemetry.
ENV STREAMLIT_SERVER_HEADLESS=true
ENV STREAMLIT_BROWSER_GATHERUSAGESTATS=false
ENV STREAMLIT_SERVER_PORT=8501

CMD ["python", "-m", "streamlit", "run", "src/prompt_generator/dashboard.py"]
