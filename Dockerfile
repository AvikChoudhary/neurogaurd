# Optional: run NeuroGuard in a container   (docker build -t neuroguard . && docker run -p 5000:5000 neuroguard)
FROM python:3.12-slim
WORKDIR /app
COPY requirements.txt .
RUN pip install --no-cache-dir flask numpy
COPY . .
RUN python -m backend.train --samples 40000
EXPOSE 5000
CMD ["python", "run.py", "--host", "0.0.0.0", "--no-browser"]
