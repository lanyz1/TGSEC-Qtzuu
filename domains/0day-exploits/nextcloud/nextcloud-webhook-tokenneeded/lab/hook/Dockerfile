FROM python:3.12-alpine
COPY server.py /server.py
RUN mkdir -p /data
EXPOSE 8080
HEALTHCHECK --interval=3s --timeout=3s --retries=10 \
  CMD python -c "import urllib.request; urllib.request.urlopen('http://127.0.0.1:8080/health')"
CMD ["python", "/server.py"]
