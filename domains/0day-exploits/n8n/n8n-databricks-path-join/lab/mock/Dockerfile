FROM python:3.12-alpine
COPY server.py /server.py
EXPOSE 8080
HEALTHCHECK --interval=3s --timeout=3s --retries=15 CMD python -c "import urllib.request; urllib.request.urlopen('http://127.0.0.1:8080/health')"
CMD ["python", "/server.py"]
