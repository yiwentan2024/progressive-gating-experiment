FROM python:3.12-slim
WORKDIR /srv
COPY dist/release_app.pyz /srv/release_app.pyz
ENV PYTHONUNBUFFERED=1
EXPOSE 8000
CMD ["python", "/srv/release_app.pyz", "--port", "8000"]
