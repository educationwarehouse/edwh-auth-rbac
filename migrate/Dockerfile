FROM educationwarehouse/edwhale-3.13:latest

USER root

WORKDIR /tmp
COPY . .
RUN uv pip install psycopg2-binary
RUN uv pip install -e .[dev]

USER microservices

WORKDIR /pythonpath
# CMD see docker-compose
