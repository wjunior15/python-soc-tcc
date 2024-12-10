FROM python:3.10-slim
LABEL MAINTAINER="Wellington Araujo <wellingtonresende15@gmail.com>"

ENV GROUP_ID=1000 \
    USER_ID=1000

WORKDIR /usr/src/analyze

COPY . .

# Instalar dependências do sistema e pacotes Python
RUN apt-get update \
    && apt-get -y install libpq-dev gcc \
    && pip install psycopg2
RUN pip install -r requirements.txt

# Definir o comando padrão para executar a aplicação
CMD ["python","analyze.py"]