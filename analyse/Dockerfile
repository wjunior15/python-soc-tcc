FROM python:3.9-slim
LABEL MAINTAINER="Wellington Araujo <wellingtonresende15@gmail.com>"

ENV GROUP_ID=1000 \
    USER_ID=1000

WORKDIR /usr/src/process

COPY . .

# Instalar dependências do sistema e pacotes Python
RUN apt-get update \
    && apt-get -y install libpq-dev gcc \
    && pip install psycopg2 \
    && pip install -U scikit-learn==1.3.2
RUN pip install -r requirements.txt

EXPOSE 8000

# Definir o comando padrão para executar a aplicação
#CMD ["python", "soc.py"]
CMD ["python","process.py"]