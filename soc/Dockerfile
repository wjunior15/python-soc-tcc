FROM python:3.9-slim
LABEL MAINTAINER="Wellington Araujo <wellingtonresende15@gmail.com>"

ENV GROUP_ID=1000 \
    USER_ID=1000

WORKDIR /usr/src/app

COPY . .


# Definir o diretório de trabalho no contêiner
WORKDIR /usr/src/soc

# Copiar os arquivos da pasta local para o contêiner
COPY . .

# Instalar dependências do sistema e pacotes Python
RUN apt-get update \
    && apt-get -y install libpq-dev gcc \
    && pip install psycopg2 \
    && pip install -U scikit-learn==1.3.2
RUN pip install -r requirements.txt

RUN DEBIAN_FRONTEND=noninteractive apt-get install -y tshark

EXPOSE 8000

# Definir o comando padrão para executar a aplicação
#CMD ["python", "soc.py"]
CMD ["./run.sh"]