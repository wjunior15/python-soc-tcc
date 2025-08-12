FROM python:3.10-slim
LABEL MAINTAINER="Wellington Araujo <wellingtonresende15@gmail.com>"

ENV GROUP_ID=1000 \
    USER_ID=1000

# Definir o diretório de trabalho no contêiner
WORKDIR /usr/src/benign

# Copiar os arquivos da pasta local para o contêiner
COPY . .

# Instalar dependências do sistema e pacotes Python
RUN apt-get update \
    && apt-get -y install libpq-dev gcc
RUN pip install -r requirements.txt

# Definir o comando padrão para executar a aplicação
CMD ["python", "benign_traffic.py"]