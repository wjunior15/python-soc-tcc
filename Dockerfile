FROM python:3.10-slim
LABEL MAINTAINER="Wellington Araujo <wellingtonresende15@gmail.com>"

ENV GROUP_ID=1000 \
    USER_ID=1000

# Defina o diretório de trabalho no contêiner
WORKDIR /app

# Copie o arquivo de requisitos
COPY requirements.txt .

# Instale as dependências do Python
RUN apt-get update \
    && apt-get -y install libpq-dev gcc \
    && pip install psycopg2
RUN pip install -r requirements.txt

# Copie o código-fonte da aplicação para o contêiner
COPY . .

#Expõe porta do banco de dados 5432
EXPOSE 5432
EXPOSE 5000

# Defina o comando padrão para executar a aplicação
CMD python app/__init__.py