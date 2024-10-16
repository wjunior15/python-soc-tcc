import os
print("Inicia Container")

cont = 0
env_var = os.getenv("DB_USER")

while 1:
    print("Container continua rodando",cont,"e pegando variaveis de ambiente",env_var)
    cont += 1