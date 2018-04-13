# 					SRSC-TP1

# Servidor AS
java AuthenticationServer multicastgroup port password salt iterations
Exemplo de execução do servidor:
java AuthenticationServer 224.224.224.224 3001 b109f3bbbc244eb82441917ed06d618b9008dd09b3befd1b5e07394c706a8bb980b1d7785e5976ec049b46df5f1326af5a2ea6d103fd07c95385ffab0cacbc86 ec6ff495fd2f79b3 1060

# MulticastReciever
java MulticastReceiver multicastgroup port
Exemplo de execução do recetor:
224.10.10.10 3000

# MulticastSender
java MulticastSender multicastgroup port timeinterval
Exemplo de execução do emissor:
224.10.10.10 3000 1

# MChatCliente
java MChatCliente nickusername/email multicastgroup port <ttl>
Exemplo de execução do multicastChat:
jose/jose@gmai.com 224.10.10.10 9001

# FileEncryption
java FileEncryption inputfile outputfile password
Exemplo de execução do fileEncryption:
res/users.conf res/users.axx password
