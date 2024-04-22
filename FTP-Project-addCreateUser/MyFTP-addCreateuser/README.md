This report documents the development of a custom-built File Transfer Protocol (FTP) system, comprising a client application and a server back-end. The project's aim was to create a system that allows users to perform secure file storage and retrieval operations over a network.

#start the server
python3 server/bin/server.py start

#create user
python3 server/bin/server.py createuser [username] [password]
python3 client/client.py -s [server ip] -P [server port] (optional) -u [new username] -p [password]

#start client
python3 client/client.py -s [server ip] -P [server port] (optional) -u [username] -p [password]

#change directory
cd xxx

#show current directory info
ls

#download file
get xxx

#upload file
put xxx

#delete file
rm xxx

#delete empty directory
rmdir xxx

#delete directory and all files inside
rm_rf xxx
