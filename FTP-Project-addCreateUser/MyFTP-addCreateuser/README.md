#start the server
python3 server/bin/server.py start

#create user
python3 server/bin/server.py createuser

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
