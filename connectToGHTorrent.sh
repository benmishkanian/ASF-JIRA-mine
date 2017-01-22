# Forwards local port 3307 to mysqld at ghtorrent.org (requires you to register your public key with them)
eval $(ssh-agent)
ssh-add /home/vagrant/.ssh/imported_id_rsa
ssh -fN -o ExitOnForwardFailure=yes -o StrictHostKeyChecking=no -L 3307:web.ghtorrent.org:3306 ghtorrent@web.ghtorrent.org