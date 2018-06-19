known instruction snippets scanner library (kiss-lib)
Offers binding to c/c++ and python

You might want to create a swap file (on a ssd preferably) for the db compression 
	'dd if=/dev/zero of=/swapfile1 bs=1024 count=1MB
	chown root:root /swapfile1' 
	chmod 0600 /swapfile1
	mkswap /swapfile1
	swapon /swapfile1
