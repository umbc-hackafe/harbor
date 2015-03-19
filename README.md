# harbor
Docker container management system

Harbor is made to make management of docker whole-system containers painless. However, it is a very niche tool that has been made to suite my 
environment. Harbor assumes you are running Rhel 7 with puppet for configuration manegement. After fighting Docker over network configuration long 
enough, I decided to manage it entirely by myself. Harbor will create a virtual network adapter for each container, and assign a static ip address to 
it. I plan to add more networking features eventually, but haven't yet.

