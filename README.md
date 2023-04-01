# Authproxy
This class implements a reverse proxy intended to work inside a Flask server, with authentication based on a Synology NAS.
It will allow you to restrict the access from internet to your internal Api REST webservices, using the credentials and users that you have created in your Synology NAS.
It will also request the OTP code if you have that configured in your NAS.