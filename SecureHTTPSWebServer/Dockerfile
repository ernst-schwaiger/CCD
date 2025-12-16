# Most recent nginx tag on dockerhub
FROM nginx:mainline-alpine3.23-perl

# config files, keys, certs, web content
COPY ./secure-websrv_nginx.conf /etc/nginx/nginx.conf
COPY ./secure-websrv_key.pem /etc/nginx/secure-websrv_key.pem
COPY ./secure-websrv_cert.pem /etc/nginx/secure-websrv_cert.pem
COPY ./html /usr/share/nginx/html

# Expose HTTPS 443
EXPOSE 443

# Run Nginx in the foreground
CMD ["nginx", "-g", "daemon off;"]

