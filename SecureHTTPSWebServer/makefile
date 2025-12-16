IMAGE_NAME=secure-websrv

all: image

image: Dockerfile $(IMAGE_NAME)_cert.pem $(IMAGE_NAME)_key.pem $(IMAGE_NAME)_nginx.conf html/index.html
	docker build -t $(IMAGE_NAME) .

$(IMAGE_NAME)_cert.pem: $(IMAGE_NAME)_csr.cnf
	# Web server key and certificate
	openssl genrsa -out root_key.pem 4096
	openssl req -new -key $(IMAGE_NAME)_key.pem -out $(IMAGE_NAME)_csr.pem -config $(IMAGE_NAME)_csr.cnf
	# Sign Web server certificate
	openssl x509 -req -in $(IMAGE_NAME)_csr.pem -CA root_cert.pem -CAkey root_key.pem -CAcreateserial -out $(IMAGE_NAME)_cert.pem -days 365 -extensions v3_req -extfile $(IMAGE_NAME)_csr.cnf

# root key
root_key.pem:
	openssl genrsa -out root_key.pem 4096

# root certificate
root_cert.pem: root_key.pem
	openssl req -x509 -new -nodes -key root_key.pem -sha256 -days 365 -out root_cert.pem

# Web server key
$(IMAGE_NAME)_key.pem:
	openssl genrsa -out $(IMAGE_NAME)_key.pem 4096

# Certificate signing request
$(IMAGE_NAME)_csr.pem: $(IMAGE_NAME)_key.pem $(IMAGE_NAME)_csr.cnf
	openssl req -new -key $(IMAGE_NAME)_key.pem -out $(IMAGE_NAME)_csr.pem -config $(IMAGE_NAME)_csr.cnf

# Web server certificate 
$(IMAGE_NAME)_cert.pem: $(IMAGE_NAME)_csr.pem root_cert.pem root_key.pem $(IMAGE_NAME)_csr.cnf
	openssl x509 -req -in $(IMAGE_NAME)_csr.pem -CA root_cert.pem -CAkey root_key.pem -CAcreateserial -out $(IMAGE_NAME)_cert.pem -days 80 -extensions v3_req -extfile $(IMAGE_NAME)_csr.cnf

# Run the webserver
websrv:
	docker run -p 44443:443 $(IMAGE_NAME)
