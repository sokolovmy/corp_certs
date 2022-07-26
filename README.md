
docker build . -t test_cert

docker run -v /hbz:/db:rw -it --rm --name test_name test_cert listcerts 'haulmont.com' '10.5.0.3'

docker run -v /hbz:/db:rw -it --rm --name test_name test_cert cert 471c40c9f452f0d6e9281ec4f9ba382e