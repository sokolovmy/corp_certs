# Corp Certs

Мониторинг сертификатов в корпоративке
Zabbix template
Version 0.1

# corp_certs.py


Скачивает зону с днс сервера.
Опрашивает все хосты из зоны на наличие открытого порта 443. Скачивает сертификаты за исключением самоподписанных и не соотвествующих этой зоне.


Usage: corp_cert.py command [arguments]

    listcerts <domain_name> <dns_server>
    cert <id>


# Установка на клиенте

## Docker image

Прописываем в конфиге Заббикса 

    UserParameter=corp_certs[*],docker run -v /var/lib/zabbix:/var/lib/zabbix -it --rm --name corp_certs holse/corp-certs $1 $2 $3

## У вас сервер Zabbix в контейнере?

Тогда можно просто запустить еще одного агента с уже подключенным скриптом

Имя docker image - corp_certs:zabbix-agent2-latest