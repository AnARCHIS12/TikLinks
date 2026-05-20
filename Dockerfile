FROM php:8.3-cli-alpine

WORKDIR /var/www/html

COPY . .

RUN mkdir -p /data \
    && chown -R www-data:www-data /data /var/www/html

USER www-data

EXPOSE 4242

CMD ["php", "-S", "0.0.0.0:4242", "index.php"]
