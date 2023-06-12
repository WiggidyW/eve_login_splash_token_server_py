FROM alpine:3.13
RUN apk add --no-cache \
    python3 \
    py3-pip \
 && pip3 install --no-cache-dir \
    requests \
    flask \
    jose
COPY ./app.py app.py
RUN chmod +x app.py
CMD ["flask run -h $HOST -p $PORT"]
    