FROM python:latest

WORKDIR /usr/src/app

copy requirements.txt ./
RUN apt update && apt install -y libgirepository1.0-dev pkg-config python3-dev libcairo2-dev python-apt pkg-config icu-devtools libicu-dev && pip install --no-cache-dir -r requirements.txt

COPY ohayou.py .

CMD ["python","./ohayou.py"]
