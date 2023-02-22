import time
import os
import logging
import threading
import uuid
import tempfile

import requests
import uvicorn
from fastapi import FastAPI, UploadFile, HTTPException
from fastapi.responses import RedirectResponse


CONFIG_SERVICE_ENDPOINT = os.environ.get('CONFIG_SERVICE_ENDPOINT', 'http://127.0.0.1:8000')
CACHE = {}
app = FastAPI(title="Antivirus Service")


def update_malicious_words_cache(interval: int = 60, retry_interval: int = 5):
    """Update of the malicious words local cache"""
    while True:
        logging.info('updating cache...')
        try:
            res = requests.get(f'{CONFIG_SERVICE_ENDPOINT}/malicious-words/')
        except requests.exceptions.RequestException as e:
            logging.error(f"Cannot fetch malicious words due to RequestException: {e}'")

            time.sleep(retry_interval)
            continue

        CACHE['malicious-words'] = res.json()['response']
        time.sleep(interval)


@app.get('/')
async def docs_redirect():
    """Redirect to docs"""
    return RedirectResponse(url='/docs')


@app.on_event("startup")
async def startup_event():
    """Startup tasks for our FastAPI application"""
    logging.basicConfig(level=logging.INFO)
    t = threading.Thread(target=update_malicious_words_cache)
    t.start()


@app.post("/scan")
async def scan_file(file: UploadFile, chunk_size: int = 1024*1024) -> dict:  # 1MB
    """Scans the file and returns clean or not using malicious words db"""
    if 'malicious-words' not in CACHE:
        # cache is not ready yet
        raise HTTPException(status_code=500, detail="Internal Server Error")

    # save uploaded file to disk
    tmp_file_path = os.path.join(tempfile.gettempdir(), str(uuid.uuid4()))
    try:
        try:
            with open(tmp_file_path, 'wb') as f:
                # read in chunks, in case the file is very big and doesn't fit into memory
                while contents := file.file.read(chunk_size):
                    f.write(contents)
        except IOError:
            raise HTTPException(status_code=500, detail="There was an error uploading the file")
        finally:
            file.file.close()

        # look for malicious words in file
        try:
            with open(tmp_file_path, 'r') as f:
                for line in f:
                    for w in CACHE['malicious-words']:
                        if line.find(w) != -1:  # if malicious word was found
                            return {"response": "detected", "malicious_word": w}
        except UnicodeDecodeError:
            raise HTTPException(status_code=400, detail="binary files are not supported at the moment")
    finally:
        # cleanup - delete the uploaded file
        if os.path.exists(tmp_file_path):
            os.remove(tmp_file_path)
    return {"response": "clean"}


if __name__ == "__main__":
    uvicorn.run(app, host="0.0.0.0", port=8080)
