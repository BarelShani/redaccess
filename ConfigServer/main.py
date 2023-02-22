import logging
import os

from fastapi import FastAPI, status, HTTPException, Response
from fastapi.responses import RedirectResponse
import redis
import uvicorn

REDIS_HOST = os.environ.get('REDIS_HOST', 'localhost')
REDIS = redis.Redis(host=REDIS_HOST, port=6379, db=0, decode_responses=True)
app = FastAPI(title="Config Service")


@app.on_event("startup")
async def startup_event():
    """Startup tasks for our FastAPI application"""
    logging.basicConfig(level=logging.INFO)


@app.get('/')
async def docs_redirect():
    """Redirect to docs"""
    return RedirectResponse(url='/docs')


@app.get("/malicious-words/")
async def get_words() -> dict:
    """Return all malicious words"""
    vals = REDIS.smembers("malicious_words")
    return {"response": vals}


@app.post("/malicious-words/", status_code=status.HTTP_201_CREATED)
async def post_words(words_list: list[str], response: Response) -> dict:
    """Add multiple malicious words"""
    changed = 0
    for w in words_list:
        changed += REDIS.sadd('malicious_words', w)

    if changed == 0:
        response.status_code = status.HTTP_200_OK

    return {"changed": changed > 0}


@app.put("/malicious-words/", status_code=status.HTTP_201_CREATED)
async def put_single_word(word: str, response: Response) -> dict:
    """Add one malicious word"""
    changed = REDIS.sadd('malicious_words', word)
    if changed == 0:
        response.status_code = status.HTTP_200_OK

    return {"changed": changed > 0}


@app.delete("/malicious-words/", status_code=status.HTTP_201_CREATED)
async def delete_word(word: str) -> dict:
    """Delete one malicious word"""
    changed = REDIS.srem("malicious_words", word)
    if changed == 0:
        logging.error(f"Cannot delete malicious word {word}: not found in db")
        raise HTTPException(status_code=404, detail="Item not found")

    return {"changed": changed > 0}


if __name__ == "__main__":
    uvicorn.run(app, host="0.0.0.0", port=8000)
