import os
import redis

redis_host = str(os.getenv("REDIS_HOST"))
redis_port = int(os.getenv("REDIS_PORT"))

redis_client = redis.StrictRedis(host=redis_host, port=redis_port, decode_responses=True)

def get_queue_item(in_queue_name, rq_client = redis_client):
    
    queue_item = rq_client.lpop(in_queue_name)
    if queue_item:
        print("Item",queue_item," retornado na fila!")
        return queue_item

    return None