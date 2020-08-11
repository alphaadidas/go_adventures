from locust import HttpUser, between, task, SequentialTaskSet
from locust.exception import ResponseError
from uuid import uuid4
from logging import info
import string
import random


def get_random_string(length):
    letters = string.ascii_lowercase
    result_str = ''.join(random.choice(letters) for i in range(length))
    print("Random string of length", length, "is:", result_str)

class SequenceOfTasks(SequentialTaskSet):

    def on_start(self):
        """ on_start is called when a Locust start before
            any task is scheduled
        """

    @task(2)
    def stats(self):
        self.client.get("/stats")

    @task(1)
    def hashpass(self):
        self.client.post("/hash",data={"password":get_random_string(10)})




class GoUser(HttpUser):
    tasks = [SequenceOfTasks]
    wait_time = between(1, 3)
