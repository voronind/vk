import json
import requests as req

class LongPool:
    def __init__(self, session):
        self.session = session

    def listen(self, method):
        server = json.loads(
            req.get(
                "https://api.vk.com/method/messages.getLongPollServer?access_token="+self.session.access_token).content)
        lastTs = server["response"]["ts"]

        while True:
            longpool = "https://" + str(server["response"]["server"]) + "?act=a_check&key=" + str(
                server["response"]["key"]) + "&ts=" + str(lastTs) + "}&wait=25&mode=2&version=1"

            response = json.loads(req.get(longpool).content)

            for event in response["updates"]:
                if (event[0] == 4) and event[3]>=2000000000:
                    print("Got a message")
                    method(event[7]["from"], event[3], event[6])

            lastTs = response["ts"]