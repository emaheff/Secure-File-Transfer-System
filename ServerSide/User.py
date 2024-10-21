class User:
    def __init__(self, user_name, uuid, public_key=None, symmetric_key=None):
        self.user_name = user_name
        self.uuid = uuid
        self.public_key = public_key
        self.symmetric_key = symmetric_key

    def getUserName(self):
        return self.user_name

    def getPublicKey(self):
        return self.public_key

    def getUuid(self):
        return self.uuid

    def setPublicKey(self, public_key):
        self.public_key = public_key

    def setSymmetricKey(self, symmetric_key):
        self.symmetric_key = symmetric_key

    def getSymmetricKey(self):
        return self.symmetric_key
