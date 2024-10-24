class User:
    """
    This class represents a user in the system with attributes such as user name, UUID, public key, and symmetric key.

    Attributes:
        user_name (str): The name of the user.
        uuid (str): The unique identifier for the user (UUID).
        public_key (str, optional): The public key of the user for encryption purposes. Defaults to None.
        symmetric_key (str, optional): The symmetric key of the user for encryption purposes. Defaults to None.

    Methods:
        getUserName(): Returns the user name.
        getPublicKey(): Returns the public key.
        getUuid(): Returns the UUID.
        setPublicKey(public_key): Sets the public key for the user.
        setSymmetricKey(symmetric_key): Sets the symmetric key for the user.
        getSymmetricKey(): Returns the symmetric key.
    """
    def __init__(self, user_name, uuid, public_key=None, symmetric_key=None):
        """
        Initializes a new instance of the User class.

        Args:
            user_name (str): The name of the user.
            uuid (str): The unique identifier (UUID) for the user.
            public_key (str, optional): The public key for the user. Defaults to None.
            symmetric_key (str, optional): The symmetric key for the user. Defaults to None.
        """
        self.user_name = user_name
        self.uuid = uuid
        self.public_key = public_key
        self.symmetric_key = symmetric_key

    def getUserName(self):
        """
        Returns the name of the user.

        Returns:
            str: The name of the user.
        """
        return self.user_name

    def getPublicKey(self):
        """
        Returns the public key of the user.

        Returns:
            str: The public key of the user, or None if not set.
        """
        return self.public_key

    def getUuid(self):
        """
        Returns the UUID of the user.

        Returns:
            str: The unique identifier (UUID) of the user.
        """
        return self.uuid

    def setPublicKey(self, public_key):
        """
        Sets the public key for the user.

        Args:
            public_key (str): The public key to set for the user.
        """
        self.public_key = public_key

    def setSymmetricKey(self, symmetric_key):
        """
        Sets the symmetric key for the user.

        Args:
            symmetric_key (str): The symmetric key to set for the user.
        """
        self.symmetric_key = symmetric_key

    def getSymmetricKey(self):
        """
        Returns the symmetric key of the user.

        Returns:
            str: The symmetric key of the user, or None if not set.
        """
        return self.symmetric_key
