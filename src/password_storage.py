import json
import os
from typing import Tuple
from enum import Enum
from Crypto.Cipher import AES
from Crypto.Protocol.KDF import PBKDF2
from Crypto.Random import get_random_bytes
import constants
import utilities


class PasswordManager:
    DATA_PATH = os.path.abspath(__file__ + "/../../data")

    class State(str, Enum):
        NOT_EMPTY = 1
        EMPTY = 2
        UNINITIALIZED = 3


    def __init__(self):
        self.passwords_file_path = self.DATA_PATH + "/passwords.bin"
        self.public_file_path = self.DATA_PATH + "/public.bin"
        self.auth_file_path = self.DATA_PATH + "/auth.bin"
        self.metadata_path = self.DATA_PATH + "/metadata.json"

        self.salt_size = constants.SALT_SIZE
        self.iv_size = constants.IV_SIZE
        self.key_size = constants.KEY_SIZE
        self.tag_size = constants.TAG_SIZE
        self.hash_iterations = constants.HASH_ITERATIONS

        self.state = None

        self.passwords = None
        self.salt = None
        self.tag = None


    def setState(self):
        """Prepares Password Manager"""
        if(not os.path.exists(self.metadata_path)):
            self.state = self.State.UNINITIALIZED
            self.storeState()
        else:
            self.loadState()
        if(self.state == self.State.NOT_EMPTY):
            self.loadPublicData()
        else:
            self.generatePublicData()


    def readMeatadata(self):
        """Reads Password Manager metadata required to operate"""
        try:
            with open(self.metadata_path, "r") as metadata_file:
                contents = json.loads(metadata_file.read())
            return contents
        except FileNotFoundError as e:
            return None
        except json.JSONDecodeError as e:
            return None
        

    def loadState(self):
        """Load Password Manager state from file"""
        try:
            self.state = self.readMeatadata()["state"]
        except:
            self.state = self.State.UNINITIALIZED


    def storeState(self):
        """Store Password Manager state to file"""
        metadata = self.readMeatadata()
        if(metadata == None):
            metadata = {}

        metadata["state"] = self.state

        with open(self.metadata_path, "w") as metadata_file:
            metadata_file.write(json.dumps(metadata))


    def storePublicData(self):
        """Store public passwords data to disk"""

        with open(self.public_file_path, "wb") as public_file:
            public_file.write(self.salt)
            public_file.write(self.iv)
            public_file.write(self.tag)


    def loadPublicData(self):
        """Load public passwords data"""
        with open(self.public_file_path, "rb") as public_file:
            content = public_file.read()
            if(len(content) == 0):
                utilities.ConsoleMessages.wrongPassword()
                exit(1)
            self.salt = content[0:self.salt_size]
            content = content[self.salt_size:]
            self.iv = content[0:self.iv_size]
            content = content[self.iv_size:]
            self.tag = content[0:]


    def generateAuthData(self, password) -> Tuple[bytes, bytes]:
        """Generate salt and hash for authentication"""
        salt = PasswordManager.generateSalt(self.salt_size)
        h = PBKDF2(password, salt, constants.PASSWORD_HASH_SIZE, self.hash_iterations)

        return salt, h


    def storeAuthData(self, salt, h):
        """Store authentication data to disk"""
        with open(self.auth_file_path, "wb") as auth_file:
            auth_file.write(salt)
            auth_file.write(h)


    def readAuthData(self):
        """Read authentication data from disk"""
        with open(self.auth_file_path, "rb") as auth_file:
            salt, h = (auth_file.read(x) for x in (self.salt_size, -1))

        return salt, h


    def authenticate(self, password):
        """Read authentication data from disk and verify authenticity via password. Store new authentication data"""
        salt, h = self.readAuthData()
        h_check= PBKDF2(password, salt, constants.PASSWORD_HASH_SIZE, constants.HASH_ITERATIONS)
        if(h_check != h):
            utilities.ConsoleMessages.wrongPassword()
            exit(1)
        
        #salt = PasswordManager.generateSalt(self.salt_size)
        #h = PBKDF2(password, salt, constants.PASSWORD_HASH_SIZE, constants.HASH_ITERATIONS)
        #self.storeAuthData(salt, h)


    def generatePublicData(self):
        """Generate public passwords data required to encrypt passwords"""
        self.iv = get_random_bytes(self.iv_size)
        self.salt = get_random_bytes(self.salt_size)
        self.tag = None


    def storePrivateData(self, ciphertext: bytes):
        """Store encryped passwords"""
        with open(self.passwords_file_path, "wb") as passwords_file:
            passwords_file.write(ciphertext)


    def getPrivateData(self) -> bytes:
        """Load encrypted password data"""
        with open(self.passwords_file_path, "rb") as passwords_file:
            return passwords_file.read()


    def initializeNewPasswordManager(self, password):
        """Initialize password manager state.\n
        Delete previous files in "data" folder and make empty files.\n
        Store authentication data.
        Store Password Manager state
        """
        utilities.ConsoleMessages.passwordManagerInitializing()

        if(os.path.exists(self.passwords_file_path)):
            os.remove(self.passwords_file_path)
        if(os.path.exists(self.public_file_path)):
            os.remove(self.public_file_path)
        if(os.path.exists(self.auth_file_path)):
            os.remove(self.auth_file_path)
        if(os.path.exists(self.metadata_path)):
            os.remove(self.metadata_path)

        open(self.passwords_file_path, "wb").close()
        open(self.public_file_path, "wb").close()
        open(self.auth_file_path, "wb").close()
        open(self.metadata_path, "w").close()

        password_bytes = password.encode("utf-8")
        salt, h = self.generateAuthData(password_bytes)

        self.state = self.State.EMPTY
        self.storeState()
        self.storeAuthData(salt, h)


    def storePassword(self, password: str, adress: str, new_password: str):
        """Store new password and encrypt"""
        if(self.state == self.State.UNINITIALIZED):
            utilities.ConsoleMessages.passwordManagerUninitialized()
            exit(0)

        password_bytes = password.encode("utf-8")
        
        self.authenticate(password_bytes)
        
        key = PasswordManager.generateKey(password_bytes, self.salt, self.key_size)

        if(self.state == self.State.EMPTY):
            self.passwords = {}
        else:
            passwords_ciphertext = self.getPrivateData()
            self.passwords = self.decryptPasswords(passwords_ciphertext, key)

        #store new password
        try:
            self.passwords[adress]
            password_changed = True
        except KeyError as e:
            password_changed = False
        self.passwords[adress] = new_password   
        if(self.state == self.State.EMPTY):
            self.state = self.State.NOT_EMPTY
            self.storeState()

        #generate new iv and salt
        self.generatePublicData()

        key = self.generateKey(password_bytes, self.salt, self.key_size)
        cipher = AES.new(key, AES.MODE_GCM, self.iv)

        passwords_ciphertext, tag = cipher.encrypt_and_digest(json.dumps(self.passwords).encode("utf-8"))

        self.tag = tag
        self.storePublicData()
        self.storePrivateData(passwords_ciphertext)

        if(password_changed):
            utilities.ConsoleMessages.passwordChanged(adress)
        else:
            utilities.ConsoleMessages.passwordStored(adress)


    def getPassword(self, password: str, adress: str):
        """Decrypt passwords, get password, encrypt again"""
        if(self.state == self.State.UNINITIALIZED):
            utilities.ConsoleMessages.passwordManagerUninitialized()
            exit(1)

        password_bytes = password.encode("utf-8")
        self.authenticate(password_bytes)
        
        if(self.state == self.State.EMPTY):
            utilities.ConsoleMessages.passwordManagerEmpty()
            exit(1)

        key = PasswordManager.generateKey(password_bytes, self.salt, self.key_size)
        passwords_ciphertext = self.getPrivateData()
        self.passwords = self.decryptPasswords(passwords_ciphertext, key)

        try:
            requested_password = self.passwords[adress]
        except KeyError as e:
            utilities.ConsoleMessages.noPasswordForAdress(adress)
            exit(1)

        utilities.ConsoleMessages.passwordForAdress(requested_password, adress)


    def decryptPasswords(self, passwords_ciphertext, key):
        """Decrypt passwords ciphertext"""
        cipher = AES.new(key, AES.MODE_GCM, self.iv)
        try:
            passwords_plaintext = cipher.decrypt_and_verify(passwords_ciphertext, self.tag)
        except ValueError as e:
            utilities.ConsoleMessages.wrongPassword()
            exit(1)
        return json.loads(passwords_plaintext.decode("utf-8"))


    @staticmethod
    def generateKey(password: bytes, salt: bytes, size: int = 512/8, iterations=100000) -> bytes:
        """Generate key using PBKDF2"""
        key=PBKDF2(password, salt, size, iterations)
        return key


    @staticmethod
    def generateSalt(size: int = 16) -> bytes:
        """Generate "size" random bytes"""
        return get_random_bytes(size)