class ConsoleMessages:
    def wrongPassword():
        print("Wrong password entered or Password Manager has been tampered.")

    def passwordManagerEmpty():
        print("Password manager is empty.\nStore password with: ./pwd_manager put [PASSWORD] [ADRESS] [NEW_PASSWORD]")

    def passwordManagerUninitialized():
        print("Password manager uninitialized.\nInitialize password manager with: ./pwd_manager init [PASSWORD]")

    def noPasswordForAdress(adress):
        print(f"There is no password stored for adress: {adress}")

    def passwordForAdress(password, adress):
        print(f"Password for adress: {adress}\n{password}")

    def passwordManagerInitializing():
        print("Initializing new environment")

    def passwordChanged(adress):
        print(f"Password changed for {adress}")

    def passwordStored(adress):
        print(f"Stored password for: {adress}")
        