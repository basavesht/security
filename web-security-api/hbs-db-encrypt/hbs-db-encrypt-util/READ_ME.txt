


Encryption Utility - This utility is to provide capability to the user to encyrpt sensitive information like apsswords using 
JASYPT Utility api. The output needs to be then copied to the corresponding property file. 
Currently this utility is used to encrypt database passwords.

1. Install hbs-db-encrypt-util.
2. Execute ./encrypt.sh 
3. Enter database password
4. Copy the encrypted value into the required database properties files. Remember to enclose the encrypted password with ENC().
5. Restart the app.