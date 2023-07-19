import config
import mysql.connector

## Database
def connect():
    return mysql.connector.connect(user=config.MYSQL_USER,
                                   password=config.MYSQL_PASSWD,
                                   database=config.MYSQL_DATABASE,
                                   host=config.MYSQL_HOST)
