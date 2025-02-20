import mysql.connector
import os
from datetime import datetime, timedelta
import jwt

# MySQL Configuration
DB_CONFIG = {
    'host': 'localhost',
    'user': 'root',
    'password': 'kali',
    'database': 'network_scanner'
}
