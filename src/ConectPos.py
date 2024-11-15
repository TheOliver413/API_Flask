import psycopg2

try:
    connection=psycopg2.connect(
        host='localhost',
        user='postgres',
        password='admin',
        database='PhishGuard'
    )

    print("Ok")
    cursor=connection.cursor()
    cursor.execute("SELECT version()")
    row=cursor.fetchone()
    print(row)
    cursor.execute("SELECT * FROM USUARIOS")
    rows=cursor.fetchall()
    for row in rows:
        print(row)
except Exception as ex:
    print(ex)
finally:
    connection.close()
    print("Good Bye!")