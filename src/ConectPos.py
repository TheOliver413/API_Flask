import psycopg2

try:
    # connection=psycopg2.connect(
    #     host='localhost',
    #     user='postgres',
    #     password='admin',
    #     database='PhishGuard'
    # )
    
    connection=psycopg2.connect(
        host='dpg-cvdngmrv2p9s7393egmg-a.oregon-postgres.render.com',
        user='phishguard_mb4u_user',
        password='RmLenVgjCG0tgzL1iKAh61AYGq2lw1zv',
        database='phishguard_mb4u'
    )

    print("Ok")
    cursor=connection.cursor()
    cursor.execute("SELECT version()")
    row=cursor.fetchone()
    print(row)
    cursor.execute("SELECT * FROM USERS")
    rows=cursor.fetchall()
    for row in rows:
        print(row)
except Exception as ex:
    print(ex)
finally:
    connection.close()
    print("Good Bye!")