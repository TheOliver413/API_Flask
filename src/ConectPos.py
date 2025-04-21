import psycopg2

try:
    # connection=psycopg2.connect(
    #     host='localhost',
    #     user='postgres',
    #     password='admin',
    #     database='PhishGuard'
    # )
    
    connection=psycopg2.connect(
        host='ep-wild-term-a2zxk9ae.eu-central-1.aws.neon.tech',
        user='neondb_owner',
        password='npg_brlfMLFIC9o0',
        database='neondb'
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