import os
import time

import mysql.connector


def get_connection(retries=10, delay=3):
    last_error = None
    for _ in range(retries):
        try:
            return mysql.connector.connect(
                host=os.getenv("MYSQL_HOST", "127.0.0.1"),
                port=int(os.getenv("MYSQL_PORT", "3306")),
                user=os.getenv("MYSQL_USER", "root"),
                password=os.getenv("MYSQL_PASSWORD", ""),
                database=os.getenv("MYSQL_DATABASE", "network_monitor"),
                charset="utf8mb4",
                autocommit=False,
            )
        except mysql.connector.Error as error:
            last_error = error
            time.sleep(delay)
    raise last_error


def mark_stale_sessions(conn):
    with conn.cursor() as cur:
        cur.execute(
            "UPDATE capture_sessions "
            "SET status = 'interrupted', ended_at = NOW(6) "
            "WHERE status = 'running'"
        )
    conn.commit()


def start_session(conn, interface_name):
    with conn.cursor() as cur:
        cur.execute(
            "INSERT INTO capture_sessions (interface_name) VALUES (%s)",
            (interface_name,),
        )
        session_id = cur.lastrowid
    conn.commit()
    return session_id


def insert_packets(conn, session_id, rows):
    sql = (
        "INSERT INTO packets "
        "(session_id, source_ip, destination_ip, protocol, size_bytes, "
        "source_port, destination_port, captured_at) "
        "VALUES (%s, %s, %s, %s, %s, %s, %s, %s)"
    )
    data = [(session_id, *row) for row in rows]
    with conn.cursor() as cur:
        cur.executemany(sql, data)
    conn.commit()


def finish_session(conn, session_id, status):
    with conn.cursor() as cur:
        cur.execute(
            "UPDATE capture_sessions SET status = %s, ended_at = NOW(6), "
            "packets_captured = (SELECT COUNT(*) FROM packets WHERE session_id = %s) "
            "WHERE id = %s",
            (status, session_id, session_id),
        )
    conn.commit()