def latest_session_id(conn):
    with conn.cursor() as cur:
        cur.execute("SELECT id FROM capture_sessions ORDER BY id DESC LIMIT 1")
        row = cur.fetchone()
    return row[0] if row else None


def _top_ips(conn, session_id, column):
    with conn.cursor() as cur:
        cur.execute(
            f"SELECT {column}, COUNT(*) AS total_packets, SUM(size_bytes) AS total_bytes "
            "FROM packets WHERE session_id = %s "
            f"GROUP BY {column} ORDER BY total_packets DESC LIMIT 5",
            (session_id,),
        )
        return cur.fetchall()


def print_stats(conn, session_id):
    with conn.cursor() as cur:
        cur.execute(
            "SELECT interface_name, started_at, ended_at, status "
            "FROM capture_sessions WHERE id = %s",
            (session_id,),
        )
        session = cur.fetchone()
        if session is None:
            print(f"Sessao {session_id} nao encontrada.")
            return

        cur.execute("SELECT COUNT(*) FROM packets WHERE session_id = %s", (session_id,))
        total = cur.fetchone()[0]

        cur.execute(
            "SELECT protocol, COUNT(*) AS total_packets FROM packets "
            "WHERE session_id = %s GROUP BY protocol ORDER BY total_packets DESC",
            (session_id,),
        )
        by_protocol = cur.fetchall()

    print(f"\n=== Sessao {session_id} | interface: {session[0]} | status: {session[3]} ===")
    print(f"Inicio: {session[1]} | Fim: {session[2]}")
    print(f"\nTotal de pacotes capturados: {total}")

    print("\nPacotes por protocolo:")
    for protocol, count in by_protocol:
        print(f"  {protocol:<10} {count}")

    print("\nTop 5 IPs de origem:")
    for ip, count, size in _top_ips(conn, session_id, "source_ip"):
        print(f"  {ip:<40} {count} pacotes | {size} bytes")

    print("\nTop 5 IPs de destino:")
    for ip, count, size in _top_ips(conn, session_id, "destination_ip"):
        print(f"  {ip:<40} {count} pacotes | {size} bytes")
    print()