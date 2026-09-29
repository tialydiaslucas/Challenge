import argparse
import signal
import threading

from dotenv import load_dotenv

load_dotenv()

from app import db, stats  # noqa: E402
from app.capture import run_capture  # noqa: E402


def build_parser():
    parser = argparse.ArgumentParser(description="Analisador de trafego de rede")
    sub = parser.add_subparsers(dest="command", required=True)

    cap = sub.add_parser("capture", help="Captura pacotes e grava no banco")
    cap.add_argument("-i", "--interface", required=True, help="Interface de rede (ex.: eth0)")
    cap.add_argument("-c", "--count", type=int, default=0, help="Parar apos N pacotes")
    cap.add_argument("-t", "--duration", type=int, default=0, help="Parar apos N segundos")
    cap.add_argument("-b", "--batch-size", type=int, default=100, help="Pacotes por INSERT em lote")

    st = sub.add_parser("stats", help="Exibe estatisticas de uma sessao")
    st.add_argument("-s", "--session", type=int, help="ID da sessao (padrao: a mais recente)")
    return parser


def main():
    args = build_parser().parse_args()
    conn = db.get_connection()

    try:
        if args.command == "capture":
            stop_event = threading.Event()
            signal.signal(signal.SIGINT, lambda *_: stop_event.set())
            signal.signal(signal.SIGTERM, lambda *_: stop_event.set())

            db.mark_stale_sessions(conn)
            print(f"Capturando em {args.interface}... (Ctrl+C para parar)")
            session_id = run_capture(
                conn,
                args.interface,
                args.batch_size,
                args.duration,
                args.count,
                stop_event,
            )
            stats.print_stats(conn, session_id)
        else:
            session_id = args.session or stats.latest_session_id(conn)
            if session_id is None:
                print("Nenhuma sessao encontrada.")
                return
            stats.print_stats(conn, session_id)
    finally:
        conn.close()


if __name__ == "__main__":
    main()