from framework.interface import server


def banner():
    print("""\033[92m
 _                          
| |__   ___  _ __ _   _ ___ 
| '_ \ / _ \| '__| | | / __|
| | | | (_) | |  | |_| \__ \
|_| |_|\___/|_|   \__,_|___/
                            


    \033[0m""")

def start_interface_server():
    print("starting the server...")
    server.main()


if __name__ == "__main__":
    banner()
    start_interface_server()
