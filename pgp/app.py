import tkinter as tk
from faker import Faker
from typing import List, Dict

from .server import Client, Server, ServerEvent


class App:
    def __init__(self):
        self.username = Faker().user_name()

        # init clients
        self.clients: Dict[Client, List[str]] = {}
        self.selected_client: Client | None = None

        # run server
        self.server = Server()
        self.server.subscribe(ServerEvent.CONNECT, self._on_connect)
        self.server.subscribe(ServerEvent.DISCONNECT, self._on_disconnect)
        self.server.subscribe(ServerEvent.MESSAGE, self._on_message)

        # create GUI
        self._init_gui()

    def _init_gui(self):
        # create main window
        self.root = tk.Tk()
        self.root.title("PGP Chat")

        self.root.grid_columnconfigure(1, weight=1)
        self.root.grid_rowconfigure(0, weight=1)

        # LEFT PANEL
        left_panel = tk.Frame(self.root, bg="lightgray")
        left_panel.grid(row=0, column=0, sticky="ns")

        # clients list
        client_list_label = tk.Label(left_panel, text="Clients", bg="lightgray")
        client_list_label.pack(pady=5)
        self.client_list = tk.Listbox(left_panel)
        self.client_list.pack(fill=tk.BOTH, expand=True, padx=5, pady=5)
        self.client_list.bind("<Double-1>", self._gui_on_client_select)

        # username
        username = tk.StringVar(value=self.username)
        username.trace_add("write", lambda *args: self._gui_on_username_change(username, *args))
        username_label = tk.Label(left_panel, text="My Username:", bg="lightgray")
        username_label.pack(pady=(10, 0))
        self.username_entry = tk.Entry(left_panel, textvariable=username, justify="center")
        self.username_entry.pack(pady=(0, 10), padx=5)

        # CENTRAL PANEL
        central_panel = tk.Frame(self.root, bg="white")
        central_panel.grid(row=0, column=1, sticky="nsew", padx=5, pady=5)

        # chat
        self.chat = tk.Text(central_panel, wrap=tk.WORD, state=tk.NORMAL, bg="white")
        self.chat.config(state=tk.DISABLED)
        self.chat.pack(fill=tk.BOTH, expand=True)

        # message input
        self.message_input = tk.Entry(central_panel)
        self.message_input.bind("<Return>", lambda _: self._gui_on_message_send())
        self.message_input.config(state=tk.DISABLED)
        self.message_input.pack(side=tk.LEFT, fill=tk.X, expand=True, padx=5, pady=5)

        # send button
        self.send_button = tk.Button(central_panel, text="Send", command=self._gui_on_message_send)
        self.send_button.config(state=tk.DISABLED)
        self.send_button.pack(side=tk.LEFT, padx=5, pady=5)

        # RIGHT PANEL
        right_panel = tk.Frame(self.root, bg="lightgray")
        right_panel.grid(row=0, column=2, sticky="ns")

        # my port
        my_port_label = tk.Label(right_panel, text=f"My Port: {self.server.port}", bg="lightgray")
        my_port_label.pack(pady=5)

        # port input
        port_label = tk.Label(right_panel, text="Port", bg="lightgray")
        port_label.pack(pady=5)
        self.port_input = tk.Entry(right_panel)
        self.port_input.bind("<Return>", lambda _: self._gui_connect_to_client())
        self.port_input.pack(padx=5, pady=5)

        # connect button
        connect_button = tk.Button(right_panel, text="Connect", command=self._gui_connect_to_client)
        connect_button.pack(pady=5)

        # update idle tasks and resize to fit contents
        self.root.update_idletasks()
        self.root.geometry("")

    def _gui_on_username_change(self, var, *args):
        self.username = var.get()

    def _gui_on_message_send(self):
        message = self.message_input.get().strip()
        if not message:
            return

        # send message
        self.server.send(self.selected_client, message)

        # add message
        self.clients[self.selected_client].append(f"You: {message}")

        # clear message input
        self.message_input.delete(0, tk.END)

        # update chat
        self._gui_update_chat()

    def _gui_update_client_list(self):
        self.client_list.delete(0, tk.END)
        for client in self.clients:
            self.client_list.insert(tk.END, client.username)

    def _gui_connect_to_client(self):
        port = self.port_input.get().strip()
        if not port:
            return

        # clear input
        self.port_input.delete(0, tk.END)

        # connect to client
        self.server.connect("localhost", int(port))

    def _gui_on_client_select(self, _):
        # get selected client
        selected_idx = self.client_list.curselection()[0]
        self.selected_client = list(self.clients.keys())[selected_idx]

        # enable message input & send button
        self.message_input.config(state=tk.NORMAL)
        self.send_button.config(state=tk.NORMAL)

        # update chat
        self._gui_update_chat()

    def _gui_update_chat(self):
        # enable chat
        self.chat.config(state=tk.NORMAL)

        # clear chat
        self.chat.delete("1.0", tk.END)

        # skip if no client is selected
        if not self.selected_client:
            # disable chat
            self.chat.config(state=tk.DISABLED)
            return

        # get messages
        messages = self.clients[self.selected_client]

        # populate chat
        for message in messages:
            self.chat.insert(tk.END, f"{message}\n")

        # disable chat
        self.chat.config(state=tk.DISABLED)

    def run(self):
            self.server.run()
            self.root.mainloop()

    def _on_connect(self, client: Client, _):
        # send my username & public key
        self.server.send(client, self.username)

        # receive their username & public key
        client.username = self.server.recv(client)

        self.clients[client] = []
        self._gui_update_client_list()

    def _on_disconnect(self, client: Client, _):
        # check if the disconnected client is the selected one
        if client == self.selected_client:
            # deselect client
            self.selected_client = None

            # disable message input & send button
            self.message_input.config(state=tk.DISABLED)
            self.send_button.config(state=tk.DISABLED)

            # update chat
            self._gui_update_chat()

        self.clients.pop(client, None)
        self._gui_update_client_list()

    def _on_message(self, client: Client, data: str):
        # add message
        self.clients[client].append(f"{client.username}: {data}")

        # update chat
        self._gui_update_chat()
