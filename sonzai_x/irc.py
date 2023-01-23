import logging

import miniircd
from miniircd import Client as BaseClient
from miniircd import Server as BaseServer
from miniircd import irc_lower

log = logging.getLogger(__name__)


class Server(BaseServer):
    ipv6 = False
    chroot = False
    setuid = False
    cloak = False
    log_file = None
    ssl_key_file = None
    password = None
    motdfile = None
    state_dir = None
    channel_log_dir = None

    def __init__(
        self,
        address,
        ports,
        debug=False,
        verbose=False,
        logger=None,
        name=b"localhost",
        network_name=b"localhost",
    ):
        self.address = address
        self.ports = ports
        self.debug = debug
        self.verbose = verbose
        self.logger = logger
        self.name = name
        self.network_name = network_name

        self.channels = {}
        self.clients = {}
        self.nicknames = {}

    def remove_channel(self, channel, internal=False):
        if not internal:
            return
        super().remove_channel(channel)


class Client(BaseClient):
    def __command_handler(self, command, arguments):
        # We can only join already created channels (i.e. those created by the server)
        if command == b"JOIN":
            channel_names = arguments[0].split(b",")
            for channel_name in channel_names:
                if irc_lower(channel_name) not in self.server.channels:
                    self.reply(b"405 %s %s :You cannot join channels" % (self.nickname, channel_name))
                    self.socket_writable_notification()

                # Otherwise ignore, for they should have been force joined
            return

        elif command == b"PRIVMSG":
            target, message = arguments
            # TODO: Send message to Slack
            self.reply(b"404 %s %s :Cannot send to channel" % (self.nickname, target))
            self.socket_writable_notification()
            return

        elif command == b"TOPIC":
            self.reply(b"482 %s %s :Cannot change topic" % (self.nickname, target))
            self.socket_writable_notification()
            return

        elif command == b"PART":
            # Thou shalt not leave!
            channel_names = arguments[0].split(b",")
            for channel_name in channel_names:
                normalized_name = irc_lower(channel_name)
                self.broadcast_join(self.channels[normalized_name])
                self.reply(b"443 %s %s :Cannot leave the channel" % (self.nickname, channel_name))
                self.socket_writable_notification()
            return

        super().__command_handler(command, arguments)

    def broadcast_join(self, channel):
        name = irc_lower(channel.name)
        self.message_channel(channel, b"JOIN", channel.name, True)
        self.channel_log(channel, b"joined", meta=True)

        if channel.topic:
            self.reply(b"332 %s %s :%s" % (self.nickname, channel.name, channel.topic))

        names_prefix = b"353 %s = %s :" % (self.nickname, name)
        names = b""
        # Max length: reply prefix ":server_name(space)" plus CRLF in
        # the end.
        names_max_len = 512 - (len(self.server.name) + 2 + 2)
        for name in sorted(x.nickname for x in channel.members):
            if not names:
                names = names_prefix + name
            # Using >= to include the space between "names" and "name".
            elif len(names) + len(name) >= names_max_len:
                self.reply(names)
                names = names_prefix + name
            else:
                names += b" " + name
        if names:
            self.reply(names)

        self.socket_writable_notification()

    def send_lusers(self):
        # Get this RPL_ISUPPORT in before lusers
        self.reply(b"005 %s CASEMAPPING=rfc1459 NETWORK=%s :are supported by this server" % (self.nickname, self.server.network_name))
        super().send_lusers()

    def send_motd(self):
        super().send_motd()

        # Client joined, force join to channels
        log.info(f"Force joining {self.prefix}")

        for name, channel in self.server.channels.items():
            log.info(f"Force joining {self.prefix} to {name}")
            self.force_join(channel)

    def force_join(self, channel):
        channel.add_member(self)
        self.channels[irc_lower(channel.name)] = channel
        self.broadcast_join(channel)

    def force_part(self, channel, message="Bye"):
        kick_message = b":%s KICK %s %s :%s" % (
            self.server.name,
            channel.name,
            self.prefix,
            message.encode("utf-8"),
        )

        for client in channel.members:
            client.message(kick_message)

        self.message_channel(
            channel,
            b"PART",
            b"%s :%s" % (channel.name, message.encode("utf-8")),
            True,
        )
        self.channel_log(channel, b"left", meta=True)

        channel.remove_client(self)
        del self.channels[irc_lower(channel.name)]


# Naughty
miniircd.Client = Client
