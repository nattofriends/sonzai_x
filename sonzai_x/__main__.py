import json
import logging
import re
from argparse import ArgumentParser
from concurrent.futures import ThreadPoolExecutor
from difflib import SequenceMatcher
from functools import partial
from html import unescape
from operator import itemgetter
from threading import Event
from threading import Thread

import sentry_sdk
from emoji import emojize
from sentry_sdk.integrations.threading import ThreadingIntegration
from slack_sdk import WebClient
from slack_sdk.errors import SlackApiError
from slack_sdk.http_retry.builtin_handlers import RateLimitErrorRetryHandler
from slack_sdk.rtm_v2 import RTMClient
from yaml import safe_load

from sonzai_x.irc import Server
from sonzai_x.key_view import KeyViewList

NO_FALLBACK_TEXT_MESSAGE = "This content can't be displayed."
# Not all punctuation is allowed before or after formatting
VALID_FORMATTING_SURROUNDINGS = r"[\x20-\x23\x25-\x2f\x3a\x3b\x3d\x3f\x40\x5b\x5c\x5d\x5f\x7b\x7d]"

log = logging.getLogger("sonzai_x")


def main():
    logging.basicConfig(
        format="[%(asctime)s] [%(levelname)s] [(%(threadName)s)%(name)s:%(funcName)s] %(message)s",
        level=logging.INFO,
    )

    parser = ArgumentParser(description="Limited bridge for exposing Slack via IRC")
    parser.add_argument("--config-file", default="config.yaml")

    args = parser.parse_args()

    SonzaiX(config_file=args.config_file)


class SonzaiX:
    def __init__(self, config_file):
        with open(config_file) as fh:
            self.config = safe_load(fh)

        if self.config["sentry"]["enabled"]:
            sentry_sdk.init(
                dsn=self.config["sentry"]["dsn"],
                ignore_errors=[KeyboardInterrupt],
                integrations=[
                    ThreadingIntegration(propagate_hub=True),
                ],
            )

        # We'll see how well using their own library for user impersonation works
        self.slack_web = WebClient(token=self.config["slack"]["user_token"])
        self.slack_web.headers["User-Agent"] = ""

        if self.config["slack"]["user_token"].startswith("xoxc"):
            log.info("Also using cookie token for Slack requests")
            self.slack_web.headers["Cookie"] = f"d={self.config['slack']['cookie_token']}"

        self.slack_web.retry_handlers.append(RateLimitErrorRetryHandler(max_retry_count=3))

        self.slack_rtm = RTMClient(
            web_client=self.slack_web,
            ping_interval=3,  # XXX: Should really find out why we keep getting disconnections
        )
        # I'm not a bot, I swear!
        self.slack_rtm.bot_id = ""

        self.slack_rtm.on("message")(partial(self.on_message.__func__, self))
        self.slack_rtm.on("channel_joined")(partial(self.on_channel_join.__func__, self))
        self.slack_rtm.on("channel_left")(partial(self.on_channel_leave.__func__, self))
        self.slack_rtm.on("channel_rename")(partial(self.on_channel_rename.__func__, self))
        self.slack_rtm.on("group_joined")(partial(self.on_channel_join.__func__, self))
        self.slack_rtm.on("group_left")(partial(self.on_channel_leave.__func__, self))
        self.slack_rtm.on("group_rename")(partial(self.on_channel_rename.__func__, self))
        self.slack_rtm.on("group_open")(partial(self.on_group_open.__func__, self))
        self.slack_rtm.on("group_close")(partial(self.on_group_close.__func__, self))
        self.slack_rtm.on("team_join")(partial(self.on_user_add.__func__, self))
        self.slack_rtm.on("user_change")(partial(self.on_user_update.__func__, self))
        self.slack_rtm.on("subteam_created")(partial(self.on_usergroup_add.__func__, self))
        self.slack_rtm.on("subteam_updated")(partial(self.on_usergroup_update.__func__, self))

        with ThreadPoolExecutor(max_workers=4) as executor:
            executor.submit(self.load_slack_users)
            executor.submit(self.load_slack_conversations)
            executor.submit(self.load_slack_usergroups)

        self.identity = self.slack_web.auth_test()

        self.irc = Server(
            name=b"localhost",
            network_name=b"SonzaiX",
            address=self.config["irc"]["address"],
            ports=[self.config["irc"]["port"]],
            verbose=self.config["irc"]["verbose"],
            debug=self.config["irc"]["debug"],
        )

        for channel in sorted(
            [channel for channel in self.conversations if channel["is_member"] and channel.get("is_open") is not False],
            key=itemgetter("name"),
        ):
            self.create_channel(channel)

        log.info("Starting Slack client")
        self.slack_rtm.connect()
        log.info("Starting IRC server")
        Thread(target=self.irc.start, name="irc", daemon=True).start()
        Event().wait()

    def load_slack_users(self):
        log.info("Getting Slack users")
        users = []
        for i, resp in enumerate(
            self.slack_web.users_list(
                limit=1000,
            )
        ):
            log.info(f"{i}: Got {len(resp['members'])} users")
            users.extend(resp["members"])

        self.users = KeyViewList(users)
        self.users_by_id = self.users.register_itemgetter("id")

    def load_slack_conversations(self):
        log.info("Getting Slack conversations")
        conversations = []
        for i, resp in enumerate(
            self.slack_web.conversations_list(
                limit=1000,
                exclude_archived=True,
                types="public_channel, private_channel, mpim",
            )
        ):
            log.info(f"{i}: Got {len(resp['channels'])} conversations")
            conversations.extend(resp["channels"])

        self.conversations = KeyViewList(conversations)
        self.conversations_by_id = self.conversations.register_itemgetter("id")

    def load_slack_usergroups(self):
        log.info("Getting Slack usergroups")
        usergroups = []
        for i, resp in enumerate(self.slack_web.usergroups_list()):
            log.info(f"{i}: Got {len(resp['usergroups'])} usergroups")
            usergroups.extend(resp["usergroups"])

        self.usergroups = KeyViewList(usergroups)
        self.usergroups_by_id = self.usergroups.register_itemgetter("id")

    def get_user_by_id(self, user_id):
        user = self.users_by_id.get(user_id)

        if not user:
            log.info(f"Going to Slack to fetch info for {user_id}")
            try:
                user = self.slack_web.users_info(user=user_id)["user"]
            except SlackApiError as e:
                if e.response["error"] == "user_not_found":
                    return
                raise

            self.users.append(user)

        return user

    def get_conversation_by_id(self, conversation_id):
        conversation = self.conversations_by_id.get(conversation_id)

        if not conversation:
            log.info(f"Going to Slack to fetch info for {conversation_id}")
            conversation = self.slack_web.conversations_info(
                channel=conversation_id,
                include_num_members=False,
            )["channel"]

            if not conversation["is_im"]:
                self.conversations.append(conversation)

        return conversation

    def get_usergroup_by_id(self, usergroup_id):
        usergroup = self.usergroups_by_id.get(usergroup_id)

        if not usergroup:
            log.info(f"Going to Slack to fetch info for {usergroup_id}")
            # There is no usergroup.info
            self.load_slack_usergroups()
            # If it isn't here now, it really isn't here
            return self.usergroups_by_id.get(usergroup_id)

        return usergroup

    def on_channel_join(self, client, payload):
        log.info(f"Received Slack join event: {payload}")

        # Well, we'll take the updated information, thanks
        channel = self.conversations_by_id.get(payload["channel"]["id"])
        channel.update(payload["channel"])

        irc_channel = self.create_channel(channel)

        log.info(f'{payload["channel"]} = {channel["name"]} = {irc_channel}')

        for client in self.irc.nicknames.values():
            log.info(f'Force joining {client} to {channel["name"]}')
            client.force_join(irc_channel)

    def on_channel_leave(self, client, payload):
        log.info(f"Received Slack leave event: {payload}")

        channel = self.get_conversation_by_id.get(payload["channel"])
        irc_channel = self.irc.get_channel(f'#{channel["name"]}'.encode("utf-8"))

        log.info(f'{payload["channel"]} = {channel["name"]} = {irc_channel}')

        # All clients should be in all channels, but...
        for client in irc_channel.members.copy():
            log.info(f'Force parting {client} from {channel["name"]}')
            client.force_part(
                irc_channel,
                message="This channel was parted in Slack",
            )

        self.irc.remove_channel(irc_channel, internal=True)

    def on_channel_rename(self, client, payload):
        log.info(f"Received Slack rename event: {payload}")

        channel = self.get_conversation_by_id(payload["channel"]["id"])
        old_name = channel["name"]
        channel.update(payload["channel"])

        irc_channel = self.irc.get_channel(f"#{old_name}".encode("utf-8"))

        log.info(f'{payload["channel"]} = {channel["name"]} = {irc_channel}')

        # All clients should be in all channels, but...
        for client in irc_channel.members.copy():
            log.info(f'Force parting {client} from {channel["name"]}')
            client.force_part(
                irc_channel,
                message=f"This channel was renamed to #{channel['name']}",
            )

        self.irc.remove_channel(irc_channel, internal=True)

        irc_channel = self.create_channel(channel)

        log.info(f'{payload["channel"]} = {channel["name"]} = {irc_channel}')

        for client in self.irc.nicknames.values():
            log.info(f'Force joining {client} to {channel["name"]}')
            client.force_join(irc_channel)

    def on_group_open(self, client, payload):
        log.info(f"Received Slack group open event: {payload}")
        return

    def on_group_close(self, client, payload):
        log.info(f"Received Slack group closed event: {payload}")
        return

    def on_user_add(self, client, payload):
        log.info("Received Slack user add event")
        self.users.append(payload["user"])

    def on_user_update(self, client, payload):
        log.info("Received Slack user update event")
        if payload["user"]["team_id"] != self.identity["team_id"]:
            # Don't really care to store all this info
            return

        self.get_user_by_id(payload["user"]["id"]).update(payload["user"])

    def on_usergroup_add(self, client, payload):
        log.info("Received Slack usergroup add event")
        self.usergroups.append(payload["subteam"])

    def on_usergroup_update(self, client, payload):
        log.info("Received Slack usergroup update event")
        self.get_usergroup_by_id(payload["subteam"]["id"]).update(payload["subteam"])

    def on_message(self, client, payload):
        log.info(
            f'Received Slack message: channel={payload["channel"]}, ' f'ts={payload["ts"]}, subtype={payload.get("subtype")}',
        )
        log.debug(json.dumps(payload, indent=2))
        subtype = payload.get("subtype")

        if subtype not in (
            None,
            "bot_message",
            "message_changed",
            "me_message",
            "channel_topic",
        ):
            log.info(f'Not handling subtype {payload.get("subtype")} right now')
            return

        if subtype == "message_changed":
            previous_message = payload["previous_message"]
            # XXX: Could be that text is same but blocks or attachments differ (unlikely) - this will not catch that
            if payload["message"]["text"] == previous_message["text"]:
                log.info("Skipping because text is the same")
                return

            channel = payload["channel"]
            payload = payload["message"]
            payload["channel"] = channel
            payload["previous_message"] = previous_message
        elif subtype == "me_message":
            payload["text"] = f'\x01ACTION {payload["text"]}\x01'

        channel = self.get_conversation_by_id(payload["channel"])

        if channel["is_im"]:
            user = self.get_user_by_id(channel["user"])
            channel_name = user["profile"]["display_name"] or user["name"]

            if payload.get("user") == self.identity["user_id"]:
                # Message from us, pretend it's from them
                payload["text"] = f"[{self.identity['user']}] {payload['text']}"
                payload["user"] = channel["user"]
        else:
            # No-op if already exists
            self.create_channel(channel)
            channel_name = f'#{channel["name"]}'

        log.info(f'Target is {payload["channel"]} = {channel_name}')

        user = self.get_user_by_id(payload["user"]) if "user" in payload else None
        username = user["profile"]["display_name"] or user["name"] if user else payload.get("username") or payload["bot_profile"]["name"]
        log.info(f"Using `{username}` as author")

        if subtype == "channel_topic":
            topic = self.format_topic(payload["topic"])
            self.send_topic(username, channel_name, topic)

        else:
            message = self.render_message(payload, subtype=subtype)
            messages = message.split("\n")

            for message in messages:
                self.send_privmsg(username, channel_name, message)

            if "files" in payload:
                log.info("Generating additional messages for uploaded files")
                prefix = "@" if self.config["formatting"]["prepend_at_to_names"] else ""
                for file in payload["files"]:
                    message = f'{prefix}{username} shared a file: {file["name"]} {file["url_private"]}'
                    self.send_privmsg(username, channel_name, message)

    def create_channel(self, slack_channel):
        irc_channel = self.irc.get_channel(f'#{slack_channel["name"]}'.encode("utf-8"))
        irc_channel.topic = self.format_topic(slack_channel["topic"]["value"]).encode("utf-8")

        return irc_channel

    def send_topic(self, username, target, topic):
        log.info(f"Sending topic from {username} to {target}")
        username = username.replace(" ", "\xa0")

        irc_message = f":{username} TOPIC {target} :{topic}".encode("utf-8")
        irc_channel = self.irc.channels.get(target.encode("utf-8"))
        irc_channel.topic = topic.encode("utf-8")

        for client in irc_channel.members:
            client.message(irc_message)
            client.socket_writable_notification()

    def send_privmsg(self, username, target, message):
        log.info(f"Sending privmsg from {username} to {target}")
        is_channel = target.startswith("#")
        username = username.replace(" ", "\xa0")

        if is_channel:
            irc_message = f":{username} PRIVMSG {target} :{message}".encode("utf-8")
            irc_channel = self.irc.channels.get(target.encode("utf-8"))
            for client in irc_channel.members:
                client.message(irc_message)
                client.socket_writable_notification()
        else:
            # Send all PMs to everyone!
            for nick, client in self.irc.nicknames.items():
                irc_message = f':{username} PRIVMSG {nick.decode("utf-8")} :{message}'.encode("utf-8")
                client.message(irc_message)
                client.socket_writable_notification()

    def render_message(self, payload, subtype=None):
        """
        Take a message payload and return text for IRC, taking into account blocks and attachments.
        `format_message` only formats Slack formatting in message text (a string)
        """

        if payload["text"] == NO_FALLBACK_TEXT_MESSAGE and self.config["formatting"]["attempt_fallback_rendering"]:
            # Could just be some smartass writing the message manually, or blocks we don't know
            # how to render yet
            rendered_blocks = self.render_blocks(payload["blocks"])
            if rendered_blocks != "":
                log.info("Using rendered blocks instead of fallback text")
                message = rendered_blocks
        else:
            message = payload["text"]

        if "attachments" in payload and self.config["formatting"]["render_attachments"]:
            for attachment in payload["attachments"]:
                if "fallback" in attachment or "text" in attachment:
                    message += f"\n{attachment['fallback'] or attachment['text']}"

        message = self.format_message(message)

        if subtype == "message_changed":
            message = self.format_message_edit(
                self.render_message(payload["previous_message"]),
                message,
            )

        return message

    def render_blocks(self, blocks):
        log.info(f"Attempting to render blocks: {blocks}")

        result = []

        for block in blocks:
            # XXX: Don't know how to render blocks of type `rich_text`, which have `elements`
            if "text" in block:
                result.append(block["text"]["text"])

        return "\n".join(result)

    def format_message_edit(self, previous_text, current_text) -> str:
        if not self.config["formatting"]["edit_diffs"]:
            return f"E: {current_text}"

        matcher = SequenceMatcher(a=previous_text, b=current_text)

        if matcher.ratio() < self.config["formatting"]["edit_diff_min_ratio"]:
            return f"E: {current_text}"

        diffed_line = "E: "
        for tag, a_m, a_n, b_m, b_n in matcher.get_opcodes():
            # Deletions are not going to play well with strikethrough spans from markdown
            # but we'll cross that bridge when we get there
            if tag == "equal":
                diffed_line += previous_text[a_m:a_n]
            elif tag == "replace":
                diffed_line += f"\x1e{previous_text[a_m:a_n]}\x1e<{current_text[b_m:b_n]}>"
            elif tag == "insert":
                diffed_line += f"<{current_text[b_m:b_n]}>"
            elif tag == "delete":
                diffed_line += f"\x1e{previous_text[a_m:a_n]}\x1e"

        return diffed_line

    def format_message(self, message):
        # https://api.slack.com/reference/surfaces/formatting

        message = message.strip("\r\n")
        # While double newlines form nice paragraph breaks in Slack, they are kind of useless in IRC
        message = re.sub(r"\n{2,}", "\n", message)
        message = unescape(message)
        message = emojize(message, language="alias")

        message = re.sub(r"<(?![@#!])(?P<link>[^>]+)>", link_replace, message)
        message = re.sub(r"<@(?P<user>[A-Za-z0-9]+)(\|(?P<alias>[^>]*))?>", self.user_replace, message)
        message = re.sub(r"<#(?P<channel>[A-Za-z0-9]+)(\|(?P<alias>[^>]*))?>", self.channel_replace, message)
        # @here, @channel, @everyone, @usergroups
        message = re.sub(r"<!(?P<special>[a-z0-9-_.]+)(\^(?P<usergroup>[^\|>]+))?(\|(?P<alias>[^>]*))?>", self.group_replace, message)
        # XXX: <!date>s not parsed, but humans are unlikely to write those

        message = formatting_replace(message)

        return message

    def format_topic(self, topic):
        return self.format_message(topic).replace("\n", " ")

    def user_replace(self, match):
        # XXX: According to https://api.slack.com/reference/surfaces/formatting,
        # user mentions could have aliases too, but I have never seen that
        prefix = "@" if self.config["formatting"]["prepend_at_to_names"] else ""
        user = self.get_user_by_id(match.groupdict()["user"])

        if user:
            return f"{prefix}{user['profile']['display_name'] or user['name']}"

        return match.group()

    def channel_replace(self, match):
        fields = match.groupdict()

        if fields["alias"]:
            return f'#{fields["alias"]}'

        channel = self.conversations_by_id.get(match.groupdict()["channel"])
        if channel:
            return f'#{channel["name"]}'

        return match.group()

    def group_replace(self, match):
        fields = match.groupdict()

        if fields["alias"]:
            return fields["alias"]

        if fields["usergroup"]:
            usergroup = self.get_usergroup_by_id(fields["usergroup"])
            if usergroup:
                return f'@{usergroup["handle"]}'

        return f'@{fields["special"]}'


def formatting_replace(message):
    code_block_starts = list(re.finditer(rf"(^|{VALID_FORMATTING_SURROUNDINGS})(?P<bt>```)", message, flags=re.M))
    code_block_ends = list(re.finditer(rf"(?P<bt>```)($|{VALID_FORMATTING_SURROUNDINGS})", message, flags=re.M))

    inline_code_starts = list(re.finditer(rf"(^|(?<={VALID_FORMATTING_SURROUNDINGS}))(?P<bt>`)(?![ `])", message, flags=re.M))
    inline_code_ends = list(re.finditer(rf"(?<![ `])(?P<bt>`)(?=$|{VALID_FORMATTING_SURROUNDINGS})", message, flags=re.M))

    code_block_ranges = pair_matches(
        merge_matches(code_block_starts, code_block_ends, "bt"),
        "bt",
    )

    inline_code_ranges = pair_matches(
        merge_matches(inline_code_starts, inline_code_ends, "bt"),
        "bt",
    )

    def format(match):
        begin, end = match.span()

        in_codeblock = in_range(begin, end, code_block_ranges)
        in_inlinecode = in_range(begin, end, inline_code_ranges)

        if in_codeblock or in_inlinecode:
            return match.group()

        matchdict = match.groupdict()

        if matchdict["marker"] == "*":
            replacement = "\x02"
        elif matchdict["marker"] == "_":
            replacement = "\x1d"
        elif matchdict["marker"] == "~":
            replacement = "\x1e"

        return f'{matchdict["prefix"]}{replacement}{matchdict["inner"]}{replacement}{matchdict["suffix"]}'

    message = re.sub(
        rf"(?P<prefix>^|{VALID_FORMATTING_SURROUNDINGS})(?P<marker>[\*_~])(?!\s+)(?P<inner>[^\*_~]+)(?<!\s)(?P=marker)(?P<suffix>$|{VALID_FORMATTING_SURROUNDINGS})",
        format,
        message,
        flags=re.M,
    )

    return message


def merge_matches(a, b, match_group):
    spans = set()
    result = []
    for match in a + b:
        span = match.span(match_group)
        if span not in spans:
            spans.add(span)
            result.append(match)
    return result


def pair_matches(matches, match_group):
    ranges = []
    matches.sort(key=lambda match: match.span(match_group))

    for n in range(0, len(matches), 2):
        # Well this can't be part of any range, sorry.
        if n == (len(matches) - 1):
            log.info(f"Dropping {matches[n]} because it is an odd one out")
            continue

        ranges.append(
            (
                matches[n].span(match_group)[0],
                matches[n + 1].span(match_group)[1] - 1,
            )
        )

    return ranges


def in_range(begin, end, ranges):
    return any([range_begin < begin and end < range_end for (range_begin, range_end) in ranges])


def link_replace(match):
    link = match.groupdict()["link"]
    text = None

    if "|" in link:
        link, text = link.split("|", maxsplit=1)

    scheme = re.search(r"^[a-zA-Z-]+:", link)

    if not scheme:
        return match.group(0)

    if text and text != link:
        # Exception: bare hostname turned link
        if link[len(scheme.group()) : -len(text)] in ("", "//"):
            return text

        # XXX: Might be nice to not render ellipsized URLs
        return f"\x1f{text}\x1f ({link})"
    else:
        return link


if __name__ == "__main__":
    main()
